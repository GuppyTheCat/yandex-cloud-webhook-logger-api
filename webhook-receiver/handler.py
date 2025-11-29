"""
Webhook Receiver Cloud Function
Fast webhook receiver that validates HMAC signature and enqueues to YMQ.
Target response time: < 200ms
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, cast

import boto3  # type: ignore
import yandexcloud  # type: ignore
from yandex.cloud.lockbox.v1.payload_service_pb2 import GetPayloadRequest  # type: ignore
from yandex.cloud.lockbox.v1.payload_service_pb2_grpc import PayloadServiceStub  # type: ignore

# --- Structured Logging Setup ---


class PythonJSONFormatter(logging.Formatter):
    """
    Formatter to output logs as JSON for Yandex Cloud Logging.
    """

    def format(self, record: logging.LogRecord) -> str:
        json_log = {
            "level": record.levelname,
            "message": record.getMessage(),
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
        }

        # Attributes to exclude
        base_attributes = {
            "args",
            "asctime",
            "created",
            "exc_info",
            "exc_text",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "message",
            "msg",
            "name",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "thread",
            "threadName",
        }

        for key, value in record.__dict__.items():
            if key not in base_attributes and not key.startswith("_"):
                json_log[key] = value

        return json.dumps(json_log)


# Configure root logger
handler_log = logging.StreamHandler(sys.stdout)
handler_log.setFormatter(PythonJSONFormatter())
logger = logging.getLogger()
logger.handlers = []
logger.addHandler(handler_log)
logger.setLevel(logging.INFO)


# --- Configuration ---


class Config:
    """Application configuration."""

    LOCKBOX_SECRET_ID: str = os.environ.get("LOCKBOX_SECRET_ID", "")
    YMQ_QUEUE_URL: str = os.environ.get("YMQ_QUEUE_URL", "")
    AWS_ACCESS_KEY_ID: str = os.environ.get("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

    @classmethod
    def validate(cls) -> None:
        if not cls.LOCKBOX_SECRET_ID:
            raise ValueError("LOCKBOX_SECRET_ID is required")
        if not cls.YMQ_QUEUE_URL:
            raise ValueError("YMQ_QUEUE_URL is required")


# --- Services ---


class SecretService:
    """Handles retrieval and caching of secrets from Lockbox."""

    _cached_secret_key: str | None = None

    @classmethod
    def get_secret_key(cls, iam_token: str | None) -> str:
        """
        Get webhook secret key, using cache if available.
        """
        if cls._cached_secret_key:
            return cls._cached_secret_key

        if not Config.LOCKBOX_SECRET_ID:
            raise ValueError("LOCKBOX_SECRET_ID not configured")

        logger.info("Fetching secret from Lockbox (Cold Start / Cache Miss)")
        try:
            # Initialize SDK with IAM token from context
            sdk: Any = yandexcloud.SDK(iam_token=iam_token)  # type: ignore
            lockbox_client: Any = sdk.client(PayloadServiceStub)  # type: ignore
            request = GetPayloadRequest(secret_id=Config.LOCKBOX_SECRET_ID)
            response = lockbox_client.Get(request)

            for entry in response.entries:
                if entry.key == "SECRET_KEY":
                    cls._cached_secret_key = str(entry.text_value)
                    return cls._cached_secret_key

            raise ValueError("SECRET_KEY not found in Lockbox secret")
        except Exception as e:
            logger.error(f"Lockbox error: {e}")
            raise


class QueueService:
    """Handles interaction with Yandex Message Queue."""

    _sqs_client: Any = None

    @classmethod
    def get_client(cls) -> Any:
        """Initialize and return cached boto3 client."""
        if cls._sqs_client:
            return cls._sqs_client

        try:
            client: Any = boto3.client(  # type: ignore
                "sqs",
                endpoint_url="https://message-queue.api.cloud.yandex.net",
                region_name="ru-central1",
                # Credentials auto-picked from env vars:
                # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
            )
            cls._sqs_client = client
            return cls._sqs_client  # type: ignore
        except Exception as e:
            logger.error(f"Failed to init YMQ client: {e}")
            raise

    @classmethod
    def enqueue_message(cls, message: dict[str, Any]) -> None:
        """Send message to YMQ."""
        client = cls.get_client()
        if not Config.YMQ_QUEUE_URL:
            raise ValueError("YMQ_QUEUE_URL not configured")

        client.send_message(
            QueueUrl=Config.YMQ_QUEUE_URL, MessageBody=json.dumps(message)
        )


class WebhookValidator:
    """Validates webhook signatures."""

    @staticmethod
    def validate_signature(body: str, signature_header: str, secret_key: str) -> bool:
        """
        Validate HMAC-SHA256 signature using timing-safe comparison.
        """
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        try:
            expected_signature = signature_header[7:]  # Remove 'sha256=' prefix

            # Calculate HMAC signature
            calculated_signature = hmac.new(
                secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(calculated_signature, expected_signature)
        except Exception as e:
            logger.error(f"Signature validation error: {e}")
            return False


# --- Main Handler ---


def build_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    """Helper to build standard API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


# Initialize client globally to potentially benefit from warm starts
try:
    QueueService.get_client()
except Exception:
    pass  # Ignore init errors at module level


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Main Cloud Function handler.
    """
    try:
        # 1. Extract Request
        headers = cast(dict[str, Any], event.get("headers", {}))
        body = cast(str, event.get("body", ""))

        # Normalize headers to lower case
        headers_lower = {k.lower(): v for k, v in headers.items()}
        signature_header = str(headers_lower.get("x-webhook-signature", ""))

        # 2. Get Auth Token (from context)
        iam_token = None
        if context and hasattr(context, "token"):
            iam_token = context.token.get("access_token")

        # 3. Retrieve Secret (from Lockbox)
        try:
            secret_key = SecretService.get_secret_key(iam_token)
        except ValueError as e:
            logger.error(f"Configuration/Auth error: {e}")
            return build_response(500, {"error": "Configuration error"})
        except Exception as e:
            logger.error(f"Secret retrieval failed: {e}")
            return build_response(500, {"error": "Internal setup error"})

        # 4. Validate Signature
        if not WebhookValidator.validate_signature(body, signature_header, secret_key):
            logger.warning("Invalid signature", extra={"signature": signature_header})
            return build_response(401, {"error": "Invalid signature"})

        # 5. Parse Payload
        try:
            payload = json.loads(body)
            event_type = payload.get("event_type", "unknown")
        except json.JSONDecodeError:
            return build_response(400, {"error": "Invalid JSON payload"})

        # 6. Prepare Message
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        message = {
            "log_id": log_id,
            "received_at": timestamp,
            "event_type": event_type,
            "payload": payload,
            "signature": signature_header,
        }

        # 7. Enqueue
        try:
            QueueService.enqueue_message(message)
            logger.info(
                "Webhook accepted",
                extra={"log_id": log_id, "event_type": event_type},
            )
            return build_response(200, {"status": "received", "log_id": log_id})

        except Exception as e:
            logger.error(f"YMQ Error: {e}", exc_info=True)
            # Return 500 to trigger retry from sender
            return build_response(500, {"error": "Failed to enqueue message"})

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return build_response(500, {"error": "Internal server error"})
