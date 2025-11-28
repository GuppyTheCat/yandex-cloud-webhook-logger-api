"""
Webhook Receiver Cloud Function
Fast webhook receiver that validates HMAC signature and enqueues to YMQ.
Target response time: < 200ms
"""

import hmac
import hashlib
import json
import uuid
import os
import logging
import sys
from datetime import datetime, timezone
from typing import Any, cast
import boto3  # type: ignore
# from botocore.exceptions import ClientError
import yandexcloud  # type: ignore
from yandex.cloud.lockbox.v1.payload_service_pb2 import GetPayloadRequest  # type: ignore
from yandex.cloud.lockbox.v1.payload_service_pb2_grpc import PayloadServiceStub  # type: ignore


# --- Structured Logging Setup ---
class PythonJSONFormatter(logging.Formatter):
    """
    Formatter to output logs as JSON for Yandex Cloud Logging.
    """

    def format(self, record: logging.LogRecord):
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

        # Add extra fields from the record (those passed via extra={...})
        # We filter out standard LogRecord attributes to avoid clutter
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
logger.handlers = []  # Remove default handlers
logger.addHandler(handler_log)
logger.setLevel(logging.INFO)


# --- Global State (Warm Start Caching) ---
sqs_client = None
cached_secret_key: str | None = None


def init_ymq_client():
    """
    Initialize global YMQ client if not exists.
    Using global variable ensures we only connect once per container instance (Warm Start).
    """
    global sqs_client
    if sqs_client:
        return sqs_client

    # Credentials should be provided via environment variables
    # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
    # If not set, boto3 will fail gracefully

    try:
        sqs_client = boto3.client(
            "sqs",
            endpoint_url="https://message-queue.api.cloud.yandex.net",
            region_name="ru-central1",
        )
        return sqs_client
    except Exception as e:
        logger.error(f"Failed to init YMQ client: {str(e)}")
        return None


def get_cached_secret(iam_token: str):
    """
    Retrieve SECRET_KEY from cache or Lockbox.
    """
    global cached_secret_key
    if cached_secret_key:
        return cached_secret_key

    lockbox_secret_id = os.environ.get("LOCKBOX_SECRET_ID")
    if not lockbox_secret_id:
        logger.error("LOCKBOX_SECRET_ID not configured")
        raise ValueError("LOCKBOX_SECRET_ID not configured")

    logger.info("Fetching secret from Lockbox (Cold Start)")
    try:
        sdk = yandexcloud.SDK(iam_token=iam_token)  # type: ignore
        lockbox_client = sdk.client(PayloadServiceStub)
        request = GetPayloadRequest(secret_id=lockbox_secret_id)
        response = lockbox_client.Get(request)

        for entry in response.entries:
            if entry.key == "SECRET_KEY":
                cached_secret_key = entry.text_value
                return cached_secret_key

        raise ValueError("SECRET_KEY key not found in Lockbox secret")

    except Exception as e:
        logger.error(f"Lockbox error: {str(e)}")
        raise


def validate_hmac_signature(body: str, signature_header: str, secret_key: str) -> bool:
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
        logger.error(f"Signature validation error: {str(e)}")
        return False


def handler(event: dict[str, Any], context: Any):
    """
    Main Cloud Function handler.
    """
    try:
        # 1. Extract request details
        headers = cast(dict[str, Any], event.get("headers", {}))
        body = cast(str, event.get("body", ""))

        # Normalize headers
        headers_lower = {k.lower(): v for k, v in headers.items()}
        signature_header = str(headers_lower.get("x-webhook-signature", ""))

        # 2. Authentication (IAM Token for Lockbox)
        iam_token = None
        if context and hasattr(context, "token"):
            iam_token = context.token.get("access_token")

        # Fallback for local testing
        if not iam_token:
            iam_token = os.environ.get("IAM_TOKEN")

        # 3. Get Secret (Cached or Fresh)
        try:
            if not iam_token:
                raise ValueError("IAM token not available")
            secret_key = get_cached_secret(iam_token)
        except Exception:
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Configuration error"}),
            }

        # 4. Validate Signature
        if not validate_hmac_signature(body, signature_header, secret_key):
            logger.warning("Invalid signature", extra={"signature": signature_header})
            return {
                "statusCode": 401,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Invalid signature"}),
            }

        # 5. Parse Payload (Minimal check)
        try:
            payload = json.loads(body)
            event_type = payload.get("event_type", "unknown")
        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Invalid JSON payload"}),
            }

        # 6. Enqueue to YMQ
        log_id = str(uuid.uuid4())
        message = {
            "log_id": log_id,
            "received_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "event_type": event_type,
            "payload": payload,
            "signature": signature_header,
        }

        queue_url = os.environ.get("YMQ_QUEUE_URL")
        sqs = init_ymq_client()

        if sqs and queue_url:
            try:
                sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))
                logger.info(
                    "Webhook accepted",
                    extra={"log_id": log_id, "event_type": event_type},
                )
            except Exception as e:
                logger.error(f"YMQ Error: {str(e)}")
                # Decide if we want to fail hard or return 200 accepted but failed to process?
                # Task requires guaranteed processing, so 500 is better so sender retries.
                return {
                    "statusCode": 500,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"error": "Failed to enqueue message"}),
                }
        else:
            logger.error("YMQ configuration missing (queue_url or client)")
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Configuration error"}),
            }

        # 7. Success Response
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"status": "received", "log_id": log_id}),
        }

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error"}),
        }
