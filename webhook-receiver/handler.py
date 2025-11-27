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
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_secret_from_lockbox():
    """
    Retrieve SECRET_KEY from Yandex Lockbox.
    In production, use yandexcloud SDK. For now, read from environment.
    """
    # For Cloud Functions, you can use environment variables or Lockbox SDK
    # https://cloud.yandex.ru/docs/lockbox/operations/
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        # Fallback: try to get from Lockbox via environment
        logger.error("SECRET_KEY not found in environment variables")
        raise ValueError("SECRET_KEY not configured")

    return secret_key


def validate_hmac_signature(body: str, signature_header: str, secret_key: str) -> bool:
    """
    Validate HMAC-SHA256 signature.

    Args:
        body: Raw request body (JSON string)
        signature_header: Value from X-Webhook-Signature header (format: sha256=<hex>)
        secret_key: Secret key from Lockbox

    Returns:
        True if signature is valid, False otherwise
    """
    if not signature_header or not signature_header.startswith("sha256="):
        logger.warning("Invalid signature format: missing 'sha256=' prefix")
        return False

    try:
        # Extract hex signature from header
        expected_signature = signature_header[7:]  # Remove 'sha256=' prefix

        # Calculate HMAC signature
        calculated_signature = hmac.new(
            secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Use timing-safe comparison to prevent timing attacks
        is_valid = hmac.compare_digest(calculated_signature, expected_signature)

        if not is_valid:
            logger.warning(
                "Signature mismatch",
                extra={
                    "expected": expected_signature[:10] + "...",
                    "calculated": calculated_signature[:10] + "...",
                },
            )

        return is_valid

    except Exception as e:
        logger.error(f"Error validating signature: {str(e)}")
        return False


def send_to_ymq(message_body: dict, queue_url: str) -> bool:
    """
    Send message to YMQ (Yandex Message Queue).
    YMQ is AWS SQS-compatible.

    Args:
        message_body: Dictionary to send as message body
        queue_url: YMQ queue URL

    Returns:
        True if successful, False otherwise
    """
    try:
        # Initialize SQS client (YMQ is AWS SQS-compatible)
        sqs = boto3.client(
            "sqs",
            endpoint_url="https://message-queue.api.cloud.yandex.net",
            region_name="ru-central1",
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        )

        # Send message to queue
        response = sqs.send_message(
            QueueUrl=queue_url, MessageBody=json.dumps(message_body)
        )

        logger.info(
            "Message sent to YMQ",
            extra={
                "message_id": response.get("MessageId"),
                "log_id": message_body.get("log_id"),
            },
        )

        return True

    except ClientError as e:
        logger.error(
            f"Failed to send message to YMQ: {str(e)}",
            extra={"error_code": e.response.get("Error", {}).get("Code")},
        )
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending to YMQ: {str(e)}")
        return False


def handler(event, context):
    """
    Main Cloud Function handler.

    Expected event structure:
    {
        "httpMethod": "POST",
        "headers": {
            "X-Webhook-Signature": "sha256=abc123..."
        },
        "body": '{"event_type": "payment.success", "data": {...}}'
    }

    Returns:
        HTTP response with status code and body
    """
    try:
        # Extract request details
        http_method = event.get("httpMethod", "POST")
        headers = event.get("headers", {})
        body = event.get("body", "")

        # Normalize header keys (case-insensitive)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        logger.info(
            "Webhook request received",
            extra={"method": http_method, "content_length": len(body)},
        )

        # Get signature from headers
        signature_header = headers_lower.get("x-webhook-signature", "")

        if not signature_header:
            logger.warning("Missing X-Webhook-Signature header")
            return {
                "statusCode": 401,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Missing signature header"}),
            }

        # Validate signature
        secret_key = get_secret_from_lockbox()
        if not validate_hmac_signature(body, signature_header, secret_key):
            logger.warning("Invalid signature - rejecting webhook")
            return {
                "statusCode": 401,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Invalid signature"}),
            }

        # Parse payload to extract event_type
        try:
            payload = json.loads(body)
            event_type = payload.get("event_type", "unknown")
        except json.JSONDecodeError:
            logger.error("Invalid JSON in request body")
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Invalid JSON payload"}),
            }

        # Generate unique log_id
        log_id = str(uuid.uuid4())

        # Prepare message for YMQ
        message = {
            "log_id": log_id,
            "received_at": datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "payload": payload,
            "signature": signature_header,
        }

        # Send to YMQ
        queue_url = os.environ.get("YMQ_QUEUE_URL")
        if not queue_url:
            logger.error("YMQ_QUEUE_URL not configured")
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Queue not configured"}),
            }

        if not send_to_ymq(message, queue_url):
            logger.error("Failed to enqueue message")
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Failed to enqueue message"}),
            }

        # Return success response
        logger.info(
            "Webhook accepted", extra={"log_id": log_id, "event_type": event_type}
        )

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"status": "received", "log_id": log_id}),
        }

    except Exception as e:
        # Catch-all error handler
        logger.error(f"Unexpected error in webhook handler: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error"}),
        }
