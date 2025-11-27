"""
Webhook Processor - Serverless Container
Processes webhook events from YMQ and saves to YDB.
Triggered by YMQ Trigger with batches of up to 10 messages.
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import ydb
import ydb.iam

# Configure structured logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Webhook Processor")

# YDB Configuration
YDB_ENDPOINT = os.environ.get("YDB_ENDPOINT")
YDB_DATABASE = os.environ.get("YDB_DATABASE")


class YMQMessage(BaseModel):
    """Model for YMQ message from trigger"""

    message_id: str
    body: str


class YMQMessageDetails(BaseModel):
    """Model for YMQ trigger message details"""

    message: YMQMessage


class YMQTriggerPayload(BaseModel):
    """Model for YMQ trigger request"""

    messages: List[Dict[str, Any]]


def get_ydb_driver():
    """
    Create and return YDB driver instance.
    Uses service account authentication in Yandex Cloud environment.
    """
    if not YDB_ENDPOINT or not YDB_DATABASE:
        raise ValueError("YDB_ENDPOINT and YDB_DATABASE must be set")

    # Create driver with service account authentication
    driver_config = ydb.DriverConfig(
        endpoint=YDB_ENDPOINT,
        database=YDB_DATABASE,
        credentials=ydb.iam.MetadataUrlCredentials(),  # Use SA from container metadata
    )

    driver = ydb.Driver(driver_config)

    try:
        driver.wait(timeout=5, fail_fast=True)
        logger.info("Successfully connected to YDB")
    except TimeoutError:
        logger.error("Failed to connect to YDB: timeout")
        raise

    return driver


def insert_webhook_log(
    driver: ydb.Driver,
    log_id: str,
    received_at: str,
    event_type: str,
    payload_json: dict,
    signature: str,
) -> bool:
    """
    Insert webhook log entry into YDB.

    Args:
        driver: YDB driver instance
        log_id: Unique log identifier (UUID)
        received_at: ISO timestamp when webhook was received
        event_type: Type of event
        payload_json: Full JSON payload
        signature: HMAC signature from header

    Returns:
        True if successful, False otherwise
    """
    try:
        session = driver.table_client.session().create()

        # Convert ISO timestamp to YDB Timestamp
        # YDB expects microseconds since epoch
        dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
        received_at_timestamp = int(dt.timestamp() * 1_000_000)

        # Current timestamp for processed_at
        processed_at_timestamp = int(datetime.now(datetime.timezone.utc).timestamp() * 1_000_000)

        # Prepare query
        query = """
        DECLARE $log_id AS Utf8;
        DECLARE $received_at AS Timestamp;
        DECLARE $event_type AS Utf8;
        DECLARE $payload_json AS JsonDocument;
        DECLARE $signature AS Utf8;
        DECLARE $processed_at AS Timestamp;
        
        UPSERT INTO webhook_logs (
            log_id,
            received_at,
            event_type,
            payload_json,
            signature,
            processed_at
        ) VALUES (
            $log_id,
            $received_at,
            $event_type,
            $payload_json,
            $signature,
            $processed_at
        );
        """

        prepared_query = session.prepare(query)

        # Execute query
        session.transaction(ydb.SerializableReadWrite()).execute(
            prepared_query,
            {
                "$log_id": log_id,
                "$received_at": received_at_timestamp,
                "$event_type": event_type or "unknown",
                "$payload_json": json.dumps(payload_json),
                "$signature": signature,
                "$processed_at": processed_at_timestamp,
            },
            commit_tx=True,
        )

        logger.info(
            "Inserted webhook log into YDB",
            extra={"log_id": log_id, "event_type": event_type},
        )

        return True

    except Exception as e:
        logger.error(
            f"Error inserting to YDB: {str(e)}", extra={"log_id": log_id}, exc_info=True
        )
        return False
    finally:
        session.close()


def process_message(driver: ydb.Driver, message_body: str) -> bool:
    """
    Process a single message from YMQ.

    Args:
        driver: YDB driver instance
        message_body: JSON string from YMQ message

    Returns:
        True if successful, False otherwise
    """
    try:
        # Parse message body
        data = json.loads(message_body)

        log_id = data.get("log_id")
        received_at = data.get("received_at")
        event_type = data.get("event_type")
        payload = data.get("payload", {})
        signature = data.get("signature")

        if not log_id or not received_at:
            logger.error("Invalid message: missing log_id or received_at")
            return False

        logger.info(
            "Processing message", extra={"log_id": log_id, "event_type": event_type}
        )

        # Insert into YDB
        success = insert_webhook_log(
            driver=driver,
            log_id=log_id,
            received_at=received_at,
            event_type=event_type,
            payload_json=payload,
            signature=signature,
        )

        return success

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in message body: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}", exc_info=True)
        return False


@app.get("/")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "webhook-processor"}


@app.post("/ymq-trigger")
async def process_ymq_trigger(request: Request):
    """
    Endpoint called by YMQ Trigger.
    Receives batches of up to 10 messages.

    Expected payload format:
    {
        "messages": [
            {
                "event_metadata": {...},
                "details": {
                    "message": {
                        "message_id": "abc-123",
                        "body": "{\"log_id\":\"...\",\"event_type\":\"...\",\"payload\":{...}}"
                    }
                }
            }
        ]
    }
    """
    try:
        # Parse request body
        payload = await request.json()

        messages = payload.get("messages", [])
        logger.info(f"Received batch of {len(messages)} messages from YMQ trigger")

        if not messages:
            logger.warning("No messages in trigger payload")
            return {"status": "success", "processed": 0}

        # Initialize YDB driver
        driver = get_ydb_driver()

        # Process each message
        success_count = 0
        error_count = 0

        for msg in messages:
            try:
                # Extract message body from YMQ trigger format
                details = msg.get("details", {})
                message = details.get("message", {})
                message_id = message.get("message_id", "unknown")
                body = message.get("body", "{}")

                logger.info("Processing message %s", message_id)

                # Process message
                if process_message(driver, body):
                    success_count += 1
                else:
                    error_count += 1
                    # Log error but continue processing other messages
                    logger.error("Failed to process message %s", message_id)

            except Exception as e:
                error_count += 1
                logger.error(
                    f"Error processing individual message: {str(e)}", exc_info=True
                )
                # Continue processing other messages
                continue

        # Close driver
        driver.stop()

        logger.info(
            "Batch processing complete: %d success, %d errors",
            success_count, error_count
        )

        # Return 200 OK to acknowledge messages
        # Even if some failed, we don't want YMQ to retry the entire batch
        return {"status": "success", "processed": success_count, "errors": error_count}

    except Exception as e:
        logger.error(f"Error in YMQ trigger handler: {str(e)}", exc_info=True)
        # Return 500 to trigger retry
        raise HTTPException(status_code=500, detail="Processing error")


@app.post("/simulate-error")
async def simulate_error():
    """
    Endpoint to simulate an error for testing logging.
    Call this to test ERROR level logging in Cloud Logging.
    """
    logger.error(
        "Simulated error for testing",
        extra={"error_type": "simulation", "severity": "ERROR"},
    )
    return {"status": "error_logged"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
