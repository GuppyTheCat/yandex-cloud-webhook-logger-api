"""
Webhook Processor - Serverless Container
Processes webhook events from YMQ and saves to YDB.
Triggered by YMQ Trigger with batches of up to 10 messages.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import ydb  # type: ignore
import ydb.iam  # type: ignore
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class Config:
    """Application configuration from environment variables."""

    YDB_ENDPOINT: str = os.environ.get("YDB_ENDPOINT", "")
    YDB_DATABASE: str = os.environ.get("YDB_DATABASE", "")

    @classmethod
    def validate(cls) -> None:
        """Validate that required configuration is present."""
        if not cls.YDB_ENDPOINT or not cls.YDB_DATABASE:
            raise ValueError(
                "YDB_ENDPOINT and YDB_DATABASE environment variables must be set"
            )


# Global YDB Driver and Session Pool
_ydb_driver: Optional[ydb.Driver] = None
_ydb_session_pool: Optional[ydb.SessionPool] = None


def get_ydb_pool() -> ydb.SessionPool:
    """Dependency to get the global YDB session pool."""
    if _ydb_session_pool is None:
        raise RuntimeError("YDB Session Pool not initialized")
    return _ydb_session_pool


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI.
    Handles startup and shutdown events, specifically YDB driver lifecycle.
    """
    global _ydb_driver, _ydb_session_pool

    Config.validate()
    logger.info("Initializing YDB driver...")

    try:
        # Create driver with service account authentication
        driver_config = ydb.DriverConfig(
            endpoint=Config.YDB_ENDPOINT,
            database=Config.YDB_DATABASE,
            credentials=ydb.iam.MetadataUrlCredentials(),  # Use SA from container metadata
        )

        driver = ydb.Driver(driver_config)
        # Wait for connection
        driver.wait(timeout=5, fail_fast=True)  # type: ignore

        _ydb_driver = driver
        _ydb_session_pool = ydb.SessionPool(driver)
        logger.info("Successfully connected to YDB")

        yield

    except Exception as e:
        logger.error(f"Failed to initialize YDB driver: {e}")
        raise
    finally:
        if _ydb_session_pool:
            logger.info("Stopping YDB session pool...")
            _ydb_session_pool.stop()  # type: ignore
        if _ydb_driver:
            logger.info("Stopping YDB driver...")
            _ydb_driver.stop()  # type: ignore


# --- Domain Models ---


class WebhookPayload(BaseModel):
    """Standardized webhook payload structure."""

    log_id: str
    received_at: str
    event_type: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None


class ProcessingResult(BaseModel):
    """Result of batch processing."""

    status: str
    processed: int
    errors: int = 0


# --- Repository Layer ---


class WebhookRepository:
    """Abstration for Webhook Log storage operations."""

    def __init__(self, pool: ydb.SessionPool):
        self.pool = pool

    def insert_log(self, webhook_data: WebhookPayload) -> bool:
        """
        Insert a webhook log entry into YDB.
        """
        try:
            # Use a synchronous wrapper for the transaction
            return self.pool.retry_operation_sync(  # type: ignore
                self._insert_tx,
                None,  # retry_settings
                webhook_data,
            )
        except Exception as e:
            logger.error(
                f"Error inserting to YDB: {e}",
                extra={"log_id": webhook_data.log_id},
                exc_info=True,
            )
            return False

    def _insert_tx(self, session: ydb.Session, webhook_data: WebhookPayload) -> bool:
        """Transaction logic for inserting a log."""
        # Parse received_at
        try:
            dt = datetime.fromisoformat(webhook_data.received_at.replace("Z", "+00:00"))
            received_at_timestamp = int(dt.timestamp() * 1_000_000)
        except ValueError:
            logger.error(f"Invalid timestamp format: {webhook_data.received_at}")
            return False

        processed_at_timestamp = int(datetime.now(timezone.utc).timestamp() * 1_000_000)

        query = """
        DECLARE $log_id AS Utf8;
        DECLARE $received_at AS Timestamp;
        DECLARE $event_type AS Utf8;
        DECLARE $payload_json AS JsonDocument;
        DECLARE $signature AS Utf8;
        DECLARE $processed_at AS Timestamp;

        UPSERT INTO webhook_logs (
            log_id, received_at, event_type, payload_json, signature, processed_at
        ) VALUES (
            $log_id, $received_at, $event_type, $payload_json, $signature, $processed_at
        );
        """

        prepared_query: Any = session.prepare(query)  # type: ignore

        session.transaction(ydb.SerializableReadWrite()).execute(  # type: ignore
            prepared_query,
            {
                "$log_id": webhook_data.log_id,
                "$received_at": received_at_timestamp,
                "$event_type": webhook_data.event_type or "unknown",
                "$payload_json": json.dumps(webhook_data.payload),
                "$signature": webhook_data.signature or "",
                "$processed_at": processed_at_timestamp,
            },
            commit_tx=True,
        )
        return True


# --- Service/Controller Layer ---

app = FastAPI(title="Webhook Processor", lifespan=lifespan)


def process_single_message(repo: WebhookRepository, message_body: str) -> bool:
    """
    Parse and process a single message body.
    """
    try:
        data = json.loads(message_body)

        # Validate using Pydantic model
        # Note: The message body structure matches what we expect in WebhookPayload
        # except 'payload' field in JSON might correspond to WebhookPayload.payload

        # Flexible parsing to handle potential structure variations
        webhook = WebhookPayload(
            log_id=data.get("log_id"),
            received_at=data.get("received_at"),
            event_type=data.get("event_type"),
            payload=data.get("payload", {}),
            signature=data.get("signature"),
        )

        logger.info(
            "Processing message",
            extra={"log_id": webhook.log_id, "event_type": webhook.event_type},
        )

        success = repo.insert_log(webhook)
        if success:
            logger.info("Successfully saved log", extra={"log_id": webhook.log_id})
        return success

    except json.JSONDecodeError:
        logger.error("Invalid JSON in message body")
        return False
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        return False


@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "webhook-processor"}


@app.post("/ymq-trigger", response_model=ProcessingResult)
async def process_ymq_trigger(
    request: Request, pool: ydb.SessionPool = Depends(get_ydb_pool)
):
    """
    Endpoint called by YMQ Trigger.
    Receives batches of up to 10 messages.
    """
    try:
        body = await request.json()
        messages = body.get("messages", [])

        logger.info(f"Received batch of {len(messages)} messages")

        if not messages:
            return ProcessingResult(status="success", processed=0)

        repo = WebhookRepository(pool)
        success_count = 0
        error_count = 0

        for msg in messages:
            try:
                details = msg.get("details", {})
                message_meta = details.get("message", {})
                message_body = message_meta.get("body", "{}")
                message_id = message_meta.get("message_id", "unknown")

                if process_single_message(repo, message_body):
                    success_count += 1
                else:
                    error_count += 1
                    logger.warning(f"Failed to process message {message_id}")

            except Exception as e:
                error_count += 1
                logger.error(f"Unexpected error in loop: {e}", exc_info=True)

        logger.info("Batch complete: %d success, %d errors", success_count, error_count)

        # Always return 200 OK to YMQ to confirm receipt/processing of the batch
        # unless we want to force a retry of the WHOLE batch
        # (usually not desired for partial failures)
        return ProcessingResult(
            status="success", processed=success_count, errors=error_count
        )

    except Exception as e:
        logger.error(f"Critical error in trigger handler: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.post("/simulate-error")
async def simulate_error():
    """Test endpoint for error logging."""
    logger.error(
        "Simulated error for testing",
        extra={"error_type": "simulation", "severity": "ERROR"},
    )
    return {"status": "error_logged"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
