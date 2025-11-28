"""
Logs API Cloud Function
Retrieves webhook event history from YDB with filtering and pagination.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, cast

import ydb  # type: ignore
import ydb.iam  # type: ignore

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


handler_log = logging.StreamHandler(sys.stdout)
handler_log.setFormatter(PythonJSONFormatter())
logger = logging.getLogger()
logger.handlers = []
logger.addHandler(handler_log)
logger.setLevel(logging.INFO)


# --- Configuration ---


class Config:
    """Application configuration."""

    YDB_ENDPOINT: str = os.environ.get("YDB_ENDPOINT", "")
    YDB_DATABASE: str = os.environ.get("YDB_DATABASE", "")

    @classmethod
    def validate(cls) -> None:
        if not cls.YDB_ENDPOINT or not cls.YDB_DATABASE:
            raise ValueError("YDB_ENDPOINT and YDB_DATABASE must be set")


# --- Database Layer ---


class YDBDriver:
    """Singleton wrapper for YDB Driver to enable warm start."""

    _driver: ydb.Driver | None = None

    @classmethod
    def get_driver(cls) -> ydb.Driver:
        if cls._driver:
            return cls._driver

        Config.validate()

        logger.info("Initializing YDB driver (Cold Start)")
        try:
            driver_config = ydb.DriverConfig(
                endpoint=Config.YDB_ENDPOINT,
                database=Config.YDB_DATABASE,
                credentials=ydb.iam.MetadataUrlCredentials(),
            )

            driver = ydb.Driver(driver_config)
            driver.wait(timeout=5, fail_fast=True)  # type: ignore

            cls._driver = driver
            logger.info("Successfully connected to YDB")
            return cls._driver

        except Exception as e:
            logger.error(f"Failed to connect to YDB: {e}")
            raise


class LogRepository:
    """Data access layer for Webhook Logs."""

    def __init__(self, driver: ydb.Driver):
        self.driver = driver

    def get_logs(
        self, limit: int = 50, event_type: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Query webhook logs with optional filtering.
        """
        try:
            # We create a session for each request.
            # In a high-load scenario, we might want a session pool,
            # but for Cloud Functions, this is often sufficient per-invocation.
            session = self.driver.table_client.session().create()  # type: ignore

            query_params: dict[str, Any] = {"$limit": limit}

            if event_type:
                logger.info(f"Querying with event_type filter: {event_type}")
                query = """
                DECLARE $event_type AS Utf8;
                DECLARE $limit AS Uint64;

                SELECT
                    log_id, received_at, event_type, payload_json, signature, processed_at
                FROM webhook_logs
                WHERE event_type = $event_type
                ORDER BY received_at DESC
                LIMIT $limit;
                """
                query_params["$event_type"] = event_type
            else:
                logger.info(f"Querying without event_type filter, limit: {limit}")
                query = """
                DECLARE $limit AS Uint64;

                SELECT
                    log_id, received_at, event_type, payload_json, signature, processed_at
                FROM webhook_logs
                ORDER BY received_at DESC
                LIMIT $limit;
                """

            # Execute
            prepared_query: Any = session.prepare(query)  # type: ignore
            result_sets = session.transaction(ydb.SerializableReadWrite()).execute(  # type: ignore
                prepared_query,
                query_params,
                commit_tx=True,
            )

            return self._parse_results(result_sets[0].rows)  # type: ignore

        except Exception as e:
            logger.error(f"Error querying YDB: {e}", exc_info=True)
            raise

    def _parse_results(self, rows: Any) -> tuple[list[dict[str, Any]], int]:
        """Convert YDB rows to list of dictionaries."""
        logs: list[dict[str, Any]] = []

        for row in rows:
            r = cast(Any, row)  # type: ignore
            log_entry: dict[str, Any] = {
                "log_id": self._decode_str(r.log_id),
                "received_at": self._ts_to_iso(r.received_at),
                "event_type": self._decode_str(r.event_type),
                "payload_json": json.loads(r.payload_json) if r.payload_json else {},
                "signature": self._decode_str(r.signature),
                "processed_at": self._ts_to_iso(r.processed_at)
                if r.processed_at
                else None,
            }
            logs.append(log_entry)

        return logs, len(logs)

    @staticmethod
    def _ts_to_iso(timestamp_us: int) -> str:
        """Convert YDB timestamp (microseconds) to ISO string."""
        dt = datetime.fromtimestamp(timestamp_us / 1_000_000, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _decode_str(value: Any) -> str:
        """Safe string decoding for YDB bytes."""
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value) if value is not None else ""


# --- Handler ---


def build_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    """Helper to build standard API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",  # CORS
        },
        "body": json.dumps(body),
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Main Cloud Function handler for logs API.
    """
    try:
        # 1. Parse Request
        query_params = cast(
            dict[str, Any], event.get("queryStringParameters", {}) or {}
        )

        # Parse limit
        try:
            limit = int(query_params.get("limit", "50"))
            limit = max(1, min(limit, 100))  # Clamp between 1 and 100
        except ValueError:
            limit = 50

        event_type = query_params.get("event_type")

        logger.info(
            "Logs query request", extra={"limit": limit, "event_type": event_type}
        )

        # 2. Get Data
        driver = YDBDriver.get_driver()
        repo = LogRepository(driver)

        logs, total = repo.get_logs(limit=limit, event_type=event_type)

        # 3. Response
        return build_response(200, {"logs": logs, "total": total})

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return build_response(500, {"error": "Database configuration error"})
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return build_response(500, {"error": "Internal server error"})
