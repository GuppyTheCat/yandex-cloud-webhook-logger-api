"""
Logs API Cloud Function
Retrieves webhook event history from YDB with filtering and pagination.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, cast
import ydb  # type: ignore
import ydb.iam  # type: ignore

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# YDB Configuration
YDB_ENDPOINT = os.environ.get("YDB_ENDPOINT")
YDB_DATABASE = os.environ.get("YDB_DATABASE")


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
        credentials=ydb.iam.MetadataUrlCredentials(),
    )

    driver = ydb.Driver(driver_config)

    try:
        driver.wait(timeout=5, fail_fast=True)  # type: ignore
        logger.info("Successfully connected to YDB")
    except TimeoutError:
        logger.error("Failed to connect to YDB: timeout")
        raise

    return driver


def timestamp_to_iso(timestamp_us: int) -> str:
    """Convert YDB timestamp (microseconds) to ISO string"""
    dt = datetime.fromtimestamp(timestamp_us / 1_000_000, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def query_webhook_logs(
    driver: ydb.Driver, limit: int = 50, event_type: str | None = None
) -> tuple[list[dict[str, Any]], int]:
    """
    Query webhook logs from YDB.

    Args:
        driver: YDB driver instance
        limit: Maximum number of results (default 50, max 100)
        event_type: Optional filter by event type

    Returns:
        Tuple of (logs list, total count)
    """
    try:
        session = driver.table_client.session().create()  # type: ignore

        # Build query based on filters - check for None and empty string
        if event_type is not None and event_type != "":
            logger.info(f"Querying with event_type filter: {event_type}")
            query = """
            DECLARE $event_type AS Utf8;
            DECLARE $limit AS Uint64;

            SELECT
                log_id,
                received_at,
                event_type,
                payload_json,
                signature,
                processed_at
            FROM webhook_logs
            WHERE event_type = $event_type
            ORDER BY received_at DESC
            LIMIT $limit;
            """
            params = {"$event_type": event_type, "$limit": limit}
        else:
            logger.info(f"Querying without event_type filter, limit: {limit}")
            query = """
            DECLARE $limit AS Uint64;

            SELECT
                log_id,
                received_at,
                event_type,
                payload_json,
                signature,
                processed_at
            FROM webhook_logs
            ORDER BY received_at DESC
            LIMIT $limit;
            """
            params = {"$limit": limit}

        logger.info(f"Executing query with params: {params}")

        # Prepare and execute query
        prepared_query: Any = session.prepare(query)  # type: ignore
        result_sets = session.transaction(ydb.SerializableReadWrite()).execute(  # type: ignore
            prepared_query, params, commit_tx=True
        )

        # Parse results
        logs: list[dict[str, Any]] = []
        for row in result_sets[0].rows:  # type: ignore
            r = cast(Any, row)
            log_entry: dict[str, Any] = {
                "log_id": r.log_id.decode("utf-8")
                if isinstance(r.log_id, bytes)
                else r.log_id,
                "received_at": timestamp_to_iso(r.received_at),
                "event_type": r.event_type.decode("utf-8")
                if isinstance(r.event_type, bytes)
                else r.event_type,
                "payload_json": json.loads(r.payload_json)
                if r.payload_json
                else {},
                "processed_at": timestamp_to_iso(r.processed_at)
                if r.processed_at
                else None,
            }
            logs.append(log_entry)

        total = len(logs)

        logger.info(
            "Retrieved %d webhook logs",
            total,
            extra={"event_type": event_type, "limit": limit},
        )

        return logs, total

    except Exception as e:
        logger.error(f"Error querying YDB: {str(e)}", exc_info=True)
        raise


def handler(event: dict[str, Any], context: Any):
    """
    Main Cloud Function handler for logs API.

    GET /webhook/logs?limit=50&event_type=payment.success

    Query Parameters:
        - limit: Number of results (default 50, max 100)
        - event_type: Filter by event type (optional)

    Returns:
        JSON response with logs array and total count
    """
    try:
        # Extract query parameters
        query_params = cast(dict[str, Any], event.get("queryStringParameters", {}) or {})

        # Parse limit parameter
        limit_str = query_params.get("limit", "50")
        try:
            limit = int(limit_str)
            # Enforce max limit
            if limit > 100:
                limit = 100
            if limit < 1:
                limit = 1
        except ValueError:
            limit = 50

        # Parse event_type filter
        event_type = query_params.get("event_type")

        logger.info(
            "Logs query request", extra={"limit": limit, "event_type": event_type}
        )

        # Connect to YDB and query logs
        driver = get_ydb_driver()

        try:
            logs, total = query_webhook_logs(
                driver=driver, limit=limit, event_type=event_type
            )
        finally:
            driver.stop()

        # Return response
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",  # Enable CORS for web clients
            },
            "body": json.dumps({"logs": logs, "total": total}),
        }

    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Database configuration error"}),
        }
    except Exception as e:
        logger.error(f"Error in logs handler: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error"}),
        }
