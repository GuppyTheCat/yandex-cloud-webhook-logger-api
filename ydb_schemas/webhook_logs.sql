-- YDB Schema for Webhook Logger API
-- Create this table in your YDB serverless database via the YDB Console query editor

CREATE TABLE webhook_logs (
    log_id Utf8 NOT NULL,              -- UUID события
    received_at Timestamp NOT NULL,     -- Когда получен webhook
    event_type Utf8,                    -- Тип события (из JSON payload)
    payload_json JsonDocument,          -- Полный JSON payload
    signature Utf8,                     -- HMAC signature из headers
    processed_at Timestamp,             -- Когда обработан (NULL до обработки)
    PRIMARY KEY (log_id)
);
