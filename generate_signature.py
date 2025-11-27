#!/usr/bin/env python3
"""
HMAC Signature Generator
Helper script to generate valid HMAC-SHA256 signatures for testing webhooks.

Usage:
    python3 generate_signature.py '{"event_type":"test","data":{}}' "your-secret-key"

Or interactively:
    python3 generate_signature.py
"""

import sys
import hmac
import hashlib
import json


def generate_signature(payload: str, secret_key: str) -> str:
    """
    Generate HMAC-SHA256 signature for a payload.

    Args:
        payload: JSON string payload
        secret_key: Secret key for HMAC

    Returns:
        Signature in format "sha256=<hex>"
    """
    signature = hmac.new(
        secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return f"sha256={signature}"


def main():
    """Main function for interactive or CLI usage"""

    if len(sys.argv) == 3:
        # CLI mode
        payload = sys.argv[1]
        secret_key = sys.argv[2]
    else:
        # Interactive mode
        print("=== HMAC Signature Generator ===\n")

        # Get payload
        print("Enter JSON payload (or press Enter for default test payload):")
        payload_input = input().strip()

        if not payload_input:
            payload = '{"event_type":"test.event","data":{"test":true}}'
            print(f"Using default payload: {payload}")
        else:
            payload = payload_input

        # Validate JSON
        try:
            json.loads(payload)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON - {e}")
            sys.exit(1)

        # Get secret key
        print("\nEnter secret key:")
        secret_key = input().strip()

        if not secret_key:
            print("Error: Secret key cannot be empty")
            sys.exit(1)

    # Generate signature
    signature = generate_signature(payload, secret_key)

    # Output
    print("\n=== Generated Signature ===")
    print(f"Payload:   {payload}")
    print(f"Signature: {signature}")

    # Generate curl command
    if "WEBHOOK_URL" in sys.argv or len(sys.argv) == 1:
        webhook_url = "${WEBHOOK_URL}"
    else:
        webhook_url = "https://your-webhook-url"

    print("\n=== Example curl command ===")
    print(f"""curl -X POST "{webhook_url}" \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Signature: {signature}" \\
  -d '{payload}'""")

    print("\n=== For bash script ===")
    print(f'SIGNATURE="{signature}"')
    print(f"PAYLOAD='{payload}'")


if __name__ == "__main__":
    main()
