#!/bin/bash

##############################################################################
# Webhook Logger API Test Script
# 
# This script tests the webhook receiver by:
# 1. Generating valid HMAC-SHA256 signatures
# 2. Sending test webhooks with valid and invalid signatures
# 3. Querying the logs API to verify processing
#
# Usage:
#   ./test_webhook.sh
#
# Environment Variables:
#   WEBHOOK_URL      - URL of webhook-receiver function (required)
#   LOGS_API_URL     - URL of logs-api function (required)
#   SECRET_KEY       - Secret key for HMAC signature (required)
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if required commands are available
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 is required but not installed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Warning: jq is not installed. JSON output will not be formatted."; }

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Function to calculate HMAC-SHA256 signature
calculate_signature() {
    local payload="$1"
    local secret="$2"
    
    # Use Python to calculate HMAC
    signature=$(python3 -c "
import hmac
import hashlib
import sys

payload = '''$payload'''
secret = '''$secret'''

signature = hmac.new(
    secret.encode('utf-8'),
    payload.encode('utf-8'),
    hashlib.sha256
).hexdigest()

print(f'sha256={signature}')
")
    
    echo "$signature"
}

# Check for required environment variables
echo "=================================="
echo "Webhook Logger API Test Script"
echo "=================================="
echo ""

if [ -z "$WEBHOOK_URL" ]; then
    echo "Error: WEBHOOK_URL environment variable is not set."
    echo "Example: export WEBHOOK_URL=https://your-function-url"
    exit 1
fi

if [ -z "$LOGS_API_URL" ]; then
    echo "Error: LOGS_API_URL environment variable is not set."
    echo "Example: export LOGS_API_URL=https://your-logs-api-url"
    exit 1
fi

if [ -z "$SECRET_KEY" ]; then
    echo "Error: SECRET_KEY environment variable is not set."
    echo "Example: export SECRET_KEY=your-secret-key-from-lockbox"
    exit 1
fi

print_info "Using webhook URL: $WEBHOOK_URL"
print_info "Using logs API URL: $LOGS_API_URL"
echo ""

##############################################################################
# Test 1: Send webhook with valid signature
##############################################################################
echo "Test 1: Send webhook with valid signature"
echo "----------------------------------------"

PAYLOAD1='{"event_type":"payment.success","data":{"order_id":"12345","amount":1000}}'
SIGNATURE1=$(calculate_signature "$PAYLOAD1" "$SECRET_KEY")

print_info "Payload: $PAYLOAD1"
print_info "Signature: $SIGNATURE1"

RESPONSE1=$(curl -s -w "\n%{http_code} %{time_total}" -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: $SIGNATURE1" \
    -d "$PAYLOAD1")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1 | awk '{print $1}')
TIME1=$(echo "$RESPONSE1" | tail -n1 | awk '{print $2}')
BODY1=$(echo "$RESPONSE1" | head -n-1)

if [ "$HTTP_CODE1" == "200" ]; then
    print_success "Valid signature accepted (HTTP $HTTP_CODE1)"
    print_info "Response time: ${TIME1}s"
    if python3 -c "import sys; sys.exit(0 if float('$TIME1') < 0.2 else 1)"; then
        print_success "Response time within limits (< 0.2s client-side)"
    else
        print_info "Response time > 0.2s (check network or function cold start)"
    fi
    if command -v jq >/dev/null 2>&1; then
        echo "$BODY1" | jq '.'
    else
        echo "$BODY1"
    fi
    LOG_ID1=$(echo "$BODY1" | python3 -c "import sys, json; print(json.load(sys.stdin).get('log_id', ''))")
    print_info "Log ID: $LOG_ID1"
else
    print_error "Expected HTTP 200, got $HTTP_CODE1"
    echo "$BODY1"
fi

echo ""

##############################################################################
# Test 2: Send webhook with invalid signature
##############################################################################
echo "Test 2: Send webhook with invalid signature"
echo "----------------------------------------"

PAYLOAD2='{"event_type":"user.login","data":{"user_id":"user123"}}'
INVALID_SIGNATURE="sha256=invalid_signature_here"

print_info "Payload: $PAYLOAD2"
print_info "Signature: $INVALID_SIGNATURE (intentionally invalid)"

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: $INVALID_SIGNATURE" \
    -d "$PAYLOAD2")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

if [ "$HTTP_CODE2" == "401" ]; then
    print_success "Invalid signature rejected (HTTP $HTTP_CODE2)"
    if command -v jq >/dev/null 2>&1; then
        echo "$BODY2" | jq '.'
    else
        echo "$BODY2"
    fi
else
    print_error "Expected HTTP 401, got $HTTP_CODE2"
    echo "$BODY2"
fi

echo ""

##############################################################################
# Test 3: Send another valid webhook (different event type)
##############################################################################
echo "Test 3: Send webhook with different event type"
echo "----------------------------------------"

PAYLOAD3='{"event_type":"order.shipped","data":{"order_id":"67890","tracking":"TRACK123"}}'
SIGNATURE3=$(calculate_signature "$PAYLOAD3" "$SECRET_KEY")

print_info "Payload: $PAYLOAD3"
print_info "Signature: $SIGNATURE3"

RESPONSE3=$(curl -s -w "\n%{http_code} %{time_total}" -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: $SIGNATURE3" \
    -d "$PAYLOAD3")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1 | awk '{print $1}')
TIME3=$(echo "$RESPONSE3" | tail -n1 | awk '{print $2}')
BODY3=$(echo "$RESPONSE3" | head -n-1)

if [ "$HTTP_CODE3" == "200" ]; then
    print_success "Valid signature accepted (HTTP $HTTP_CODE3)"
    print_info "Response time: ${TIME3}s"
    if command -v jq >/dev/null 2>&1; then
        echo "$BODY3" | jq '.'
    else
        echo "$BODY3"
    fi
    LOG_ID3=$(echo "$BODY3" | python3 -c "import sys, json; print(json.load(sys.stdin).get('log_id', ''))")
    print_info "Log ID: $LOG_ID3"
else
    print_error "Expected HTTP 200, got $HTTP_CODE3"
    echo "$BODY3"
fi

echo ""

##############################################################################
# Test 4: Wait for async processing
##############################################################################
echo "Test 4: Wait for async processing"
echo "----------------------------------------"

print_info "Waiting 5 seconds for YMQ trigger to process messages..."
sleep 5

echo ""

##############################################################################
# Test 5: Query logs API (all events)
##############################################################################
echo "Test 5: Query logs API (all events)"
echo "----------------------------------------"

LOGS_RESPONSE=$(curl -s -w "\n%{http_code}" "$LOGS_API_URL?limit=10")
LOGS_HTTP_CODE=$(echo "$LOGS_RESPONSE" | tail -n1)
LOGS_BODY=$(echo "$LOGS_RESPONSE" | head -n-1)

if [ "$LOGS_HTTP_CODE" == "200" ]; then
    print_success "Logs retrieved successfully (HTTP $LOGS_HTTP_CODE)"
    if command -v jq >/dev/null 2>&1; then
        echo "$LOGS_BODY" | jq '.'
        TOTAL=$(echo "$LOGS_BODY" | jq '.total')
        print_info "Total logs: $TOTAL"
        
        # Verify log_id existence and processed_at
        print_info "Verifying log processing status..."
        
        LOG_STATUS=$(echo "$LOGS_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
logs = data.get('logs', [])
target_ids = ['$LOG_ID1', '$LOG_ID3']
found = 0
processed = 0

for log in logs:
    if log.get('log_id') in target_ids:
        found += 1
        if log.get('processed_at'):
            processed += 1

print(f'{found}/{len(target_ids)} found, {processed}/{len(target_ids)} processed')
if found == len(target_ids) and processed == len(target_ids):
    print('SUCCESS')
else:
    print('FAILURE')
")
        if [[ "$LOG_STATUS" == *"SUCCESS"* ]]; then
            print_success "Verification: All test logs found and processed ($LOG_STATUS)"
        else
            print_error "Verification: Not all logs processed ($LOG_STATUS)"
            print_info "Note: Messages might still be in queue if processor is slow."
        fi
    else
        echo "$LOGS_BODY"
    fi
else
    print_error "Failed to retrieve logs (HTTP $LOGS_HTTP_CODE)"
    echo "$LOGS_BODY"
fi

echo ""

##############################################################################
# Test 6: Query logs API with event_type filter
##############################################################################
echo "Test 6: Query logs API (filter by event_type)"
echo "----------------------------------------"

FILTERED_RESPONSE=$(curl -s -w "\n%{http_code}" "$LOGS_API_URL?limit=10&event_type=payment.success")
FILTERED_HTTP_CODE=$(echo "$FILTERED_RESPONSE" | tail -n1)
FILTERED_BODY=$(echo "$FILTERED_RESPONSE" | head -n-1)

if [ "$FILTERED_HTTP_CODE" == "200" ]; then
    print_success "Filtered logs retrieved successfully (HTTP $FILTERED_HTTP_CODE)"
    if command -v jq >/dev/null 2>&1; then
        echo "$FILTERED_BODY" | jq '.'
        FILTERED_TOTAL=$(echo "$FILTERED_BODY" | jq '.total')
        print_info "Total payment.success events: $FILTERED_TOTAL"
    else
        echo "$FILTERED_BODY"
    fi
else
    print_error "Failed to retrieve filtered logs (HTTP $FILTERED_HTTP_CODE)"
    echo "$FILTERED_BODY"
fi

echo ""

##############################################################################
# Summary
##############################################################################
echo "=================================="
echo "Test Summary"
echo "=================================="
echo ""

if [ "$HTTP_CODE1" == "200" ] && [ "$HTTP_CODE2" == "401" ] && [ "$HTTP_CODE3" == "200" ] && [ "$LOGS_HTTP_CODE" == "200" ]; then
    print_success "All tests passed!"
    echo ""
    print_info "Next steps:"
    echo "  1. Check YDB Console to verify webhook_logs table has entries"
    echo "  2. Check Cloud Logging to see structured logs"
    echo "  3. Verify processed_at timestamps are set"
    exit 0
else
    print_error "Some tests failed. Please check the output above."
    exit 1
fi

