#!/bin/bash
# Deploy Wazuh rules via REST API (no SSH needed)

WAZUH_API="https://192.168.0.141:55000"
WAZUH_USER="${WAZUH_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_PASS:-wazuh-wui}"

RULE_FILES=("$@")

if [ ${#RULE_FILES[@]} -eq 0 ]; then
    echo "Usage: $0 <rule-file.xml> [rule-file2.xml] [rule-file3.xml] ..."
    echo ""
    echo "Examples:"
    echo "  $0 rules/my_rule.xml                          # Deploy single file"
    echo "  $0 rules/*.xml                                # Deploy all XML files"
    echo "  $0 rules/rule1.xml rules/rule2.xml           # Deploy multiple files"
    exit 1
fi

# Validate all files exist
for RULE_FILE in "${RULE_FILES[@]}"; do
    if [ ! -f "$RULE_FILE" ]; then
        echo "Error: File $RULE_FILE not found"
        exit 1
    fi
done

echo "Step 1: Validating ${#RULE_FILES[@]} rule file(s)..."
echo ""

# Run XML validation on all files
for RULE_FILE in "${RULE_FILES[@]}"; do
    echo "  Validating: $(basename "$RULE_FILE")"
    xmllint --noout "$RULE_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "✗ XML validation failed for $RULE_FILE"
        exit 1
    fi
done
echo "✓ All XML files valid"

# Run rule ID conflict check
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_RAC_DIR="$(dirname "$SCRIPT_DIR")"
python3 "$WAZUH_RAC_DIR/scripts/check_rule_ids.py" 2>&1
if [ $? -ne 0 ]; then
    echo "✗ Rule validation failed"
    exit 1
fi

echo ""
echo "Step 2: Deploying ${#RULE_FILES[@]} rule file(s) via Wazuh API..."

# Get API token
TOKEN=$(curl -s -u "$WAZUH_USER:$WAZUH_PASS" -k -X GET "$WAZUH_API/security/user/authenticate" | jq -r '.data.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "Error: Failed to authenticate with Wazuh API"
    exit 1
fi

echo "✓ Authenticated"
echo ""

# Upload each rule file
UPLOAD_COUNT=0
FAILED_COUNT=0

for RULE_FILE in "${RULE_FILES[@]}"; do
    FILENAME=$(basename "$RULE_FILE")
    echo "  Uploading: $FILENAME"

    RESPONSE=$(curl -s -k -X PUT "$WAZUH_API/rules/files/$FILENAME?overwrite=true" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$RULE_FILE")

    # Check upload result
    UPLOAD_ERROR=$(echo "$RESPONSE" | jq -r '.error')
    if [ "$UPLOAD_ERROR" != "0" ]; then
        echo "    ✗ Upload failed: $(echo "$RESPONSE" | jq -r '.message')"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        UPLOADED_FILE=$(echo "$RESPONSE" | jq -r '.data.affected_items[0]')
        echo "    ✓ Uploaded: $UPLOADED_FILE"
        UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
    fi
done

if [ $FAILED_COUNT -gt 0 ]; then
    echo ""
    echo "✗ $FAILED_COUNT file(s) failed to upload"
    exit 1
fi

echo ""
echo "✓ Successfully uploaded $UPLOAD_COUNT file(s)"

# Restart manager
echo ""
echo "Step 3: Restarting Wazuh manager..."
RESTART_RESPONSE=$(curl -s -k -X PUT "$WAZUH_API/manager/restart" \
    -H "Authorization: Bearer $TOKEN")

RESTART_ERROR=$(echo "$RESTART_RESPONSE" | jq -r '.error')
if [ "$RESTART_ERROR" != "0" ]; then
    echo "✗ Restart failed"
    echo "$RESTART_RESPONSE" | jq '.'
    exit 1
fi

echo "✓ Manager restarted"
echo ""
echo "✅ Deployment complete! Rule is now active on Wazuh server."
