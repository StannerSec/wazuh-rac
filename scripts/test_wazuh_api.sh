#!/bin/bash
# Test Wazuh API endpoints to find alert/log queries

WAZUH_API="https://192.168.0.141:55000"
TOKEN=$(curl -s -u "wazuh-wui:wazuh-wui" -k -X GET "$WAZUH_API/security/user/authenticate" | jq -r '.data.token')

echo "=== Wazuh API Endpoint Discovery ==="
echo ""

echo "1. Testing /manager/stats/analysisd"
curl -s -k -X GET "$WAZUH_API/manager/stats/analysisd" -H "Authorization: Bearer $TOKEN" | jq '.'
echo ""

echo "2. Testing /manager/logs/summary"
curl -s -k -X GET "$WAZUH_API/manager/logs/summary" -H "Authorization: Bearer $TOKEN" | jq '.'
echo ""

echo "3. Listing agents"
curl -s -k -X GET "$WAZUH_API/agents?limit=5" -H "Authorization: Bearer $TOKEN" | jq '.data.affected_items[] | {id, name, ip, status}'
