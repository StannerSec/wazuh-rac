#!/bin/bash
# Query Wazuh alerts via REST API

WAZUH_API="https://192.168.0.141:55000"
WAZUH_USER="${WAZUH_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_PASS:-wazuh-wui}"

# Get API token
TOKEN=$(curl -s -u "$WAZUH_USER:$WAZUH_PASS" -k -X GET "$WAZUH_API/security/user/authenticate" | jq -r '.data.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "Error: Failed to authenticate with Wazuh API"
    exit 1
fi

# Function to query alerts
query_alerts() {
    local endpoint="$1"
    local description="$2"

    echo "=== $description ==="
    curl -s -k -X GET "$WAZUH_API/$endpoint" \
        -H "Authorization: Bearer $TOKEN" | jq '.'
    echo ""
}

# Parse command line arguments
case "$1" in
    recent)
        # Get recent alerts (last 5)
        query_alerts "alerts?limit=5&sort=-timestamp" "Recent Alerts (Last 5)"
        ;;

    rule)
        # Query alerts by rule ID
        RULE_ID="$2"
        if [ -z "$RULE_ID" ]; then
            echo "Usage: $0 rule <rule_id>"
            exit 1
        fi
        query_alerts "alerts?rule_id=$RULE_ID&limit=10&sort=-timestamp" "Alerts for Rule ID: $RULE_ID"
        ;;

    agent)
        # Query alerts by agent
        AGENT_NAME="$2"
        if [ -z "$AGENT_NAME" ]; then
            echo "Usage: $0 agent <agent_name>"
            exit 1
        fi
        query_alerts "alerts?agent_name=$AGENT_NAME&limit=10&sort=-timestamp" "Alerts for Agent: $AGENT_NAME"
        ;;

    level)
        # Query alerts by severity level
        LEVEL="$2"
        if [ -z "$LEVEL" ]; then
            echo "Usage: $0 level <severity_level>"
            exit 1
        fi
        query_alerts "alerts?rule_level=$LEVEL&limit=10&sort=-timestamp" "Alerts with Severity Level: $LEVEL"
        ;;

    today)
        # Get today's alerts
        query_alerts "alerts?date=today&limit=20&sort=-timestamp" "Today's Alerts"
        ;;

    count)
        # Get alert count summary
        echo "=== Alert Count Summary ==="
        curl -s -k -X GET "$WAZUH_API/alerts/summary/rule" \
            -H "Authorization: Bearer $TOKEN" | jq '.data | {total_alerts: .total_affected_items, top_rules: .affected_items[0:5]}'
        ;;

    custom)
        # Custom query endpoint
        QUERY="$2"
        if [ -z "$QUERY" ]; then
            echo "Usage: $0 custom 'query_parameters'"
            echo "Example: $0 custom 'rule_id=100001&limit=5'"
            exit 1
        fi
        query_alerts "alerts?$QUERY" "Custom Query"
        ;;

    *)
        echo "Wazuh Alert Query Tool"
        echo ""
        echo "Usage: $0 <command> [arguments]"
        echo ""
        echo "Commands:"
        echo "  recent              - Get 5 most recent alerts"
        echo "  rule <rule_id>      - Get alerts for specific rule ID"
        echo "  agent <agent_name>  - Get alerts for specific agent"
        echo "  level <1-15>        - Get alerts by severity level"
        echo "  today               - Get today's alerts"
        echo "  count               - Get alert count summary"
        echo "  custom '<params>'   - Custom query parameters"
        echo ""
        echo "Examples:"
        echo "  $0 recent"
        echo "  $0 rule 100001"
        echo "  $0 agent 001"
        echo "  $0 level 12"
        echo "  $0 custom 'rule_id=100001&agent_id=001&limit=10'"
        exit 1
        ;;
esac
