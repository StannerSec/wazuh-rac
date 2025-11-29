#!/bin/bash
# Query Wazuh Indexer (OpenSearch) for alerts

INDEXER_URL="https://192.168.0.141:9200"
INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
INDEXER_PASS="${WAZUH_INDEXER_PASS:-admin}"

# Use wildcard pattern to match all alert indices
INDEX="wazuh-alerts*"

echo "Querying Wazuh Indexer for alerts..."
echo "Index: $INDEX"
echo ""

case "$1" in
    recent)
        # Get 10 most recent alerts
        echo "=== Recent Alerts ==="
        curl -s -u "$INDEXER_USER:$INDEXER_PASS" -k -X POST \
            "$INDEXER_URL/$INDEX/_search" \
            -H 'Content-Type: application/json' \
            -d '{
              "query": {"match_all": {}},
              "size": 10,
              "sort": [{"timestamp": "desc"}]
            }' | jq '.hits.hits[]._source | {timestamp, rule_id: .rule.id, rule_description: .rule.description, agent: .agent.name}'
        ;;

    rule)
        # Query by rule ID
        RULE_ID="$2"
        if [ -z "$RULE_ID" ]; then
            echo "Usage: $0 rule <rule_id>"
            exit 1
        fi
        echo "=== Alerts for Rule $RULE_ID ==="
        curl -s -u "$INDEXER_USER:$INDEXER_PASS" -k -X GET \
            "$INDEXER_URL/$INDEX/_search" \
            -H 'Content-Type: application/json' \
            -d "{
              \"query\": {
                \"match\": {
                  \"rule.id\": \"$RULE_ID\"
                }
              },
              \"size\": 20,
              \"sort\": [{\"timestamp\": \"desc\"}]
            }" | jq '.hits.hits[]._source | {timestamp, rule_id: .rule.id, agent: .agent.name, data: .data}'
        ;;

    count)
        # Count alerts
        echo "=== Alert Count ==="
        curl -s -u "$INDEXER_USER:$INDEXER_PASS" -k -X GET \
            "$INDEXER_URL/$INDEX/_count" | jq '{total_alerts: .count}'
        ;;

    *)
        echo "Wazuh Indexer Query Tool"
        echo ""
        echo "Usage: $0 <command> [arguments]"
        echo ""
        echo "Commands:"
        echo "  recent           - Get 10 most recent alerts"
        echo "  rule <rule_id>   - Get alerts for specific rule ID"
        echo "  count            - Count total alerts today"
        echo ""
        echo "Examples:"
        echo "  $0 recent"
        echo "  $0 rule 100001"
        echo "  $0 count"
        ;;
esac
