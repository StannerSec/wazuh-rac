# Query Wazuh Alerts on Server

Since the Wazuh Indexer is bound to localhost (127.0.0.1), queries must be run **on the Wazuh server itself**.

## Run These Commands on the Wazuh Server

### 1. Get Recent Alerts

```bash
curl -s -k -u "wazuh-wui:wazuh-wui" -H "Content-Type: application/json" \
  -X POST "https://127.0.0.1:9200/wazuh-alerts*/_search" -d '{
    "size": 10,
    "sort": [{"timestamp": "desc"}],
    "query": {"match_all": {}}
  }' | jq -r '.hits.hits[]._source | "\(.timestamp) | Rule \(.rule.id): \(.rule.description) | Agent: \(.agent.name // "N/A")"'
```

### 2. Query Alerts by Rule ID

```bash
RULE_ID="100001"

curl -s -k -u "wazuh-wui:wazuh-wui" -H "Content-Type: application/json" \
  -X POST "https://127.0.0.1:9200/wazuh-alerts*/_search" -d "{
    \"size\": 20,
    \"sort\": [{\"timestamp\": \"desc\"}],
    \"query\": {
      \"term\": {
        \"rule.id\": \"$RULE_ID\"
      }
    }
  }" | jq -r '.hits.hits[]._source | "\(.timestamp) | \(.rule.description) | Agent: \(.agent.name // "N/A")"'
```

### 3. Count Total Alerts

```bash
curl -s -k -u "wazuh-wui:wazuh-wui" \
  "https://127.0.0.1:9200/wazuh-alerts*/_count" | jq '{total_alerts: .count}'
```

### 4. Get Alert Summary by Rule

```bash
curl -s -k -u "wazuh-wui:wazuh-wui" -H "Content-Type: application/json" \
  -X POST "https://127.0.0.1:9200/wazuh-alerts*/_search" -d '{
    "size": 0,
    "aggs": {
      "rules": {
        "terms": {
          "field": "rule.id",
          "size": 10
        }
      }
    }
  }' | jq '.aggregations.rules.buckets[] | {rule_id: .key, count: .doc_count}'
```

## Save as Script on Wazuh Server

Copy this to `/tmp/query_alerts.sh` on the Wazuh server and run it there.
