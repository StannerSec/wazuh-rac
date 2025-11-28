#!/bin/bash
  set -e

  # Configuration
  WAZUH_HOST="${WAZUH_HOST:-localhost}"
  WAZUH_USER="${WAZUH_USER:-wazuh}"
  WAZUH_RULES_DIR="/var/ossec/etc/rules"
  WAZUH_DECODERS_DIR="/var/ossec/etc/decoders"
  LOCAL_RULES_DIR="$(dirname "$0")/../rules"
  LOCAL_DECODERS_DIR="$(dirname "$0")/../decoders"

  echo "🚀 Starting Wazuh Rules as Code deployment..."

  # Step 1: Validate rules
  echo ""
  echo "Step 1: Validating rule IDs..."
  python3 "$(dirname "$0")/check_rule_ids.py"

  if [ $? -ne 0 ]; then
      echo "❌ Validation failed. Please fix conflicts before deploying."
      exit 1
  fi

  # Step 2: Test XML syntax
  echo ""
  echo "Step 2: Validating XML syntax..."
  for file in "$LOCAL_RULES_DIR"/*.xml; do
      if [ -f "$file" ]; then
          xmllint --noout "$file" 2>&1
          if [ $? -ne 0 ]; then
              echo "❌ XML syntax error in $file"
              exit 1
          fi
      fi
  done
  echo "✅ All XML files are well-formed"

  # Step 3: Deploy to Wazuh manager
  echo ""
  echo "Step 3: Deploying to Wazuh manager..."

  if [ "$WAZUH_HOST" == "localhost" ] || [ "$WAZUH_HOST" == "127.0.0.1" ]; then
      # Local deployment
      echo "Deploying locally..."

      # Copy rules
      sudo cp -v "$LOCAL_RULES_DIR"/*.xml "$WAZUH_RULES_DIR/" 2>/dev/null || true

      # Copy decoders
      sudo cp -v "$LOCAL_DECODERS_DIR"/*.xml "$WAZUH_DECODERS_DIR/" 2>/dev/null || true

      # Set permissions
      sudo chown -R wazuh:wazuh "$WAZUH_RULES_DIR" "$WAZUH_DECODERS_DIR"
      sudo chmod -R 660 "$WAZUH_RULES_DIR"/*.xml "$WAZUH_DECODERS_DIR"/*.xml 2>/dev/null || true

  else
      # Remote deployment via SSH
      echo "Deploying to remote host: $WAZUH_HOST..."

      # Copy rules
      scp "$LOCAL_RULES_DIR"/*.xml "${WAZUH_USER}@${WAZUH_HOST}:/tmp/" 2>/dev/null || true
      ssh "${WAZUH_USER}@${WAZUH_HOST}" "sudo mv /tmp/*.xml $WAZUH_RULES_DIR/ && sudo chown wazuh:wazuh $WAZUH_RULES_DIR/*.xml && sudo chmod 660 $WAZUH_RULES_DIR/*.xml"

      # Copy decoders
      scp "$LOCAL_DECODERS_DIR"/*.xml "${WAZUH_USER}@${WAZUH_HOST}:/tmp/" 2>/dev/null || true
      ssh "${WAZUH_USER}@${WAZUH_HOST}" "sudo mv /tmp/*.xml $WAZUH_DECODERS_DIR/ && sudo chown wazuh:wazuh $WAZUH_DECODERS_DIR/*.xml && sudo chmod 660 $WAZUH_DECODERS_DIR/*.xml"
  fi

  # Step 4: Verify Wazuh configuration
  echo ""
  echo "Step 4: Verifying Wazuh configuration..."

  if [ "$WAZUH_HOST" == "localhost" ] || [ "$WAZUH_HOST" == "127.0.0.1" ]; then
      sudo /var/ossec/bin/wazuh-logtest-legacy -t 2>/dev/null || sudo /var/ossec/bin/wazuh-logtest -t 2>/dev/null || echo "⚠️  Could not verify configuration"
  else
      ssh "${WAZUH_USER}@${WAZUH_HOST}" "sudo /var/ossec/bin/wazuh-logtest -t" 2>/dev/null || echo "⚠️  Could not verify configuration"
  fi

  # Step 5: Restart Wazuh manager
  echo ""
  echo "Step 5: Restarting Wazuh manager..."

  if [ "$WAZUH_HOST" == "localhost" ] || [ "$WAZUH_HOST" == "127.0.0.1" ]; then
      sudo systemctl restart wazuh-manager
      sleep 5
      sudo systemctl status wazuh-manager --no-pager
  else
      ssh "${WAZUH_USER}@${WAZUH_HOST}" "sudo systemctl restart wazuh-manager"
      sleep 5
      ssh "${WAZUH_USER}@${WAZUH_HOST}" "sudo systemctl status wazuh-manager --no-pager"
  fi

  echo ""
  echo "✅ Deployment completed successfully!"
  echo ""
  echo "Next steps:"
  echo "  1. Review the deployment in Wazuh dashboard"
  echo "  2. Commit changes: git add . && git commit -m 'Deploy: [description]'"
  echo "  3. Push to GitHub: git push origin main"
