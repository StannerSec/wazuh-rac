  #!/bin/bash
  set -e  # Exit on error

  # Get the script directory
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

  # Load environment variables if .env exists
  if [ -f "$PROJECT_DIR/.env" ]; then
      echo "📄 Loading configuration from .env file..."
      set -a
      source "$PROJECT_DIR/.env"
      set +a
      echo "   WAZUH_HOST loaded as: $WAZUH_HOST"
  fi

  # Configuration with clear defaults
  WAZUH_HOST="${WAZUH_HOST:-192.168.0.141}"
  WAZUH_USER="${WAZUH_USER:-wazuh-user}"
  WAZUH_PORT="${WAZUH_PORT:-22}"
  SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa_wazuh}"
  WAZUH_RULES_DIR="/var/ossec/etc/rules"
  WAZUH_DECODERS_DIR="/var/ossec/etc/decoders"
  LOCAL_RULES_DIR="$PROJECT_DIR/rules"
  LOCAL_DECODERS_DIR="$PROJECT_DIR/decoders"

  # SSH options as array for ssh (uses -p for port)
  SSH_OPTS=(-i "$SSH_KEY" -p "$WAZUH_PORT" -o StrictHostKeyChecking=no)
  # SCP options as array (uses -P for port)
  SCP_OPTS=(-i "$SSH_KEY" -P "$WAZUH_PORT" -o StrictHostKeyChecking=no)

  # Determine if deployment is local or remote
  IS_LOCAL=false
  if [ "$WAZUH_HOST" == "localhost" ] || [ "$WAZUH_HOST" == "127.0.0.1" ]; then
      IS_LOCAL=true
  fi

  echo "🚀 Starting Wazuh Rules as Code deployment..."
  echo "📍 Target: $WAZUH_HOST ($([ "$IS_LOCAL" == "true" ] && echo "local" || echo "remote"))"
  echo ""

  # Step 1: Validate rules
  echo "Step 1: Validating rule IDs..."
  python3 "$SCRIPT_DIR/check_rule_ids.py"

  if [ $? -ne 0 ]; then
      echo "❌ Validation failed. Please fix conflicts before deploying."
      exit 1
  fi

  # Step 2: Test XML syntax
  echo ""
  echo "Step 2: Validating XML syntax..."
  XML_COUNT=0
  XML_ERRORS=0

  # Check rules directory
  if [ -d "$LOCAL_RULES_DIR" ]; then
      for file in "$LOCAL_RULES_DIR"/*.xml; do
          if [ -f "$file" ]; then
              echo "  Validating: $(basename "$file")"
              if xmllint --noout "$file" 2>&1; then
                  ((XML_COUNT+=1))
              else
                  echo "❌ XML syntax error in $file"
                  ((XML_ERRORS+=1))
              fi
          fi
      done
  fi

  # Check decoders directory
  if [ -d "$LOCAL_DECODERS_DIR" ]; then
      for file in "$LOCAL_DECODERS_DIR"/*.xml; do
          if [ -f "$file" ]; then
              echo "  Validating: $(basename "$file")"
              if xmllint --noout "$file" 2>&1; then
                  ((XML_COUNT+=1))
              else
                  echo "❌ XML syntax error in $file"
                  ((XML_ERRORS+=1))
              fi
          fi
      done
  fi

  if [ $XML_ERRORS -gt 0 ]; then
      echo "❌ Found $XML_ERRORS XML syntax errors"
      exit 1
  fi

  echo "✅ All $XML_COUNT XML files are well-formed"

  # Step 3: Test SSH connection (for remote deployment)
  if [ "$IS_LOCAL" == "false" ]; then
      echo ""
      echo "Step 3: Testing SSH connection to $WAZUH_HOST..."

      if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 -o BatchMode=yes "${WAZUH_USER}@${WAZUH_HOST}" "echo 'Connection successful'" 2>/dev/null; then
          echo "❌ Cannot connect to $WAZUH_HOST"
          echo "Please ensure:"
          echo "  1. SSH key authentication is set up: ssh-copy-id -i $SSH_KEY ${WAZUH_USER}@${WAZUH_HOST}"
          echo "  2. Host is reachable: ping $WAZUH_HOST"
          echo "  3. SSH port $WAZUH_PORT is correct"
          echo "  4. SSH key exists: $SSH_KEY"
          exit 1
      fi
      echo "✅ SSH connection established"
  fi

  # Step 4: Deploy to Wazuh manager
  echo ""
  echo "Step 4: Deploying to Wazuh manager..."

  if [ "$IS_LOCAL" == "true" ]; then
      # Local deployment
      echo "Deploying locally..."

      # Copy rules
      if compgen -G "$LOCAL_RULES_DIR/*.xml" > /dev/null; then
          echo "  Copying rules..."
          sudo cp -v "$LOCAL_RULES_DIR"/*.xml "$WAZUH_RULES_DIR/"
      else
          echo "  No rules to deploy"
      fi

      # Copy decoders
      if compgen -G "$LOCAL_DECODERS_DIR/*.xml" > /dev/null; then
          echo "  Copying decoders..."
          sudo cp -v "$LOCAL_DECODERS_DIR"/*.xml "$WAZUH_DECODERS_DIR/"
      else
          echo "  No decoders to deploy"
      fi

      # Set permissions (use root:wazuh based on your server's ownership)
      sudo chown -R root:wazuh "$WAZUH_RULES_DIR" "$WAZUH_DECODERS_DIR" 2>/dev/null || true
      sudo chmod 660 "$WAZUH_RULES_DIR"/*.xml 2>/dev/null || true
      sudo chmod 660 "$WAZUH_DECODERS_DIR"/*.xml 2>/dev/null || true

  else
      # Remote deployment via SSH
      echo "Deploying to remote host: $WAZUH_HOST..."

      # Copy rules
      if compgen -G "$LOCAL_RULES_DIR/*.xml" > /dev/null; then
          echo "  Copying rules to $WAZUH_HOST..."
          scp "${SCP_OPTS[@]}" "$LOCAL_RULES_DIR"/*.xml "${WAZUH_USER}@${WAZUH_HOST}:/tmp/"
          echo "  Installing rules..."
          ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo mv /tmp/*.xml '$WAZUH_RULES_DIR/' && sudo chown root:wazuh '$WAZUH_RULES_DIR'/* && sudo chmod 660 '$WAZUH_RULES_DIR'/*.xml 2>/dev/null || true"
          echo "  ✅ Rules deployed"
      else
          echo "  No rules to deploy"
      fi

      # Copy decoders
      if compgen -G "$LOCAL_DECODERS_DIR/*.xml" > /dev/null; then
          echo "  Copying decoders to $WAZUH_HOST..."
          scp "${SCP_OPTS[@]}" "$LOCAL_DECODERS_DIR"/*.xml "${WAZUH_USER}@${WAZUH_HOST}:/tmp/"
          echo "  Installing decoders..."
          ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo mv /tmp/*.xml '$WAZUH_DECODERS_DIR/' && sudo chown root:wazuh '$WAZUH_DECODERS_DIR'/* && sudo chmod 660 '$WAZUH_DECODERS_DIR'/*.xml 2>/dev/null || true"
          echo "  ✅ Decoders deployed"
      else
          echo "  No decoders to deploy"
      fi
  fi

  echo "✅ Files deployed successfully"

  # Step 5: Verify Wazuh configuration
  echo ""
  echo "Step 5: Verifying Wazuh configuration..."

  if [ "$IS_LOCAL" == "true" ]; then
      if sudo /var/ossec/bin/wazuh-control -s 2>&1 | grep -q "wazuh-analysisd is running"; then
          echo "✅ Configuration verified"
      else
          echo "⚠️  Configuration verification unavailable"
      fi
  else
      if ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo /var/ossec/bin/wazuh-control -s 2>&1 | grep -q 'wazuh-analysisd is running'"; then
          echo "✅ Configuration verified"
      else
          echo "⚠️  Configuration verification unavailable"
      fi
  fi

  # Step 6: Restart Wazuh manager
  echo ""
  echo "Step 6: Restarting Wazuh manager..."

  if [ "$IS_LOCAL" == "true" ]; then
      sudo systemctl restart wazuh-manager
      sleep 3
      if sudo systemctl is-active --quiet wazuh-manager; then
          echo "✅ Wazuh manager is running"
      else
          echo "❌ Wazuh manager failed to start"
          sudo systemctl status wazuh-manager --no-pager
          exit 1
      fi
  else
      ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo systemctl restart wazuh-manager"
      sleep 3
      if ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo systemctl is-active --quiet wazuh-manager"; then
          echo "✅ Wazuh manager is running"
      else
          echo "❌ Wazuh manager failed to start"
          ssh "${SSH_OPTS[@]}" "${WAZUH_USER}@${WAZUH_HOST}" "sudo systemctl status wazuh-manager --no-pager"
          exit 1
      fi
  fi

  echo ""
  echo "✅ Deployment completed successfully!"
  echo ""
  echo "📊 Next steps:"
  echo "  1. Review the deployment in Wazuh dashboard: https://$WAZUH_HOST"
  echo "  2. Test your rules with sample logs"
  echo "  3. Commit changes: git add . && git commit -m 'Deploy: [description]'"
  echo "  4. Push to GitHub: git push origin main"