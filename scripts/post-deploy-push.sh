#!/bin/bash
  set -e

  # Check if there are changes to commit
  if [ -z "$(git status --porcelain)" ]; then
      echo "No changes to commit"
      exit 0
  fi

  # Show changes
  echo "📝 Changes to be committed:"
  git status --short

  # Prompt for commit message
  read -p "Enter commit message (or press Enter to skip push): " COMMIT_MSG

  if [ -z "$COMMIT_MSG" ]; then
      echo "Skipping git push"
      exit 0
  fi

  # Commit and push
  git add rules/ decoders/
  git commit -m "$COMMIT_MSG"

  # Ask for branch
  read -p "Push to which branch? [main]: " BRANCH
  BRANCH=${BRANCH:-main}

  git push origin "$BRANCH"

  echo "✅ Changes pushed to GitHub ($BRANCH)"