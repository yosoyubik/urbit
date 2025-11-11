#!/usr/bin/env bash
set -e

echo "Cleaning up local test files..."

# Remove urbit from git staging
if git diff --cached --name-only | grep -q "^urbit$"; then
  echo "✓ Removing urbit from git staging"
  git restore --staged urbit
else
  echo "  urbit not in git staging"
fi

# Remove urbit binary
if [ -f urbit ]; then
  echo "✓ Removing urbit binary"
  rm urbit
else
  echo "  urbit binary not found"
fi

echo ""
echo "Cleanup complete!"
