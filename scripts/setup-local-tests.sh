#!/usr/bin/env bash
set -e

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
  DARWIN_ARCH="aarch64"
elif [ "$ARCH" = "x86_64" ]; then
  DARWIN_ARCH="x86_64"
else
  echo "Unsupported architecture: $ARCH"
  exit 1
fi

echo "Detected architecture: darwin-${DARWIN_ARCH}"
echo ""

# Download urbit binary if not present
if [ ! -f urbit ]; then
  echo "Downloading urbit binary..."
  base="https://bootstrap.urbit.org/vere/edge"
  vere=$(curl -s ${base}/last)
  url="${base}/v${vere}/vere-v${vere}-darwin-${DARWIN_ARCH}"

  echo "Downloading from: $url"
  curl -Lo urbit "$url"
  chmod +x urbit
  echo "✓ Downloaded urbit v${vere}"
else
  echo "✓ urbit binary already exists"
fi

echo ""

# Verify urbit works
echo "Verifying urbit binary..."
./urbit --version
echo ""

# Add to git temporarily
echo "Adding urbit to git (temporarily for Nix)..."
git add -f urbit
echo "✓ urbit added to git staging"
echo ""

echo "================================================"
echo "Setup complete! You can now run:"
echo ""
echo "  nix flake check --print-build-logs"
echo ""
echo "After testing, clean up with:"
echo "  git restore --staged urbit && rm urbit"
echo "================================================"
