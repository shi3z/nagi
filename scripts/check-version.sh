#!/bin/bash
# Check npm registry version and auto-bump if x.y changed

set -e

PACKAGE_NAME="nagi-terminal"
PACKAGE_JSON="$(dirname "$0")/../package.json"

# Get local version
LOCAL_VERSION=$(grep '"version"' "$PACKAGE_JSON" | sed 's/.*"\([0-9]*\.[0-9]*\.[0-9]*\)".*/\1/')
LOCAL_XY=$(echo "$LOCAL_VERSION" | cut -d. -f1,2)

# Get npm registry version
NPM_VERSION=$(npm view "$PACKAGE_NAME" version 2>/dev/null || echo "0.0.0")
NPM_XY=$(echo "$NPM_VERSION" | cut -d. -f1,2)

echo "Local version: $LOCAL_VERSION (x.y = $LOCAL_XY)"
echo "NPM version:   $NPM_VERSION (x.y = $NPM_XY)"

if [ "$LOCAL_XY" != "$NPM_XY" ]; then
    echo ""
    echo "x.y version changed! Updating local version..."

    # Set new version to NPM's x.y.0
    NEW_VERSION="${NPM_XY}.0"

    # Update package.json
    sed -i "s/\"version\": \"$LOCAL_VERSION\"/\"version\": \"$NEW_VERSION\"/" "$PACKAGE_JSON"

    echo "Updated to $NEW_VERSION"
    echo ""
    echo "Run the following to commit and publish:"
    echo "  git add package.json && git commit -m 'Bump version to $NEW_VERSION' && git push"
    echo "  npm publish"
else
    echo ""
    echo "No x.y change detected."
fi
