#!/bin/bash
# Release script for Anagnor
# Usage: ./release.sh v1.0.0

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v1.0.0"
    exit 1
fi

VERSION=$1

echo "Creating release $VERSION..."

# Ensure we're on main branch
git checkout main
git pull origin main

# Create and push tag
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"

echo "Release $VERSION created!"
echo "GitHub Actions will automatically build and publish the release."
echo "Check: https://github.com/wslabn/anagnor/actions"