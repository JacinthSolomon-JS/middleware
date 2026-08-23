#!/usr/bin/env bash
set -e

VERSION=$1

if [ -z "$VERSION" ]; then
  echo "Usage: ./scripts/release.sh <vX.Y.Z>"
  exit 1
fi

DATE=$(date +%Y-%m-%d)

echo "Preparing release $VERSION for $DATE..."

# Replace [Unreleased] header with the new version tag
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [$VERSION] - $DATE/" CHANGELOG.md

git add CHANGELOG.md
git commit -m "chore(release): bump version to $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

echo "Release $VERSION tagged successfully! Run 'git push origin main --tags' to publish."