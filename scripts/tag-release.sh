#!/usr/bin/env bash
set -e

TAG=$1
MESSAGE=$2

if [ -z "$TAG" ] || [ -z "$MESSAGE" ]; then
  echo "Usage: ./scripts/tag-release.sh <tag-name> <release-message>"
  echo "Example: ./scripts/tag-release.sh v1.1.0 'Initial release of entropy inspection module'"
  exit 1
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "Tagging branch '$CURRENT_BRANCH' with '$TAG'..."

# Create annotated tag
git tag -a "$TAG" -m "$MESSAGE"

# Push tag to remote
git push origin "$TAG"

echo "Tag '$TAG' created and pushed successfully!"