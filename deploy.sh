#!/bin/sh
set -eu

cd "$(dirname "$0")"

./report.sh
cd gh-pages
touch .nojekyll
git add -A
COMMIT=$(git commit-tree "$(git write-tree)" -m "Publish loader fuzzing report")
git update-ref HEAD "$COMMIT"
git push -f
echo "deploy: pushed gh-pages"
