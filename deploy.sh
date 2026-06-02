#!/bin/sh
# Regenerate the report and publish it to the orphan `gh-pages` branch.
#
# The branch holds ONLY the generated site (index.html, crashes.json,
# findings.json, .nojekyll); it is checked out as a git worktree at ./gh-pages
# (ignored on the main branch). Run after ./gen.sh and ./check.sh so the report
# reflects the current fixtures and backend results.
set -eu

cd "$(dirname "$0")"
WORKTREE=gh-pages
REMOTE=${REMOTE:-origin}

# Ensure the gh-pages worktree exists, reusing the branch if it already does.
if [ ! -e "$WORKTREE/.git" ]; then
    if git show-ref --verify --quiet refs/heads/gh-pages \
        || git ls-remote --exit-code --heads "$REMOTE" gh-pages >/dev/null 2>&1; then
        git worktree add "$WORKTREE" gh-pages
    else
        git worktree add --orphan -b gh-pages "$WORKTREE"
    fi
fi

# Generate the site into the worktree (report defaults here too).
./report.sh "$WORKTREE"
touch "$WORKTREE/.nojekyll"

git -C "$WORKTREE" add -A
if git -C "$WORKTREE" diff --cached --quiet; then
    echo "deploy: no changes to publish"
    exit 0
fi
git -C "$WORKTREE" commit -m "Publish loader fuzzing report"
git -C "$WORKTREE" push "$REMOTE" gh-pages
echo "deploy: pushed gh-pages to $REMOTE"
