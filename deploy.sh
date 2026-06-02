#!/bin/sh
set -eu

cd "$(dirname "$0")"
p=gh-pages r=${REMOTE:-origin}
g() { git -C "$p" "$@"; }

[ -e "$p/.git" ] || {
    if git show-ref --verify --quiet "refs/heads/$p" \
        || git ls-remote --exit-code --heads "$r" "$p" >/dev/null 2>&1; then
        git worktree add "$p" "$p"
    else
        git worktree add --orphan -b "$p" "$p"
    fi
}

./report.sh "$p"
touch "$p/.nojekyll"

g add -A
g diff --cached --quiet && { echo "deploy: no changes to publish"; exit 0; }
g commit -m "Publish loader fuzzing report"
g push "$r" "$p"
echo "deploy: pushed $p to $r"
