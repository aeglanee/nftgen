#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root"

echo "## Session context ($(date -u +%FT%TZ))"
echo
echo "Repo: $root"
echo "Branch: $(git branch --show-current 2>/dev/null || echo '(detached)')"
echo
echo "### Recent commits"
git log --oneline -10 2>/dev/null || true
echo
echo "### Repo map"
if command -v tree >/dev/null 2>&1; then
  tree -L 2 -d -I '.git|node_modules|.terraform|result' --noreport
else
  find . -maxdepth 2 -type d \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -not -path '*/result/*' | sort
fi
echo
for d in README.md docs/progress.md DESIGN.md DECISIONS.md PLAN.md; do
  [ -e "$d" ] && echo "Doc present: $d"
done
