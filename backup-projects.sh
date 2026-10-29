#!/bin/bash
# Back every project in ~ and ~/Desktop up to a PRIVATE GitHub repo.
#
#   ./backup-projects.sh            DRY RUN - shows the plan, changes nothing
#   ./backup-projects.sh --go       do it
#   ./backup-projects.sh --go NAME  just one project
#
# What it does per project:
#   1. writes/extends .gitignore so secrets can never be committed
#   2. git init if needed
#   3. uncommitted work  ->  committed on a `staging` branch (NEVER main)
#   4. creates a private GitHub repo if there isn't a remote
#   5. pushes main + staging
#
# What it NEVER does:
#   - merge staging into main (you do that via PR, after reviewing)
#   - force-push, rewrite history, or delete anything
#   - commit a .env / keystore / pem (it aborts that project instead)
set -uo pipefail

GO=false; ONLY=""
for a in "$@"; do
  case "$a" in --go) GO=true ;; --*) ;; *) ONLY="$a" ;; esac
done

ROOTS=("$HOME" "$HOME/Desktop")
# Folders that are duplicates, scratch, or someone else's downloaded code.
# Edit this list if you want any of them backed up after all.
EXCLUDE=(
  "code for js before sdk update"
  "code for js before sdk update copy"
  "code for js before sdk update copy 2"
  "code for js before sdk update copy before new layout"
  "untitled folder 2"
  "untitled folder 3"
  "AI-Background-Remover-main"
)
SKIP_RE='^(Library|Desktop|Documents|Downloads|Movies|Music|Pictures|Public|Applications|flutter|dev|go|Parallels|VirtualBox|SweetDu-Keys|\..*)$'
SECRET_RE='(^|/)(\.env($|\..*)|.*\.pem|.*serviceAccount.*\.json|.*\.p12|.*\.keystore|.*\.jks)$'

GITIGNORE_BLOCK='
# ---- added by backup-projects.sh ----
node_modules/
vendor/
Pods/
.dart_tool/
venv/
__pycache__/
*.pyc
build/
dist/
.next/
out/
DerivedData/
*.apk
*.ipa

# secrets - NEVER commit
.env
.env.*
!.env.example
*.pem
*.p12
*.keystore
*.jks
*serviceAccount*.json

.DS_Store
*.log
'

$GO || { echo "================ DRY RUN ================"; echo "Nothing will change. Re-run with --go to apply."; echo; }

made=0; pushed=0; staged=0; blocked=0; seen=0

is_project() {
  local p="$1"
  [ -d "$p/.git" ] || [ -f "$p/package.json" ] || [ -f "$p/CLAUDE.md" ] \
    || [ -f "$p/pubspec.yaml" ] || [ -f "$p/requirements.txt" ] \
    || [ -f "$p/composer.json" ] || [ -f "$p/index.html" ] || [ -f "$p/Gemfile" ]
}

for root in "${ROOTS[@]}"; do
  [ -d "$root" ] || continue
  for d in "$root"/*/; do
    p="${d%/}"
    base="$(basename "$p")"
    [[ "$base" =~ $SKIP_RE ]] && continue
    skip=false
    for x in "${EXCLUDE[@]}"; do [ "$base" = "$x" ] && skip=true && break; done
    $skip && { echo "--- $base   (excluded: duplicate/scratch/third-party)"; continue; }
    is_project "$p" || continue
    [ -n "$ONLY" ] && [ "$base" != "$ONLY" ] && continue
    seen=$((seen+1))

    repo=$(echo "$base" | tr ' ' '-' | tr -cd '[:alnum:]._-')
    # A folder whose name is all non-ASCII (e.g. "÷≥") sanitises to nothing,
    # which would create a nameless repo. Skip it rather than guess.
    if [ "${#repo}" -lt 2 ]; then
      echo "--- $base"
      echo "    ! skipped - folder name gives no usable repo name. Rename it first."
      seen=$((seen-1)); continue
    fi
    echo "--- $base   ->   $repo"

    # 1. gitignore BEFORE anything gets staged
    if [ ! -f "$p/.gitignore" ] || ! grep -qE '^\.env$' "$p/.gitignore" 2>/dev/null; then
      echo "    . gitignore: adding secret + dependency rules"
      $GO && printf '%s' "$GITIGNORE_BLOCK" >> "$p/.gitignore"
    fi

    # 2. init
    if [ ! -d "$p/.git" ]; then
      echo "    . git init (new repo)"
      $GO && { git -C "$p" init -q -b main || { echo "    ! init failed"; continue; }; }
    fi

    if ! $GO; then
      dirty=$(git -C "$p" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
      rem=$(git -C "$p" remote 2>/dev/null | head -1)
      echo "    . uncommitted: ${dirty:-?}   remote: ${rem:-none (would create private repo $repo)}"
      [ "${dirty:-0}" != "0" ] && echo "    . would commit those onto 'staging'"
      continue
    fi

    # 3. secret guard
    git -C "$p" add -A 2>/dev/null
    leak=$(git -C "$p" diff --cached --name-only 2>/dev/null | grep -E "$SECRET_RE" | grep -v '\.env\.example$' || true)
    if [ -n "$leak" ]; then
      echo "    !! SKIPPED - these secrets would be committed:"
      echo "$leak" | head -5 | sed 's/^/       /'
      echo "       (already-tracked files need: git rm --cached <file>)"
      git -C "$p" reset -q 2>/dev/null
      blocked=$((blocked+1)); continue
    fi

    has_commits=$(git -C "$p" rev-parse HEAD >/dev/null 2>&1 && echo yes || echo no)
    cur=$(git -C "$p" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)

    if [ "$has_commits" = "no" ]; then
      # brand new repo: first commit lands on main, that's fine - nothing to overwrite
      if ! git -C "$p" diff --cached --quiet 2>/dev/null; then
        git -C "$p" -c user.email="developer@hutsy.ca" -c user.name="webfromdev" \
            commit -q -m "Initial backup commit" && echo "    + initial commit on $cur"
      fi
    elif ! git -C "$p" diff --cached --quiet 2>/dev/null; then
      # existing repo with uncommitted work -> put it on staging, never main
      if git -C "$p" show-ref --verify -q refs/heads/staging; then
        git -C "$p" checkout -q staging 2>/dev/null || { echo "    ! cannot switch to staging"; git -C "$p" reset -q; continue; }
      else
        git -C "$p" checkout -q -b staging 2>/dev/null || { echo "    ! cannot create staging"; git -C "$p" reset -q; continue; }
        echo "    + created branch 'staging' from $cur"
      fi
      git -C "$p" add -A 2>/dev/null
      git -C "$p" -c user.email="developer@hutsy.ca" -c user.name="webfromdev" \
          commit -q -m "WIP backup $(date -u +%Y-%m-%dT%H:%MZ)" \
          && { echo "    + uncommitted work committed on 'staging'"; staged=$((staged+1)); }
    else
      git -C "$p" reset -q 2>/dev/null
      echo "    = nothing uncommitted"
    fi

    # 4. remote
    if ! git -C "$p" remote | grep -q .; then
      echo "    + creating PRIVATE repo $repo"
      if gh repo create "$repo" --private --source="$p" --remote=origin >/dev/null 2>&1; then
        made=$((made+1))
      else
        echo "    ! repo create failed (name already taken?) - skipping push"; continue
      fi
    fi

    # 5. push every local branch we have, main included, no force
    ok=false
    for br in $(git -C "$p" for-each-ref --format='%(refname:short)' refs/heads/); do
      if git -C "$p" push -u origin "$br" >/dev/null 2>&1; then
        echo "    + pushed $br"; ok=true
      else
        echo "    ! push failed for $br"
      fi
    done
    $ok && pushed=$((pushed+1))
    now=$(git -C "$p" rev-parse --abbrev-ref HEAD 2>/dev/null)
    [ "$now" = "staging" ] && echo "    . left on branch 'staging' (your files are untouched)"
  done
done

echo
echo "========================================="
echo "projects seen      : $seen"
if $GO; then
  echo "repos created      : $made"
  echo "projects pushed    : $pushed"
  echo "work saved to staging: $staged"
  echo "skipped for secrets: $blocked"
  echo
  echo "main was never merged into. Open PRs on GitHub when you want staging -> main."
else
  echo
  echo "This was a DRY RUN. Re-run with --go to apply."
fi
