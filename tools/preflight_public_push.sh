#!/usr/bin/env bash
set -Eeuo pipefail

# Liquefy public push preflight (safe by default)
# - Initializes git if missing
# - Stages changes
# - Scans staged content for secret-like patterns and private path hints
# - Reports exact staged file list + diffstat
# - DOES NOT PUSH
# - DOES NOT COMMIT unless --commit is passed

usage() {
  cat <<'EOF'
Usage:
  tools/preflight_public_push.sh [repo_dir] [remote_url] [branch] [options]

Positional args:
  repo_dir    Default: current directory
  remote_url  Default: https://github.com/Parad0x-Labs/openclaw_liquefy.git
  branch      Default: main

Options:
  --commit                    Create a LOCAL commit after preflight passes
  --commit-message "msg"      Commit message to use with --commit
  --max-bytes N               Fail if staged file > N bytes (default 20971520 = 20MB)
  --allow-large               Disable large file guard
  --use-current-staging       Do NOT run git add -A (inspect exactly what is already staged)
  --yes                       Skip interactive confirmation prompts (still no push)
  -h, --help                  Show this help

Notes:
  - This script never pushes.
  - It scans staged content only.
  - By default it stages all changes first (git add -A).
  - Use --use-current-staging to inspect exactly the currently staged set.
  - It warns on private path/name hints and fails on secret-like patterns.
EOF
}

REPO_DIR="${1:-$PWD}"
REMOTE_URL="${2:-https://github.com/Parad0x-Labs/openclaw_liquefy.git}"
BRANCH="${3:-main}"

DO_COMMIT=0
COMMIT_MSG=""
MAX_BYTES=$((20 * 1024 * 1024))
ALLOW_LARGE=0
ASSUME_YES=0
USE_CURRENT_STAGING=0

# If positional args omitted and first arg is an option
if [[ "${1:-}" == -* ]]; then
  REPO_DIR="$PWD"
  REMOTE_URL="https://github.com/Parad0x-Labs/openclaw_liquefy.git"
  BRANCH="main"
fi

# Parse options after up to 3 positional args
shift_count=0
for arg in "$@"; do
  [[ "$arg" == -* ]] && break
  shift_count=$((shift_count + 1))
  [[ $shift_count -ge 3 ]] && break
done
if [[ $shift_count -gt 0 ]]; then
  shift "$shift_count"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit)
      DO_COMMIT=1
      shift
      ;;
    --commit-message)
      COMMIT_MSG="${2:-}"
      shift 2
      ;;
    --max-bytes)
      MAX_BYTES="${2:-}"
      shift 2
      ;;
    --allow-large)
      ALLOW_LARGE=1
      shift
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    --use-current-staging)
      USE_CURRENT_STAGING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

sanitize_url() {
  printf '%s' "$1" | sed -E 's#(https?://)[^/@]+@#\1***@#'
}

confirm() {
  local prompt="$1"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  read -r -p "$prompt [y/N]: " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

# Stuff that often leaks. Add org-specific strings as needed.
USER_NAME="$(id -un 2>/dev/null || true)"
HOME_DIR="${HOME:-}"
NAME_HINTS=(
  "${USER_NAME}"
  "Desktop/27122025"
  "${HOME_DIR}"
  "/Users/"
)

SECRET_PATTERNS=(
  "BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"
  "-----BEGIN PRIVATE KEY-----"
  "AKIA[0-9A-Z]{16}"
  "xox[baprs]-[0-9A-Za-z-]{10,}"
  "ghp_[A-Za-z0-9]{36}"
  "github_pat_[A-Za-z0-9_]{20,}"
  "sk-[A-Za-z0-9]{20,}"
  "LIQUEFY_DEFAULT_SECRET"
  "tracevault_default_key"
  "password[[:space:]]*="
  "secret[[:space:]]*="
  "api[_-]?key[[:space:]]*="
  "LIQUEFY_SECRET[[:space:]]*="
)

echo "== Liquefy public push preflight =="
echo "Repo dir:   $REPO_DIR"
echo "Remote URL: $(sanitize_url "$REMOTE_URL")"
echo "Branch:     $BRANCH"
echo

cd "$REPO_DIR"

if [[ ! -d .git ]]; then
  echo "[STEP] Initializing local git repo..."
  git init
fi

if [[ ! -f .gitignore ]]; then
  echo "[WARN] .gitignore missing. Creating a safe starter .gitignore..."
  cat > .gitignore <<'EOF'
__pycache__/
*.pyc
.venv/
venv/
.env
*.pem
*.key
*.p12
*.pfx
.DS_Store
bench/results/
bench/*.csv
benchmarks/latest*.csv
**/latest_ci*.csv
EOF
fi

if git remote get-url origin >/dev/null 2>&1; then
  current_origin="$(git remote get-url origin)"
  echo "[INFO] origin already set to: $(sanitize_url "$current_origin")"
  if [[ "$current_origin" != "$REMOTE_URL" ]]; then
    echo "[WARN] origin differs from requested remote."
    if confirm "Replace origin with requested remote?"; then
      git remote set-url origin "$REMOTE_URL"
      echo "[OK] origin updated"
    else
      echo "[INFO] Keeping existing origin"
    fi
  fi
else
  echo "[STEP] Adding origin remote..."
  git remote add origin "$REMOTE_URL"
fi

current_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
if [[ "$current_branch" != "$BRANCH" ]]; then
  echo "[STEP] Switching branch to $BRANCH..."
  git checkout -B "$BRANCH"
fi

echo
if [[ "$USE_CURRENT_STAGING" -eq 1 ]]; then
  echo "[STEP] Using current staged set (--use-current-staging); skipping git add -A"
else
  echo "[STEP] Staging all changes (git add -A)..."
  git add -A
fi

echo
echo "--------------------"
echo "[REPORT] git status -sb"
git status -sb
echo "--------------------"
echo

echo "[REPORT] Diffstat (staged):"
git diff --cached --stat || true
echo

echo "[STEP] Scanning staged content for secret-like patterns..."
secret_hit=0
for pat in "${SECRET_PATTERNS[@]}"; do
  if git grep -nI -E "$pat" --cached >/dev/null 2>&1; then
    echo "[FAIL] Secret-like pattern matched: $pat"
    git grep -nI -E "$pat" --cached | head -n 20 || true
    secret_hit=1
  fi
done
if [[ "$secret_hit" -eq 1 ]]; then
  echo
  echo "[ABORT] Secret-like content detected in staged files. Fix and rerun."
  exit 2
fi
echo "[OK] No secret-like patterns detected in staged content."
echo

echo "[STEP] Scanning staged content for private path/name hints..."
hint_hit=0
for hint in "${NAME_HINTS[@]}"; do
  [[ -z "$hint" ]] && continue
  if git grep -nI --fixed-strings "$hint" --cached >/dev/null 2>&1; then
    echo "[WARN] Found hint '$hint' in staged content (review manually):"
    git grep -nI --fixed-strings "$hint" --cached | head -n 20 || true
    hint_hit=1
  fi
done
if [[ "$hint_hit" -eq 0 ]]; then
  echo "[OK] No obvious private path/name hints found in staged content."
fi
echo

echo "[STEP] Scanning staged filenames for private path leaks..."
path_warn=0
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if [[ "$f" == *"/Users/"* || "$f" == *"${USER_NAME}"* ]]; then
    echo "[WARN] Suspicious staged path name: $f"
    path_warn=1
  fi
done < <(git diff --cached --name-only)
if [[ "$path_warn" -eq 0 ]]; then
  echo "[OK] No suspicious staged file paths."
fi
echo

if [[ "$ALLOW_LARGE" -eq 0 ]]; then
  echo "[STEP] Scanning staged files for large blobs > $MAX_BYTES bytes..."
  python3 - <<PY
import os, subprocess, sys
MAX_BYTES = int(${MAX_BYTES})
proc = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"], capture_output=True, check=True)
names = [p for p in proc.stdout.decode("utf-8", "replace").split("\x00") if p]
bad = []
for p in names:
    if not os.path.isfile(p):
        continue
    try:
        sz = os.path.getsize(p)
    except OSError:
        continue
    if sz > MAX_BYTES:
        bad.append((sz, p))
if bad:
    bad.sort(reverse=True)
    print(f"[FAIL] Large staged files > {MAX_BYTES} bytes:")
    for sz, p in bad[:50]:
        print(f"  {sz:>10}  {p}")
    sys.exit(3)
print("[OK] No oversized staged files.")
PY
  echo
else
  echo "[INFO] Large file guard disabled (--allow-large)"
  echo
fi

echo "[STEP] Checking staged diff for whitespace/merge markers..."
if ! git diff --cached --check; then
  echo "[ABORT] Staged diff check failed (whitespace/conflict markers)."
  exit 4
fi
echo "[OK] Staged diff check passed."
echo

echo "[REPORT] Exact staged file list:"
git diff --cached --name-only | sed 's/^/  - /'
echo

echo "[INFO] This script never pushes."
if [[ "$DO_COMMIT" -ne 1 ]]; then
  echo "[DONE] Preflight passed. Review with:"
  echo "  git diff --cached --stat"
  echo "  git diff --cached"
  echo "Then commit manually (recommended) or rerun with --commit."
  exit 0
fi

if [[ -z "$COMMIT_MSG" ]]; then
  COMMIT_MSG="chore: initial public drop (preflight)"
fi

echo "[STEP] About to create LOCAL commit only (no push)."
if ! confirm "Proceed with local commit?"; then
  echo "[INFO] Commit skipped. Staged changes remain for review."
  exit 0
fi

git commit -m "$COMMIT_MSG" || {
  echo "[INFO] Nothing to commit."
  exit 0
}

echo
echo "✅ Local commit created. No push was performed."
echo "Next manual steps:"
echo "  git show --stat HEAD"
echo "  git push -u origin $BRANCH   # enter PAT when prompted"
