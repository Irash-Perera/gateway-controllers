#!/usr/bin/env bash
# release-v0.10.0.sh — Creates and pushes annotated git tags for every policy
# at v0.10.0, mirroring the steps in release-policy.yml.
#
# For each policy it:
#   1. Validates policy structure (go.mod present, module path correct)
#   2. Validates version consistency (policy-definition.yaml == 0.10.0)
#   3. Ensures the tag doesn't already exist
#   4. Asks for confirmation, then creates and pushes the tag
#
# Usage:
#   ./scripts/release-v0.10.0.sh [--dry-run]
#
# Flags:
#   --dry-run    Validate everything but skip tag creation and push.

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
TARGET_VERSION="0.10.0"
REPO="github.com/wso2/apk"          # fallback; overridden by git remote below
DRY_RUN=false

# ── Arg parsing ───────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ── Resolve repo root and remote ──────────────────────────────────────────────
REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"
if [[ "$REMOTE_URL" =~ github\.com[:/]([^/]+/[^/.]+)(\.git)?$ ]]; then
  REPO="github.com/${BASH_REMATCH[1]}"
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────
echo "==> Checking prerequisites..."

if [[ -n "$(git status --porcelain)" ]]; then
  echo "❌ Working tree is not clean. Commit or stash changes first."
  git status --short
  exit 1
fi

CURRENT_COMMIT="$(git rev-parse HEAD)"
echo "   Repo   : $REPO"
echo "   Branch : $(git rev-parse --abbrev-ref HEAD)"
echo "   Commit : $(git rev-parse --short HEAD)"
echo ""

# ── Per-policy loop ───────────────────────────────────────────────────────────
TAGGED=()
SKIPPED=()
FAILED=()

while IFS= read -r def_file; do
  policy_dir="$(dirname "$def_file")"
  policy="$(basename "$policy_dir")"
  tag="policies/${policy}/v${TARGET_VERSION}"

  echo "--- ${policy} ---"

  # ── Version consistency ───────────────────────────────────────────────────
  raw_version="$(grep '^version:' "$def_file" | awk '{print $2}' | tr -d 'v')"
  if [[ "$raw_version" != "$TARGET_VERSION" ]]; then
    echo "   SKIP: policy-definition.yaml version is v${raw_version}, not v${TARGET_VERSION}"
    SKIPPED+=("${policy}")
    echo ""
    continue
  fi

  # ── Tag uniqueness ────────────────────────────────────────────────────────
  if git rev-parse "$tag" &>/dev/null 2>&1; then
    echo "   SKIP: tag already exists (${tag})"
    SKIPPED+=("${policy}")
    echo ""
    continue
  fi

  # ── Policy structure ──────────────────────────────────────────────────────
  if [[ ! -f "${policy_dir}/go.mod" ]]; then
    echo "   FAIL: missing go.mod"
    FAILED+=("${policy}")
    echo ""
    continue
  fi

  expected_module="${REPO}/policies/${policy}"
  actual_module="$(grep '^module ' "${policy_dir}/go.mod" | awk '{print $2}')"
  if [[ "$expected_module" != "$actual_module" ]]; then
    echo "   FAIL: go.mod module mismatch"
    echo "         expected: $expected_module"
    echo "         actual:   $actual_module"
    FAILED+=("${policy}")
    echo ""
    continue
  fi

  echo "   Tag    : $tag"
  echo "   Commit : $(git rev-parse --short "$CURRENT_COMMIT")"

  # ── Dry run ───────────────────────────────────────────────────────────────
  if [[ "$DRY_RUN" == true ]]; then
    echo "   DRY RUN — skipping tag creation."
    echo ""
    continue
  fi

  # ── Confirm per policy ────────────────────────────────────────────────────
  read -r -p "   Create and push tag? [y/N/q] " confirm
  case "$confirm" in
    y|Y)
      git tag -a "$tag" "$CURRENT_COMMIT" -m "Release ${policy} v${TARGET_VERSION}"
      echo "   git tag  : ✅"
      git push origin "$tag"
      echo "   git push : ✅"
      TAGGED+=("$tag")
      ;;
    q|Q)
      echo "   Quit — stopping early."
      break
      ;;
    *)
      echo "   Skipped."
      SKIPPED+=("${policy}")
      ;;
  esac

  echo ""

done < <(find policies -maxdepth 2 -name "policy-definition.yaml" | sort)

# ── Summary ───────────────────────────────────────────────────────────────────
echo "==> Done."
echo "   Tagged  : ${#TAGGED[@]}"
echo "   Skipped : ${#SKIPPED[@]}"
echo "   Failed  : ${#FAILED[@]}"

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo ""
  echo "❌ Policies with validation errors:"
  for f in "${FAILED[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
