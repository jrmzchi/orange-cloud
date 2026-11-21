#!/bin/bash
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CHECK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/meowflare-oauth.XXXXXX")"
trap 'rm -rf "$CHECK_DIR"' EXIT
APP_DIR="$REPO_DIR/apps/ios/Orange Cloud/Orange Cloud"
swiftc -swift-version 5 -default-isolation MainActor -module-cache-path "$CHECK_DIR/module-cache" \
  "$APP_DIR/Models/PermissionModels.swift" \
  "$APP_DIR/ViewModels/PermissionSelectionViewModel.swift" \
  "$REPO_DIR/scripts/OAuthPermissionChecks.swift" \
  -o "$CHECK_DIR/check-oauth"
"$CHECK_DIR/check-oauth"
