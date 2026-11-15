#!/usr/bin/env bash
# deploy.sh — 兼容旧部署入口，直接转调 install.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$HERE/install.sh" "$@"
