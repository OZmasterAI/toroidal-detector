#!/usr/bin/env bash
set -euo pipefail

DETECTOR_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Adding PostToolUse hook to Claude Code settings..."

SETTINGS="$HOME/.claude/settings.json"
if [ ! -f "$SETTINGS" ]; then
    echo "{}" > "$SETTINGS"
fi

HOOK_CMD="python3 $DETECTOR_DIR/detector.py"

if grep -q "toroidal-detector\|findings_detector" "$SETTINGS" 2>/dev/null; then
    echo "    Hook already registered in settings.json"
else
    echo "    Add this to your settings.json under hooks.PostToolUse:"
    echo ""
    echo "    {"
    echo "      \"hooks\": {"
    echo "        \"PostToolUse\": ["
    echo "          {"
    echo "            \"type\": \"command\","
    echo "            \"command\": \"$HOOK_CMD\""
    echo "          }"
    echo "        ]"
    echo "      }"
    echo "    }"
    echo ""
    echo "    Or merge it with your existing PostToolUse hooks."
fi

echo "==> Done. Findings will be saved to: $DETECTOR_DIR/detected/"
echo "    Use save_finding.py for manual reviewed findings."
