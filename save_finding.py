#!/usr/bin/env python3
"""Manual finding saver — called by Claude to record reviewed findings.

Usage: echo '{"title":"...","severity":"...","category":"...","project":"...","summary":"...","details":"...","attack_vector":"...","example":"...","impact":"...","remediation":"...","references":"..."}' | python3 save_finding.py
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime

REPO = os.path.dirname(os.path.abspath(__file__))

CATEGORY_DIRS = {
    "security": "reviewed/security",
    "bug": "reviewed/bugs",
    "bugs": "reviewed/bugs",
    "performance": "reviewed/performance",
    "perf": "reviewed/performance",
    "smart-contract": "reviewed/smart-contract",
    "contract": "reviewed/smart-contract",
    "economic": "reviewed/economic",
    "econ": "reviewed/economic",
}


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text[:80].rstrip("-")


def save(data: dict) -> str:
    title = data.get("title", "untitled")
    severity = data.get("severity", "medium")
    category = data.get("category", "security")
    project = data.get("project", "unknown")
    date = datetime.now().strftime("%Y-%m-%d")

    subdir = CATEGORY_DIRS.get(category, "reviewed/security")
    slug = slugify(title)
    filename = f"{date}-{slug}.md"
    filepath = os.path.join(REPO, subdir, filename)

    # Dedup: skip if file already exists
    if os.path.exists(filepath):
        return f"SKIP: {filepath} already exists"

    template_path = os.path.join(REPO, "templates", "reviewed.md")
    with open(template_path) as f:
        content = f.read()

    content = content.format(
        title=title,
        severity=severity,
        category=category,
        project=project,
        date=date,
        summary=data.get("summary", ""),
        details=data.get("details", ""),
        attack_vector=data.get("attack_vector", ""),
        example=data.get("example", ""),
        impact=data.get("impact", ""),
        remediation=data.get("remediation", ""),
        references=data.get("references", ""),
    )

    with open(filepath, "w") as f:
        f.write(content)

    subprocess.run(
        ["git", "add", filepath],
        cwd=REPO,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", f"finding({category}): {title}"],
        cwd=REPO,
        capture_output=True,
    )

    return f"SAVED: {filepath}"


if __name__ == "__main__":
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        print("ERROR: expected JSON on stdin", file=sys.stderr)
        sys.exit(1)
    result = save(data)
    print(result)
