"""Tests for false-positive filtering in toroidal-detector."""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from detector import ALL_PATTERNS, ALL_CODE_PATTERNS, _fnv1a


# --- FP category 1: self-reference (own README in git diff) ---

README_DIFF_SNIPPET = """\
diff --git a/toroidal-detector/README.md b/toroidal-detector/README.md
+| **Security** | CVEs, XSS, SQLi, SSRF, hardcoded secrets, weak crypto, disabled TLS | 35 |
+| **Bugs** | Panics, segfaults, data races, deadlocks, null derefs, OOM | 18 |
+| **Smart contract** | Reentrancy, unchecked calls, tx.origin, selfdestruct, oracle manipulation | 15 |
"""

GIT_LOG_SNIPPET = """\
commit abc1234
Author: OZ <logsai88@gmail.com>

    detected(security): xss-XSS

 detected/security/2026-04-26-xss-xss.md | 20 +++++++
"""


def test_self_reference_detected():
    """The README snippet contains pattern keywords — verify they DO match raw."""
    matches = []
    for pattern, name, cat, sev in ALL_PATTERNS:
        if pattern.search(README_DIFF_SNIPPET):
            matches.append(name)
    assert len(matches) > 0, "Expected README keywords to trigger patterns"
    assert "xss" in matches or "ssrf" in matches or "reentrancy" in matches


# --- FP category 2: hex addresses/txhashes mistaken for private keys ---

HEX_NOT_KEYS = [
    # tx hash in git log
    "Transaction: 0x00000550ab97a17cfb3b4accb33220581180000000000000000000000000000000",
    # address in code comment
    "address: 0x0083951d6e5d5cebf863e820c2317a864880000000000000000000000000000000",
    # block hash in output
    "block 0x512f68781c9b411aca0e27e400d0b6a810300000000000000000000000000000000",
]

HEX_REAL_KEYS = [
    # clearly assigned to a key variable
    'private_key = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f15a22f44f6b0ee2b3"',
    # wallet secret
    "WALLET_SECRET=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
]


def test_hex_context_filtering():
    """Bare 0x{64} without key-context words should be skippable."""
    key_context_re = re.compile(
        r"(?:private|secret|key|wallet|mnemonic|seed).{0,50}0x[0-9a-fA-F]{64}\b"
        r"|0x[0-9a-fA-F]{64}\b.{0,50}(?:private|secret|key|wallet)",
        re.IGNORECASE,
    )
    for text in HEX_NOT_KEYS:
        assert not key_context_re.search(text), (
            f"Should NOT flag (no key context): {text[:60]}"
        )
    for text in HEX_REAL_KEYS:
        assert key_context_re.search(text), (
            f"Should flag (has key context): {text[:60]}"
        )


# --- FP category 3: markdown doc lines ---

DOC_LINES = [
    "| **Security** | CVEs, XSS, SQLi, SSRF | 35 |",
    "## Smart Contract Patterns",
    "```python",
    "- Detects reentrancy patterns in Solidity",
    "* pattern-matches for SQL injection",
]

CODE_LINES = [
    "eval(request.body)",
    'password = "hunter2"',
    "subprocess.call(cmd, shell=True)",
    "-----BEGIN RSA PRIVATE KEY-----",
]


def test_doc_line_regex():
    """Doc-format lines should be identified as non-code."""
    doc_re = re.compile(
        r"^\s*(?:"
        r"\|.*\|.*\|"
        r"|#{1,4}\s"
        r"|```"
        r"|\*\*.*\*\*.*\|"
        r"|[-*]\s.*(?:pattern|detect|scan|flag|match)"
        r")",
        re.IGNORECASE,
    )
    for line in DOC_LINES:
        assert doc_re.match(line), f"Should be detected as doc: {line}"
    for line in CODE_LINES:
        assert not doc_re.match(line), f"Should NOT be detected as doc: {line}"


# --- Validate that real findings still match ---

REAL_FINDINGS = [
    ("CVE-2026-42334", "cve"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key-in-code"),
    ("AKIA1234567890ABCDEF", "aws-access-key"),
    ("panic: runtime error", "panic"),
]


def test_real_findings_still_match():
    """Real security findings must still be detected after filtering."""
    all_pats = ALL_PATTERNS + [(p, n, c, s) for p, n, c, s, _l in ALL_CODE_PATTERNS]
    for text, expected_name in REAL_FINDINGS:
        found = False
        for pattern, name, _cat, _sev in all_pats:
            if name == expected_name and pattern.search(text):
                found = True
                break
        assert found, f"Pattern '{expected_name}' should match: {text}"


def test_integration_self_reference_skip():
    """End-to-end: _is_self_reference + _strip_doc_lines kill the README FP."""
    from detector import _is_self_reference, _strip_doc_lines

    git_diff_with_readme = """\
diff --git a/toroidal-detector/README.md b/toroidal-detector/README.md
+# Toroidal Detector
+
+Passive security and bug detector for Claude Code. PostToolUse hook that
+pattern-matches the output against 150+ signatures.
+
+| **Security** | CVEs, XSS, SQLi, SSRF, hardcoded secrets | 35 |
+| **Smart contract** | Reentrancy, unchecked calls, tx.origin | 15 |
"""
    assert _is_self_reference(git_diff_with_readme), "Should detect self-reference"

    # Even if self-reference check were disabled, doc-line stripping removes table rows
    stripped = _strip_doc_lines(git_diff_with_readme)
    remaining_matches = []
    for pattern, name, _, _ in ALL_PATTERNS:
        if pattern.search(stripped):
            remaining_matches.append(name)
    # XSS, SSRF, reentrancy should NOT match after stripping doc lines
    assert "xss" not in remaining_matches, (
        f"XSS should be filtered, got: {remaining_matches}"
    )
    assert "reentrancy" not in remaining_matches


def test_integration_hex_no_context():
    """End-to-end: bare hex in git log doesn't trigger hex-private-key pattern."""
    from detector import ALL_CODE_PATTERNS

    git_log_output = (
        "commit 0x4c0883a69102937d6231471b5dbb6204fe512961708279f15a22f44f6b0ee2b3"
    )
    for pattern, name, _, _, _ in ALL_CODE_PATTERNS:
        if name == "hex-private-key-256bit":
            assert not pattern.search(git_log_output), (
                "Bare hex in git log should not match"
            )
            # But with key context it should
            key_assignment = f'private_key = "{git_log_output.split()[-1]}"'
            assert pattern.search(key_assignment), "Hex with key context should match"
            break


if __name__ == "__main__":
    test_self_reference_detected()
    test_hex_context_filtering()
    test_doc_line_regex()
    test_real_findings_still_match()
    test_integration_self_reference_skip()
    test_integration_hex_no_context()
    print("All tests passed.")
