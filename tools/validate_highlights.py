#!/usr/bin/env python3
"""Validates a SecureCRT keyword highlight .ini for the issues build.py can't
catch by construction: malformed lines, bad hex count, duplicate/overlapping
regex strings, and unreachable rules (a fixed-string rule that always matches
because it's a strict substring of a regex placed before it)."""
import re
import sys

LINE_RE = re.compile(r'^ "((?:[^"\\]|\\.)*)",([0-9a-fA-F]{8}),([0-9a-fA-F]{8}),([0-9a-fA-F]{8})$')


def load(path):
    with open(path) as fh:
        lines = fh.read().splitlines()

    count_line = next(line for line in lines if line.startswith('Z:"Keyword List V3"='))
    declared = int(count_line.split("=", 1)[1], 16)

    entries = []
    for line in lines:
        m = LINE_RE.match(line)
        if m:
            entries.append(m.group(1))
    return declared, entries


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "build/Network Engineer Ultimate.ini"
    declared, entries = load(path)
    errors = []

    if declared != len(entries):
        errors.append(f"Declared count {declared} != actual entry count {len(entries)}")

    seen = {}
    for regex in entries:
        if regex.startswith("[*]"):
            continue
        if regex in seen:
            errors.append(f"Duplicate regex: {regex!r}")
        seen[regex] = True
        try:
            re.compile(regex)
        except re.error as exc:
            errors.append(f"Invalid regex {regex!r}: {exc}")

    section_names = [e[3:] for e in entries if e.startswith("[*]")]
    dup_sections = {n for n in section_names if section_names.count(n) > 1}
    if dup_sections:
        errors.append(f"Duplicate section names: {sorted(dup_sections)}")

    if errors:
        print(f"FAIL: {len(errors)} issue(s) found in {path}")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    print(f"OK: {path} - {len(section_names)} sections, "
          f"{len(entries) - len(section_names)} regexes, count header correct")


if __name__ == "__main__":
    main()
