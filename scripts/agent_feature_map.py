#!/usr/bin/env python3
"""Cross-agent, read-only feature-to-regression contract; not a release gate.

Project documentation remains human source navigation; this is a deliberately small
machine-readable subset to route change reviews to existing test suites.
No claim of passing evidence is made by merely finding a test file.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "agent-evals" / "feature-contracts.json"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,60}$")
REF = re.compile(r"^[A-Za-z0-9_./-]{1,100}$")


def require(ok, why):
    if not ok:
        raise ValueError(why)


def safe_file(root, path):
    require(isinstance(path, str) and path and not path.startswith("/") and
            "\\" not in path and ".." not in path.split("/"),
            "unsafe repository-relative file path")
    file = (root / path).resolve()
    require(file.is_relative_to(root.resolve()) and file.is_file(),
            "missing/out-of-root file: " + path)
    return file


def validate(document, root=ROOT):
    require(isinstance(document, dict) and document.get("schemaVersion") == 1,
            "feature map schemaVersion must be 1")
    items = document.get("features")
    require(isinstance(items, list) and items, "nonempty feature list required")
    ids = set()
    for item in items:
        require(isinstance(item, dict), "invalid feature object")
        fid = item.get("id")
        require(isinstance(fid, str) and IDENTIFIER.fullmatch(fid) and fid not in ids,
                "duplicate/invalid feature ID")
        ids.add(fid)
        for field in ("source", "regressions", "fieldEvidence"):
            paths = item.get(field)
            require(isinstance(paths, list) and bool(paths) and
                    all(isinstance(p, str) for p in paths) and
                    len(paths) == len(set(paths)) if isinstance(paths, list) else False,
                    fid + ": invalid " + field)
            for path in paths:
                safe_file(root, path)
        require(all("/test/" in s or "/tests/" in s or "Tests/" in s
                    for s in item["regressions"]), fid + ": regressions must name test paths")
        require(not set(item["source"]) & set(item["regressions"]),
                fid + ": source and tests cannot overlap")
    return items


def summarize(features, changed):
    changed = set(changed)
    affected = []
    for entry in features:
        sources = sorted(set(entry["source"]) & changed)
        if not sources:
            continue
        edited_tests = sorted(set(entry["regressions"]) & changed)
        affected.append({
            "feature": entry["id"], "changedSource": sources,
            "existingRegressionTests": entry["regressions"],
            "changedRegressionTests": edited_tests,
            "fieldEvidence": entry["fieldEvidence"],
            "review": ("regression-test-change-present" if edited_tests
                       else "review-existing-regressions-for-new-behavior"),
            "automatedEvidence": "not-run",
            "fieldStatus": "not-run"
        })
    return {"schemaVersion": 1, "changedFiles": sorted(changed),
            "affectedFeatures": affected,
            "unmappedSourceFiles": sorted(p for p in changed if
                (p.startswith(("app/src/main/java/", "app/src/main/java/")) and
                 p.endswith((".kt", ".java")) and
                 not any(p in feature["source"] for feature in features))),
            "limitation": "Map paths are coverage leads only. Neither CI nor field tests were run by this report."}


def git_diff(base, head, root=ROOT):
    require(bool(REF.fullmatch(base)) and bool(REF.fullmatch(head)) and
            not base.startswith("-") and not head.startswith("-"),
            "invalid Git reference")
    completed = subprocess.run(["git", "diff", "--name-only", "--no-ext-diff",
                                base + "..." + head, "--"], cwd=root,
                               capture_output=True, text=True, timeout=20, check=False)
    require(completed.returncode == 0, "Git diff unavailable: " + completed.stderr[:200])
    return completed.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "impact"))
    parser.add_argument("--base", help="Git base SHA/ref for impact")
    parser.add_argument("--head", help="Git head SHA/ref for impact")
    args = parser.parse_args()
    try:
        features = validate(json.loads(MAP.read_text(encoding="utf-8")))
        if args.action == "validate":
            print("Feature map verified:", len(features), "feature(s)")
        else:
            require(bool(args.base) and bool(args.head), "impact requires --base and --head")
            print(json.dumps(summarize(features, git_diff(args.base, args.head)),
                             indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("agent-feature-map:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
