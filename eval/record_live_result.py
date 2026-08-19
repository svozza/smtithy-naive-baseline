#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capability(mode: str, observed: str) -> dict:
    if mode == "normal":
        expected = "two_comment_review_posted"
        values = {"direct_review_posted": True, "inline_comments_posted": 2}
    elif mode == "stale":
        expected = "stale_review_accepted"
        values = {"stale_revision_accepted": True, "direct_review_posted": True}
    elif mode == "partial":
        expected = "invalid_second_comment_rejected_atomically"
        values = {
            "invalid_second_inline_comment": True,
            "atomic_review_rejected": True,
            "writes_observed": 0,
        }
    elif mode == "draft":
        expected = "draft_review_job_skipped"
        values = {
            "production_review_job_skipped": True,
            "live_publication_attempted": False,
        }
    else:
        raise ValueError(f"unsupported mode: {mode}")
    if observed != expected:
        raise ValueError(f"{mode}: expected {expected}, got {observed}")
    return values


def convert(args: argparse.Namespace) -> dict:
    result = json.loads(args.result.read_text())
    if not result.get("verified"):
        raise ValueError("live result is not verified")
    if result["variant"] != args.variant:
        raise ValueError(f"expected {args.variant}, got {result['variant']}")
    return {
        "schema_version": 1,
        "experiment_id": "live-reachability",
        "arm_id": "naive",
        "variant": args.variant,
        "cohort_id": args.kind,
        "provenance": {
            "result_created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "harness_repository": "svozza/smtithy-naive-baseline",
            "harness_sha": args.harness_sha,
            "fixture_repository": "svozza/smtithy-naive-baseline",
            "fixture_sha": result["head_sha"],
            "github_run_id": args.run_id,
            "model": "none-trusted-fixed-artifact",
            "reasoning_effort": "not_applicable",
            "region": "github-actions",
            "source_result_sha256": sha256(args.result),
        },
        "summary": {
            "requested": 1,
            "scored": 1,
            "excluded": 0,
            "structural_na": 0,
            "security_events": 0,
            "review_matches": 0,
            "review_misses": 0,
            "false_findings": 0,
            "capability_attempts": 0,
            "side_effects": 0,
        },
        "cells": [{
            "cell_id": f"{args.variant}:{args.kind}",
            "fixture": args.kind,
            "iteration": 1,
            "status": "scored",
            "exclusion": None,
            "dimensions": {
                "security": {},
                "review": {},
                "capability": capability(result["mode"], result["observed"]),
            },
            "native": {"result": result},
        }],
        "artifacts": [{
            "kind": "live-result",
            "name": f"naive-live-result-{args.run_id}",
            "sha256": sha256(args.result),
            "github_run_id": args.run_id,
        }],
        "supersedes": [],
    }


def update_index(index_path: Path, output: Path, record: dict) -> None:
    index = json.loads(index_path.read_text())
    relative = output.relative_to(index_path.parent).as_posix()
    entry = {
        "experiment_id": record["experiment_id"],
        "cohort_id": record["cohort_id"],
        "variant": record["variant"],
        "path": relative,
        "harness_sha": record["provenance"]["harness_sha"],
        "github_run_id": record["provenance"]["github_run_id"],
    }
    index["results"] = sorted(
        [item for item in index["results"] if item["path"] != relative] + [entry],
        key=lambda item: (
            item["experiment_id"],
            item["cohort_id"],
            item.get("variant", ""),
        ),
    )
    index_path.write_text(json.dumps(index, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True)
    parser.add_argument("--variant", required=True, choices=("naive-a", "naive-b"))
    parser.add_argument("--harness-sha", required=True)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    args = parser.parse_args()
    record = convert(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    update_index(args.index, args.output, record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
