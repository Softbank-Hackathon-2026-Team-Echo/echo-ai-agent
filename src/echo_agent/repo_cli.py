"""Read an exact Git commit and report migration risks; --model opts into Claude."""

import argparse
import json
from pathlib import Path

from echo_agent.precheck_model import ModelConfigError
from echo_agent.repo_analysis import CLOUDS, analyze, to_findings
from echo_agent.repo_model import RepoReviewer
from echo_agent.repo_source import SourceError, github_snapshot, local_snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local-repo", type=Path)
    source.add_argument("--github-repo", help="public GitHub owner/name, no credentials")
    parser.add_argument("--commit", required=True, help="exact 40-character commit SHA")
    parser.add_argument("--source-cloud", choices=sorted(CLOUDS), required=True)
    parser.add_argument("--target-cloud", choices=sorted(CLOUDS), required=True)
    parser.add_argument("--environment-id", default="00000000-0000-0000-0000-000000000001")
    parser.add_argument(
        "--model", action="store_true", help="one paid Claude review of masked evidence"
    )
    args = parser.parse_args(argv)
    try:
        reviewer = RepoReviewer.from_env() if args.model else None
        snapshot = (
            local_snapshot(args.local_repo, args.commit)
            if args.local_repo
            else github_snapshot(args.github_repo, args.commit)
        )
        report = analyze(snapshot, args.source_cloud, args.target_cloud)
        if reviewer is not None:
            reviewer.review(report)
        report["findings"] = to_findings(report, args.environment_id)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return (
            0 if report["status"] == "ANALYZED" and report["modelReviewStatus"] != "FAILED" else 1
        )
    except (SourceError, ModelConfigError, ValueError, OSError) as error:
        code = error.code if isinstance(error, SourceError) else "REPO_CONFIG_INVALID"
        print(json.dumps({"status": "UNAVAILABLE", "failureCode": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
