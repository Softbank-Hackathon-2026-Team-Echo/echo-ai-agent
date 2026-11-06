"""Optional PRECHECK stage; existing findings schema, no new WAS result fields."""

import time
from collections.abc import Callable, Mapping
from typing import Any

from echo_agent.precheck_rules import parse_snapshot
from echo_agent.repo_analysis import CLOUDS, analyze, to_findings
from echo_agent.repo_model import RepoReviewer
from echo_agent.repo_source import RepoSnapshot, SourceError, github_snapshot


class RepoPrecheck:
    def __init__(
        self,
        reviewer: RepoReviewer | None = None,
        *,
        loader: Callable[..., RepoSnapshot] = github_snapshot,
        location: str = "local/development",
    ) -> None:
        self.reviewer = reviewer
        self.loader = loader
        self.location = location

    def run(self, raw: Mapping[str, Any], *, seconds: float) -> dict[str, Any]:
        """repository={repo, commitSha} is a proposed optional PRECHECK input extension.

        Never infer the deployed commit from main/HEAD or use scenarioRef as customer source.
        Missing/unavailable source produces an explicit coverage warning, not a clean scan.
        """
        deadline = time.monotonic() + min(seconds, 100)
        environment = parse_snapshot(raw)
        env_id = environment.source.environment_id
        descriptor = raw.get("repository")
        try:
            if not isinstance(descriptor, Mapping):
                raise SourceError("REPO_INPUT_MISSING")
            if set(descriptor) != {"repo", "commitSha"}:
                raise SourceError("REPO_INPUT_INVALID")
            if seconds < 5:
                raise SourceError("SOURCE_TIMEOUT")
            source, target = environment.source.kind, environment.target.kind
            if source not in CLOUDS or target not in CLOUDS:
                raise SourceError("CLOUD_UNSUPPORTED")
            snapshot = self.loader(
                descriptor["repo"], descriptor["commitSha"], seconds=min(seconds, 30)
            )
            report = analyze(snapshot, str(source), str(target))
            if self.reviewer is not None:
                self.reviewer.review(
                    report, seconds=deadline - time.monotonic(), location=self.location
                )
            return {
                "status": report["status"],
                "findings": to_findings(report, env_id),
                "model": report["model"],
                "processing": report.get("processing"),
                "simulated": report.get("simulated", False),
                "modelReviewStatus": report["modelReviewStatus"],
                "observationCount": len(report["observations"]),
            }
        except (SourceError, ValueError, TypeError, KeyError) as error:
            code = error.code if isinstance(error, SourceError) else "REPO_INPUT_INVALID"
            return {
                "status": "UNAVAILABLE",
                "failureCode": code,
                "model": None,
                "processing": None,
                "simulated": False,
                "observationCount": 0,
                "findings": [
                    {
                        "control": "repo-coverage",
                        "environmentId": env_id,
                        "result": "WARN",
                        "origin": "RULE",
                        "title": "저장소 분석을 수행하지 못했습니다",
                        "reason": f"원인 코드: {code}. 저장소 분석 결과가 없는 상태입니다.",
                        "suggestedFix": "저장소·정확한 배포 커밋·접근 가능 여부를 확인하세요.",
                    }
                ],
            }


def merge_result(result: dict[str, Any], repo: dict[str, Any]) -> None:
    """Append bounded findings and aggregate actual transfer accounting."""
    existing = result["findings"]
    additions = repo["findings"]
    available = max(0, 100 - len(existing))
    if result["status"] == "SUCCEEDED":
        result["findings"] = [*existing, *additions[:available]]
    if (
        result["status"] == "SUCCEEDED"
        and result.get("model") is None
        and repo.get("model") is not None
    ):
        result["model"] = repo["model"]
    result["simulated"] = bool(result["simulated"] or repo.get("simulated"))
    transfer = repo.get("processing")
    if transfer is None:
        return
    previous = result.get("processing")
    if previous is None:
        result["processing"] = transfer
        return
    # Both modules use the same configured provider/model and controller location.
    result["processing"] = {
        **previous,
        "dataClasses": sorted(set(previous["dataClasses"]) | set(transfer["dataClasses"])),
        "externalTransferBytes": (previous.get("externalTransferBytes") or 0)
        + transfer["externalTransferBytes"],
    }
