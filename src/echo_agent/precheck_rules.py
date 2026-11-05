"""사전 점검 규칙 비교(모델 없음). 순수 함수만 둔다: 입력 스냅숏 → `configDiff`·`findings`.

러프 러너(AI 에이전트 4 초안)가 쓴다. 모델 분석을 얹을 때는 이 결과를 그대로 두고
`origin="AI"` 항목을 따로 더하면 된다(WAS 는 AI finding 의 PASS 를 받지 않는다, 계약 §3.3).

WAS 가 만드는 `inputSnapshot` v1 모양(echo-was 러너 API SPEC AD-9):

    {schemaVersion: 1,
     service: {id, name, containerPort, healthCheckPath},
     source: {environmentId, kind, config, imageDigest, variableKeys[]},
     target: {environmentId, kind, config, imageDigest(null 가능), variableKeys[]},
     findings: [{controlId, result, source, environmentId, collectedAt}]}   # 최근 50개 이하

스냅숏에는 비밀 값·변수 값이 없다(변수는 이름만). 그래도 설정 키 이름에 `secret` 이 들어간
칸은 값을 비교 결과에 옮기지 않는다.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

SNAPSHOT_SCHEMA_VERSION = 1

# WAS 결과 검사 상한(echo-was SPEC AD-11): configDiff 200 · findings 100 · 문자열 2,000자.
CONFIG_DIFF_LIMIT = 200
FINDINGS_LIMIT = 100
TEXT_LIMIT = 2_000
# 안내 문장에 늘어놓는 이름 수. 넘으면 "외 n개"로 줄인다.
NAME_LIST_LIMIT = 8

CONFIG_DIFF_CONTROL = "config-diff"
RECENT_FINDINGS_CONTROL = "recent-findings"

# 최근 findings 중 조치가 필요한 결과.
_ATTENTION_RESULTS = ("FAIL", "WARN")


class Severity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


class FindingResult(StrEnum):
    PASS = "PASS"  # noqa: S105 — 판정 값이다(비밀번호 아님)
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class SnapshotError(ValueError):
    """스냅숏 모양이 v1 이 아니다. 메시지에는 칸 이름만 넣는다(값은 넣지 않는다)."""


@dataclass(frozen=True)
class EnvironmentSide:
    environment_id: str
    kind: str | None
    config: Mapping[str, Any]
    image_digest: str | None
    variable_keys: frozenset[str]


@dataclass(frozen=True)
class RecentFinding:
    control_id: str
    result: str
    environment_id: str | None


@dataclass(frozen=True)
class PrecheckSnapshot:
    source: EnvironmentSide
    target: EnvironmentSide
    findings: tuple[RecentFinding, ...]


@dataclass(frozen=True)
class ConfigDiff:
    key: str
    source: str | None
    target: str | None
    severity: Severity

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "target": self.target,
            "origin": "RULE",
            "severity": self.severity.value,
        }


@dataclass(frozen=True)
class Finding:
    control: str
    environment_id: str
    result: FindingResult
    title: str
    reason: str
    suggested_fix: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "environmentId": self.environment_id,
            "result": self.result.value,
            "title": self.title,
            "reason": self.reason,
            "origin": "RULE",
            "suggestedFix": self.suggested_fix,
        }


@dataclass(frozen=True)
class PrecheckAnalysis:
    config_diff: tuple[ConfigDiff, ...]
    findings: tuple[Finding, ...]

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.result is not FindingResult.PASS)


# ---------------------------------------------------------------- 입력 읽기


def parse_snapshot(raw: Mapping[str, Any]) -> PrecheckSnapshot:
    """WAS 의 `inputSnapshot` 을 읽는다. v1 이 아니거나 필수 칸이 없으면 `SnapshotError`."""
    if not isinstance(raw, Mapping):
        raise SnapshotError("inputSnapshot must be an object")
    if raw.get("schemaVersion") != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotError("inputSnapshot.schemaVersion must be 1")
    source = _parse_side(raw.get("source"), "source")
    target = _parse_side(raw.get("target"), "target")
    findings_raw = raw.get("findings") or []
    if not isinstance(findings_raw, list):
        raise SnapshotError("inputSnapshot.findings must be a list")
    findings = tuple(
        _parse_recent_finding(item) for item in findings_raw if isinstance(item, Mapping)
    )
    return PrecheckSnapshot(source=source, target=target, findings=findings)


def _parse_side(raw: Any, name: str) -> EnvironmentSide:
    if not isinstance(raw, Mapping):
        raise SnapshotError(f"inputSnapshot.{name} must be an object")
    environment_id = raw.get("environmentId")
    if not isinstance(environment_id, str) or not environment_id:
        raise SnapshotError(f"inputSnapshot.{name}.environmentId is required")
    config = raw.get("config") or {}
    if not isinstance(config, Mapping):
        raise SnapshotError(f"inputSnapshot.{name}.config must be an object")
    kind = raw.get("kind")
    digest = raw.get("imageDigest")
    if digest is not None and not isinstance(digest, str):
        raise SnapshotError(f"inputSnapshot.{name}.imageDigest must be a string or null")
    keys = raw.get("variableKeys") or []
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        raise SnapshotError(f"inputSnapshot.{name}.variableKeys must be a list of strings")
    return EnvironmentSide(
        environment_id=environment_id,
        kind=kind if isinstance(kind, str) else None,
        config=config,
        image_digest=digest,
        variable_keys=frozenset(keys),
    )


def _parse_recent_finding(raw: Mapping[str, Any]) -> RecentFinding:
    environment_id = raw.get("environmentId")
    return RecentFinding(
        control_id=str(raw.get("controlId") or "unknown"),
        result=str(raw.get("result") or "UNKNOWN").upper(),
        environment_id=environment_id if isinstance(environment_id, str) else None,
    )


# ---------------------------------------------------------------- 비교


def diff_environments(source: EnvironmentSide, target: EnvironmentSide) -> list[ConfigDiff]:
    """출발·도착 환경의 차이. 순서: 종류 → 설정(키 이름순) → 이미지 → 변수 이름(이름순)."""
    diffs: list[ConfigDiff] = []
    if source.kind != target.kind:
        diffs.append(ConfigDiff("kind", source.kind, target.kind, Severity.INFO))

    source_config = flatten_config(source.config)
    target_config = flatten_config(target.config)
    for key in sorted(source_config.keys() | target_config.keys()):
        if _is_secret_key(key):
            continue
        left, right = source_config.get(key), target_config.get(key)
        if left != right:
            diffs.append(ConfigDiff(key, left, right, Severity.INFO))

    # 도착 digest 가 없음(아직 배포 전)도 여기서 차이로 잡힌다.
    if source.image_digest != target.image_digest:
        diffs.append(
            ConfigDiff("imageDigest", source.image_digest, target.image_digest, Severity.INFO)
        )

    for name in sorted(source.variable_keys - target.variable_keys):
        diffs.append(ConfigDiff(f"variables.{name}", "present", None, Severity.WARN))
    for name in sorted(target.variable_keys - source.variable_keys):
        diffs.append(ConfigDiff(f"variables.{name}", None, "present", Severity.INFO))
    return diffs[:CONFIG_DIFF_LIMIT]


def flatten_config(config: Mapping[str, Any], prefix: str = "") -> dict[str, str | None]:
    """중첩 설정을 `a.b` 키로 편다. 값은 비교·표시용 문자열(목록·객체는 정렬 JSON)."""
    flat: dict[str, str | None] = {}
    for key, value in config.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping) and value:
            flat.update(flatten_config(value, f"{path}."))
        else:
            flat[path] = _display_value(value)
    return flat


def _display_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, str):
        text = value
    elif isinstance(value, int | float):
        text = str(value)
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _clip(text)


def _is_secret_key(key: str) -> bool:
    return "secret" in key.rsplit(".", 1)[-1].lower()


# ---------------------------------------------------------------- 경고·안내


def build_findings(snapshot: PrecheckSnapshot, diffs: Iterable[ConfigDiff]) -> list[Finding]:
    """차이 → `config-diff` finding 1개(차이 있으면 WARN, 없으면 PASS) + 최근 findings 경고."""
    diffs = list(diffs)
    findings = [_config_diff_finding(snapshot, diffs)]
    recent = _recent_findings_warning(snapshot)
    if recent is not None:
        findings.append(recent)
    return findings[:FINDINGS_LIMIT]


def _config_diff_finding(snapshot: PrecheckSnapshot, diffs: list[ConfigDiff]) -> Finding:
    target_id = snapshot.target.environment_id
    if not diffs:
        return Finding(
            control=CONFIG_DIFF_CONTROL,
            environment_id=target_id,
            result=FindingResult.PASS,
            title="출발·도착 환경 설정 차이 없음",
            reason="종류·설정·이미지 digest·변수 이름이 모두 같습니다",
            suggested_fix=None,
        )
    warn = sum(1 for d in diffs if d.severity is Severity.WARN)
    return Finding(
        control=CONFIG_DIFF_CONTROL,
        environment_id=target_id,
        result=FindingResult.WARN,
        title="도착 환경 설정이 출발 환경과 다릅니다",
        reason=_clip(f"설정 차이 {len(diffs)}건(경고 {warn}건): {_summary(diffs)}"),
        suggested_fix=_clip("\n".join(guidance_lines(snapshot, diffs))),
    )


def guidance_lines(snapshot: PrecheckSnapshot, diffs: list[ConfigDiff]) -> list[str]:
    """차이 종류마다 조치 안내 한 줄. 경고(WARN)를 먼저 둔다."""
    by_key = {d.key: d for d in diffs}
    lines: list[str] = []

    missing = [d.key.removeprefix("variables.") for d in diffs if _is_missing_variable(d)]
    if missing:
        lines.append(
            f"- 도착 환경에 없는 변수 {len(missing)}개: {_names(missing)}. 이전 전에 도착 환경에 "
            "같은 이름으로 등록하세요(비밀 값은 비밀 참조로)."
        )
    if "kind" in by_key:
        kind = by_key["kind"]
        lines.append(
            f"- 클라우드 종류가 바뀝니다({kind.source} → {kind.target}). 인그레스 클래스·인증서·"
            "접근 역할처럼 클라우드마다 다른 설정을 도착 환경 양식으로 채웠는지 확인하세요."
        )
    if "region" in by_key:
        region = by_key["region"]
        lines.append(
            f"- 리전이 바뀝니다({region.source} → {region.target}). 데이터 위치 규정과 사용자 "
            "지연 시간을 확인하세요."
        )
    if "imageDigest" in by_key:
        if snapshot.target.image_digest is None:
            lines.append(
                "- 도착 환경에 배포된 이미지가 아직 없습니다. 이전 때 출발 환경과 같은 이미지 "
                f"digest({_short_digest(snapshot.source.image_digest)})로 배포하는지 확인하세요."
            )
        else:
            lines.append(
                "- 도착 환경 이미지 digest 가 출발과 다릅니다. 같은 이미지로 이전할지, 다른 "
                "버전이 의도한 것인지 확인하세요."
            )
    extra = [d.key.removeprefix("variables.") for d in diffs if _is_extra_variable(d)]
    if extra:
        lines.append(
            f"- 도착 환경에만 있는 변수 {len(extra)}개: {_names(extra)}. 의도한 값인지 확인하세요."
        )
    others = [d.key for d in diffs if _is_other_config(d)]
    if others:
        lines.append(
            f"- 그 밖의 설정 {len(others)}개가 다릅니다: {_names(others)}. 의도한 차이인지 "
            "확인하세요."
        )
    return lines


_SPECIAL_KEYS = frozenset({"kind", "region", "imageDigest"})


def _is_missing_variable(diff: ConfigDiff) -> bool:
    return diff.key.startswith("variables.") and diff.target is None


def _is_extra_variable(diff: ConfigDiff) -> bool:
    return diff.key.startswith("variables.") and diff.source is None


def _is_other_config(diff: ConfigDiff) -> bool:
    return diff.key not in _SPECIAL_KEYS and not diff.key.startswith("variables.")


def _recent_findings_warning(snapshot: PrecheckSnapshot) -> Finding | None:
    attention = [f for f in snapshot.findings if f.result in _ATTENTION_RESULTS]
    if not attention:
        return None
    target_id = snapshot.target.environment_id
    on_target = any(f.environment_id == target_id for f in attention)
    environment_id = target_id if on_target else (attention[0].environment_id or target_id)
    fail = sum(1 for f in attention if f.result == "FAIL")
    controls = sorted({f.control_id for f in attention})
    return Finding(
        control=RECENT_FINDINGS_CONTROL,
        environment_id=environment_id,
        result=FindingResult.WARN,
        title="최근 보안 검사에 해결하지 않은 결과가 있습니다",
        reason=_clip(
            f"최근 검사 FAIL {fail}건 · WARN {len(attention) - fail}건: {_names(controls)}"
        ),
        suggested_fix=(
            "- 이전 전에 해당 통제를 다시 검사해 해결하거나, 보안 게이트의 기한부 예외를 "
            "등록하세요."
        ),
    )


# ---------------------------------------------------------------- 진입점


def analyze(raw_snapshot: Mapping[str, Any]) -> PrecheckAnalysis:
    """스냅숏 하나 → 비교 결과. 입력이 같으면 결과도 같다(시각·난수 없음)."""
    snapshot = parse_snapshot(raw_snapshot)
    diffs = diff_environments(snapshot.source, snapshot.target)
    findings = build_findings(snapshot, diffs)
    return PrecheckAnalysis(config_diff=tuple(diffs), findings=tuple(findings))


# ---------------------------------------------------------------- 문자열 도우미


def _summary(diffs: list[ConfigDiff]) -> str:
    return _names([d.key for d in diffs])


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:NAME_LIST_LIMIT])
    rest = len(names) - NAME_LIST_LIMIT
    return f"{shown} 외 {rest}개" if rest > 0 else shown


def _short_digest(digest: str | None) -> str:
    if not digest:
        return "없음"
    return digest[:19] + "…" if len(digest) > 19 else digest


def _clip(text: str) -> str:
    return text if len(text) <= TEXT_LIMIT else text[: TEXT_LIMIT - 1] + "…"
