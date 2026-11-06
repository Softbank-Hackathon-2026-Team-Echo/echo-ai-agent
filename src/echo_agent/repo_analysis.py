"""Python AST observations and migration risk candidates. No customer code execution."""

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from echo_agent.precheck_model import mask_tokens, secret_candidates
from echo_agent.repo_source import RepoSnapshot

CATEGORIES = {"REGION", "CLOUD_SDK", "SECRET", "LOCAL_STATE"}
LABELS = {
    "REGION": "리전 하드코딩",
    "CLOUD_SDK": "클라우드 SDK",
    "SECRET": "비밀값 패턴",
    "LOCAL_STATE": "로컬 상태 저장",
}
MAX_OBSERVATIONS = 30
CLOUDS = {"aws", "gcp", "azure", "onprem"}
_REGION = re.compile(
    r"\b(?:(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:north|south|east|west|central|northeast|"
    r"northwest|southeast|southwest)-[1-9]|(?:asia|australia|europe|northamerica|southamerica|"
    r"us|me|africa)-(?:east|west|central|north|south|northeast|northwest|southeast|southwest)[1-9])\b"
)
_SECRET_NAME = re.compile(r"(?i)(?:password|passwd|secret|token|api_?key|access_key|private_key)")
_ASSIGNMENT = re.compile(
    r"(?im)([\"']?\b\w*(?:password|passwd|secret|token|api_?key|access_key)\w*[\"']?\s*[:=]\s*)"
    r'(?:[rubf]*(?:"""[\s\S]*?(?:"""|\Z)|\x27{3}[\s\S]*?(?:\x27{3}|\Z))|[^\r\n]*)'
)
_PRIVATE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", re.S
)
_KNOWN_CREDENTIAL = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-ant-[A-Za-z0-9_-]+|AIza[0-9A-Za-z_-]{35}|-----BEGIN [^-]*PRIVATE KEY-----"
)
_SDK = {
    "boto3": "aws",
    "botocore": "aws",
    "google.cloud": "gcp",
    "google-cloud-": "gcp",
    "azure": "azure",
}
_RECOMMEND = {
    "REGION": "리전을 환경별 설정으로 분리하고 대상 환경에서 사용하는 값을 확인하세요.",
    "CLOUD_SDK": "이전 후에도 해당 SDK가 필요한지, 권한과 접속 경로를 확인하세요.",
    "SECRET": "실제 자격 증명인지 확인하고, 맞다면 폐기·회전 후 비밀 저장소로 옮기세요.",
    "LOCAL_STATE": "데이터 영속성과 공유 필요성을 확인하고 저장소 이전을 준비하세요.",
}


def redact_source(text: str) -> str:
    """Mask before clipping, preserving line numbers; heuristic, not a secret scanner proof."""
    text = _PRIVATE.sub(lambda m: "***" + "\n" * m[0].count("\n"), text)
    text = _ASSIGNMENT.sub(lambda m: m[1] + "***" + "\n" * m[0][len(m[1]) :].count("\n"), text)
    text = mask_tokens(text)
    return "\n".join(
        "[REDACTED TOKEN]" if secret_candidates(line) else line for line in text.split("\n")
    )


def safe_text(value: str, limit: int = 1500) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", redact_source(value))[:limit]


def _cloud_module(module: str) -> str | None:
    for name, cloud in _SDK.items():
        if module == name or module.startswith(name + "."):
            return cloud
    return None


def _literal_secret(value: Any) -> bool:
    if not isinstance(value, str) or len(value.strip()) < 4:
        return False
    return not (
        value.lower() in {"none", "null", "false", "true", "changeme", "example", "placeholder"}
        or value.startswith(("${", "{{", "os.getenv", "os.environ"))
        or set(value) <= {"*", "x", "X"}
    )


@dataclass(frozen=True)
class Observation:
    id: str
    category: str
    path: str
    line: int
    text: str
    fact: str
    severity: str

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "location": {"path": self.path, "line": self.line},
            "evidence": {"id": self.id, "text": self.text},
            "observation": self.fact,
            "certainty": "OBSERVED",
            "origin": "RULE",
            "severity": self.severity,
            "recommendation": _RECOMMEND[self.category],
            "riskStatus": "REQUIRES_REVIEW",
        }

    def finding(self, environment_id: str) -> dict[str, Any]:
        # Existing WAS fields suffice for the current UI; source location is human-readable.
        return {
            "control": f"repo-{self.category.lower().replace('_', '-')}",
            "environmentId": environment_id,
            "result": "WARN",
            "origin": "RULE",
            "title": f"[정적 관측/{self.severity}] {LABELS[self.category]}",
            "reason": safe_text(
                f"{self.path}:{self.line} — {self.fact}\n근거: {self.text}\n"
                "소스에 나타난 패턴이며 실제 이전 실패를 확정하지 않습니다."
            ),
            "suggestedFix": _RECOMMEND[self.category],
        }


def observe(snapshot: RepoSnapshot) -> tuple[list[Observation], dict[str, int]]:
    results: list[Observation] = []
    seen: set[tuple[str, int, str]] = set()
    coverage = {"syntaxErrors": 0, "truncatedObservations": 0}
    for file in snapshot.files:
        lines = redact_source(file.content).splitlines()

        def add(
            category: str,
            line: int,
            fact: str,
            *,
            path: str = file.path,
            source_lines: list[str] = lines,
        ) -> None:
            key = (path, line, category)
            if key in seen or not 1 <= line <= len(source_lines):
                return
            seen.add(key)
            if len(results) >= MAX_OBSERVATIONS:
                coverage["truncatedObservations"] += 1
                return
            identity = hashlib.sha256(f"{path}:{line}:{category}".encode()).hexdigest()[:16]
            results.append(
                Observation(
                    f"RE{identity}",
                    category,
                    path,
                    line,
                    source_lines[line - 1][:600],
                    fact,
                    "HIGH" if category == "SECRET" else "MEDIUM",
                )
            )

        # Known credential patterns are evidence candidates, not proof that a key is valid.
        for number, raw_line in enumerate(file.content.splitlines(), 1):
            if _KNOWN_CREDENTIAL.search(raw_line):
                add(
                    "SECRET",
                    number,
                    "알려진 자격 증명 또는 개인 키 패턴이 있습니다. 유효성은 확인하지 않았습니다.",
                )
        if not file.path.endswith(".py"):
            for number, raw_line in enumerate(file.content.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if _REGION.search(raw_line):
                    add(
                        "REGION",
                        number,
                        "설정 또는 의존성 파일에 리전 문자열이 직접 적혀 있습니다.",
                    )
                for name, cloud in _SDK.items():
                    if re.search(
                        r"(?<![\w-])" + re.escape(name) + r"(?:[\w.-]*)(?:[\s\"'=<>~\[]|$)",
                        raw_line,
                    ):
                        add(
                            "CLOUD_SDK",
                            number,
                            f"{cloud} SDK 이름이 선언돼 있습니다. 실제 호출 여부는 미확인입니다.",
                        )
            continue
        try:
            tree = ast.parse(file.content)
        except (SyntaxError, ValueError, RecursionError):
            coverage["syntaxErrors"] += 1
            continue
        imports: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
                    if imported_cloud := _cloud_module(alias.name):
                        add(
                            "CLOUD_SDK",
                            node.lineno,
                            f"{imported_cloud} SDK import가 있습니다. 실행 경로는 미확인입니다.",
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{module}.{alias.name}"
                if imported_cloud := _cloud_module(module):
                    add(
                        "CLOUD_SDK",
                        node.lineno,
                        f"{imported_cloud} SDK import가 있습니다. 실제 실행 경로는 미확인입니다.",
                    )
                elif module == "google" and any(a.name == "cloud" for a in node.names):
                    add(
                        "CLOUD_SDK",
                        node.lineno,
                        "gcp SDK 모듈 import가 있습니다. 실제 실행 경로는 미확인입니다.",
                    )

        def name_of(node: ast.expr, aliases: dict[str, str] = imports) -> str:
            if isinstance(node, ast.Name):
                return aliases.get(node.id, node.id)
            if isinstance(node, ast.Attribute):
                return f"{name_of(node.value)}.{node.attr}"
            return ""

        # AST traversal never resolves imports, calls eval or loads customer Python modules.
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if _REGION.search(node.value):
                    add(
                        "REGION",
                        node.lineno,
                        "Python 소스에 리전 문자열 리터럴이 있습니다. 실행 여부는 미확인입니다.",
                    )
            if isinstance(node, ast.Assign | ast.AnnAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if isinstance(value, ast.Constant) and _literal_secret(value.value):
                    if any(_SECRET_NAME.search(ast.unparse(target)) for target in targets):
                        add(
                            "SECRET",
                            node.lineno,
                            "비밀값 이름에 문자열이 할당돼 있습니다. 실제 비밀인지는 미확인입니다.",
                        )
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and _SECRET_NAME.search(key.value)
                        and isinstance(value, ast.Constant)
                        and _literal_secret(value.value)
                    ):
                        add(
                            "SECRET",
                            value.lineno,
                            "비밀값을 뜻하는 딕셔너리 키에 문자열이 직접 할당되어 있습니다.",
                        )
            if (
                isinstance(node, ast.keyword)
                and node.arg
                and _SECRET_NAME.search(node.arg)
                and isinstance(node.value, ast.Constant)
                and _literal_secret(node.value.value)
            ):
                add(
                    "SECRET",
                    node.value.lineno,
                    "비밀값 이름의 함수 인자에 문자열이 직접 전달됩니다.",
                )
            if not isinstance(node, ast.Call):
                continue
            called = name_of(node.func)
            if called == "sqlite3.connect" and node.args:
                value = node.args[0]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    add(
                        "LOCAL_STATE",
                        node.lineno,
                        "SQLite가 파일 또는 메모리를 참조합니다. 영속성은 미확인입니다.",
                    )
            if called == "shelve.open":
                add("LOCAL_STATE", node.lineno, "shelve 기반 로컬 상태 저장 호출이 있습니다.")
            if called in {"open", "io.open"}:
                mode: Any = (
                    node.args[1].value
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                    else None
                )
                for keyword in node.keywords:
                    if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                        mode = keyword.value.value
                if isinstance(mode, str) and any(c in mode for c in "wax+"):
                    add(
                        "LOCAL_STATE",
                        node.lineno,
                        "파일 쓰기 호출이 있습니다. 마운트·복제·영속성은 미확인입니다.",
                    )
    return results, coverage


def analyze(snapshot: RepoSnapshot, source_cloud: str, target_cloud: str) -> dict[str, Any]:
    if source_cloud not in CLOUDS or target_cloud not in CLOUDS:
        raise ValueError("unsupported cloud")
    observations, coverage = observe(snapshot)
    return {
        "schemaVersion": 1,
        "kind": "repo-analysis.v1",
        "status": "ANALYZED" if snapshot.files else "NO_SUPPORTED_FILES",
        "source": snapshot.manifest(),
        "migration": {"source": source_cloud, "target": target_cloud},
        "observations": [o.to_json() for o in observations],
        "coverage": coverage,
        "suggestions": [],
        "model": None,
        "modelReviewStatus": "NOT_REQUESTED",
        "limitations": [
            "Python과 허용한 설정 파일의 정적 패턴만 검사했습니다.",
            "관측은 확정된 소스 패턴입니다. 실제 실행·비밀값 유효성·이전 실패는 확정하지 않습니다.",
            "제외·상한·문법 오류가 있을 수 있으며 발견 0건은 안전 판정이 아닙니다.",
            "비밀값 검출·마스킹은 알려진 패턴 기반이며 모든 비밀을 탐지한다고 보장하지 않습니다.",
        ],
        "codeExecuted": False,
        "patches": [],
    }


def to_findings(report: dict[str, Any], environment_id: str) -> list[dict[str, Any]]:
    output = []
    for item in report["observations"]:
        observation = Observation(
            item["id"],
            item["category"],
            item["location"]["path"],
            item["location"]["line"],
            item["evidence"]["text"],
            item["observation"],
            item["severity"],
        )
        output.append(observation.finding(environment_id))
    for suggestion in report["suggestions"]:
        observation = next(
            o for o in report["observations"] if o["id"] == suggestion["observationId"]
        )
        location = observation["location"]
        output.append(
            {
                "control": "repo-ai-review",
                "environmentId": environment_id,
                "result": "WARN",
                "origin": "AI",
                "title": "[AI 추정] " + LABELS[observation["category"]],
                "reason": safe_text(
                    f"{location['path']}:{location['line']} — {suggestion['explanation']}\n"
                    f"근거: {observation['evidence']['text']}\n"
                    "의미적 정확성은 사람 검토가 필요합니다."
                ),
                "suggestedFix": safe_text(suggestion["recommendation"]),
            }
        )
    if (
        report["status"] != "ANALYZED"
        or any(report["coverage"].values())
        or any(
            count for reason, count in report["source"]["skipped"].items() if reason != "excluded"
        )
    ):
        output.append(
            {
                "control": "repo-coverage",
                "environmentId": environment_id,
                "result": "WARN",
                "origin": "RULE",
                "title": "저장소 분석 범위 제한",
                "reason": "일부 파일을 분석하지 못했습니다. 발견 0건은 안전 판정이 아닙니다.",
                "suggestedFix": "분석 보고서의 파일 목록과 제외·상한 기록을 확인하세요.",
            }
        )
    return output
