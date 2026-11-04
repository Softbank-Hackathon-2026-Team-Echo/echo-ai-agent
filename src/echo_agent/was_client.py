"""WAS 러너 API 클라이언트(계약 부록 A §3.2 · echo-was 러너 API SPEC §5.2).

| 호출 | 자격 | 경로 |
|---|---|---|
| 실행 가져가기 | 러너 토큰 `echo_rnr_…` | `POST /api/v1/runner/runs:claim` |
| 하트비트 | 실행 토큰 `echo_run_…` | `POST /api/v1/runner/runs/{id}/heartbeat` |
| 진행 이벤트 | 실행 토큰 | `POST /api/v1/runner/runs/{id}/events` (한 번에 최대 100개) |
| 결과 제출 | 실행 토큰 | `POST /api/v1/runner/runs/{id}/result` |

- 표준 라이브러리(`urllib.request`)만 쓴다. 새 의존성 없음.
- 토큰은 환경 변수(`ECHO_RUNNER_TOKEN`)로만 받고, 예외 메시지·`repr`·로그에 넣지 않는다.
- 응답은 WAS 공통 봉투 `{success, code?, message?, data}` 이다. 실패면 `code` 로 예외를 고른다.
- 모델 도구로 노출하지 않는다. 이 클라이언트는 제어 프로세스(결정적 코드)만 쓴다.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Self

RUNNER_TOKEN_PREFIX = "echo_rnr_"  # noqa: S105 — 접두어(값 아님)
RUN_TOKEN_PREFIX = "echo_run_"  # noqa: S105 — 접두어(값 아님)
API_PREFIX = "/api/v1/runner"
EVENTS_BATCH_LIMIT = 100
DEFAULT_TIMEOUT_SECONDS = 15.0
USER_AGENT = "echo-ai-agent-precheck-runner/0.1"

# https 가 아니어도 되는 곳(로컬 개발 WAS).
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# (요청, 시간 제한) → (HTTP 상태, 본문). 시험에서 바꿔 끼운다.
Transport = Callable[[urllib.request.Request, float], tuple[int, bytes]]


class WasConfigError(Exception):
    """환경 변수가 없거나 모양이 틀렸다. 메시지에는 변수 이름만 넣는다."""


class WasError(Exception):
    """WAS 가 실패로 답했다. 메시지에는 HTTP 상태·오류 코드만 넣는다."""

    def __init__(self, status: int, code: str | None) -> None:
        super().__init__(f"WAS answered {status} {code or 'NO_CODE'}")
        self.status = status
        self.code = code


class RunNotActiveError(WasError):
    """409 `RUN_NOT_ACTIVE`: 마감·임대 지남, 취소됨, 이미 끝난 실행."""


class ResultAlreadySubmittedError(WasError):
    """409 `RESULT_ALREADY_SUBMITTED`: 결과 두 번째 제출."""


class RunnerTokenInvalidError(WasError):
    """401 `RUNNER_TOKEN_INVALID`: 토큰 없음·형식 오류·철회·다른 실행의 토큰."""


_ERRORS_BY_CODE: dict[str, type[WasError]] = {
    "RUN_NOT_ACTIVE": RunNotActiveError,
    "RESULT_ALREADY_SUBMITTED": ResultAlreadySubmittedError,
    "RUNNER_TOKEN_INVALID": RunnerTokenInvalidError,
}


@dataclass(frozen=True)
class ClaimedRun:
    """가져간 실행 하나. `run_token` 은 `repr` 에 나오지 않는다."""

    id: str
    kind: str
    org_id: str | None
    service_id: str | None
    source_environment_id: str | None
    target_environment_id: str | None
    input_snapshot: Mapping[str, Any]
    input_hash: str | None
    scenario_ref: str | None
    deadline_at: datetime
    lease_until: datetime | None
    run_token: str = field(repr=False)


def urllib_transport(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    """기본 전송. 4xx·5xx 도 (상태, 본문)으로 돌려준다(봉투의 `code` 를 읽으려고)."""
    try:
        # 주소의 scheme 은 WasClient 가 만들 때 https(또는 로컬 http)로 확인했다.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


class WasClient:
    def __init__(
        self,
        base_url: str,
        runner_token: str,
        *,
        transport: Transport = urllib_transport,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = _validate_base_url(base_url)
        if not runner_token.startswith(RUNNER_TOKEN_PREFIX):
            raise WasConfigError(f"ECHO_RUNNER_TOKEN must start with {RUNNER_TOKEN_PREFIX}")
        self._runner_token = runner_token
        self._transport = transport
        self._timeout = timeout_seconds

    def __repr__(self) -> str:
        return f"WasClient(base_url={self.base_url!r})"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kwargs: Any) -> Self:
        """`ECHO_WAS_URL`·`ECHO_RUNNER_TOKEN` 으로 만든다. 값은 어디에도 출력하지 않는다."""
        env = os.environ if env is None else env
        base_url = env.get("ECHO_WAS_URL", "").strip()
        token = env.get("ECHO_RUNNER_TOKEN", "").strip()
        missing = [
            name
            for name, value in (("ECHO_WAS_URL", base_url), ("ECHO_RUNNER_TOKEN", token))
            if not value
        ]
        if missing:
            raise WasConfigError(f"missing environment variable: {', '.join(missing)}")
        return cls(base_url, token, **kwargs)

    # ------------------------------------------------------------ 러너 토큰

    def claim(
        self, runner_id: str, capabilities: Sequence[str] = ("PRECHECK",)
    ) -> ClaimedRun | None:
        """가져갈 실행이 없으면 None."""
        data = self._post(
            f"{API_PREFIX}/runs:claim",
            self._runner_token,
            {"runnerId": runner_id, "capabilities": list(capabilities)},
        )
        run = data.get("run")
        if run is None:
            return None
        token = data.get("runToken")
        if not isinstance(run, Mapping) or not isinstance(token, str):
            raise WasError(200, "CLAIM_RESPONSE_INVALID")
        if not token.startswith(RUN_TOKEN_PREFIX):
            raise WasError(200, "CLAIM_RESPONSE_INVALID")
        return _parse_claimed_run(run, token)

    # ------------------------------------------------------------ 실행 토큰

    def heartbeat(self, run: ClaimedRun) -> datetime | None:
        """임대 연장. 새 `leaseUntil`(없으면 None). 끝난 실행이면 `RunNotActiveError`."""
        data = self._post(self._run_path(run, "heartbeat"), run.run_token, {})
        return _parse_time(data.get("leaseUntil"))

    def send_events(self, run: ClaimedRun, events: Sequence[Mapping[str, Any]]) -> int | None:
        """이벤트를 100개씩 나눠 보낸다. 마지막 응답의 `acceptedUpTo`."""
        accepted: int | None = None
        for start in range(0, len(events), EVENTS_BATCH_LIMIT):
            batch = [dict(event) for event in events[start : start + EVENTS_BATCH_LIMIT]]
            data = self._post(self._run_path(run, "events"), run.run_token, {"events": batch})
            value = data.get("acceptedUpTo")
            accepted = value if isinstance(value, int) else accepted
        return accepted

    def submit_result(self, run: ClaimedRun, result: Mapping[str, Any]) -> str | None:
        """결과 제출. WAS 가 저장한 `status`. 두 번째 제출은 `ResultAlreadySubmittedError`."""
        data = self._post(self._run_path(run, "result"), run.run_token, dict(result))
        status = data.get("status")
        return status if isinstance(status, str) else None

    # ------------------------------------------------------------ 내부

    @staticmethod
    def _run_path(run: ClaimedRun, action: str) -> str:
        return f"{API_PREFIX}/runs/{urllib.parse.quote(run.id, safe='')}/{action}"

    def _post(self, path: str, token: str, body: Mapping[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 — scheme 은 __init__ 에서 확인
            self.base_url + path,
            data=json.dumps(body, ensure_ascii=False).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        status, raw = self._transport(request, self._timeout)
        envelope = _decode(raw)
        if 200 <= status < 300 and envelope.get("success", True) is not False:
            data = envelope.get("data")
            return data if isinstance(data, dict) else {}
        code = envelope.get("code")
        code = code if isinstance(code, str) else None
        error_type = _ERRORS_BY_CODE.get(code or "", WasError)
        raise error_type(status, code)


def _validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url.strip())
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        pass
    elif parsed.scheme == "http" and host in _LOCAL_HOSTS:
        pass
    else:
        raise WasConfigError("ECHO_WAS_URL must be https:// (http:// only for localhost)")
    if parsed.query or parsed.fragment:
        raise WasConfigError("ECHO_WAS_URL must not have a query or fragment")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


def _decode(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _parse_claimed_run(run: Mapping[str, Any], token: str) -> ClaimedRun:
    run_id = run.get("id")
    deadline = _parse_time(run.get("deadlineAt"))
    snapshot = run.get("inputSnapshot")
    if not isinstance(run_id, str) or deadline is None or not isinstance(snapshot, Mapping):
        raise WasError(200, "CLAIM_RESPONSE_INVALID")
    return ClaimedRun(
        id=run_id,
        kind=str(run.get("kind") or ""),
        org_id=_str_or_none(run.get("orgId")),
        service_id=_str_or_none(run.get("serviceId")),
        source_environment_id=_str_or_none(run.get("sourceEnvironmentId")),
        target_environment_id=_str_or_none(run.get("targetEnvironmentId")),
        input_snapshot=snapshot,
        input_hash=_str_or_none(run.get("inputHash")),
        scenario_ref=_str_or_none(run.get("scenarioRef")),
        deadline_at=deadline,
        lease_until=_parse_time(run.get("leaseUntil")),
        run_token=token,
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # 시간대가 없으면 UTC 로 본다(WAS 는 UTC 로 낸다).
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None
