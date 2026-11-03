# AI 에이전트 2-1: 작업 공간 샌드박스 + 에이전트 루프(로컬 Docker) SPEC

- 상태: Draft (2026-11-04, 김형래)
- 작성일: 2026-11-04
- Depth: Standard (새 Python 패키지, WAS·인프라 변경 없음)
- GitHub 이슈: https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/2 (AI 에이전트 2) — 첫 부분
- 근거: AI 에이전트 1 SPEC(PR #9) D-1·D-2·D-4·D-5·AD-1·AD-7, §7 보안 요건, §9 PoC / 부록 A 계약의 이벤트 모양
- 저장소: `echo-ai-agent` · 브랜치 `feat/ai-2-sandbox-runner` (`main` = `80f821a`에서) · PR로 올린다

## 1. 목표

실행 하나마다 새 작업 공간 컨테이너를 만들고, 모델(Tool Runner)이 그 안에서만 명령을 실행하게 한다. 컨테이너는 네트워크·비밀·쓰기 가능한 시스템 파일이 없다. 단계·명령·결과를 계약의 이벤트 모양으로 남긴다. 같은 코드가 나중에 샌드박스 VM(GCP)에서 돈다.

## 2. 확인된 사실 (11/4)

- `anthropic` 1.17.0(10/20)에 `client.beta.messages.tool_runner`와 `@beta_async_tool`이 있다. 매개변수는 `max_iterations`·`output_config`(`effort`)·`fallbacks`(`"default"` 가능)·`betas`. 도구 안에서 `ToolError`를 올리면 `is_error` 결과로 모델에 돌아간다.
- `python:3.13-slim` 이미지에는 `GPG_KEY`(CPython 배포 서명 공개키 지문) 환경 변수가 들어 있다. 비밀은 아니다.
- Docker Desktop(로컬)에서 `--tmpfs`의 `uid`·`gid`·`size`·`mode` 옵션이 동작한다. tmpfs에는 `docker cp`가 안 되어 파일은 표준 입력 tar로 넣는다.

## 3. 범위

### 3.1 이번에 한다
- `src/echo_agent/sandbox.py`: `DockerSandbox`(만들기·파일 넣기·명령 실행·파일 읽기/쓰기·지우기)
- `src/echo_agent/tools.py`: 모델 도구 `workspace_exec`·`read_file`·`write_file`
- `src/echo_agent/agent.py`: Tool Runner 루프 `run_agent`
- `src/echo_agent/events.py`: 실행 이벤트(계약 부록 A의 `seq·at·step·level·message·data`)
- `src/echo_agent/poc.py`: SPEC §9 PoC를 로컬 Docker로 재현(명령 실행 + 격리 확인 6개 + 정리 확인)
- 시험(Docker 실제 격리 시험 포함), CI(`ruff`·`mypy`·`pytest`)

### 3.2 다음 PR
- WAS 계약(부록 A) 클라이언트: 실행 가져가기·하트비트·이벤트·결과 제출(계약 승인 뒤)
- 검사 컨테이너(패치마다 새로)·보호 파일 차단·패치 해시(AI #5), 분석 구조화 출력(AI #4)
- 샌드박스 VM Terraform·배포(인프라 담당 확인 뒤)

## 4. 결정

| ID | 결정 | 출처 |
|---|---|---|
| D-1 | 작업 공간 컨테이너: `--network none`, `--read-only` + `/workspace`(256MB)·`/tmp`(64MB) tmpfs, 사용자 `65532:65532`, `--cap-drop ALL`, `no-new-privileges`, pids 128, 메모리 512MB(스왑 없음), CPU 1. 볼륨·Docker 소켓·환경 변수 파일을 넘기지 않고, 넘기는 환경 변수는 `HOME=/tmp` 하나뿐 | AI #1 AD-1 |
| D-2 | 기반 이미지는 digest로 고정한 `python:3.13-slim`. 바꿀 때 digest를 함께 고친다 | AI #1 AD-2 |
| D-3 | 호스트는 셸 없이 `docker`를 인자 목록으로 부른다. 모델의 명령 문자열은 컨테이너 안 `sh -c`에만 들어간다 | AI #1 D-5 |
| D-4 | 명령마다 컨테이너 안 `timeout`(기본 60초, TERM 뒤 2초에 KILL) + 호스트 쪽 10초 여유. 출력은 stdout·stderr 각각 앞 16,000자만 남기고 나머지는 읽어서 버린다 | AI #1 AD-1 |
| D-5 | 파일 경로는 `/workspace` 아래 상대 경로만 받는다(절대 경로·`..`·빈 경로·역슬래시·NUL 거부) | AI #1 §7 |
| D-6 | 샌드박스는 `async with`로만 쓰고, 나갈 때(실패 포함) `docker rm --force --volumes`로 지운다. 컨테이너 이름 `echo-ws-<runId>`, 라벨 `echo.sandbox=workspace`·`echo.run-id` | AI #1 §7 실행 단위 |
| D-7 | 모델 `claude-opus-5-5`, effort 기본 `medium`, `max_iterations` 기본 12, `max_tokens` 8,000. `fallbacks="default"` + 베타 `server-side-fallback-2026-07-01`. 거절이면 루프를 멈추고 "AI 검토 없음" 이벤트 | AI #1 D-2·AD-7 |
| D-8 | 키는 SDK 기본값(`ANTHROPIC_API_KEY`)으로 제어 프로세스만 읽는다. 작업 공간에 넘기지 않는다(시험이 호스트에 심은 가짜 값이 컨테이너에 없음을 확인) | AI #1 D-5 |
| D-9 | 이벤트 message는 고정 영어 문장, 값은 data. data 안 문자열은 2,000자에서 자른다 | 부록 A §3.2 |
| AD-1 | 격리 확인의 환경 변수 검사는 이름 허용 목록(`PATH`·`HOME`·`HOSTNAME`·`LANG`·`PWD`·`PYTHON_VERSION`·`PYTHON_SHA256`·`GPG_KEY`)과 비교한다. 목록 밖 이름이 보이면 실패 | AI-default |
| AD-2 | 의존성은 `uv` + `exclude-newer = 2026-10-21`(그 뒤 배포본은 고르지 않음). 액션은 커밋 SHA로 고정 | AI-default |

## 5. Acceptance criteria

| AC | 확인 | 시험 |
|---|---|---|
| AC-1 | `docker run` 인자에 D-1 설정이 모두 있고, 볼륨·소켓·환경 변수 파일·특권이 없다 | `test_run_args_apply_every_isolation_setting` |
| AC-2 | 샌드박스에서 명령 하나가 실제로 돌고 출력이 돌아온다(AI #1 완료 기준 "명령 하나 실제 실행"의 로컬 재현) | `test_command_runs_inside_workspace`, `python -m echo_agent.poc` |
| AC-3 | 외부 연결·메타데이터 서버 접속이 실패하고, 루트 파일 시스템 쓰기가 실패하고, 비루트·권한 0이며, 허용된 환경 변수만 있다 | `test_isolation_check_holds[*]` |
| AC-4 | 호스트의 키·토큰 값이 작업 공간 어디에도 없다 | `test_host_secrets_never_reach_the_workspace` |
| AC-5 | 시간 제한·출력 자르기·작업 공간 크기·프로세스 수 제한이 걸린다 | `test_command_is_stopped_*`, `test_large_output_*`, `test_workspace_size_*`, `test_process_count_*` |
| AC-6 | 실행이 끝나거나 실패해도 컨테이너가 0개 남는다 | `test_sandbox_is_removed_*` |
| AC-7 | 에이전트 루프가 상한·fallback·도구를 넘기고, 거절을 "AI 검토 없음"으로 처리한다 | `tests/test_agent_loop.py` |
| AC-8 | 경로 이탈과 도구 실패가 모델에 오류로 돌아간다 | `test_safe_relative_path_*`, `test_file_tools_*` |

## 6. 리스크

- **R-a 로컬 Docker Desktop과 VM의 Docker 동작이 다르다** → 같은 시험을 VM에서 다시 돌린다(AI #1 §9 PoC). CI(ubuntu)에서도 Docker 시험이 돈다.
- **R-b 기반 이미지의 HIGH 취약점(운영 demo-app과 같은 계열)** → 작업 공간은 네트워크·비밀이 없어 영향이 작다. 갱신 digest로 바꾸는 것은 이미지 검사 결과를 보고 한다.
- **R-c 모델이 같은 명령을 반복해 비용이 는다** → `max_iterations`·`max_tokens` 상한, 실행 마감(15분)은 WAS 계약 쪽에서 한 번 더 건다.
