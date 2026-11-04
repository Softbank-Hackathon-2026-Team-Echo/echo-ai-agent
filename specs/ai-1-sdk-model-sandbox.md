# AI 에이전트 1: 에이전트 SDK·모델·샌드박스 방식 SPEC

- 상태: Draft (2026-11-03, 김형래 검토 전. 9절 PoC는 로컬 Docker와 샌드박스 VM 모두 통과(11/4). 8절 Q5 원문 대조 남음)
- 작성일: 2026-11-03
- Depth: Standard
- GitHub 이슈: https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/1 (AI 에이전트 1 `[결정]`, 담당 hyeongrae-kim)
- 관련
  - echo-ai-agent #2(샌드박스 생성·실행·로그) · #3(권한 경계) · #4(사전 점검) · #5(수정안 검증) · #6(검증 게이트 + 사람 승인) · #8(기능 격차 매핑)
  - echo-was #25(보안 통제, `specs/sec-1-security-controls.md`) · #30(사람 승인·사전 승인)
  - echo-infra #23(네트워크) · #24(신원)
  - echo-frontend #8(에이전트 작업 화면, 담당 프론트)
- 기준: echo-was `main` = `b7c108c`, echo-infra `main` = `4f0fb4f`, echo-frontend `main` = `e63cc91`, echo-demo-app `main` = `0ff0d44`, GCP 프로젝트 `team-echo-final`(직접 조회)
- 마감: 2026-11-08(일) 10:00 KST. P0는 그 전에 구현하고, P1·P2는 추가 항목으로 이어 간다.

## 1. 목표

AI 에이전트를 **무엇으로 만들고(SDK·모델) 어디서 돌릴지(샌드박스)** 정한다. 그리고 고른 방식으로 샌드박스에서 명령 하나를 실제로 실행해 확인한다.

이 결정 위에서 최종 발표 요건 **"AI 에이전트가 샌드박스에서 점검·수정하는 모습"**을 만든다.
- 에이전트는 이전 전에 출발·도착 환경과 고객 앱을 점검하고, 운영과 분리된 샌드박스에서 수정안을 만든다.
- 수정안은 에이전트가 고칠 수 없는 고정 검사를 통과해야 하고, 사람이 승인해야 한다.
- 에이전트는 운영을 읽기만 한다. 운영을 바꾸려는 시도는 거부되고 기록된다.

## 2. 확인된 사실 (11/3)

### 2.1 저장소
- echo-ai-agent에는 README만 있다(`80f821a`). AI 이슈 8개는 모두 Todo이고, 김형래가 맡았다.
- **echo-was 에이전트 신원**
  - 에이전트 토큰 `Authorization: Bearer echo_agt_…`는 GET·HEAD만 허용한다.
  - 쓰기 시도는 403 `AGENT_READ_ONLY`이고 `audit_logs`(행위자 AGENT)에 남는다(`app/auth/guards.py`).
  - 이전 계획 승인은 사람만 할 수 있다.
- echo-was 용어 사전 후속 용어
  - 에이전트 = "샌드박스 쓰기 + 운영 읽기만"
  - 샌드박스 = "별도 네임스페이스 또는 VM"
  - 승인(에이전트 변경) = "AI 수정의 운영 반영을 개발자 이상의 사람이 허락한 기록"
- **echo-frontend E01-2 사전 점검 화면**은 계약 4-5 모양으로 브라우저 시뮬레이션이 있다(`src/lib/api/prechecks.ts`, `PRECHECK_API_READY = false`).
  - 모양: 샌드박스 ID · 단계 · 로그 · `featureGaps` · `configDiff` · 패치(diff·검증 통과 수) · 거부된 시도
  - 단계 값: `SANDBOX · CONFIG_DIFF · FEATURE_GAPS · PATCH_VERIFY · APPROVAL`

### 2.2 GCP (직접 조회, `team-echo-final`)
- 김형래 계정은 `roles/owner`다.
- API: compute·iam·secretmanager·logging·oslogin은 켜져 있고, iap는 꺼져 있다.
- 할당량: VPC 2/5, 라우터 1/10, 서울 리전 E2 CPU 0/24, 인스턴스 3/24.
- Terraform 상태 버킷 `gs://echo-tfstate-team-echo-final/gcp/`에 접근할 수 있다.
- 조직 정책: 외부 IP·VPC 피어링·SA 생성 제한 없음. 기본 SA 자동 Editor 부여는 막혀 있다.
- 기존 VPC는 `default`·`echo-dev` 두 개다.
  - `default`는 SSH·RDP·ICMP를 0.0.0.0/0에 열어 두었다(VM 없음).
  - `echo-dev`는 내부 대역 전체 허용 규칙이 있다.

### 2.3 운영 고객 앱 이미지 (직접 검사, Trivy 0.75.0)
- 운영 demo-app `…/echo-demo-app@sha256:3a8211ce…`에 **수정 버전이 있는 HIGH 취약점 5건**이 있다: msgpack 2, setuptools 1, urllib3 2.
- 같은 5건이 베이스 이미지 `python:3.13-slim` 단독 검사에도 나온다. 그래서 앱 의존성이 아니라 **베이스 이미지의 파이썬 패키지**에서 온 것으로 본다.
- 참고: 오래된 `python:3.13.0-slim`은 HIGH 39·CRITICAL 7(합계 46)이다.

### 2.4 SDK·모델 (Anthropic 문서 기준)
- Python SDK의 Tool Runner(`client.beta.messages.tool_runner` + `@beta_tool`)는 우리가 정의한 도구만 반복 호출하는 루프를 제공한다. 우리가 직접 호스팅하고, 회차마다 승인·차단·결과 수정 같은 고리를 걸 수 있다.
- 구조화 출력은 `client.messages.parse()`(Pydantic 스키마)로 응답을 검증한다.
- 기본 모델 `claude-opus-5-5`
  - 입력 $4 / 출력 $20 per MTok, 1M 맥락.
  - 생각(thinking)은 끌 수 없어서 effort로 조절한다(기본 `medium`).
  - 도구 강제 지정(`tool_choice` any·tool)은 400이다.
  - 안전 분류기가 거절하면 `stop_reason = "refusal"`이다. 서버 측 fallback(`fallbacks: "default"`)을 켤 수 있다.

## 3. 범위

### 3.1 이번에 정한다 (이 문서)
1. 에이전트 루프 방식과 모델(4·5절)
2. 샌드박스 위치·구조·보안 요건(4·6·7절)
3. 샌드박스 인정 기준(8절)
4. 시연 시나리오(10절)
5. PoC 방법과 결과(9절)

### 3.2 하지 않는다 (P1·P2 추가 항목으로 유지)
- 운영 고객 저장소로의 자동 PR(PR 봇) — P0 반영은 시나리오 사본 브랜치까지(D-8·D-9)
- 쿼터·실시간 권한처럼 클러스터·클라우드에서 직접 읽어야 하는 점검 — P0는 UNKNOWN(10.1절)
- k3s·gVisor 기반 더 강한 격리, 별도 GCP 프로젝트 분리
- AI 배포 보조(AI #7), 평가 범위 확장(고정 시나리오 밖)
- 인프라(Terraform) 수정안의 반영 — 설명으로만 남긴다

### 3.3 이 저장소 밖 (담당 따로, 안내서로 전달)
- **echo-was:** 사전 점검·AI 제안 API, 실행 큐, 실행 토큰, 결과 검증, AI 패치 승인, 감사(계약은 부록 A). echo-was 담당 검토
- **echo-infra:** 샌드박스 VPC·VM Terraform. 저장소 규칙상 apply 전에 서동옥 님 확인
- **echo-frontend:** E01-2 실제 연결(frontend #8) → 김도영 님
- **echo-demo-app:** 운영 이미지 취약점 해소 → Saccharine1211 님

## 4. 결정

| ID | 결정 | 출처 |
|---|---|---|
| D-1 | 에이전트 루프는 **Anthropic Python SDK Tool Runner**로 만들고 우리가 호스팅한다. 도구가 실행되는 곳(작업 공간 컨테이너)과 키가 있는 곳(제어 프로세스)을 우리가 나누기 위해서다 | 사용자(11/3, 관리형 에이전트 제외) |
| D-2 | 모델은 `claude-opus-5-5`, effort를 명시한다(분석 `medium`, 수정 `high`, 가칭). 거절(`refusal`)이면 "AI 검토 없음"으로 처리하고, 서버 측 fallback을 켠다 | AI-default(검토 필요) |
| D-3 | 분석(사전 점검의 차이·격차·설명)은 에이전트 루프 없이 **호출 한 번 + 구조화 출력**으로 한다. 입력은 WAS가 모은 설정·검사 결과다 | AI-default |
| D-4 | 샌드박스는 **GCP `team-echo-final` 안 새 VPC + VM 1대 + 실행마다 새 Docker 컨테이너**에 둔다 | 사용자(11/3) |
| D-5 | **모든 Claude 호출은 샌드박스의 제어 프로세스만** 한다. echo-was는 Anthropic 키와 Anthropic으로 나가는 연결을 갖지 않는다 | 사용자 승인 계획(11/3) |
| D-6 | 제어 프로세스가 WAS를 **폴링**한다(들어오는 연결 0). 자격 증명 3종과 API는 부록 A의 계약을 따른다 | 사용자 승인 계획(11/3) |
| D-7 | AI 결과는 판정을 혼자 바꾸지 못한다(PASS 불가, 기본 WARN, 사람 확인 뒤 차단 사유). 재난복구 실행 경로에서 부르지 않는다. AGENT는 SYSTEM 신원·사전 승인을 쓸 수 없다 | 사용자(11/3), echo-was #25 D-7 |
| D-8 | 수정안의 반영은 사람 승인 뒤에만 한다. **P0의 반영 대상은 이 저장소의 시나리오 사본 브랜치**(`applied/<runId>`)이고, 운영 고객 저장소로의 PR(PR 봇)은 P1이다 | 사용자(11/3, P0·P1 범위), 이슈 #6 "반영 1건 기록" |
| D-9 | **P0 반영 절차:** ① 사람이 승인하면 WAS가 `APPLY_PATCH` 실행을 만든다 ② 제어 프로세스가 승인 때의 `patchHash`와 다시 계산한 해시를 비교한다 ③ 같으면 이 저장소 전용 배포 키(쓰기, **이 저장소 하나만**, Secret Manager 보관, 제어 프로세스만 가짐)로 `applied/<runId>` 브랜치에 커밋한다 ④ 커밋 SHA를 결과로 제출한다 ⑤ WAS가 "반영됨"과 커밋 SHA를 감사에 남긴다. 운영 저장소·운영 환경에는 아무것도 쓰지 않는다 | AI-default(검토 필요) |
| AD-1 | 작업 공간 컨테이너는 `--network none`, 읽기 전용 루트 + 작업 디렉터리만 tmpfs, 비루트, `--cap-drop ALL`, `no-new-privileges`, 메모리·CPU·pids·시간 제한, Docker 소켓 미마운트, 비밀값 0으로 띄운다 | AI-default |
| AD-2 | 검사 컨테이너는 패치마다 새로 띄운다. 검사 도구는 digest로 고정하고 읽기 전용으로 마운트한다. **보호 파일**(테스트·검사 설정·CI 워크플로·정책·예외 파일)을 건드린 패치는 검사 전에 `BLOCKED(PROTECTED_FILE_CHANGED)`로 처리한다 | AI-default |
| AD-3 | 이미지 검증은 제어 프로세스가 `docker build --network none --pull=false`로 패치된 Dockerfile을 빌드해 Trivy로 검사한다. 베이스 이미지와 의존성 단계 캐시는 샌드박스 준비 때(원본 커밋, 제어 프로세스가 직접) 미리 만든다. 결과 이미지는 실행이 끝나면 지운다 | AI-default(위험은 12절) |
| AD-4 | 비밀 전달: Anthropic 키·러너 토큰·에이전트 토큰을 Secret Manager 비밀 하나씩으로 둔다. **비밀 단위로만** VM SA에 읽기 권한을 준다(프로젝트 역할 0개). 제어 프로세스가 시작할 때 메모리로 읽는다 | AI-default |
| AD-5 | Terraform은 echo-infra의 **새 루트 `terraform/environments/gcp/ai-sandbox/`**(상태 경로 분리)에 둔다. 기존 `gcp/dev` 루트를 바꾸지 않아 apply 영향을 줄인다 | AI-default(서동옥 님 확인 필요) |
| AD-6 | VM: e2-standard-2(가칭), Shielded VM, OS Login, 공인 IP 없음, Cloud NAT로 443만 나감, 쓰지 않을 때 중지 | AI-default |
| AD-7 | 비용 상한: 실행 마감 15분, 동시 실행 1개, 실행당 출력 토큰 상한. 고정 시나리오 리허설 기준 하루 수십 회 이내로 쓴다 | AI-default |

## 5. 에이전트 루프 후보 비교

| 후보 | 하는 일 | 장점 | 단점 | 선택 |
|---|---|---|---|---|
| 직접 작성한 루프(Messages API) | `tool_use`가 끝날 때까지 우리가 반복 | 의존성 최소, 완전한 통제 | 루프·오류 처리를 다 만들어야 함 | 아니요 |
| **Tool Runner (Python SDK)** | 우리가 정의한 도구로 SDK가 반복 | 코드가 적고 회차마다 고리를 걸 수 있음, 실행 위치를 우리가 정함 | 우리가 호스팅해야 함 | **예** |
| 관리형 에이전트(Managed Agents) | Anthropic이 루프와 세션별 컨테이너를 운영 | 만들 것이 가장 적음 | 샌드박스가 우리 클라우드 밖이고 위치·격리를 우리가 정하지 못함 | 아니요(사용자 결정) |
| Claude Agent SDK | Claude Code 하네스(파일·셸 도구 내장)를 라이브러리로 | 기본 도구가 많음 | 기본 도구가 실행되는 곳과 키 위치를 나누기 어렵고, 우리가 호스팅해야 함 | 아니요 |

**도구 목록(P0)**

| 도구 | 하는 일 |
|---|---|
| `workspace_exec(cmd)` | 작업 공간 컨테이너에서 명령 실행. 네트워크 없음, 시간·출력 제한 |
| `read_file(path)` · `write_file(path, content)` | 작업 공간 파일만 |
| `platform_request(method, path, body?)` | 에이전트 토큰으로 echo-was 호출. 메서드를 걸러내지 않는다. 경계는 서버가 지킨다(쓰기는 403 + 감사) |
| `submit_patch(summary)` | 작업 공간의 변경을 수정안으로 확정 → 제어 프로세스가 고정 검사 |

## 6. 샌드박스 후보 비교

| 후보 | 격리 | 만드는 비용 | 비고 | 선택 |
|---|---|---|---|---|
| 관리형 에이전트 컨테이너 | 우리 클라우드 밖 | 가장 적음 | 위치·격리를 우리가 정하지 못함 | 아니요(사용자 결정) |
| 기존 GKE의 별도 네임스페이스 | 관제탑·고객 앱 대기 환경과 같은 클러스터 | 적음 | 그 VPC는 내부 전체 허용이고 NetworkPolicy가 0건이라 격리를 새로 다 만들어야 함 | 아니요 |
| 별도 GCP 프로젝트의 VM | 프로젝트 단위 IAM 분리 | 중간 | 프로젝트 생성·결제 연결이 필요 | P1 |
| **같은 프로젝트의 새 VPC + VM** | 망·신원·자원 분리(피어링 없음, 역할 0개 SA) | 적음 | 프로젝트 Owner·Editor는 접근할 수 있음(한계로 기록) | **예** |

## 7. 구조와 보안 요건

```text
[운영: echo-dev VPC, GKE의 echo-was]          [샌드박스: 새 VPC — 피어링·VPN 없음]
 WAS API ◀─ 에이전트 토큰(읽기만) ─────────  제어 프로세스 (Tool Runner, 키 보유)
   ▲                                           │ 명령 전달
   │ ① 실행 가져가기(러너 토큰)                    ▼
   │ ② 이벤트·결과 제출(실행 토큰)          작업 공간 컨테이너 (비밀 0, 네트워크 없음)
   └───────────────────────────────────    검사 컨테이너 (패치마다 새로, 고정 검사)
                                  └─ Anthropic API (제어 프로세스만, 443)
```

| 영역 | 요건 | 확인 방법 |
|---|---|---|
| 망 | 새 VPC, 기존 VPC와 피어링·공유 VPC·VPN 없음 | `echo-dev` 대역·WAS DB·진입점 VM 접속 실패 |
| 들어오는 연결 | 공인 IP 없음, 인바운드 기본 거부. 관리는 IAP SSH만(필요할 때 iap API를 켬) | 외부에서 접속 불가 |
| 나가는 연결 | Cloud NAT로 443만. 접속할 도메인 목록(Anthropic API·`api.echoport.uk`·GitHub)은 제어 프로세스가 지킨다. 작업 공간은 네트워크 없음 | 작업 공간에서 외부 연결 실패 |
| 메타데이터 | 작업 공간은 네트워크가 없어 메타데이터 서버에 닿지 않음. VM SA는 프로젝트 역할 0개 | 작업 공간에서 토큰 요청 실패 |
| 비밀 | 키·토큰은 제어 프로세스 메모리에만 있음. 작업 공간·검사 컨테이너에 0 | 환경 변수·파일·마운트 검사 0건 |
| 실행 단위 | 실행마다 새 컨테이너, 끝나면 삭제. 캐시·볼륨 공유 없음 | 실행 후 남은 컨테이너·볼륨 0 |
| 실행 제한 | AD-1 설정 | 제한 초과 시 강제 종료 |
| 검사 무결성 | AD-2·AD-3. 검사는 모델이 아니라 제어 프로세스가 돌림 | 테스트 파일을 고친 수정안이 차단됨 |
| 운영 접근 | WAS API + 에이전트 토큰(짧은 만료)만. 클라우드·클러스터 API 직접 접근 없음 | 쓰기 403 + 감사(AGENT) |
| 결과 전달 | 실행 1회용 토큰으로 그 실행만 제출. WAS가 스키마·크기·AI PASS 금지를 검증 | 다른 실행 ID·재사용 거부 |
| 기록 | 실행 ID로 단계·명령·검사 결과·거부를 남김. 로그는 비밀 가리기를 거침 | E01-2 화면·감사에서 실행 ID로 조회 |
| 비용 | AD-7 + VM 중지 + 예산 알림 | 알림 확인 |

## 8. 샌드박스 인정 기준 (원장 Q5)

- **원장 `final_features_v6.md`의 Q5 원문은 노션에 있어 확인하지 못했다.** 김형래가 원문과 대조해 이 절을 확정한다.
- 이 문서의 기준(제안): 아래를 모두 만족하면 샌드박스로 본다.
  1. 운영과 망이 분리되어 있다(피어링·VPN 없음, 운영 대역 접속 불가).
  2. 운영 신원·비밀이 없다(작업 공간 비밀 0, VM SA 역할 0개).
  3. 실행마다 새로 만들고 지운다.
  4. 운영 변경이 불가능하고, 시도하면 거부·기록된다.
  5. 실행 ID·단계·로그를 화면에서 볼 수 있다.

## 9. PoC (완료 기준: 고른 방식으로 샌드박스에서 명령 하나 실제 실행)

| 순서 | 할 일 | 확인 | 로컬 Docker 재현 (11/4 15:03 KST) | 샌드박스 VM |
|---|---|---|---|---|
| 1 | 샌드박스 VPC·VM apply(서동옥 님 확인 뒤, 김형래) | VM이 공인 IP 없이 뜸 | 해당 없음 | **통과(11/4 19:41):** echo-infra `gcp/ai-sandbox` apply(16개 생성·변경 0). VM `echo-sandbox-runner` 내부 IP `10.70.0.2`, 공인 IP 없음, Secure Boot. 접속은 IAP SSH만 |
| 2 | 제어 프로세스 설치, Secret Manager에서 키 읽기 | 키가 메모리에만 있음 | 해당 없음(로컬은 환경 변수) | **통과(19:49):** VM SA가 `echo-sandbox-anthropic-api-key`를 Secret Manager에서 읽어 프로세스 환경 변수로만 넘김. 실행 출력·홈·`/tmp`에서 키 값 0건. 운영 비밀(`echo-dev-entry-weights-token`) 읽기는 `PERMISSION_DENIED`, 프로젝트 VM 목록도 권한 없음 |
| 3 | Tool Runner로 `workspace_exec("python -c 'print(1)'")` 실행 | 출력 `1`, 이벤트 기록 | **모델로 통과(11/4 17:45):** `claude-opus-5-5`가 1턴에 `workspace_exec`로 명령 실행(종료 0, 출력 `1`), 2턴에 결과 보고 후 끝. 토큰 입력 2,236·출력 128, 거절 없음. 키 값은 출력 전체에서 0건 | **모델로 통과(19:49):** 같은 러너(`a783aac`)로 `claude-opus-5-5`가 1턴에 명령 실행(종료 0, 출력 `1`), 2턴에 보고. 토큰 2,236/130 |
| 4 | 작업 공간에서 `curl https://example.com` · 메타데이터 요청 · `echo-dev` 대역 접속 | 모두 실패 | **통과:** `https://example.com`·`169.254.169.254` 접속 모두 실패(`--network none`이라 루프백만 있음, 특정 대역 접속도 같은 이유로 불가) | **통과:** 작업 공간 격리 6개 통과. VM 자체도 `echo-dev` 대역(`10.60.0.6:8080`·`10.60.0.8:443`)·바깥 80 접속 실패, 443(`api.anthropic.com` 401, `api.echoport.uk` 204)만 됨 |
| 5 | 작업 공간 환경 변수·파일에서 키 검색 | 0건 | **통과:** 환경 변수는 허용 이름만, 호스트에 심은 가짜 키 값이 작업 공간에 없음(`test_host_secrets_never_reach_the_workspace`) | **통과:** 러너 시험 40개(Docker 격리·비밀 시험 포함) VM에서 통과 |
| 6 | 실행 끝난 뒤 컨테이너·볼륨 | 0개 | **통과:** 남은 컨테이너 0(`docker ps -a --filter label=echo.sandbox`) | **통과:** 남은 컨테이너 0 |

- 로컬 재현: echo-ai-agent PR #11(`feat/ai-2-sandbox-runner`, `4771c8a`)에서 `uv run python -m echo_agent.poc`(15:03)와 `--with-model`(17:45) 모두 종료 코드 0. 격리 확인 6개(외부 연결·메타데이터 차단, 루트 쓰기 차단, 비루트 `65532`, 권한 `CapEff 0`, 허용된 환경 변수만) 모두 통과. Docker 시험(격리·비밀·정리) 9개 통과.
- 샌드박스 VM(11/4 19:49 KST): 같은 러너 `a783aac`를 IAP SSH로 올려(uv 0.8.17 sha256 확인, `uv sync --frozen`) `python -m echo_agent.poc --with-model` 종료 코드 0. 이슈 완료 기준 "고른 방식으로 샌드박스에서 명령 하나를 실제로 실행"을 채웠다.

결과는 이 표와 이슈 댓글에 시각·명령·출력과 함께 남긴다.

## 10. 시연 시나리오

**점검 대상**
- 운영 demo-app과 같은 커밋(`0ff0d44`)의 사본을 이 저장소 `scenarios/demo-app-0ff0d44/`에 둔다.
- echo-demo-app 저장소는 고치지 않는다.

### 10.1 사전 점검 입력과 출처 (이슈 #4 완료 기준 항목)

- 실제 클러스터를 읽는 어댑터가 아직 없어서(echo-was 환경 어댑터는 가짜, 실제 EKS 어댑터 echo-was #13은 담당 없음), P0는 **저장소에 선언된 설정**을 고정 커밋으로 읽는다.
- 출처는 `DECLARED`(선언 설정)로 표시해 "실제 적용 상태"와 구분한다. 읽을 수 없는 항목은 UNKNOWN이다.

| 점검 항목(이슈 #4) | P0 출처 | 표시 | P1 |
|---|---|---|---|
| 권한 | echo-infra Terraform의 IAM·Access Entry·SA 바인딩(고정 커밋) | `DECLARED` | 클라우드 IAM 읽기(읽기 전용 신원) |
| 쿼터 | 없음 | UNKNOWN | 클라우드 쿼터 API |
| 버전 | 쿠버네티스: Terraform 클러스터 버전 설정. 앱: 이미지 digest·베이스 이미지 태그 | `DECLARED` | 클러스터 API `/version` |
| 스토리지 | 매니페스트의 PVC·StorageClass(`replication/k8s/*`, `demo-app/*`) | `DECLARED` | 클러스터 API |
| 복제 설정 `wal_level` | `replication/k8s/*/10-postgres.yaml`의 Postgres 설정 | `DECLARED` | DB 읽기 전용 계정(`pg_monitor`)으로 `SHOW wal_level` |
| 기본 키 | demo-app `sql/schema.sql`(복제 표에 PK가 있는가) | `DECLARED` | DB 카탈로그 조회 |
| 이미지 취약점 | 검사 워크플로 Trivy 결과(운영 digest) | real | — |
| 설정 위반 | Trivy config(Dockerfile·매니페스트·Terraform) | real | — |

- 이슈 #4의 "경고 1건 이상과 조치 안내"는 위 결과에서 만든다. 지금 운영 이미지 HIGH 5건, readiness 검사 `/healthz`(DB를 보지 않음), Postgres 공개 노출 등이 실제로 해당한다.
- 입력은 WAS가 모아 실행 입력(`inputSnapshot`)으로 넘긴다. 저장소 파일은 제어 프로세스가 고정 커밋으로 받아 작업 공간에 읽기 전용으로 넣는다.

**흐름**
1. **점검(분석)**
   - 입력: 출발 aws-tokyo·도착 gcp-seoul 설정 차이, 운영 이미지 검사 결과(HIGH 5), Dockerfile·매니페스트 설정 검사 결과
   - 결과: 차이(`configDiff`), 기능 격차(`featureGaps`), AI 경고(`findings`, 사람 확인 전 WARN)
2. **수정안 1 — 통과 예상**
   - 문제: 운영 이미지의 HIGH 5건
   - 에이전트가 Dockerfile 런타임 단계를 고친다(예: 쓰지 않는 파이썬 패키지를 갱신하거나 제거).
   - 고정 검사: 단위 시험 + 다시 빌드한 이미지 Trivy HIGH 0 + gitleaks → `PROPOSED` → **사람 승인** → **반영**(D-9: 사본 브랜치 `applied/<runId>`에 커밋, 커밋 SHA 기록)
3. **수정안 2 — 차단 예상**
   - 문제: "CI에 보안 검사가 없다"
   - 고치려면 반드시 `.github/workflows/`(보호 파일)를 바꿔야 하므로 `BLOCKED(PROTECTED_FILE_CHANGED)`가 된다.
   - 화면 문구: "검사 설정은 AI가 바꿀 수 없다. 사람이 직접 반영한다."
4. **운영 변경 시도**
   - 진행자가 "이 수정을 운영에 바로 반영해"라고 지시한다.
   - 에이전트가 `platform_request("POST", …/deploy-requests)`를 부르고, 403 `AGENT_READ_ONLY`로 거부된다.
   - `blockedAttempts`와 감사(AGENT)에 남는다.
5. **이전으로 연결**
   - 사전 점검 기록이 echo-was #25의 C-AI-1을 채운다.
   - 운영 이미지가 그대로면 C-IMG-1이 FAIL이라 게이트가 차단 사유를 보인다.
   - 담당자가 수정을 반영해 새 digest가 생기면 다시 검사해 통과한다.

**재현성 (리허설 5회 기준)**
- 대상 커밋·프롬프트 버전·effort를 고정한다.
- 판정은 고정 검사가 한다.
- 5회 결과가 다르면 수정 지시 범위를 좁힌다.
- 대체 경로로 "녹화된 실제 실행"을 표시해 쓴다.

## 11. 인수 조건

| AC | 확인 | 어디서 |
|---|---|---|
| AC-1 | 5·6절 후보 비교와 4절 결정이 있다 | 문서 |
| AC-2 | 8절 인정 기준이 원장 Q5 원문과 대조되어 있다 | 문서(김형래) |
| AC-3 | 9절 PoC 1~6이 실제 결과로 채워져 있다(명령 하나 실제 실행 포함) | 샌드박스 |
| AC-4 | 7절 확인 방법 중 망·비밀·메타데이터·실행 단위가 실측으로 확인된다 | 샌드박스 |
| AC-5 | 10.1절 표의 출처가 구현과 같고, 읽을 수 없는 항목이 UNKNOWN으로 나온다(이슈 #4) | 러너·echo-was |
| AC-6 | 승인 1건이 `applied/<runId>` 커밋으로 반영되고, 해시가 다르거나 BLOCKED인 패치는 반영되지 않는다(이슈 #6) | 러너·echo-was |

## 12. 사전 부검 (데모 날 기준)
- **P-a 이미지 빌드 검증(AD-3)이 호스트 Docker 데몬에서 돈다** → 빌드 컨테이너도 네트워크가 없고 비밀이 없으며, 빌드 옵션은 모델이 아니라 제어 프로세스가 정한다. 더 강한 격리(rootless 빌드·gVisor)는 P1.
- **P-b 빌드가 의존성 받기에서 멈춘다** → 의존성 단계 캐시를 준비 때 만든다. 캐시가 없으면 그 검사는 UNKNOWN으로 기록한다(PASS 아님).
- **P-c 안전 분류기가 보안 점검 요청을 거절한다** → `refusal` 처리 + 서버 측 fallback, 그래도 거절이면 "AI 검토 없음"으로 표시한다.
- **P-d 에이전트가 매번 다른 수정안을 낸다** → 10절 재현성 대책.
- **P-e 샌드박스 VM이 비용을 계속 쓴다** → 시연 시간 외에는 중지, 예산 알림.

## 13. 위임 세부 (구현자가 정하고 보고)
- 제어 프로세스 패키지 구조, 프롬프트 문구, 출력 스키마 세부 칸, 컨테이너 이미지 구성, 보호 파일 목록의 경로 패턴, VM 기계 유형.

## 14. 완료 뒤 알릴 것
- **서동옥:** 같은 프로젝트에 샌드박스 VPC·VM을 만든다는 것, 새 Terraform 루트 위치(AD-5) 확인 요청, `default` VPC의 SSH·RDP 공개
- **Saccharine1211:** 부록 A 계약(WAS에 새 API·표·검사기), 용어 사전의 "사전 점검" 담당 표기 합의, demo-app 이미지 HIGH 5건
- **김도영:** E01-2 단계 값 대응(`SANDBOX_CREATE…SANDBOX_DELETE` ↔ 화면 `SANDBOX…APPROVAL`), 계약 4-5 수정안
- **팀:** 10절 시연 시나리오

## 부록 A. WAS ↔ AI 러너 계약 v1 (초안)

초안은 같은 폴더의 [`ai-1-appendix-a-was-runner-contract.md`](ai-1-appendix-a-was-runner-contract.md)다. echo-was 담당과 합의되면 echo-was 문서(`docs/`)로 옮기고, 여기에는 링크만 남긴다.
