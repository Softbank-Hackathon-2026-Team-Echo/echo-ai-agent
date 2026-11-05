# echo-demo-app 이미지. Echo 플랫폼의 빌드 실행기가 저장소 주소 + 커밋으로 이 파일을 빌드한다.
# 앱은 시작할 때 sql/schema.sql 로 스키마를 맞춘다(AUTO_MIGRATE=false 로 끌 수 있다).

FROM python:3.13-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# --- builder: 의존성만 /opt/venv 에 설치 ---
FROM base AS builder
COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# --- runner ---
FROM base AS runner
ENV PATH="/opt/venv/bin:$PATH" \
    PORT=8080
WORKDIR /app

RUN groupadd --system --gid 1001 app && \
    useradd --system --uid 1001 --gid app --no-create-home app

COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY sql ./sql

# K8s runAsNonRoot 가 검증할 수 있도록 숫자 UID 로 지정한다.
USER 1001:1001

EXPOSE 8080
# exec 형식이어야 SIGTERM 이 셸을 거치지 않고 Python 프로세스에 전달된다. 포트는 PORT 환경 변수.
CMD ["python", "-m", "app"]
