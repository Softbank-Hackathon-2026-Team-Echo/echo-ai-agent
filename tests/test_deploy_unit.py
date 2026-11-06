"""VM 러너 systemd 유닛(`deploy/echo-precheck-runner.service`) 정적 검사.

러너 사용자 HOME 이 `/nonexistent` 이고 `ProtectSystem=strict` 라,
docker(BuildKit 토큰 seed)·trivy(DB)가 쓰는 자리를 상태 폴더 아래로 돌려야
반영 빌드·스캔이 돈다(11/6 운영 E2E `IMAGE_BUILD_FAILED`).
"""

from pathlib import Path

UNIT = Path(__file__).resolve().parents[1] / "deploy" / "echo-precheck-runner.service"
STATE_DIR = "/var/lib/echo-precheck-runner"


def _service_settings() -> list[tuple[str, str]]:
    settings: list[tuple[str, str]] = []
    section = ""
    for raw in UNIT.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]":
            key, _, value = line.partition("=")
            settings.append((key, value))
    return settings


def _environment() -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in _service_settings():
        if key == "Environment":
            name, _, setting = value.partition("=")
            env[name] = setting
    return env


def test_tool_dirs_point_under_state_directory() -> None:
    env = _environment()
    assert dict(_service_settings())["StateDirectory"] == "echo-precheck-runner"
    for name in ("DOCKER_CONFIG", "TRIVY_CACHE_DIR", "CLOUDSDK_CONFIG"):
        assert env[name].startswith(STATE_DIR + "/"), name


def test_confinement_is_not_weakened() -> None:
    settings = dict(_service_settings())
    assert settings["User"] == "echo-runner"
    assert settings["ProtectSystem"] == "strict"
    assert settings["ProtectHome"] == "yes"
    assert settings["PrivateTmp"] == "yes"
    assert settings["NoNewPrivileges"] == "yes"
    assert "ReadWritePaths" not in settings
