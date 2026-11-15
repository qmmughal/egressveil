from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from egressveil.config import CONFIG_ENV_VAR

# A string with the *shape* of an API key, assembled at runtime so no
# credential-like literal exists in the source tree. It is not a real secret.
FAKE_CREDENTIAL = "sk-" + "egressveil-test-" + "0" * 24


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Keep tests independent of the developer's real config and environment."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for var in (
        CONFIG_ENV_VAR,
        "ANTHROPIC_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    yield workdir


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[[str], Path]:
    def _write(text: str, name: str = "egressveil.yaml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def example_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "configs" / "egressveil.example.yaml"
