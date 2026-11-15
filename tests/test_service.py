from __future__ import annotations

import plistlib
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from egressveil.cli import app
from egressveil.service import LABEL, TASK_NAME, install_plan, serve_args, uninstall_plan

# POSIX-style paths render identically on every OS the tests run on.
PY: Path = PurePosixPath("/opt/py dir/bin/python3")  # type: ignore[assignment]
LOG: Path = PurePosixPath("/home/u/.egressveil/gateway.log")  # type: ignore[assignment]
CFG: Path = PurePosixPath("/home/u/proj/egressveil.yaml")  # type: ignore[assignment]
HOME: Path = PurePosixPath("/home/u")  # type: ignore[assignment]
WIN_PY = Path("C:/Python/python.exe")
WIN_LOG = Path("C:/Users/A B/.egressveil/gateway.log")
WIN_HOME = Path("C:/Users/A B")
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def test_serve_args() -> None:
    assert serve_args(LOG, None) == ["-m", "egressveil", "serve", "--log-file", str(LOG)]
    assert serve_args(LOG, CFG)[-2:] == ["--config", str(CFG)]


def test_windows_task_xml() -> None:
    plan = install_plan("windows", python=WIN_PY, config=None, log_file=WIN_LOG, home=WIN_HOME)
    ((path, xml),) = plan.files.items()
    assert path.name == "egressveil-task.xml"
    root = ET.fromstring(xml.replace('encoding="UTF-16"', ""))  # noqa: S314 - our own output
    command = root.find(".//t:Exec/t:Command", NS)
    arguments = root.find(".//t:Exec/t:Arguments", NS)
    level = root.find(".//t:RunLevel", NS)
    assert command is not None and arguments is not None and level is not None
    assert command.text == str(WIN_PY)  # pythonw.exe is used only when it exists
    assert (arguments.text or "").startswith("-m egressveil serve --log-file ")
    assert f'"{WIN_LOG}"' in (arguments.text or "")  # path with a space is quoted
    assert level.text == "LeastPrivilege"
    assert plan.commands[0][:4] == ["schtasks", "/Create", "/TN", TASK_NAME]


def test_macos_launchd_plist() -> None:
    plan = install_plan("macos", python=PY, config=None, log_file=LOG, home=HOME, uid=501)
    ((path, text),) = plan.files.items()
    assert str(path) == f"/home/u/Library/LaunchAgents/{LABEL}.plist"
    doc = plistlib.loads(text.encode())
    assert doc["Label"] == LABEL
    assert doc["ProgramArguments"][:4] == [str(PY), "-m", "egressveil", "serve"]
    assert doc["RunAtLoad"] is True
    assert ["launchctl", "bootstrap", "gui/501", str(path)] in plan.commands
    assert 0 in plan.allow_failure  # bootout of a not-yet-loaded agent may fail


def test_linux_systemd_unit() -> None:
    plan = install_plan("linux", python=PY, config=CFG, log_file=LOG, home=HOME)
    ((path, unit),) = plan.files.items()
    assert str(path) == "/home/u/.config/systemd/user/egressveil.service"
    assert '"/opt/py dir/bin/python3" "-m" "egressveil" "serve"' in unit
    assert '"--config" "/home/u/proj/egressveil.yaml"' in unit
    assert "NoNewPrivileges=true" in unit
    assert ["systemctl", "--user", "enable", "--now", "egressveil.service"] in plan.commands


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_uninstall_removes_what_install_writes(platform: str) -> None:
    py, log, home = (WIN_PY, WIN_LOG, WIN_HOME) if platform == "windows" else (PY, LOG, HOME)
    inst = install_plan(platform, python=py, config=None, log_file=log, home=home, uid=501)
    uninst = uninstall_plan(platform, home=home, state_dir=log.parent, uid=501)
    assert set(inst.files) == set(uninst.remove)
    assert uninst.commands


def test_install_dry_run_changes_nothing(tmp_path: Path) -> None:
    before = sorted(p.name for p in tmp_path.rglob("*"))
    result = CliRunner().invoke(app, ["service", "install", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert "would run:" in result.output
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_uninstall_dry_run() -> None:
    result = CliRunner().invoke(app, ["service", "uninstall", "--dry-run"])
    assert result.exit_code == 0
    assert "would run:" in result.output


def test_serve_has_log_file_option() -> None:
    assert "--log-file" in CliRunner().invoke(app, ["serve", "--help"]).output
