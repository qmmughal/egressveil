"""``egressveil service``: run the gateway in the background at login.

Per-user only, no administrator rights:

* **Windows**: a Task Scheduler task (defined from XML, so long paths work)
  that starts ``pythonw -m egressveil serve`` at logon, without a console.
* **macOS**: a launchd agent in ``~/Library/LaunchAgents``.
* **Linux**: a systemd ``--user`` unit.

Everything is computed as a :class:`ServicePlan` first (files to write and
commands to run), so ``--dry-run`` shows exactly what would happen.
"""

from __future__ import annotations

import os
import plistlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final
from xml.sax.saxutils import escape

__all__ = [
    "LABEL",
    "TASK_NAME",
    "ServicePlan",
    "current_platform",
    "install_plan",
    "serve_args",
    "status_command",
    "uninstall_plan",
]

TASK_NAME: Final = "EgressVeil"
LABEL: Final = "io.github.qmmughal.egressveil"
UNIT: Final = "egressveil.service"


@dataclass(frozen=True, slots=True)
class ServicePlan:
    platform: str
    files: dict[Path, str] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    remove: list[Path] = field(default_factory=list)
    allow_failure: frozenset[int] = frozenset()
    """Indexes of commands whose failure is fine (e.g. stopping a stopped task)."""


def current_platform() -> str:
    plat: str = sys.platform
    if plat == "win32":
        return "windows"
    if plat == "darwin":
        return "macos"
    return "linux"


def serve_args(log_file: Path, config: Path | None) -> list[str]:
    args = ["-m", "egressveil", "serve", "--log-file", str(log_file)]
    if config is not None:
        args += ["--config", str(config)]
    return args


def _windowless_python(python: Path) -> Path:
    candidate = python.with_name("pythonw.exe")
    return candidate if candidate.exists() else python


def _quote_windows(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def _task_xml(python: Path, args: list[str]) -> str:
    arguments = " ".join(_quote_windows(a) for a in args)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>EgressVeil: local privacy gateway for AI coding agents</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(str(python))}</Command>
      <Arguments>{escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _systemd_unit(python: Path, args: list[str]) -> str:
    def q(a: str) -> str:
        return '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'

    exec_start = " ".join(q(a) for a in [str(python), *args])
    return f"""[Unit]
Description=EgressVeil local privacy gateway for AI coding agents
Documentation=https://github.com/qmmughal/egressveil

[Service]
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=default.target
"""


def _launchd_plist(python: Path, args: list[str], log_file: Path) -> str:
    doc = {
        "Label": LABEL,
        "ProgramArguments": [str(python), *args],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "StandardOutPath": str(log_file),
        "StandardErrorPath": str(log_file),
        "ProcessType": "Background",
    }
    return plistlib.dumps(doc).decode("utf-8")


def _paths(platform: str, home: Path, state_dir: Path) -> Path:
    if platform == "windows":
        return state_dir / "egressveil-task.xml"
    if platform == "macos":
        return home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    return home / ".config" / "systemd" / "user" / UNIT


def install_plan(
    platform: str,
    *,
    python: Path,
    config: Path | None,
    log_file: Path,
    home: Path,
    uid: int | None = None,
) -> ServicePlan:
    args = serve_args(log_file, config)
    target = _paths(platform, home, log_file.parent)
    if platform == "windows":
        return ServicePlan(
            platform,
            files={target: _task_xml(_windowless_python(python), args)},
            commands=[
                ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(target), "/F"],
                ["schtasks", "/Run", "/TN", TASK_NAME],
            ],
        )
    if platform == "macos":
        domain = f"gui/{uid if uid is not None else os.getuid()}"  # type: ignore[attr-defined,unused-ignore]
        return ServicePlan(
            platform,
            files={target: _launchd_plist(python, args, log_file)},
            commands=[
                ["launchctl", "bootout", f"{domain}/{LABEL}"],
                ["launchctl", "bootstrap", domain, str(target)],
            ],
            allow_failure=frozenset({0}),
        )
    return ServicePlan(
        platform,
        files={target: _systemd_unit(python, args)},
        commands=[
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", UNIT],
        ],
    )


def uninstall_plan(
    platform: str, *, home: Path, state_dir: Path, uid: int | None = None
) -> ServicePlan:
    target = _paths(platform, home, state_dir)
    if platform == "windows":
        return ServicePlan(
            platform,
            commands=[
                ["schtasks", "/End", "/TN", TASK_NAME],
                ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            ],
            remove=[target],
            allow_failure=frozenset({0}),
        )
    if platform == "macos":
        domain = f"gui/{uid if uid is not None else os.getuid()}"  # type: ignore[attr-defined,unused-ignore]
        return ServicePlan(
            platform,
            commands=[["launchctl", "bootout", f"{domain}/{LABEL}"]],
            remove=[target],
            allow_failure=frozenset({0}),
        )
    return ServicePlan(
        platform,
        commands=[
            ["systemctl", "--user", "disable", "--now", UNIT],
            ["systemctl", "--user", "daemon-reload"],
        ],
        remove=[target],
        allow_failure=frozenset({0}),
    )


def status_command(platform: str, uid: int | None = None) -> list[str]:
    if platform == "windows":
        return ["schtasks", "/Query", "/TN", TASK_NAME]
    if platform == "macos":
        domain = f"gui/{uid if uid is not None else os.getuid()}"  # type: ignore[attr-defined,unused-ignore]
        return ["launchctl", "print", f"{domain}/{LABEL}"]
    return ["systemctl", "--user", "is-active", UNIT]
