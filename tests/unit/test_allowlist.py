from __future__ import annotations

import pytest

from panos_mcp.client import commands
from panos_mcp.client.allowlist import ReadOnlyViolation, check_request


def op(cmd: str, **extra: str) -> dict[str, str]:
    return {"type": "op", "cmd": cmd, **extra}


ALLOWED_OPS = [
    commands.show_system_info(),
    commands.show_ha_state(),
    commands.show_devices_all(),
    commands.show_devicegroups(),
    commands.show_dg_hierarchy(),
    commands.show_templates(),
    commands.show_jobs_all(),
    commands.show_job(5),
    commands.check_pending_changes(),
    commands.show_dynamic_address_group(),
    commands.show_dynamic_address_group("web-servers"),
    commands.request_license_info(),
    commands.test_security_policy_match(
        from_zone="trust",
        to_zone="untrust",
        source="10.1.1.5",
        destination="192.0.2.10",
        protocol=6,
        destination_port=443,
    ),
]


@pytest.mark.parametrize("cmd", ALLOWED_OPS)
def test_allowed_op_commands(cmd: str) -> None:
    check_request(op(cmd))


def test_op_with_target_allowed() -> None:
    check_request(op(commands.show_system_info(), target="900000000001"))


@pytest.mark.parametrize("action", ["get", "show"])
def test_config_read_allowed(action: str) -> None:
    check_request({"type": "config", "action": action, "xpath": "/config/shared/address"})


@pytest.mark.parametrize("log_type", ["traffic", "threat", "url", "system", "config"])
def test_log_start_allowed(log_type: str) -> None:
    check_request({"type": "log", "log-type": log_type, "query": "", "nlogs": "20"})


def test_log_get_only_for_started_jobs() -> None:
    check_request({"type": "log", "action": "get", "job-id": "7"}, {7})
    with pytest.raises(ReadOnlyViolation):
        check_request({"type": "log", "action": "get", "job-id": "8"}, {7})


@pytest.mark.parametrize(
    "action",
    [
        "set",
        "edit",
        "delete",
        "move",
        "rename",
        "clone",
        "override",
        "multi-move",
        "complete",
        "add",
    ],
)
def test_config_writes_rejected(action: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_request({"type": "config", "action": action, "xpath": "/config/shared/address"})


@pytest.mark.parametrize(
    "cmd",
    [
        "<commit></commit>",
        "<commit-all><shared-policy></shared-policy></commit-all>",
        "<revert><config></config></revert>",
        "<request><license><fetch></fetch></license></request>",
        "<request><license><install></install></license></request>",
        "<request><license><deactivate><key><mode>auto</mode></key></deactivate></license></request>",
        "<request><system><restart></restart></system></request>",
        "<request><batch><reboot></reboot></batch></request>",
        "<request><license><info><extra></extra></info></license></request>",
        "<clear><session><all></all></session></clear>",
        "<debug><software><restart></restart></software></debug>",
        "<set><system><setting><target-vsys>vsys2</target-vsys></setting></system></set>",
        "<show><system><info></info></system></show><show></show>",
        "<show><system>",
        "not xml",
    ],
)
def test_dangerous_or_malformed_ops_rejected(cmd: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_request(op(cmd))


@pytest.mark.parametrize(
    "params",
    [
        {"type": "commit", "cmd": "<commit></commit>"},
        {"type": "import", "category": "configuration"},
        {"type": "export", "category": "configuration"},
        {"type": "user-id", "cmd": "<uid-message/>"},
        {"type": "report", "reporttype": "predefined"},
        {"type": "config", "action": "get", "xpath": "/devices/entry"},
        {"type": "config", "action": "get", "xpath": "/config/shared", "element": "<x/>"},
        {"type": "log", "log-type": "hipmatch"},
        {"type": "log", "action": "finish", "job-id": "1"},
        {"type": "keygen", "user": "admin", "password": "x"},
    ],
)
def test_other_requests_rejected(params: dict[str, str]) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_request(params, {1})


def test_keygen_only_at_startup() -> None:
    check_request({"type": "keygen", "user": "admin", "password": "x"}, allow_keygen=True)
