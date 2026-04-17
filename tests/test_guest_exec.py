from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import load_config
from proxmox_mcp.guest_exec import GuestExecService


class _Result:
    def __init__(self, *, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class GuestExecTests(unittest.TestCase):
    def _load_config(self, text: str):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(text.strip() + "\n", encoding="utf-8")
            return load_config(config_path)

    def test_qemu_guest_agent_falls_back_to_ssh(self) -> None:
        config = self._load_config(
            """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec]
default_timeout_seconds = 30
max_output_bytes = 1024
poll_interval_seconds = 1

[guest_exec.ssh_targets.vm101]
node = "pve1"
vmid = 101
type = "qemu"
host = "10.0.0.50"
user = "root"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "token"
token_secret = "secret"
verify_tls = true

[profiles.operator]
capabilities = ["vm.guest.exec"]

[clients.ops]
token = "abc"
profile = "operator"
"""
        )
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if argv[:4] == ["pvesh", "create", "/nodes/pve1/qemu/101/agent/exec", "--output-format"]:
                return _Result(returncode=255, stderr=b"QEMU guest agent is not running")
            if argv[0] == "ssh":
                return _Result(stdout=b"ok\n")
            raise AssertionError(f"unexpected argv: {argv}")

        service = GuestExecService(config, runner=runner, sleep_fn=lambda _: None)
        result = service.execute(
            node="pve1",
            vmid=101,
            vm_type="qemu",
            argv=["/bin/echo", "ok"],
            timeout_seconds=5,
        )
        self.assertEqual(result["backend"], "ssh")
        self.assertEqual(result["result"]["stdout"], "ok\n")

    def test_lxc_exec_uses_pct(self) -> None:
        config = self._load_config(
            """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec]
default_timeout_seconds = 30
max_output_bytes = 1024
poll_interval_seconds = 1

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "token"
token_secret = "secret"
verify_tls = true

[profiles.operator]
capabilities = ["vm.guest.exec"]

[clients.ops]
token = "abc"
profile = "operator"
"""
        )

        def runner(argv, **kwargs):
            self.assertEqual(argv[:4], ["pct", "exec", "102", "--"])
            return _Result(stdout=b"hello\n")

        service = GuestExecService(config, runner=runner, sleep_fn=lambda _: None)
        result = service.execute(
            node="pve1",
            vmid=102,
            vm_type="lxc",
            argv=["/bin/echo", "hello"],
            timeout_seconds=5,
        )
        self.assertEqual(result["backend"], "pct")
        self.assertEqual(result["result"]["stdout"], "hello\n")
