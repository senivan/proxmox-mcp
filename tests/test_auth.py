from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.auth import authenticate, extract_tls_peer_identity
from proxmox_mcp.config import load_config


class AuthTests(unittest.TestCase):
    def _write_config(self, root: Path, client_extra: str = "", tls_enabled: bool = False) -> Path:
        config_path = root / "config.toml"
        config_path.write_text(
            f"""
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = {"true" if tls_enabled else "false"}
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
client_ca_file = "./tls/ca.crt"
require_client_cert = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "mcp@pam!default"
token_secret = "secret"
verify_tls = true

[profiles.readonly]
capabilities = ["inventory.read", "vm.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
{client_extra.strip()}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        return config_path

    def test_authenticate_accepts_matching_tls_common_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = self._write_config(
                root, client_extra='tls_client_common_name = "ops-laptop"', tls_enabled=True
            )
            config = load_config(config_path)
            peer_identity = extract_tls_peer_identity(
                {"subject": ((("commonName", "ops-laptop"),),)},
                b"test-cert",
            )
            authn = authenticate(
                config,
                authorization_header="Bearer abc",
                client_id_header="ops_laptop",
                tls_peer_identity=peer_identity,
            )
            self.assertEqual(authn.principal.client_id, "ops_laptop")

    def test_authenticate_rejects_mismatched_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected_fingerprint = hashlib.sha256(b"expected-cert").hexdigest()
            config_path = self._write_config(
                root,
                client_extra=f'tls_client_fingerprint_sha256 = "{expected_fingerprint}"',
                tls_enabled=True,
            )
            config = load_config(config_path)
            peer_identity = extract_tls_peer_identity(
                {"subject": ((("commonName", "ops-laptop"),),)},
                b"actual-cert",
            )
            with self.assertRaises(PermissionError) as ctx:
                authenticate(
                    config,
                    authorization_header="Bearer abc",
                    client_id_header="ops_laptop",
                    tls_peer_identity=peer_identity,
                )
            self.assertIn("fingerprint mismatch", str(ctx.exception))

    def test_authenticate_rejects_missing_client_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = load_config(self._write_config(Path(tmp_dir)))
            with self.assertRaises(PermissionError) as ctx:
                authenticate(config, authorization_header="Bearer abc", client_id_header=None)
            self.assertIn("missing X-Client-Id", str(ctx.exception))

    def test_authenticate_rejects_unknown_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = load_config(self._write_config(Path(tmp_dir)))
            with self.assertRaises(PermissionError) as ctx:
                authenticate(config, authorization_header="Bearer abc", client_id_header="unknown")
            self.assertIn("unknown client", str(ctx.exception))

    def test_authenticate_rejects_missing_bearer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = load_config(self._write_config(Path(tmp_dir)))
            with self.assertRaises(PermissionError) as ctx:
                authenticate(config, authorization_header=None, client_id_header="ops_laptop")
            self.assertIn("missing bearer token", str(ctx.exception))

    def test_authenticate_rejects_invalid_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = load_config(self._write_config(Path(tmp_dir)))
            with self.assertRaises(PermissionError) as ctx:
                authenticate(
                    config, authorization_header="Bearer wrong", client_id_header="ops_laptop"
                )
            self.assertIn("invalid bearer token", str(ctx.exception))

    def test_authenticate_requires_tls_common_name_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = load_config(
                self._write_config(Path(tmp_dir), client_extra='tls_client_common_name = "ops"')
            )
            with self.assertRaises(PermissionError) as ctx:
                authenticate(config, authorization_header="Bearer abc", client_id_header="ops_laptop")
            self.assertIn("common name", str(ctx.exception))

    def test_authenticate_requires_tls_fingerprint_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            fingerprint = hashlib.sha256(b"expected").hexdigest()
            config = load_config(
                self._write_config(
                    Path(tmp_dir), client_extra=f'tls_client_fingerprint_sha256 = "{fingerprint}"'
                )
            )
            with self.assertRaises(PermissionError) as ctx:
                authenticate(config, authorization_header="Bearer abc", client_id_header="ops_laptop")
            self.assertIn("client certificate fingerprint", str(ctx.exception))

    def test_extract_tls_peer_identity_hashes_der(self) -> None:
        identity = extract_tls_peer_identity({}, b"binary-cert")
        self.assertIsNone(identity.common_name)
        self.assertEqual(identity.fingerprint_sha256, hashlib.sha256(b"binary-cert").hexdigest())
