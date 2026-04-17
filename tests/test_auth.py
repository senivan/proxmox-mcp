from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.auth import authenticate, extract_tls_peer_identity
from proxmox_mcp.config import load_config


class AuthTests(unittest.TestCase):
    def test_authenticate_accepts_matching_tls_common_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = true
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
tls_client_common_name = "ops-laptop"
""".strip()
                + "\n",
                encoding="utf-8",
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
            config_path = root / "config.toml"
            expected_fingerprint = hashlib.sha256(b"expected-cert").hexdigest()
            config_path.write_text(
                f"""
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = true
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
tls_client_fingerprint_sha256 = "{expected_fingerprint}"
""".strip()
                + "\n",
                encoding="utf-8",
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
