import os
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption

def _keys():
    private=ed25519.Ed25519PrivateKey.generate()
    public=private.public_key()
    return (
        private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode(),
        public.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode(),
    )

def test_agent_token_verification(monkeypatch):
    private,public=_keys()
    monkeypatch.setenv("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY",public)
    monkeypatch.setenv("PRIMEVPN_NODE_ID","node-1")
    from agent_security import verify_control_token
    token=jwt.encode(
        {"sub":"node-1","tenant_id":"tenant-1","type":"node_access","scopes":["read"],"iat":1,"exp":4102444800,"jti":"test-jti","iss":"primevpn-control","aud":"primevpn-agent"},
        private,algorithm="EdDSA",
    )
    claims=verify_control_token(token)
    assert claims["sub"]=="node-1"

def test_agent_token_wrong_node_rejected(monkeypatch):
    private,public=_keys()
    monkeypatch.setenv("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY",public)
    monkeypatch.setenv("PRIMEVPN_NODE_ID","node-1")
    from agent_security import verify_control_token
    token=jwt.encode(
        {"sub":"node-2","tenant_id":"tenant-1","type":"node_access","scopes":["read"],"iat":1,"exp":4102444800,"jti":"test-jti-2","iss":"primevpn-control","aud":"primevpn-agent"},
        private,algorithm="EdDSA",
    )
    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        verify_control_token(token)


def test_wg_dump_reports_public_key_not_private_key(monkeypatch):
    import app as agent_app

    class Result:
        returncode = 0
        stdout = "PRIVATE_KEY\tPUBLIC_KEY\t51820\toff\n"
        stderr = ""

    monkeypatch.setattr(agent_app.subprocess, "run", lambda *args, **kwargs: Result())
    result = agent_app._wg_dump("wg0")
    assert result["public_key"] == "PUBLIC_KEY"
    assert result["private_key_present"] is True
    assert result["listen_port"] == 51820


def test_revoke_removes_only_target_from_persistent_config():
    import app as agent_app
    config="[Interface]\nPrivateKey = server\n\n[Peer]\nPublicKey = one\nAllowedIPs = 10.0.0.2/32\n\n[Peer]\nPublicKey = two\nAllowedIPs = 10.0.0.3/32\n"
    result=agent_app.without_peer(config,"one")
    assert "PrivateKey = server" in result
    assert "PublicKey = one" not in result
    assert "PublicKey = two" in result
    assert result.count("[Peer]")==1


def test_interface_rejects_paths_and_overlong_names():
    import app as agent_app
    import pytest
    from fastapi import HTTPException
    for name in ["../etc/passwd","wg0;reboot","a"*16]:
        with pytest.raises(HTTPException):agent_app.safe_interface(name)
    assert agent_app.safe_interface("wg0")=="wg0"
