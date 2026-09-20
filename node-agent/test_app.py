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
