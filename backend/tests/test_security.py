from app.security import hash_password,verify_password,create_access_token,decode_access_token
def test_password_hash():
 raw="A-strong-test-password-123!";h=hash_password(raw);assert h!=raw;assert verify_password(raw,h);assert not verify_password("wrong",h)
def test_token():
 p=decode_access_token(create_access_token("a","t","tenant_operator"));assert p["sub"]=="a" and p["tenant_id"]=="t"

def test_access_token_has_bound_audience_and_issuer():
    token=create_access_token("a","t","tenant_operator")
    payload=decode_access_token(token)
    assert payload["iss"]=="primevpn-control"
    assert payload["aud"]=="primevpn-web"
    assert payload["jti"]
