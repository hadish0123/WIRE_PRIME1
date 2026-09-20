from app.security import hash_password,verify_password,create_access_token,decode_access_token
def test_password_hash():
 raw="A-strong-test-password-123!";h=hash_password(raw);assert h!=raw;assert verify_password(raw,h);assert not verify_password("wrong",h)
def test_token():
 p=decode_access_token(create_access_token("a","t","tenant_operator"));assert p["sub"]=="a" and p["tenant_id"]=="t"