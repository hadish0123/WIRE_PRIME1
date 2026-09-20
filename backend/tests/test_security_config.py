from app.security import new_bootstrap_token,hash_token

def test_bootstrap_hash_is_not_plaintext():
 raw,digest=new_bootstrap_token()
 assert digest==hash_token(raw)
 assert digest!=raw
