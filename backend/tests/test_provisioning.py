import pytest
from app.security import new_bootstrap_token,hash_token
def test_bootstrap_token_is_hashed():
 raw,h=new_bootstrap_token();assert raw and len(raw)>30;assert h==hash_token(raw);assert h!=raw
def test_bootstrap_tokens_are_unique():
 a,_=new_bootstrap_token();b,_=new_bootstrap_token();assert a!=b
