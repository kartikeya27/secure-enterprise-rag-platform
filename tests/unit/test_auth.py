import time
import jwt
import pytest
from fastapi import HTTPException
from app.auth import decode_token
from app.config import Settings


def config():
    return Settings('local','local','issuer','audience','y'*40,'','postgresql://app:secret@db/demo','hash','http://localhost:11434','all-minilm')


def mint(**overrides):
    now = int(time.time())
    payload = dict(sub='alice',tenant_id='alpha',roles=['data_steward'],groups=['finance'],
                   clearance='restricted',iat=now,exp=now+100,iss='issuer',aud='audience')
    payload.update(overrides)
    return jwt.encode(payload,'y'*40,algorithm='HS256')


def test_valid_jwt():
    assert decode_token(mint(),config()).tenant_id == 'alpha'


@pytest.mark.parametrize('changes', [
    {'exp': 0}, {'aud':'wrong'}, {'iss':'not-trusted'}, {'groups':'finance'},
])
def test_invalid_claims_denied(changes):
    with pytest.raises(HTTPException) as exc:
        decode_token(mint(**changes),config())
    assert exc.value.status_code == 401


def test_production_rejects_local_token_config(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('AUTH_MODE', 'local')
    monkeypatch.setenv('LOCAL_JWT_SECRET', 'a'*40)
    monkeypatch.setenv('DATABASE_URL','postgresql://x:y@db/z')
    with pytest.raises(RuntimeError, match='MUST use OIDC'):
        Settings.from_env()
