"""Local demo JWT and production OIDC RS256 verification."""
from dataclasses import dataclass
import re
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, Request
from .config import Settings

IDENTIFIER = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,127}$')
TENANT = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
CLEARANCE = {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3}


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[str]
    groups: frozenset[str]
    clearance: str

    @property
    def clearance_rank(self) -> int:
        return CLEARANCE[self.clearance]


def principal_from_claims(claims: dict) -> Principal:
    subject, tenant = claims.get('sub'), claims.get('tenant_id')
    roles, groups = claims.get('roles'), claims.get('groups')
    clearance = claims.get('clearance')
    if (not isinstance(subject, str) or not IDENTIFIER.fullmatch(subject) or
            not isinstance(tenant, str) or not TENANT.fullmatch(tenant) or
            not isinstance(roles, list) or not isinstance(groups, list) or
            not isinstance(clearance, str) or clearance not in CLEARANCE):
        raise HTTPException(status_code=401, detail='Invalid identity claims')
    if (len(roles) > 32 or len(groups) > 64 or
            any(not isinstance(v, str) or not IDENTIFIER.fullmatch(v) for v in roles + groups)):
        raise HTTPException(status_code=401, detail='Invalid identity groups/roles')
    return Principal(subject, tenant, frozenset(roles), frozenset(groups), clearance)


def decode_token(token: str, settings: Settings) -> Principal:
    try:
        if settings.auth_mode == 'local':
            claims = jwt.decode(token, settings.local_jwt_secret, algorithms=['HS256'],
                                issuer=settings.issuer, audience=settings.audience,
                                options={'require': ['exp', 'iat', 'iss', 'aud', 'sub']})
        else:
            # Restrict signing algorithms and validate the configured issuer and audience.
            jwk = jwt.PyJWKClient(settings.jwks_url).get_signing_key_from_jwt(token)
            claims = jwt.decode(token, jwk.key, algorithms=['RS256'],
                                issuer=settings.issuer, audience=settings.audience,
                                options={'require': ['exp', 'iat', 'iss', 'aud', 'sub']})
        return principal_from_claims(claims)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail='Invalid or expired access token') from exc


def current_principal(request: Request, authorization: Annotated[str | None, Header()] = None) -> Principal:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Bearer token required')
    return decode_token(authorization[7:], request.app.state.settings)


PrincipalDep = Annotated[Principal, Depends(current_principal)]
