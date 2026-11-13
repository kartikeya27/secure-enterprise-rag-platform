import pytest
from app.auth import Principal, principal_from_claims
from app.policy import Resource, can_read, can_ingest, can_audit
from fastapi import HTTPException


@pytest.fixture
def alice():
    return Principal('alice','alpha',frozenset(['data_steward']),frozenset(['finance']), 'confidential')


@pytest.mark.parametrize('resource,expected', [
    (Resource('alpha','internal',frozenset()), True),
    (Resource('alpha','confidential',frozenset(['finance'])), True),
    (Resource('alpha','restricted',frozenset(['finance'])), False),
    (Resource('alpha','internal',frozenset(['engineering'])), False),
    (Resource('beta','public',frozenset()), False),
    (Resource('alpha','UNKNOWN',frozenset()), False),
])
def test_entitlement_denies_unapproved(alice, resource, expected):
    assert can_read(alice, resource) is expected


def test_ingest_guard(alice):
    assert can_ingest(alice, 'confidential', frozenset(['finance']))
    assert not can_ingest(alice, 'restricted', frozenset())
    assert not can_ingest(alice, 'internal', frozenset(['hr']))
    assert not can_ingest(Principal('bob','alpha',frozenset(),frozenset(['finance']),'restricted'), 'public', frozenset())


def test_auditor_separate_role(alice):
    assert not can_audit(alice)
    assert can_audit(Principal('auditor','alpha',frozenset(['security_auditor']),frozenset(), 'restricted'))


def test_claims_fail_closed():
    valid = dict(sub='alice',tenant_id='alpha',roles=['data_steward'],groups=['finance'],clearance='restricted')
    assert principal_from_claims(valid).tenant_id == 'alpha'
    for mutation in [dict(tenant_id='../beta'), dict(groups='finance'), dict(clearance='root'), dict(roles=None),dict(sub='')]:
        with pytest.raises(HTTPException) as exc:
            principal_from_claims({**valid, **mutation})
        assert exc.value.status_code == 401
