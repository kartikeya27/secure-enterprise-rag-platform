"""Pure, independently testable authorization decisions; deny by default."""
from dataclasses import dataclass
from .auth import CLEARANCE, Principal


@dataclass(frozen=True)
class Resource:
    tenant_id: str
    classification: str
    allowed_groups: frozenset[str]


def can_read(principal: Principal, resource: Resource) -> bool:
    return (principal.tenant_id == resource.tenant_id
            and resource.classification in CLEARANCE
            and principal.clearance_rank >= CLEARANCE[resource.classification]
            and (not resource.allowed_groups or bool(principal.groups & resource.allowed_groups)))


def can_ingest(principal: Principal, classification: str, allowed_groups: frozenset[str]) -> bool:
    return ('data_steward' in principal.roles
            and classification in CLEARANCE
            and principal.clearance_rank >= CLEARANCE[classification]
            and (not allowed_groups or bool(principal.groups & allowed_groups)))


def can_audit(principal: Principal) -> bool:
    return 'security_auditor' in principal.roles
