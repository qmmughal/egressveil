"""Policy evaluation: map findings to actions, most restrictive wins."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Final

from egressveil.policy import PolicyAction

if TYPE_CHECKING:
    from egressveil.config import PolicyConfig
    from egressveil.detectors import Finding

__all__ = ["SEVERITY", "PolicyEngine", "most_restrictive"]

SEVERITY: Final[dict[PolicyAction, int]] = {
    PolicyAction.ALLOW: 0,
    PolicyAction.LOG_ONLY: 1,
    PolicyAction.REDACT: 2,
    PolicyAction.BLOCK: 3,
}


def most_restrictive(actions: Iterable[PolicyAction]) -> PolicyAction:
    """``BLOCK`` > ``REDACT`` > ``LOG_ONLY`` > ``ALLOW``; ``ALLOW`` if empty."""
    return max(actions, key=SEVERITY.__getitem__, default=PolicyAction.ALLOW)


class PolicyEngine:
    def __init__(self, policy: PolicyConfig) -> None:
        self._rules = {rule.detector: rule.action for rule in policy.rules}
        self._default = policy.default_action

    def action_for(self, finding: Finding) -> PolicyAction:
        return self._rules.get(finding.detector, self._default)
