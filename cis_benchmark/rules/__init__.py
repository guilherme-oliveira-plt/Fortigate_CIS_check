"""
CIS Benchmark Rules Package
============================
Contains Level 1 (Basic) and Level 2 (Advanced) CIS FortiGate Benchmark rules.
"""

from cis_benchmark.rules.base import CISRule, RuleResult, RuleSeverity, CISLevel
from cis_benchmark.rules.level1_rules import get_level1_rules
from cis_benchmark.rules.level2_rules import get_level2_rules


def get_all_rules():
    """Get all CIS benchmark rules (Level 1 + Level 2)."""
    return get_level1_rules() + get_level2_rules()


__all__ = [
    "CISRule",
    "RuleResult",
    "RuleSeverity",
    "CISLevel",
    "get_all_rules",
    "get_level1_rules",
    "get_level2_rules",
]
