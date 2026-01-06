"""
Adversarial Benchmark: Red Team LLM vs Tenuo

An attacker LLM tries to bypass Tenuo's constraints.
The attacker:
- Has a goal (e.g., exfiltrate data to external email)
- Can make tool calls
- Receives feedback on blocked attempts
- Adapts strategy based on failures

Measures:
- Success rate: Did the attacker achieve the goal?
- Attempts: How many tries before success/timeout?
- Strategies: What evasion techniques were attempted?
"""

from .redteam import RedTeamBenchmark, AttackResult
from .scenarios import ADVERSARIAL_SCENARIOS
from .statistics import (
    aggregate_runs,
    calculate_confidence_interval,
    format_ci,
    compare_conditions,
    AggregatedResult,
)
from .metrics import calculate_enhanced_metrics, estimate_cost, EnhancedMetrics

__all__ = [
    "RedTeamBenchmark",
    "AttackResult",
    "ADVERSARIAL_SCENARIOS",
    "aggregate_runs",
    "calculate_confidence_interval",
    "format_ci",
    "compare_conditions",
    "AggregatedResult",
    "calculate_enhanced_metrics",
    "estimate_cost",
    "EnhancedMetrics",
]

