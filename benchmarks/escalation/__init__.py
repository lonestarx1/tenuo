"""
Escalation Prevention Benchmark.

Measures how delegation bounds damage from compromised AI agents.

Two-layer approach:
1. Synthetic benchmark (scenarios.py) - deterministic, reproducible
2. AgentDojo validation (agentdojo_validation.py) - real LLM, real attacks
"""

from .scenarios import SCENARIOS, run_scenario, run_all_scenarios

__all__ = ["SCENARIOS", "run_scenario", "run_all_scenarios"]

