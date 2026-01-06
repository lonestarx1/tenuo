"""
Statistical analysis for adversarial benchmark.

Provides confidence interval calculation, multi-run aggregation,
and statistical comparison for academic rigor.
"""

import math
from dataclasses import dataclass, field
from typing import Optional

from .redteam import AttackResult


@dataclass
class AggregatedResult:
    """Aggregated statistics across multiple runs."""

    scenario: str
    goal: str
    runs: int = 0
    
    # Defense statistics
    defense_rate_mean: float = 0.0
    defense_rate_std: float = 0.0
    defense_rate_ci_lower: float = 0.0
    defense_rate_ci_upper: float = 0.0
    
    # Attempt statistics
    attempts_mean: float = 0.0
    attempts_std: float = 0.0
    
    # Individual run data
    successes: list[bool] = field(default_factory=list)
    attempt_counts: list[int] = field(default_factory=list)
    strategies_seen: set[str] = field(default_factory=set)
    
    @property
    def bypassed_count(self) -> int:
        return sum(1 for s in self.successes if s)
    
    @property
    def defended_count(self) -> int:
        return sum(1 for s in self.successes if not s)


def calculate_mean(values: list[float]) -> float:
    """Calculate arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def calculate_std(values: list[float], mean: Optional[float] = None) -> float:
    """Calculate sample standard deviation."""
    if len(values) < 2:
        return 0.0
    if mean is None:
        mean = calculate_mean(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def calculate_confidence_interval(
    values: list[float],
    confidence: float = 0.95,
) -> tuple[float, float, float]:
    """
    Calculate confidence interval for a sample.
    
    Uses t-distribution for small samples.
    
    Args:
        values: Sample values
        confidence: Confidence level (default 0.95 for 95% CI)
        
    Returns:
        (mean, ci_lower, ci_upper)
    """
    if not values:
        return 0.0, 0.0, 0.0
    
    n = len(values)
    mean = calculate_mean(values)
    
    if n < 2:
        return mean, mean, mean
    
    std = calculate_std(values, mean)
    
    # t-values for common confidence levels and sample sizes
    # Using approximation for simplicity
    if confidence == 0.95:
        t_value = 2.0 + 4.0 / n  # Approximation of t_{0.025, n-1}
    elif confidence == 0.99:
        t_value = 2.6 + 6.0 / n
    else:
        t_value = 2.0  # Default to ~95%
    
    margin = t_value * std / math.sqrt(n)
    
    return mean, max(0.0, mean - margin), min(1.0, mean + margin)


def aggregate_runs(results: list[AttackResult]) -> AggregatedResult:
    """
    Aggregate multiple runs of the same scenario.
    
    Args:
        results: List of AttackResults from same scenario
        
    Returns:
        AggregatedResult with statistics
    """
    if not results:
        raise ValueError("No results to aggregate")
    
    # All results should be same scenario
    scenario = results[0].scenario
    goal = results[0].goal
    
    agg = AggregatedResult(
        scenario=scenario,
        goal=goal,
        runs=len(results),
    )
    
    # Collect data from runs
    defense_rates = []
    for r in results:
        agg.successes.append(r.success)
        agg.attempt_counts.append(r.num_attempts)
        agg.strategies_seen.update(r.strategies_tried)
        
        # Defense rate per run: 1 if defended, 0 if bypassed
        defense_rates.append(0.0 if r.success else 1.0)
    
    # Calculate statistics
    mean, ci_lower, ci_upper = calculate_confidence_interval(defense_rates)
    agg.defense_rate_mean = mean
    agg.defense_rate_ci_lower = ci_lower
    agg.defense_rate_ci_upper = ci_upper
    agg.defense_rate_std = calculate_std(defense_rates, mean)
    
    agg.attempts_mean = calculate_mean([float(x) for x in agg.attempt_counts])
    agg.attempts_std = calculate_std([float(x) for x in agg.attempt_counts])
    
    return agg


def format_ci(mean: float, lower: float, upper: float) -> str:
    """Format confidence interval for display."""
    return f"{mean:.1%} (95% CI: {lower:.1%}-{upper:.1%})"


def compare_conditions(
    condition_a: list[AttackResult],
    condition_b: list[AttackResult],
    label_a: str = "A",
    label_b: str = "B",
) -> dict:
    """
    Compare two experimental conditions.
    
    Useful for ablation studies (e.g., recon vs no-recon).
    
    Args:
        condition_a: Results from condition A
        condition_b: Results from condition B
        label_a: Name for condition A
        label_b: Name for condition B
        
    Returns:
        Comparison statistics
    """
    agg_a = aggregate_runs(condition_a) if condition_a else None
    agg_b = aggregate_runs(condition_b) if condition_b else None
    
    comparison = {
        "conditions": {label_a: None, label_b: None},
        "difference": None,
    }
    
    if agg_a:
        comparison["conditions"][label_a] = {
            "runs": agg_a.runs,
            "defense_rate": agg_a.defense_rate_mean,
            "defense_rate_ci": (agg_a.defense_rate_ci_lower, agg_a.defense_rate_ci_upper),
            "attempts_mean": agg_a.attempts_mean,
        }
    
    if agg_b:
        comparison["conditions"][label_b] = {
            "runs": agg_b.runs,
            "defense_rate": agg_b.defense_rate_mean,
            "defense_rate_ci": (agg_b.defense_rate_ci_lower, agg_b.defense_rate_ci_upper),
            "attempts_mean": agg_b.attempts_mean,
        }
    
    if agg_a and agg_b:
        comparison["difference"] = {
            "defense_rate_diff": agg_b.defense_rate_mean - agg_a.defense_rate_mean,
            "attempts_diff": agg_b.attempts_mean - agg_a.attempts_mean,
        }
    
    return comparison
