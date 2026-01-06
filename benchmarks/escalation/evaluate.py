#!/usr/bin/env python3
"""
Escalation Prevention Benchmark CLI.

Measures how delegation bounds damage from compromised AI agents.

Usage:
    python -m benchmarks.escalation.evaluate
    python -m benchmarks.escalation.evaluate --scenario email_exfil
    python -m benchmarks.escalation.evaluate --output results/report.json
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

from .scenarios import SCENARIOS, run_scenario, run_all_scenarios, ScenarioResult


def print_result(result: ScenarioResult, verbose: bool = True):
    """Print formatted result for a single scenario."""
    width = 75

    print()
    print("+" + "-" * (width - 2) + "+")
    print(f"| {'ESCALATION PREVENTION BENCHMARK':<{width-4}} |")
    print("+" + "-" * (width - 2) + "+")
    print(f"| Scenario: {result.name:<{width-14}} |")
    print(f"| {result.description:<{width-4}} |")
    print(f"| Attacks tested: {len(result.attacks):<{width-20}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")
    print(f"| {'Metric':<23} | {'p-agent (broad)':<16} | {'q-agent (delegated)':<{width-49}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")
    print(f"| {'Attacks allowed':<23} | {result.p_allowed:<16} | {result.q_allowed:<{width-49}} |")
    print(f"| {'Attacks blocked':<23} | {result.p_blocked:<16} | {result.q_blocked:<{width-49}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")

    violations_str = str(result.escalation_prevented)
    rate_str = f"{result.escalation_prevention_rate:.1%}"
    print(f"| {'POLICY VIOLATIONS BLOCKED:':<26} {violations_str:<{width-31}} |")
    print(f"| {'ENFORCEMENT RATE:':<26} {rate_str:<{width-31}} |")
    print("+" + "-" * (width - 2) + "+")

    if verbose:
        print()
        print("Attack Details:")
        print("-" * width)

        for i, attack in enumerate(result.attacks, 1):
            p_status = "allowed" if attack.p_allowed else "BLOCKED"
            q_status = "allowed" if attack.q_allowed else "BLOCKED"
            prevented = " [POLICY VIOLATION]" if attack.escalation_prevented else ""

            args_str = ", ".join(f"{k}={v!r}" for k, v in list(attack.args.items())[:2])
            if len(attack.args) > 2:
                args_str += ", ..."

            print(f"  {i:2}. {attack.tool}({args_str})")
            print(f"      p-agent: {p_status:<8} | q-agent: {q_status}{prevented}")


def print_summary(results: list[ScenarioResult]):
    """Print overall summary."""
    total_attacks = sum(len(r.attacks) for r in results)
    total_p_allowed = sum(r.p_allowed for r in results)
    total_q_allowed = sum(r.q_allowed for r in results)
    total_prevented = sum(r.escalation_prevented for r in results)

    print()
    print("=" * 75)
    print("OVERALL SUMMARY")
    print("=" * 75)
    print()
    print("Threat Model:")
    print("  p-agent: Trusted orchestrator with broad authority")
    print("  q-agent: Task executor with minimal delegated authority (COMPROMISED)")
    print()
    print(f"{'Metric':<30} {'Value':<20}")
    print("-" * 50)
    print(f"{'Scenarios tested':<30} {len(results):<20}")
    print(f"{'Total attacks':<30} {total_attacks:<20}")
    print(f"{'p-agent would allow':<30} {total_p_allowed:<20}")
    print(f"{'q-agent allowed':<30} {total_q_allowed:<20}")
    print(f"{'Policy violations blocked':<30} {total_prevented:<20}")
    print(f"{'Enforcement rate':<30} {total_prevented/total_p_allowed:.1%}")
    print()
    print("=" * 75)
    print()
    print("Conclusion: Same attacks, different warrants.")
    print(f"{total_prevented} of {total_p_allowed} calls violated q-agent's policy and were blocked.")
    print("These same calls would have succeeded for p-agent.")
    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(
        description="Escalation prevention benchmark"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print summary",
    )
    args = parser.parse_args()

    # Run scenarios
    if args.scenario == "all":
        results = run_all_scenarios()
    else:
        results = [run_scenario(args.scenario)]

    # Print results
    for result in results:
        print_result(result, verbose=not args.quiet)

    if len(results) > 1:
        print_summary(results)

    # Save results
    if args.output:
        total_attacks = sum(len(r.attacks) for r in results)
        total_prevented = sum(r.escalation_prevented for r in results)
        total_p_allowed = sum(r.p_allowed for r in results)

        output_data = {
            "timestamp": datetime.now().isoformat(),
            "threat_model": {
                "p_agent": "Trusted orchestrator with broad authority",
                "q_agent": "Task executor with minimal delegated authority (assumed compromised)",
            },
            "scenarios": [
                {
                    "name": r.name,
                    "description": r.description,
                    "attacks": len(r.attacks),
                    "p_allowed": r.p_allowed,
                    "q_allowed": r.q_allowed,
                    "policy_violations_blocked": r.escalation_prevented,
                    "enforcement_rate": r.escalation_prevention_rate,
                }
                for r in results
            ],
            "summary": {
                "total_attacks": total_attacks,
                "total_p_allowed": total_p_allowed,
                "total_q_allowed": sum(r.q_allowed for r in results),
                "total_prevented": total_prevented,
                "prevention_rate": total_prevented / total_p_allowed if total_p_allowed else 0,
            },
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()

