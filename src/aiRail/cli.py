"""trustrail CLI — command-line interface for guardrail checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from trustrail import __version__


def _cmd_check(args: argparse.Namespace) -> int:
    """Run a guard check on text or file content."""
    from trustrail.guard import Guard
    from trustrail.models.enums import GuardStage

    # Resolve stage
    try:
        stage = GuardStage(args.stage)
    except ValueError:
        print(
            f"Error: Invalid stage '{args.stage}'. Valid stages: {[s.value for s in GuardStage]}",
            file=sys.stderr,
        )
        return 2

    # Get text
    if args.text:
        text = args.text
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 2
        text = path.read_text(encoding="utf-8")
    else:
        print("Error: Must provide --text or --file", file=sys.stderr)
        return 2

    # Create guard
    profile = getattr(args, "profile", "default")
    guard = Guard.from_profile(profile)

    result = guard.check(text, stage)

    output = {
        "action": result.action.value,
        "score": result.score.value,
        "stage": result.stage.value,
        "rules_evaluated": result.rules_evaluated,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category.value,
                "severity": f.severity.value,
                "message": f.message,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
    }

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(f"Action: {result.action.value.upper()}")
        print(f"Score:  {result.score.value}/100")
        print(f"Stage:  {result.stage.value}")
        print(f"Rules:  {result.rules_evaluated} evaluated")
        if result.findings:
            print("\nFindings:")
            for f in result.findings:
                print(f"  [{f.severity.value.upper()}] {f.rule_id} - {f.message}")
        else:
            print("\nNo findings.")

    return 0 if result.is_allowed else 1


def _cmd_validate_config(args: argparse.Namespace) -> int:
    """Validate a guardrails YAML config file."""
    path = Path(args.config_file)
    if not path.exists():
        print(f"Error: Config file not found: {args.config_file}", file=sys.stderr)
        return 2

    try:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
    except ImportError:
        # Try JSON if yaml not available
        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"Error parsing config: {exc}", file=sys.stderr)
            return 1

    try:
        from trustrail.models.config import GuardConfig

        config = GuardConfig.model_validate(data)
        print(f"Config valid: {path}")
        print(f"  fail_mode: {config.fail_mode.value}")
        print(f"  block_at: {config.block_at}")
        print(f"  warn_at:  {config.warn_at}")
        return 0
    except Exception as exc:
        print(f"Config validation error: {exc}", file=sys.stderr)
        return 1


def _cmd_explain(args: argparse.Namespace) -> int:
    """Explain a rule by ID."""
    from trustrail.rules.base import registry

    rule_class = registry.get(args.rule_id)
    if rule_class is None:
        print(f"Error: Rule '{args.rule_id}' not found.", file=sys.stderr)
        print(f"Known rule IDs: {', '.join(sorted(registry.all_ids()))}")
        return 2

    print(f"Rule ID:     {rule_class.rule_id}")
    print(f"Name:        {rule_class.rule_name}")
    print(f"Category:    {rule_class.category.value}")
    print(f"Phase:       {rule_class.phase.value}")
    print(f"Severity:    {rule_class.default_severity.value}")
    print(f"Action:      {rule_class.default_action.value}")
    print(f"Description: {rule_class.description}")
    return 0


def _cmd_list_rules(args: argparse.Namespace) -> int:
    """List all known rules."""
    from trustrail.rules.base import registry

    rules = sorted(registry.all_rules(), key=lambda r: r.rule_id)
    for rule in rules:
        category_filter = getattr(args, "category", None)
        if category_filter and rule.category.value != category_filter:
            continue
        print(f"{rule.rule_id:<12} [{rule.category.value:<20}] {rule.rule_name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustrail",
        description="trustrail — GenAI/LLM Guardrails CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # check
    check_p = subparsers.add_parser("check", help="Check text or file against guardrails")
    check_p.add_argument(
        "--stage", required=True, help="Guard stage (e.g. user_input, llm_response)"
    )
    check_p.add_argument("--text", help="Text to check")
    check_p.add_argument("--file", help="File to check")
    check_p.add_argument(
        "--profile", default="default", help="Guard profile (default/balanced/strict)"
    )
    check_p.add_argument("--json", action="store_true", help="Output as JSON")

    # validate-config
    vc_p = subparsers.add_parser("validate-config", help="Validate a guardrails config file")
    vc_p.add_argument("config_file", help="Path to YAML or JSON config file")

    # explain
    exp_p = subparsers.add_parser("explain", help="Explain a rule by ID")
    exp_p.add_argument("rule_id", help="Rule ID (e.g. PI-001)")

    # list-rules
    lr_p = subparsers.add_parser("list-rules", help="List all known rules")
    lr_p.add_argument("--category", help="Filter by category")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "check": _cmd_check,
        "validate-config": _cmd_validate_config,
        "explain": _cmd_explain,
        "list-rules": _cmd_list_rules,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(2)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
