"""Sigma detection engine."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NamedTuple

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaRegularExpression

from .ocsf_pipeline import get_ocsf_pipeline

RULES_DIR = Path(__file__).parent / "sigma_rules"


class SigmaEngineError(ValueError):
    """Raised when a Sigma rule fails to parse or encounters unsupported features."""
    pass


class Match(NamedTuple):
    rule_title: str
    rule_id: str
    technique_ids: list[str]
    evidence: dict[str, Any]


# TODO: SSH brute-force (needs correlation across multiple auth events)
# TODO: abnormal data volume (needs session-level aggregation)


def _get_field(ev: dict[str, Any], path: str) -> Any:
    curr = ev
    for p in path.split("."):
        if not isinstance(curr, dict) or p not in curr:
            return None
        curr = curr[p]
    return curr


def _evaluate_node(node: Any, event: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Evaluate a pySigma AST node against an event dictionary.
    
    Returns:
        (matched, evidence_dict)
    """
    if isinstance(node, ConditionAND):
        evidence: dict[str, Any] = {}
        for arg in node.args:
            matched, ev = _evaluate_node(arg, event)
            if not matched:
                return False, {}
            evidence.update(ev)
        return True, evidence

    if isinstance(node, ConditionOR):
        evidence = {}
        any_matched = False
        for arg in node.args:
            matched, ev = _evaluate_node(arg, event)
            if matched:
                any_matched = True
                evidence.update(ev)
        return any_matched, evidence

    if isinstance(node, ConditionNOT):
        # A NOT condition passes if its child fails.
        # It's a filter, so we don't return evidence from it.
        matched, _ = _evaluate_node(node.args[0], event)
        if not matched:
            return True, {}
        return False, {}

    if isinstance(node, ConditionFieldEqualsValueExpression):
        # Known limitation: this evaluator currently only supports string-type Sigma values
        # (endswith/contains/re/plain equality via regex). SigmaNumber, SigmaBool, SigmaNull
        # field types are NOT YET supported and will need explicit handling before any rule
        # using numeric comparisons (e.g. port numbers, byte thresholds) is added —
        # flag this as a known limitation for future Zeek-based rules.
        if not (isinstance(node.value, SigmaRegularExpression) or hasattr(node.value, "to_regex")):
            raise SigmaEngineError(
                f"Unsupported Sigma value type '{type(node.value).__name__}' for field '{node.field}'. "
                "Only string-type Sigma values (endswith/contains/re/plain equality via regex) are currently supported."
            )

        val = _get_field(event, node.field)
        if val is None:
            return False, {}

        if isinstance(node.value, SigmaRegularExpression):
            pat = str(node.value.regexp)
        else:
            pat = str(node.value.to_regex().regexp)

        try:
            if re.match(f"^{pat}$", str(val), re.IGNORECASE):
                return True, {node.field: str(val)}
        except re.error as e:
            raise SigmaEngineError(f"Invalid regex pattern '{pat}' for field '{node.field}': {e}") from e

        return False, {}

    if isinstance(node, ConditionValueExpression):
        raise SigmaEngineError(
            "Keyword search without field name is not supported. Rules must specify field names."
        )

    return False, {}


class SigmaEngine:
    def __init__(self, rules_dir: Path | str | None = RULES_DIR, rule_yaml: str | None = None):
        self.rules: list[SigmaRule] = []
        pipeline = get_ocsf_pipeline()
        
        if rule_yaml:
            try:
                collection = SigmaCollection.from_yaml(rule_yaml)
                for rule in collection.rules:
                    pipeline.apply(rule)
                    self.rules.append(rule)
            except Exception as e:
                raise SigmaEngineError(f"Failed to parse rule: {e}") from e
            return

        if rules_dir:
            rules_dir = Path(rules_dir)
            if rules_dir.exists():
                for path in sorted(rules_dir.glob("*.yml")):
                    try:
                        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
                        for rule in collection.rules:
                            pipeline.apply(rule)
                            self.rules.append(rule)
                    except Exception as e:
                        raise SigmaEngineError(f"Failed to parse rule {path.name}: {e}") from e

    def evaluate(self, event: dict[str, Any]) -> list[Match]:
        matches = []
        for rule in self.rules:
            if not rule.detection.parsed_condition:
                continue
                
            node = rule.detection.parsed_condition[0].parsed
            matched, evidence = _evaluate_node(node, event)
            if matched:
                technique_ids = []
                for t in rule.tags:
                    if t.namespace == "attack" and re.match(r"^t\d+", t.name, re.IGNORECASE):
                        # Ensure uppercase technique ID format: "t1566.001" -> "T1566.001"
                        technique_ids.append("T" + t.name[1:])
                
                matches.append(Match(
                    rule_title=rule.title,
                    rule_id=str(rule.id) if rule.id else "",
                    technique_ids=technique_ids,
                    evidence=evidence
                ))
        return matches

    def evaluate_batch(self, events: list[dict[str, Any]]) -> list[list[Match]]:
        return [self.evaluate(ev) for ev in events]


_default_engine = None


def evaluate(event: dict[str, Any]) -> list[Match]:
    global _default_engine
    if _default_engine is None:
        _default_engine = SigmaEngine()
    return _default_engine.evaluate(event)


def evaluate_batch(events: list[dict[str, Any]]) -> list[list[Match]]:
    global _default_engine
    if _default_engine is None:
        _default_engine = SigmaEngine()
    return _default_engine.evaluate_batch(events)
