"""
Independent-benchmark harness — runs MACE against a MITRE ATT&CK style
evaluation script so the team can publish detection-coverage numbers
without paying for the full Round-N MITRE evaluation upfront.
"""
from .mitre_attack import MITRE_TESTS, run_evaluation, EvaluationResult

__all__ = ["MITRE_TESTS", "run_evaluation", "EvaluationResult"]
