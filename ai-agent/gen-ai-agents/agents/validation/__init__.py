"""
Validation Layer - Pre-filtering and LLM validation for security threats.

This module provides heuristic analysis and LLM-based validation to filter
false positives before passing threats to the main analysis pipeline.
"""

from .feature_analyzer import FeatureAnalyzer
from .llm_validator import LLMValidator
from .validating_prompt import build_validation_prompt

__all__ = ["FeatureAnalyzer", "LLMValidator", "build_validation_prompt"]
