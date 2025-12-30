"""Secure Mail Triage agents and pipeline components."""  # Package docstring summarizing contents.

from .agents import AgentResult, Email
from .pipeline import ClassificationPipeline, create_llm_pipeline

__all__ = ["AgentResult", "Email", "ClassificationPipeline", "create_llm_pipeline"]
