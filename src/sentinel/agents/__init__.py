"""SENTINEL agent system.

Exports all agent classes and the base class.
"""

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.agents.red.recon import ReconAgent
from sentinel.agents.red.exploit import ExploitAgent
from sentinel.agents.red.report import ReportAgent
from sentinel.agents.blue.monitor import MonitorAgent
from sentinel.agents.blue.defender import DefenderAgent
from sentinel.agents.blue.forensics import ForensicsAgent

__all__ = [
    "BaseAgent",
    "AgentResult",
    "ReconAgent",
    "ExploitAgent",
    "ReportAgent",
    "MonitorAgent",
    "DefenderAgent",
    "ForensicsAgent",
]
