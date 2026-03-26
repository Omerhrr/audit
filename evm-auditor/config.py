"""
Configuration settings for EVM Solidity Auditing Agent
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum

# Base Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
SESSIONS_DIR = DATA_DIR / "sessions"
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = DATA_DIR / "reports"
CACHE_DIR = DATA_DIR / "cache"

# Ensure directories exist
for dir_path in [DATA_DIR, SESSIONS_DIR, TEMPLATES_DIR, REPORTS_DIR, CACHE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


class Severity(Enum):
    """Bug severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    GAS = "Gas Optimization"


class LeadStatus(Enum):
    """Status of analysis leads"""
    NEW = "new"
    RANKED = "ranked"
    TRIAGED = "triaged"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class ModelProvider(Enum):
    """Supported LLM providers"""
    ZAI = "z-ai"
    OPENROUTER = "openrouter"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


@dataclass
class ModelConfig:
    """Model configuration settings"""
    provider: ModelProvider = ModelProvider.ZAI
    model_name: str = "glm-4-plus"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 8192
    timeout: int = 120


@dataclass
class SlitherConfig:
    """Slither static analysis configuration"""
    enabled: bool = True
    detectors: List[str] = field(default_factory=list)  # Empty = all detectors
    exclude_detectors: List[str] = field(default_factory=list)
    external_libraries: bool = True
    skip_assembly: bool = False


@dataclass
class FoundryConfig:
    """Foundry/Forge configuration"""
    enabled: bool = True
    fuzz_runs: int = 256
    fuzz_seed: Optional[int] = None
    fork_url: Optional[str] = None
    fork_block: Optional[int] = None
    gas_reports: bool = True
    verbosity: int = 2


@dataclass
class Z3Config:
    """Z3 symbolic execution configuration"""
    enabled: bool = True
    timeout_ms: int = 30000
    max_depth: int = 50
    simplify: bool = True


@dataclass
class AuditConfig:
    """Main auditing configuration"""
    model: ModelConfig = field(default_factory=ModelConfig)
    slither: SlitherConfig = field(default_factory=SlitherConfig)
    foundry: FoundryConfig = field(default_factory=FoundryConfig)
    z3: Z3Config = field(default_factory=Z3Config)
    continuous_audit: bool = True
    max_iterations: int = 10
    parallel_analysis: bool = True
    max_workers: int = 4


# Default configuration instance
DEFAULT_CONFIG = AuditConfig()


# Severity Colors (for UI)
SEVERITY_COLORS = {
    Severity.CRITICAL: "#FF0000",
    Severity.HIGH: "#FF4500",
    Severity.MEDIUM: "#FFA500",
    Severity.LOW: "#FFD700",
    Severity.INFORMATIONAL: "#4169E1",
    Severity.GAS: "#32CD32",
}

# Status Colors (for UI)
STATUS_COLORS = {
    LeadStatus.NEW: "#808080",
    LeadStatus.RANKED: "#4169E1",
    LeadStatus.TRIAGED: "#9932CC",
    LeadStatus.TESTING: "#FFA500",
    LeadStatus.CONFIRMED: "#32CD32",
    LeadStatus.DISMISSED: "#DC143C",
}
