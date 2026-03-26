"""
Core data models for EVM Solidity Auditing Agent
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
from enum import Enum

from config import Severity, LeadStatus


@dataclass
class SourceLocation:
    """Location in source code"""
    file_path: str
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    
    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}:{self.start_column}"


@dataclass
class FunctionInfo:
    """Information about a Solidity function"""
    name: str
    contract: str
    visibility: str  # public, private, internal, external
    mutability: str  # view, pure, payable, nonpayable
    parameters: List[Dict[str, str]]  # [{name, type}]
    returns: List[Dict[str, str]]  # [{name, type}]
    modifiers: List[str]
    location: Optional[SourceLocation] = None
    is_virtual: bool = False
    is_override: bool = False
    implemented: bool = True
    
    def signature(self) -> str:
        params = ", ".join(f"{p['type']} {p.get('name', '')}".strip() for p in self.parameters)
        returns_str = ""
        if self.returns:
            rets = ", ".join(f"{r['type']}" for r in self.returns)
            returns_str = f" returns ({rets})"
        return f"function {self.name}({params}) {self.visibility} {self.mutability}{returns_str}"


@dataclass
class ContractInfo:
    """Information about a Solidity contract"""
    name: str
    file_path: str
    kind: str  # contract, interface, library, abstract
    functions: List[FunctionInfo] = field(default_factory=list)
    variables: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    modifiers: List[Dict[str, Any]] = field(default_factory=list)
    inherits: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    implemented_interfaces: List[str] = field(default_factory=list)
    location: Optional[SourceLocation] = None
    is_proxy: bool = False
    implementation: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    
    def get_public_functions(self) -> List[FunctionInfo]:
        return [f for f in self.functions if f.visibility in ('public', 'external')]
    
    def get_state_changing_functions(self) -> List[FunctionInfo]:
        return [f for f in self.functions if f.mutability not in ('view', 'pure')]


@dataclass
class CallEdge:
    """Edge in the call graph"""
    caller: str  # Contract.function
    callee: str  # Contract.function or external call
    call_type: str  # internal, external, delegatecall, staticcall
    location: Optional[SourceLocation] = None
    
    def __hash__(self):
        return hash((self.caller, self.callee, self.call_type))
    
    def __eq__(self, other):
        if not isinstance(other, CallEdge):
            return False
        return (self.caller == other.caller and 
                self.callee == other.callee and 
                self.call_type == other.call_type)


@dataclass
class CallGraph:
    """Call graph for contracts"""
    nodes: Set[str] = field(default_factory=set)  # Contract.function nodes
    edges: List[CallEdge] = field(default_factory=list)
    entry_points: Set[str] = field(default_factory=set)  # External/public functions
    
    def add_edge(self, edge: CallEdge):
        self.nodes.add(edge.caller)
        self.nodes.add(edge.callee)
        self.edges.append(edge)
        
    def get_callers(self, callee: str) -> List[CallEdge]:
        return [e for e in self.edges if e.callee == callee]
    
    def get_callees(self, caller: str) -> List[CallEdge]:
        return [e for e in self.edges if e.caller == caller]
    
    def get_reachable_from(self, start: str) -> Set[str]:
        """Get all nodes reachable from start node"""
        visited = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for edge in self.get_callees(node):
                if edge.callee not in visited:
                    stack.append(edge.callee)
        return visited


@dataclass
class VulnerabilityLead:
    """A potential vulnerability identified during analysis"""
    id: str
    title: str
    description: str
    severity: Severity
    status: LeadStatus
    confidence: float  # 0.0 to 1.0
    
    # Source information
    affected_contracts: List[str]
    affected_functions: List[str]
    location: Optional[SourceLocation] = None
    
    # Analysis details
    detection_method: str = ""  # slither, llm, z3, manual
    category: str = ""  # reentrancy, access-control, etc.
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    # Attack path
    attack_vector: str = ""
    preconditions: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    impact: str = ""
    
    # Verification
    foundry_poc: Optional[str] = None  # Path to Foundry test
    z3_verification: Optional[str] = None  # Z3 proof/counterexample
    confirmed: bool = False
    false_positive: bool = False
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    related_leads: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "affected_contracts": self.affected_contracts,
            "affected_functions": self.affected_functions,
            "location": str(self.location) if self.location else None,
            "detection_method": self.detection_method,
            "category": self.category,
            "cwe": self.cwe,
            "attack_vector": self.attack_vector,
            "preconditions": self.preconditions,
            "attack_steps": self.attack_steps,
            "impact": self.impact,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
        }


@dataclass
class FuzzResult:
    """Result from fuzzing campaign"""
    lead_id: str
    total_runs: int
    successful_runs: int
    failed_runs: int
    counterexample: Optional[Dict[str, Any]] = None
    gas_used: Optional[int] = None
    coverage: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "lead_id": self.lead_id,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "failed_runs": self.failed_runs,
            "counterexample": self.counterexample,
            "gas_used": self.gas_used,
            "coverage": self.coverage,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Z3VerificationResult:
    """Result from Z3 symbolic verification"""
    lead_id: str
    satisfiable: bool  # True if attack path is possible
    model: Optional[Dict[str, Any]] = None  # Satisfying assignment
    constraints: List[str] = field(default_factory=list)
    solver_time_ms: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "lead_id": self.lead_id,
            "satisfiable": self.satisfiable,
            "model": self.model,
            "constraints": self.constraints,
            "solver_time_ms": self.solver_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class BugReport:
    """Complete bug report"""
    id: str
    title: str
    lead: VulnerabilityLead
    description: str
    severity: Severity
    impact: str
    likelihood: str
    
    # Technical details
    affected_contracts: List[str]
    affected_functions: List[str]
    attack_vector: str
    preconditions: List[str]
    attack_steps: List[str]
    
    # Proof of concept
    poc_code: Optional[str] = None
    poc_path: Optional[str] = None
    
    # Mitigation
    mitigation: str = ""
    recommendation: str = ""
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    auditor_notes: str = ""
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "affected_contracts": self.affected_contracts,
            "affected_functions": self.affected_functions,
            "attack_vector": self.attack_vector,
            "preconditions": self.preconditions,
            "attack_steps": self.attack_steps,
            "poc_code": self.poc_code,
            "poc_path": self.poc_path,
            "mitigation": self.mitigation,
            "recommendation": self.recommendation,
            "created_at": self.created_at.isoformat(),
            "auditor_notes": self.auditor_notes,
            "references": self.references,
        }


@dataclass
class Session:
    """Audit session state"""
    id: str
    name: str
    project_path: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Contracts loaded
    contracts: List[ContractInfo] = field(default_factory=list)
    call_graph: Optional[CallGraph] = None
    
    # Analysis state
    leads: List[VulnerabilityLead] = field(default_factory=list)
    fuzz_results: List[FuzzResult] = field(default_factory=list)
    z3_results: List[Z3VerificationResult] = field(default_factory=list)
    
    # Reports
    reports: List[BugReport] = field(default_factory=list)
    
    # External integrations
    github_url: Optional[str] = None
    etherscan_api_key: Optional[str] = None
    alchemy_api_key: Optional[str] = None
    deployed_addresses: Dict[str, str] = field(default_factory=dict)  # contract -> address
    
    # Audit progress
    total_functions: int = 0
    analyzed_functions: int = 0
    audit_iterations: int = 0
    unexplored_paths: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "project_path": self.project_path,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "contracts": [c.name for c in self.contracts],
            "leads_count": len(self.leads),
            "confirmed_leads": len([l for l in self.leads if l.confirmed]),
            "reports_count": len(self.reports),
            "github_url": self.github_url,
            "total_functions": self.total_functions,
            "analyzed_functions": self.analyzed_functions,
            "audit_iterations": self.audit_iterations,
        }
