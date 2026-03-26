"""
Session Management Module for EVM Solidity Auditing Agent

Maintains all leads, tests, fuzz results, and reports across sessions.
Provides persistent storage and state management.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import asdict

from models import (
    Session, ContractInfo, CallGraph, VulnerabilityLead,
    FuzzResult, Z3VerificationResult, BugReport
)
from config import SESSIONS_DIR, LeadStatus


class SessionManager:
    """
    Manages audit sessions with persistent storage.
    
    Features:
    - Create, load, save, and delete sessions
    - Track leads, test results, and reports
    - Export session data for backup/sharing
    """
    
    def __init__(self, sessions_dir: Path = SESSIONS_DIR):
        self.sessions_dir = sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[Session] = None
        
    def create_session(self, name: str, project_path: str, 
                       github_url: Optional[str] = None) -> Session:
        """Create a new audit session"""
        session_id = str(uuid.uuid4())[:8]
        session = Session(
            id=session_id,
            name=name,
            project_path=project_path,
            github_url=github_url,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        self.current_session = session
        self._save_session(session)
        return session
    
    def load_session(self, session_id: str) -> Optional[Session]:
        """Load an existing session by ID"""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
            session = self._deserialize_session(data)
            self.current_session = session
            return session
        except Exception as e:
            print(f"Error loading session {session_id}: {e}")
            return None
    
    def save_current_session(self) -> bool:
        """Save the current session to disk"""
        if not self.current_session:
            return False
        self.current_session.updated_at = datetime.now()
        return self._save_session(self.current_session)
    
    def _save_session(self, session: Session) -> bool:
        """Internal method to save session to disk"""
        session_file = self.sessions_dir / f"{session.id}.json"
        try:
            data = self._serialize_session(session)
            with open(session_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving session {session.id}: {e}")
            return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        session_file = self.sessions_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
            if self.current_session and self.current_session.id == session_id:
                self.current_session = None
            return True
        return False
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all available sessions"""
        sessions = []
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                sessions.append({
                    "id": data.get("id"),
                    "name": data.get("name"),
                    "project_path": data.get("project_path"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "leads_count": len(data.get("leads", [])),
                    "reports_count": len(data.get("reports", [])),
                    "github_url": data.get("github_url"),
                })
            except Exception:
                continue
        return sorted(sessions, key=lambda x: x.get("updated_at", ""), reverse=True)
    
    # === Lead Management ===
    
    def add_lead(self, lead: VulnerabilityLead) -> bool:
        """Add a new vulnerability lead to current session"""
        if not self.current_session:
            return False
        self.current_session.leads.append(lead)
        return self.save_current_session()
    
    def update_lead(self, lead_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing lead"""
        if not self.current_session:
            return False
        for lead in self.current_session.leads:
            if lead.id == lead_id:
                for key, value in updates.items():
                    if hasattr(lead, key):
                        setattr(lead, key, value)
                lead.updated_at = datetime.now()
                return self.save_current_session()
        return False
    
    def get_lead(self, lead_id: str) -> Optional[VulnerabilityLead]:
        """Get a specific lead by ID"""
        if not self.current_session:
            return None
        for lead in self.current_session.leads:
            if lead.id == lead_id:
                return lead
        return None
    
    def get_leads_by_status(self, status: LeadStatus) -> List[VulnerabilityLead]:
        """Get all leads with a specific status"""
        if not self.current_session:
            return []
        return [l for l in self.current_session.leads if l.status == status]
    
    def get_confirmed_leads(self) -> List[VulnerabilityLead]:
        """Get all confirmed vulnerability leads"""
        if not self.current_session:
            return []
        return [l for l in self.current_session.leads if l.confirmed]
    
    def dismiss_lead(self, lead_id: str, reason: str = "") -> bool:
        """Mark a lead as false positive/dismissed"""
        return self.update_lead(lead_id, {
            "status": LeadStatus.DISMISSED,
            "false_positive": True,
            "notes": [reason] if reason else []
        })
    
    # === Contract Management ===
    
    def add_contract(self, contract: ContractInfo) -> bool:
        """Add a parsed contract to the session"""
        if not self.current_session:
            return False
        self.current_session.contracts.append(contract)
        self.current_session.total_functions += len(contract.functions)
        return self.save_current_session()
    
    def set_call_graph(self, call_graph: CallGraph) -> bool:
        """Set the call graph for the session"""
        if not self.current_session:
            return False
        self.current_session.call_graph = call_graph
        return self.save_current_session()
    
    def get_contract(self, name: str) -> Optional[ContractInfo]:
        """Get a contract by name"""
        if not self.current_session:
            return None
        for contract in self.current_session.contracts:
            if contract.name == name:
                return contract
        return None
    
    # === Test Results Management ===
    
    def add_fuzz_result(self, result: FuzzResult) -> bool:
        """Add a fuzzing result"""
        if not self.current_session:
            return False
        self.current_session.fuzz_results.append(result)
        return self.save_current_session()
    
    def add_z3_result(self, result: Z3VerificationResult) -> bool:
        """Add a Z3 verification result"""
        if not self.current_session:
            return False
        self.current_session.z3_results.append(result)
        return self.save_current_session()
    
    def get_fuzz_result(self, lead_id: str) -> Optional[FuzzResult]:
        """Get fuzz result for a lead"""
        if not self.current_session:
            return None
        for result in self.current_session.fuzz_results:
            if result.lead_id == lead_id:
                return result
        return None
    
    def get_z3_result(self, lead_id: str) -> Optional[Z3VerificationResult]:
        """Get Z3 result for a lead"""
        if not self.current_session:
            return None
        for result in self.current_session.z3_results:
            if result.lead_id == lead_id:
                return result
        return None
    
    # === Report Management ===
    
    def add_report(self, report: BugReport) -> bool:
        """Add a bug report to the session"""
        if not self.current_session:
            return False
        self.current_session.reports.append(report)
        return self.save_current_session()
    
    def get_report(self, report_id: str) -> Optional[BugReport]:
        """Get a report by ID"""
        if not self.current_session:
            return None
        for report in self.current_session.reports:
            if report.id == report_id:
                return report
        return None
    
    # === Progress Tracking ===
    
    def update_progress(self, analyzed_functions: int = None,
                        audit_iterations: int = None,
                        unexplored_paths: List[str] = None) -> bool:
        """Update audit progress"""
        if not self.current_session:
            return False
        if analyzed_functions is not None:
            self.current_session.analyzed_functions = analyzed_functions
        if audit_iterations is not None:
            self.current_session.audit_iterations = audit_iterations
        if unexplored_paths is not None:
            self.current_session.unexplored_paths = unexplored_paths
        return self.save_current_session()
    
    def get_progress(self) -> Dict[str, Any]:
        """Get current audit progress"""
        if not self.current_session:
            return {}
        return {
            "total_functions": self.current_session.total_functions,
            "analyzed_functions": self.current_session.analyzed_functions,
            "progress_percent": (
                self.current_session.analyzed_functions / 
                max(self.current_session.total_functions, 1) * 100
            ),
            "audit_iterations": self.current_session.audit_iterations,
            "unexplored_paths_count": len(self.current_session.unexplored_paths),
            "leads_count": len(self.current_session.leads),
            "confirmed_count": len([l for l in self.current_session.leads if l.confirmed]),
        }
    
    # === Serialization ===
    
    def _serialize_session(self, session: Session) -> Dict[str, Any]:
        """Serialize session to dictionary"""
        return {
            "id": session.id,
            "name": session.name,
            "project_path": session.project_path,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "contracts": [self._serialize_contract(c) for c in session.contracts],
            "call_graph": self._serialize_call_graph(session.call_graph) if session.call_graph else None,
            "leads": [l.to_dict() for l in session.leads],
            "fuzz_results": [r.to_dict() for r in session.fuzz_results],
            "z3_results": [r.to_dict() for r in session.z3_results],
            "reports": [r.to_dict() for r in session.reports],
            "github_url": session.github_url,
            "etherscan_api_key": session.etherscan_api_key,
            "alchemy_api_key": session.alchemy_api_key,
            "deployed_addresses": session.deployed_addresses,
            "total_functions": session.total_functions,
            "analyzed_functions": session.analyzed_functions,
            "audit_iterations": session.audit_iterations,
            "unexplored_paths": session.unexplored_paths,
        }
    
    def _deserialize_session(self, data: Dict[str, Any]) -> Session:
        """Deserialize session from dictionary"""
        # This is a simplified deserialization
        # Full implementation would properly reconstruct all nested objects
        session = Session(
            id=data.get("id"),
            name=data.get("name"),
            project_path=data.get("project_path"),
            created_at=datetime.fromisoformat(data.get("created_at")),
            updated_at=datetime.fromisoformat(data.get("updated_at")),
            github_url=data.get("github_url"),
            etherscan_api_key=data.get("etherscan_api_key"),
            alchemy_api_key=data.get("alchemy_api_key"),
            deployed_addresses=data.get("deployed_addresses", {}),
            total_functions=data.get("total_functions", 0),
            analyzed_functions=data.get("analyzed_functions", 0),
            audit_iterations=data.get("audit_iterations", 0),
            unexplored_paths=data.get("unexplored_paths", []),
        )
        
        # Deserialize leads
        for lead_data in data.get("leads", []):
            from config import Severity
            lead = VulnerabilityLead(
                id=lead_data.get("id"),
                title=lead_data.get("title"),
                description=lead_data.get("description"),
                severity=Severity(lead_data.get("severity")),
                status=LeadStatus(lead_data.get("status")),
                confidence=lead_data.get("confidence", 0.0),
                affected_contracts=lead_data.get("affected_contracts", []),
                affected_functions=lead_data.get("affected_functions", []),
                detection_method=lead_data.get("detection_method", ""),
                category=lead_data.get("category", ""),
                attack_vector=lead_data.get("attack_vector", ""),
                preconditions=lead_data.get("preconditions", []),
                attack_steps=lead_data.get("attack_steps", []),
                impact=lead_data.get("impact", ""),
                confirmed=lead_data.get("confirmed", False),
                tags=lead_data.get("tags", []),
                notes=lead_data.get("notes", []),
            )
            session.leads.append(lead)
        
        return session
    
    def _serialize_contract(self, contract: ContractInfo) -> Dict[str, Any]:
        """Serialize contract info"""
        return {
            "name": contract.name,
            "file_path": contract.file_path,
            "kind": contract.kind,
            "functions": [asdict(f) for f in contract.functions],
            "variables": contract.variables,
            "events": contract.events,
            "errors": contract.errors,
            "modifiers": contract.modifiers,
            "inherits": contract.inherits,
            "imports": contract.imports,
            "is_proxy": contract.is_proxy,
            "implementation": contract.implementation,
        }
    
    def _serialize_call_graph(self, call_graph: CallGraph) -> Dict[str, Any]:
        """Serialize call graph"""
        return {
            "nodes": list(call_graph.nodes),
            "edges": [
                {
                    "caller": e.caller,
                    "callee": e.callee,
                    "call_type": e.call_type,
                }
                for e in call_graph.edges
            ],
            "entry_points": list(call_graph.entry_points),
        }
    
    # === Export Functions ===
    
    def export_session(self, export_path: Path) -> bool:
        """Export session to a portable JSON file"""
        if not self.current_session:
            return False
        try:
            data = self._serialize_session(self.current_session)
            with open(export_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error exporting session: {e}")
            return False
    
    def import_session(self, import_path: Path) -> Optional[Session]:
        """Import session from a JSON file"""
        try:
            with open(import_path, 'r') as f:
                data = json.load(f)
            session = self._deserialize_session(data)
            # Generate new ID for imported session
            session.id = str(uuid.uuid4())[:8]
            self._save_session(session)
            return session
        except Exception as e:
            print(f"Error importing session: {e}")
            return None


# Singleton instance
session_manager = SessionManager()
