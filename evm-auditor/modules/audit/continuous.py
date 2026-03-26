"""
Continuous Auditing Module for EVM Solidity Auditing Agent

Ensures exhaustive exploration after each confirmed bug.
Updates session memory continuously.
"""
import asyncio
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from models import (
    Session, ContractInfo, CallGraph, VulnerabilityLead,
    FunctionInfo
)
from config import LeadStatus


class AuditPhase(Enum):
    """Phases of the auditing process"""
    INITIALIZATION = "initialization"
    PARSING = "parsing"
    STATIC_ANALYSIS = "static_analysis"
    LEAD_GENERATION = "lead_generation"
    LEAD_RANKING = "lead_ranking"
    SYMBOLIC_VERIFICATION = "symbolic_verification"
    POC_GENERATION = "poc_generation"
    POC_EXECUTION = "poc_execution"
    REPORTING = "reporting"
    CONTINUOUS_AUDIT = "continuous_audit"
    COMPLETED = "completed"


@dataclass
class AuditProgress:
    """Progress tracking for auditing"""
    phase: AuditPhase
    phase_progress: float  # 0.0 to 1.0
    total_progress: float  # 0.0 to 1.0
    current_task: str
    completed_tasks: List[str]
    started_at: datetime
    estimated_remaining_seconds: Optional[int] = None


class ContinuousAuditor:
    """
    Orchestrates the continuous auditing process.
    
    Features:
    - Manages audit workflow across all modules
    - Tracks progress and state
    - Ensures exhaustive coverage
    - Handles interrupts and resumption
    """
    
    def __init__(
        self,
        session: Session,
        model_brain=None,
        slither_analyzer=None,
        z3_executor=None,
        foundry_integration=None,
        session_manager=None,
    ):
        self.session = session
        self.model_brain = model_brain
        self.slither = slither_analyzer
        self.z3 = z3_executor
        self.foundry = foundry_integration
        self.session_manager = session_manager
        
        # State
        self.progress = AuditProgress(
            phase=AuditPhase.INITIALIZATION,
            phase_progress=0.0,
            total_progress=0.0,
            current_task="Initializing",
            completed_tasks=[],
            started_at=datetime.now(),
        )
        self.is_running = False
        self.should_stop = False
        
        # Callbacks
        self.on_progress_update: Optional[Callable[[AuditProgress], None]] = None
        self.on_lead_found: Optional[Callable[[VulnerabilityLead], None]] = None
        self.on_bug_confirmed: Optional[Callable[[VulnerabilityLead], None]] = None
        self.on_phase_complete: Optional[Callable[[AuditPhase], None]] = None
        
        # Audit configuration
        self.max_iterations = 10
        self.confidence_threshold = 0.5
        self.analyzed_functions: List[str] = []
        self.unexplored_paths: List[str] = []
    
    def get_progress(self) -> AuditProgress:
        """Get current audit progress"""
        return self.progress
    
    async def run_audit(self, max_iterations: int = None) -> bool:
        """
        Run the complete auditing process.
        
        Returns True if completed successfully.
        """
        self.is_running = True
        self.should_stop = False
        self.max_iterations = max_iterations or self.max_iterations
        
        try:
            # Phase 1: Initialization
            await self._run_phase(AuditPhase.INITIALIZATION, self._initialize)
            
            if self.should_stop:
                return False
            
            # Phase 2: Parsing
            await self._run_phase(AuditPhase.PARSING, self._parse_contracts)
            
            # Phase 3: Static Analysis (Slither)
            await self._run_phase(AuditPhase.STATIC_ANALYSIS, self._run_slither)
            
            # Phase 4: LLM-based Lead Generation
            await self._run_phase(AuditPhase.LEAD_GENERATION, self._generate_leads)
            
            # Phase 5: Lead Ranking
            await self._run_phase(AuditPhase.LEAD_RANKING, self._rank_leads)
            
            # Phase 6: Symbolic Verification
            await self._run_phase(AuditPhase.SYMBOLIC_VERIFICATION, self._verify_symbolic)
            
            # Phase 7: POC Generation and Execution
            await self._run_phase(AuditPhase.POC_GENERATION, self._generate_pocs)
            await self._run_phase(AuditPhase.POC_EXECUTION, self._execute_pocs)
            
            # Phase 8: Continuous Audit Loop
            await self._run_continuous_audit()
            
            # Phase 9: Reporting
            await self._run_phase(AuditPhase.REPORTING, self._generate_reports)
            
            self.progress.phase = AuditPhase.COMPLETED
            self._update_progress(1.0, "Audit completed")
            
            return True
            
        except Exception as e:
            self._update_progress(0, f"Error: {str(e)}")
            return False
        finally:
            self.is_running = False
    
    async def _run_phase(self, phase: AuditPhase, phase_func):
        """Run a single audit phase"""
        self.progress.phase = phase
        self._update_progress(0, f"Starting {phase.value}")
        
        await phase_func()
        
        self.progress.completed_tasks.append(phase.value)
        if self.on_phase_complete:
            self.on_phase_complete(phase)
    
    def _update_progress(self, phase_progress: float, current_task: str):
        """Update progress and notify callback"""
        self.progress.phase_progress = phase_progress
        self.progress.current_task = current_task
        
        # Calculate total progress
        phase_weights = {
            AuditPhase.INITIALIZATION: 0.05,
            AuditPhase.PARSING: 0.10,
            AuditPhase.STATIC_ANALYSIS: 0.15,
            AuditPhase.LEAD_GENERATION: 0.20,
            AuditPhase.LEAD_RANKING: 0.10,
            AuditPhase.SYMBOLIC_VERIFICATION: 0.15,
            AuditPhase.POC_GENERATION: 0.10,
            AuditPhase.POC_EXECUTION: 0.10,
            AuditPhase.CONTINUOUS_AUDIT: 0.03,
            AuditPhase.REPORTING: 0.02,
        }
        
        total = 0.0
        for p, weight in phase_weights.items():
            if p == self.progress.phase:
                total += weight * phase_progress
                break
            elif p.value in self.progress.completed_tasks:
                total += weight
        
        self.progress.total_progress = total
        
        if self.on_progress_update:
            self.on_progress_update(self.progress)
    
    def stop(self):
        """Stop the auditing process"""
        self.should_stop = True
    
    async def _initialize(self):
        """Initialize audit state"""
        self._update_progress(0.5, "Loading session data")
        await asyncio.sleep(0.1)  # Allow async operations
        self._update_progress(1.0, "Initialization complete")
    
    async def _parse_contracts(self):
        """Parse all contracts in the project"""
        from modules.parser.code_parser import solidity_parser
        
        project_path = self.session.project_path
        results = solidity_parser.parse_directory(project_path)
        
        total = len(results)
        for i, result in enumerate(results):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Parsing {result.file_path}")
            
            for contract in result.contracts:
                self.session.contracts.append(contract)
            
            await asyncio.sleep(0.05)
        
        # Build call graph
        if self.session.contracts:
            source_files = {}
            for result in results:
                if result.success:
                    try:
                        source_files[result.file_path] = Path(result.file_path).read_text()
                    except Exception:
                        pass
            
            self.session.call_graph = solidity_parser.build_call_graph(
                self.session.contracts, source_files
            )
        
        self._update_progress(1.0, f"Parsed {len(self.session.contracts)} contracts")
    
    async def _run_slither(self):
        """Run Slither static analysis"""
        if not self.slither:
            self._update_progress(1.0, "Slither not available, skipping")
            return
        
        total = len(self.session.contracts)
        for i, contract in enumerate(self.session.contracts):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Analyzing {contract.name}")
            
            try:
                leads = self.slither.analyze(Path(contract.file_path))
                for lead in leads:
                    self.session.leads.append(lead)
                    if self.on_lead_found:
                        self.on_lead_found(lead)
            except Exception as e:
                print(f"Slither error on {contract.name}: {e}")
            
            await asyncio.sleep(0.05)
        
        self._update_progress(1.0, f"Slither found {len(self.session.leads)} leads")
    
    async def _generate_leads(self):
        """Generate additional leads using LLM"""
        if not self.model_brain:
            self._update_progress(1.0, "Model brain not available, skipping")
            return
        
        total = len(self.session.contracts)
        for i, contract in enumerate(self.session.contracts):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Analyzing {contract.name} with LLM")
            
            try:
                source_code = Path(contract.file_path).read_text()
                leads = await self.model_brain.analyze_contract(contract, source_code)
                
                for lead in leads:
                    self.session.leads.append(lead)
                    if self.on_lead_found:
                        self.on_lead_found(lead)
            except Exception as e:
                print(f"LLM analysis error on {contract.name}: {e}")
            
            await asyncio.sleep(0.1)
        
        self._update_progress(1.0, f"Total leads: {len(self.session.leads)}")
    
    async def _rank_leads(self):
        """Rank vulnerability leads"""
        if not self.model_brain:
            self._update_progress(1.0, "Skipping ranking")
            return
        
        self._update_progress(0, "Ranking leads")
        
        ranked = await self.model_brain.rank_leads(self.session.leads)
        self.session.leads = ranked
        
        self._update_progress(1.0, f"Ranked {len(ranked)} leads")
    
    async def _verify_symbolic(self):
        """Verify leads with Z3 symbolic execution"""
        if not self.z3:
            self._update_progress(1.0, "Z3 not available, skipping")
            return
        
        # Only verify high-confidence leads
        leads_to_verify = [
            l for l in self.session.leads 
            if l.confidence >= self.confidence_threshold and 
               l.status not in (LeadStatus.CONFIRMED, LeadStatus.DISMISSED)
        ]
        
        total = len(leads_to_verify)
        for i, lead in enumerate(leads_to_verify):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Verifying {lead.title}")
            lead.status = LeadStatus.TESTING
            
            # Find related function
            function = None
            for contract in self.session.contracts:
                for func in contract.functions:
                    if func.name in lead.affected_functions:
                        function = func
                        break
            
            if function:
                try:
                    result = self.z3.verify_vulnerability(lead, function, contract)
                    self.session.z3_results.append(result)
                    
                    if result.satisfiable:
                        lead.status = LeadStatus.TRIAGED
                        lead.z3_verification = str(result.model)
                    else:
                        lead.confidence *= 0.8  # Reduce confidence
                        
                except Exception as e:
                    print(f"Z3 verification error: {e}")
            
            await asyncio.sleep(0.05)
        
        self._update_progress(1.0, "Symbolic verification complete")
    
    async def _generate_pocs(self):
        """Generate Foundry POC tests"""
        if not self.model_brain:
            self._update_progress(1.0, "Model brain not available, skipping POC generation")
            return
        
        # Generate POCs for triaged leads
        leads_with_poc = [
            l for l in self.session.leads
            if l.status == LeadStatus.TRIAGED and not l.foundry_poc
        ]
        
        total = len(leads_with_poc)
        for i, lead in enumerate(leads_with_poc):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Generating POC for {lead.title}")
            
            # Find contract
            contract = None
            for c in self.session.contracts:
                if c.name in lead.affected_contracts:
                    contract = c
                    break
            
            if contract:
                try:
                    source_code = Path(contract.file_path).read_text()
                    poc_code = await self.model_brain.generate_foundry_poc(
                        lead, contract, source_code
                    )
                    lead.foundry_poc = poc_code
                except Exception as e:
                    print(f"POC generation error: {e}")
            
            await asyncio.sleep(0.1)
        
        self._update_progress(1.0, "POC generation complete")
    
    async def _execute_pocs(self):
        """Execute Foundry POC tests"""
        if not self.foundry:
            self._update_progress(1.0, "Foundry not available, skipping POC execution")
            return
        
        leads_to_test = [
            l for l in self.session.leads
            if l.foundry_poc and not l.confirmed
        ]
        
        total = len(leads_to_test)
        for i, lead in enumerate(leads_to_test):
            if self.should_stop:
                return
            
            self._update_progress(i / total, f"Testing {lead.title}")
            
            # Find contract
            contract = None
            for c in self.session.contracts:
                if c.name in lead.affected_contracts:
                    contract = c
                    break
            
            if contract:
                try:
                    confirmed, poc_path = self.foundry.verify_vulnerability(
                        lead, contract
                    )
                    
                    if confirmed:
                        lead.confirmed = True
                        lead.status = LeadStatus.CONFIRMED
                        lead.foundry_poc = poc_path
                        
                        if self.on_bug_confirmed:
                            self.on_bug_confirmed(lead)
                    else:
                        lead.confidence *= 0.5
                        
                except Exception as e:
                    print(f"POC execution error: {e}")
            
            await asyncio.sleep(0.1)
        
        self._update_progress(1.0, "POC execution complete")
    
    async def _run_continuous_audit(self):
        """Run continuous auditing loop"""
        self.progress.phase = AuditPhase.CONTINUOUS_AUDIT
        
        for iteration in range(self.max_iterations):
            if self.should_stop:
                return
            
            self._update_progress(
                iteration / self.max_iterations,
                f"Continuous audit iteration {iteration + 1}"
            )
            
            # Identify unexplored paths
            if self.model_brain:
                unexplored = await self.model_brain.identify_unexplored_paths(
                    self.session.contracts,
                    self.session.call_graph,
                    self.analyzed_functions
                )
                
                if not unexplored:
                    break
                
                self.unexplored_paths = unexplored
                
                # Analyze unexplored paths
                for path in unexplored[:5]:  # Limit per iteration
                    # Parse contract.function format
                    parts = path.split('.')
                    if len(parts) == 2:
                        contract_name, func_name = parts
                        
                        # Find contract and function
                        for contract in self.session.contracts:
                            if contract.name == contract_name:
                                for func in contract.functions:
                                    if func.name == func_name:
                                        # Analyze this function
                                        await self._analyze_function(contract, func)
                                        self.analyzed_functions.append(path)
                                        break
            
            self.session.audit_iterations = iteration + 1
            
            await asyncio.sleep(0.1)
        
        self._update_progress(1.0, "Continuous audit complete")
    
    async def _analyze_function(self, contract: ContractInfo, function: FunctionInfo):
        """Analyze a single function for vulnerabilities"""
        if self.model_brain:
            try:
                source_code = Path(contract.file_path).read_text()
                
                # Generate focused lead for this function
                context = f"Focus on function: {function.name}"
                leads = await self.model_brain.analyze_contract(
                    contract, source_code, context
                )
                
                for lead in leads:
                    if function.name in lead.affected_functions:
                        self.session.leads.append(lead)
                        if self.on_lead_found:
                            self.on_lead_found(lead)
                            
            except Exception as e:
                print(f"Function analysis error: {e}")
    
    async def _generate_reports(self):
        """Generate final reports"""
        from modules.reporting.generator import report_generator
        
        self._update_progress(0, "Generating reports")
        
        confirmed_leads = [l for l in self.session.leads if l.confirmed]
        
        # Generate individual bug reports
        for i, lead in enumerate(confirmed_leads):
            self._update_progress(
                0.5 * (i / len(confirmed_leads)),
                f"Generating report for {lead.title}"
            )
            
            report = report_generator.generate_report(lead, lead.foundry_poc or "")
            self.session.reports.append(report)
        
        # Generate session report
        if confirmed_leads:
            self._update_progress(0.75, "Generating summary report")
            report_generator.generate_session_report(
                self.session.to_dict(),
                self.session.reports
            )
        
        self._update_progress(1.0, f"Generated {len(confirmed_leads)} reports")
