"""
Slither Static Analysis Module for EVM Solidity Auditing Agent

Integrates Slither for detecting common vulnerabilities and risky patterns.
"""
import json
import subprocess
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import uuid

from models import VulnerabilityLead, ContractInfo
from config import Severity, LeadStatus


@dataclass
class SlitherFinding:
    """A finding from Slither analysis"""
    check: str
    impact: str
    confidence: str
    description: str
    file: str
    line: int
    contract: str
    function: str
    code_snippet: str = ""
    markdown: str = ""


class SlitherAnalyzer:
    """
    Wrapper for Slither static analyzer.
    
    Features:
    - Run Slither analysis on contracts
    - Parse and convert findings to vulnerability leads
    - Filter and prioritize results
    """
    
    # Slither check to severity mapping
    IMPACT_TO_SEVERITY = {
        'High': Severity.HIGH,
        'Medium': Severity.MEDIUM,
        'Low': Severity.LOW,
        'Informational': Severity.INFORMATIONAL,
    }
    
    # Severity mapping from Slither lowercase impact
    SEVERITY_MAP = {
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'informational': Severity.INFORMATIONAL,
        'optimization': Severity.GAS,
    }
    
    def is_installed(self) -> bool:
        """Check if Slither is installed"""
        try:
            result = subprocess.run(
                ['slither', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def analyze(
        self,
        target_path: Path,
        solc_version: Optional[str] = None,
        detectors: Optional[List[str]] = None,
        exclude_detectors: Optional[List[str]] = None,
        external_libraries: bool = True,
        filter_paths: Optional[List[str]] = None,
    ) -> List[VulnerabilityLead]:
        """
        Run Slither analysis on a target path.
        
        Args:
            target_path: Path to Solidity file or directory
            solc_version: Specific solc version to use
            detectors: Specific detectors to run (None = all)
            exclude_detectors: Detectors to exclude
            external_libraries: Whether to analyze external libraries
            filter_paths: Paths to exclude from analysis
            
        Returns:
            List of vulnerability leads from Slither findings
        """
        if not self.is_installed():
            raise RuntimeError("Slither is not installed. Install with: pip install slither-analyzer")
        
        # Build command
        cmd = ['slither', str(target_path), '--json', '-']
        
        # Add solc version if specified
        if solc_version:
            cmd.extend(['--solc-solcs-select', solc_version])
        
        # Add detector filters
        if detectors:
            cmd.extend(['--detect', ','.join(detectors)])
        if exclude_detectors:
            cmd.extend(['--exclude', ','.join(exclude_detectors)])
        
        # Exclude external libraries if specified
        if not external_libraries:
            cmd.append('--skip-assembly')
        
        # Add filter paths
        if filter_paths:
            for path in filter_paths:
                cmd.extend(['--filter-paths', path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse JSON output
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    return self._parse_findings(output)
                except json.JSONDecodeError:
                    # Try to parse from stderr if stdout is empty
                    if result.stderr:
                        # Slither sometimes outputs to stderr
                        pass
            
            return []
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Slither analysis timed out")
        except Exception as e:
            raise RuntimeError(f"Slither analysis failed: {e}")
    
    def _parse_findings(self, output: Dict[str, Any]) -> List[VulnerabilityLead]:
        """Parse Slither JSON output into vulnerability leads"""
        leads = []
        
        # Slither JSON format varies by version
        results = output.get('results', {})
        detectors = results.get('detectors', [])
        
        for finding in detectors:
            lead = self._create_lead_from_finding(finding)
            if lead:
                leads.append(lead)
        
        return leads
    
    def _create_lead_from_finding(self, finding: Dict[str, Any]) -> Optional[VulnerabilityLead]:
        """Create a vulnerability lead from a Slither finding"""
        try:
            check = finding.get('check', 'unknown')
            impact = finding.get('impact', 'medium').lower()
            confidence = finding.get('confidence', 'medium').lower()
            description = finding.get('description', '')
            
            # Get affected elements
            elements = finding.get('elements', [])
            contracts = set()
            functions = set()
            locations = []
            
            for element in elements:
                if element.get('type') == 'contract':
                    contracts.add(element.get('name', ''))
                elif element.get('type') == 'function':
                    contracts.add(element.get('contract', {}).get('name', ''))
                    functions.add(element.get('name', ''))
                
                # Get source location
                source_mapping = element.get('source_mapping', {})
                if source_mapping:
                    file_path = source_mapping.get('filename_relative', '')
                    lines = source_mapping.get('lines', [])
                    if lines:
                        locations.append(f"{file_path}:{lines[0]}")
            
            # Calculate confidence score
            confidence_score = {
                'high': 0.9,
                'medium': 0.6,
                'low': 0.3,
            }.get(confidence, 0.5)
            
            lead = VulnerabilityLead(
                id=str(uuid.uuid4())[:8],
                title=f"{check}: {description[:100]}",
                description=description,
                severity=self.SEVERITY_MAP.get(impact, Severity.MEDIUM),
                status=LeadStatus.NEW,
                confidence=confidence_score,
                affected_contracts=list(contracts),
                affected_functions=list(functions),
                detection_method='slither',
                category=check,
                tags=[check, 'static-analysis'],
                notes=[f"Slither check: {check}", f"Confidence: {confidence}"],
            )
            
            return lead
            
        except Exception as e:
            print(f"Error parsing Slither finding: {e}")
            return None
    
    def analyze_contract(
        self,
        contract_info: ContractInfo,
        source_code: str,
        solc_version: Optional[str] = None
    ) -> List[VulnerabilityLead]:
        """
        Analyze a single contract from source code.
        Writes to temp file and runs Slither.
        """
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write contract to temp file
            contract_file = Path(tmpdir) / f"{contract_info.name}.sol"
            contract_file.write_text(source_code)
            
            # Run analysis
            return self.analyze(
                contract_file,
                solc_version=solc_version
            )
    
    def get_available_detectors(self) -> List[Dict[str, str]]:
        """Get list of available Slither detectors"""
        try:
            result = subprocess.run(
                ['slither', '--list-detectors-json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout:
                detectors = json.loads(result.stdout)
                return [
                    {
                        'name': d.get('check', ''),
                        'impact': d.get('impact', ''),
                        'description': d.get('title', ''),
                    }
                    for d in detectors
                ]
        except Exception:
            pass
        
        # Return default list of common detectors
        return [
            {'name': 'reentrancy-eth', 'impact': 'high', 'description': 'Reentrancy vulnerabilities'},
            {'name': 'reentrancy-no-eth', 'impact': 'medium', 'description': 'Reentrancy without ETH transfer'},
            {'name': 'arbitrary-send', 'impact': 'high', 'description': 'Arbitrary ETH transfer'},
            {'name': 'controlled-delegatecall', 'impact': 'high', 'description': 'Controlled delegatecall'},
            {'name': 'suicidal', 'impact': 'high', 'description': 'Contracts that can self-destruct'},
            {'name': 'uninitialized-state', 'impact': 'high', 'description': 'Uninitialized state variables'},
            {'name': 'uninitialized-storage', 'impact': 'high', 'description': 'Uninitialized storage pointers'},
            {'name': 'locked-ether', 'impact': 'medium', 'description': 'Locked ETH in contract'},
            {'name': 'dangerous-enum-conversion', 'impact': 'medium', 'description': 'Dangerous enum conversion'},
            {'name': 'incorrect-equality', 'impact': 'medium', 'description': 'Incorrect equality checks'},
            {'name': 'unchecked-lowlevel', 'impact': 'medium', 'description': 'Unchecked low-level calls'},
            {'name': 'unchecked-return', 'impact': 'medium', 'description': 'Unchecked return values'},
            {'name': 'assembly', 'impact': 'informational', 'description': 'Assembly usage'},
            {'name': 'low-level-calls', 'impact': 'informational', 'description': 'Low-level call usage'},
            {'name': 'naming-convention', 'impact': 'informational', 'description': 'Naming convention violations'},
        ]
    
    def get_detector_categories(self) -> Dict[str, List[str]]:
        """Get detectors grouped by category"""
        return {
            'Reentrancy': ['reentrancy-eth', 'reentrancy-no-eth'],
            'Access Control': ['suicidal', 'controlled-delegatecall', 'arbitrary-send'],
            'Arithmetic': ['integer-overflow', 'integer-underflow', 'divide-before-multiply'],
            'State Issues': ['uninitialized-state', 'uninitialized-storage', 'constable-states'],
            'ETH Handling': ['locked-ether', 'arbitrary-send', 'eth-transfer'],
            'External Calls': ['unchecked-lowlevel', 'unchecked-return', 'low-level-calls'],
            'Logic': ['incorrect-equality', 'boolean-equal', 'constant-primitives'],
            'Code Quality': ['assembly', 'naming-convention', 'unused-state'],
            'Gas Optimization': ['gas-costs', 'redundant-statements', 'dead-code'],
        }


# Singleton instance
slither_analyzer = SlitherAnalyzer()
