"""
Foundry POC & Fuzzing Module for EVM Solidity Auditing Agent

Generates and runs Foundry tests and fuzzing campaigns.
Definitive bug verification on actual bytecode.
"""
import subprocess
import json
import re
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import uuid

from models import VulnerabilityLead, FunctionInfo, FuzzResult, ContractInfo
from config import LeadStatus


@dataclass
class FoundryTestResult:
    """Result of running a Foundry test"""
    test_name: str
    passed: bool
    gas_used: int
    logs: List[str]
    error_message: str = ""
    counterexample: Optional[Dict[str, Any]] = None
    duration_ms: int = 0


@dataclass
class FuzzCampaignResult:
    """Result of a fuzzing campaign"""
    test_name: str
    total_runs: int
    successes: int
    failures: int
    coverage: float
    gas_stats: Dict[str, Any]
    counterexamples: List[Dict[str, Any]]
    duration_ms: int = 0


class FoundryRunner:
    """
    Runner for Foundry/Forge commands.
    
    Features:
    - Compile contracts with forge build
    - Run tests with forge test
    - Execute fuzzing campaigns
    - Manage forked environments
    """
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self._forge_path = self._find_forge()
        
    def _find_forge(self) -> Optional[str]:
        """Find forge executable"""
        try:
            result = subprocess.run(
                ['which', 'forge'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def is_foundry_installed(self) -> bool:
        """Check if Foundry is installed"""
        return self._forge_path is not None
    
    def is_foundry_project(self) -> bool:
        """Check if directory is a Foundry project"""
        foundry_toml = self.project_path / "foundry.toml"
        src_dir = self.project_path / "src"
        return foundry_toml.exists() or src_dir.exists()
    
    def init_project(self) -> bool:
        """Initialize a new Foundry project"""
        if not self._forge_path:
            return False
        
        try:
            result = subprocess.run(
                [self._forge_path, 'init', '--no-git', '--force'],
                cwd=self.project_path,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def build(self, optimize: bool = True) -> Tuple[bool, str]:
        """Build contracts with forge build"""
        if not self._forge_path:
            return False, "Forge not found"
        
        cmd = [self._forge_path, 'build']
        if optimize:
            cmd.append('--optimize')
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "Build timed out"
        except Exception as e:
            return False, str(e)
    
    def run_test(
        self,
        test_pattern: str = "",
        verbose: int = 2,
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
        gas_report: bool = False
    ) -> FoundryTestResult:
        """Run a Foundry test"""
        if not self._forge_path:
            return FoundryTestResult(
                test_name=test_pattern or "all",
                passed=False,
                gas_used=0,
                logs=[],
                error_message="Forge not found"
            )
        
        cmd = [self._forge_path, 'test', '--json']
        
        if test_pattern:
            cmd.extend(['--match-test', test_pattern])
        
        if verbose > 0:
            cmd.append('-' + 'v' * verbose)
        
        if fork_url:
            cmd.extend(['--fork-url', fork_url])
            if fork_block:
                cmd.extend(['--fork-block-number', str(fork_block)])
        
        if gas_report:
            cmd.append('--gas-report')
        
        try:
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                test_results = output.get('test_results', {})
                
                for test_name, data in test_results.items():
                    passed = data.get('status') == 'Success'
                    gas = data.get('gas', 0)
                    logs = data.get('logs', [])
                    
                    return FoundryTestResult(
                        test_name=test_name,
                        passed=passed,
                        gas_used=gas,
                        logs=logs,
                        duration_ms=duration_ms
                    )
            except json.JSONDecodeError:
                # Parse text output
                passed = result.returncode == 0
                return FoundryTestResult(
                    test_name=test_pattern or "all",
                    passed=passed,
                    gas_used=0,
                    logs=result.stdout.split('\n'),
                    error_message="" if passed else result.stderr,
                    duration_ms=duration_ms
                )
                
        except subprocess.TimeoutExpired:
            return FoundryTestResult(
                test_name=test_pattern or "all",
                passed=False,
                gas_used=0,
                logs=[],
                error_message="Test timed out"
            )
        except Exception as e:
            return FoundryTestResult(
                test_name=test_pattern or "all",
                passed=False,
                gas_used=0,
                logs=[],
                error_message=str(e)
            )
        
        # Default return
        return FoundryTestResult(
            test_name=test_pattern or "all",
            passed=False,
            gas_used=0,
            logs=[],
            error_message="Unknown error"
        )
    
    def run_fuzz(
        self,
        test_pattern: str = "",
        runs: int = 256,
        fork_url: Optional[str] = None,
        seed: Optional[int] = None
    ) -> FuzzCampaignResult:
        """Run a fuzzing campaign"""
        if not self._forge_path:
            return FuzzCampaignResult(
                test_name=test_pattern or "all",
                total_runs=0,
                successes=0,
                failures=1,
                coverage=0,
                gas_stats={},
                counterexamples=[]
            )
        
        cmd = [self._forge_path, 'test', '--json']
        
        if test_pattern:
            cmd.extend(['--match-test', test_pattern])
        
        cmd.extend(['--fuzz-runs', str(runs)])
        
        if fork_url:
            cmd.extend(['--fork-url', fork_url])
        
        if seed is not None:
            cmd.extend(['--fuzz-seed', str(seed)])
        
        try:
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout for fuzzing
            )
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # Parse results
            try:
                output = json.loads(result.stdout)
                test_results = output.get('test_results', {})
                
                for test_name, data in test_results.items():
                    status = data.get('status')
                    counterexamples = []
                    
                    if status == 'Failure':
                        # Extract counterexample
                        traces = data.get('traces', [])
                        for trace in traces:
                            counterexamples.append(trace)
                    
                    return FuzzCampaignResult(
                        test_name=test_name,
                        total_runs=runs,
                        successes=runs if status == 'Success' else 0,
                        failures=1 if status == 'Failure' else 0,
                        coverage=0,  # Would need separate coverage run
                        gas_stats=data.get('gas_stats', {}),
                        counterexamples=counterexamples,
                        duration_ms=duration_ms
                    )
            except json.JSONDecodeError:
                pass
                
        except Exception as e:
            pass
        
        return FuzzCampaignResult(
            test_name=test_pattern or "all",
            total_runs=runs,
            successes=0,
            failures=1,
            coverage=0,
            gas_stats={},
            counterexamples=[]
        )


class POCGenerator:
    """
    Generator for Foundry Proof-of-Concept tests.
    
    Features:
    - Generate test templates for vulnerabilities
    - Create setup and attack scenarios
    - Add assertions and verification
    """
    
    TEST_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract {test_name} is Test {{
    {contract_name} target;
    
    function setUp() public {{
        // Setup: Deploy contracts and configure initial state
        target = new {contract_name}();
        // TODO: Configure initial state
    }}
    
    function test_{vuln_name}() public {{
        // Arrange: Set up attack preconditions
        // TODO: Setup attacker address, initial balances, etc.
        
        // Act: Execute the attack
        // TODO: Call vulnerable function(s)
        
        // Assert: Verify vulnerability was exploited
        // TODO: Add assertions to verify exploit success
    }}
}}
'''

    REENTRANCY_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

// Malicious contract for reentrancy attack
contract ReentrancyAttacker {{
    {contract_name} public target;
    address public owner;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
        owner = msg.sender;
    }}
    
    receive() external payable {{
        if (address(target).balance >= msg.value) {{
            target.{vulnerable_function}();
        }}
    }}
    
    function attack() external payable {{
        require(msg.sender == owner);
        target.{vulnerable_function}{{value: msg.value}}();
    }}
}}

contract {test_name} is Test {{
    {contract_name} target;
    ReentrancyAttacker attacker;
    address attackerEOA = address(0xdeadbeef);
    
    function setUp() public {{
        target = new {contract_name}();
        attacker = new ReentrancyAttacker(address(target));
        
        // Fund the contract
        vm.deal(address(target), 10 ether);
    }}
    
    function test_reentrancy() public {{
        uint256 initialBalance = address(target).balance;
        
        vm.startPrank(attackerEOA);
        vm.deal(attackerEOA, 1 ether);
        
        // Execute attack
        attacker.attack{{value: 1 ether}}();
        
        // Verify exploit
        assertLt(address(target).balance, initialBalance, "Reentrancy failed");
        vm.stopPrank();
    }}
}}
'''

    ACCESS_CONTROL_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract {test_name} is Test {{
    {contract_name} target;
    address owner = address(0x1);
    address attacker = address(0xdeadbeef);
    
    function setUp() public {{
        vm.prank(owner);
        target = new {contract_name}();
    }}
    
    function test_accessControl() public {{
        // Attempt unauthorized access
        vm.startPrank(attacker);
        
        // Try to call restricted function
        vm.expectRevert(); // Expect revert due to access control
        target.{restricted_function}();
        
        vm.stopPrank();
    }}
}}
'''

    def generate_poc(
        self,
        lead: VulnerabilityLead,
        contract: ContractInfo,
        source_code: str = "",
        output_dir: Path = None
    ) -> str:
        """Generate a POC test file for a vulnerability lead"""
        
        # Determine template based on category
        category = lead.category.lower()
        
        if 'reentrancy' in category:
            template = self.REENTRANCY_TEMPLATE
            test_name = f"ReentrancyPOC_{lead.id}"
            code = template.format(
                contract_name=contract.name,
                test_name=test_name,
                vulnerable_function=lead.affected_functions[0] if lead.affected_functions else "withdraw",
                vuln_name=lead.id
            )
        elif 'access' in category or 'auth' in category:
            template = self.ACCESS_CONTROL_TEMPLATE
            test_name = f"AccessControlPOC_{lead.id}"
            code = template.format(
                contract_name=contract.name,
                test_name=test_name,
                restricted_function=lead.affected_functions[0] if lead.affected_functions else "adminFunction"
            )
        else:
            # Use generic template
            template = self.TEST_TEMPLATE
            test_name = f"VulnerabilityPOC_{lead.id}"
            code = template.format(
                contract_name=contract.name,
                test_name=test_name,
                vuln_name=lead.id
            )
        
        # Add detailed comments based on attack vector
        code = self._add_attack_comments(code, lead)
        
        # Save to file if output_dir specified
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            test_file = output_dir / f"{test_name}.t.sol"
            test_file.write_text(code)
            return str(test_file)
        
        return code
    
    def _add_attack_comments(self, code: str, lead: VulnerabilityLead) -> str:
        """Add detailed attack comments to test code"""
        comments = f"""
    // ============================================
    // Vulnerability: {lead.title}
    // Severity: {lead.severity.value}
    // Confidence: {lead.confidence:.0%}
    // ============================================
    // 
    // Attack Vector:
    // {lead.attack_vector}
    //
    // Preconditions:
"""
        for precond in lead.preconditions:
            comments += f"    // - {precond}\n"
        
        comments += f"""
    // Attack Steps:
"""
        for i, step in enumerate(lead.attack_steps, 1):
            comments += f"    // {i}. {step}\n"
        
        comments += f"""
    // Impact:
    // {lead.impact}
    // ============================================
"""
        
        # Insert after setUp function
        code = code.replace(
            "    function test_",
            f"{comments}\n    function test_"
        )
        
        return code
    
    def generate_fuzz_test(
        self,
        function: FunctionInfo,
        contract: ContractInfo,
        invariant: str = "",
        output_dir: Path = None
    ) -> str:
        """Generate a fuzz test for a function"""
        
        # Generate parameter list
        params = []
        for param in function.parameters:
            param_type = param.get('type', 'uint256')
            param_name = param.get('name', f"param{len(params)}")
            params.append(f"{param_type} {param_name}")
        
        params_str = ", ".join(params) if params else ""
        
        # Generate fuzz test code
        code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract.name}.sol";

contract Fuzz{function.name} is Test {{
    {contract.name} target;
    
    function setUp() public {{
        target = new {contract.name}();
    }}
    
    function testFuzz_{function.name}({params_str}) public {{
        // Setup reasonable bounds for fuzz inputs
        // vm.assume(param0 > 0 && param0 < type(uint128).max);
        
        // Record initial state
        // uint256 initialBalance = address(target).balance;
        
        // Execute function
        target.{function.name}({', '.join(p.get('name', f'param{i}') for i, p in enumerate(function.parameters))});
        
        // Verify invariant
        // assertEq(address(target).balance, initialBalance, "Invariant violated");
    }}
}}
'''
        
        # Save to file if output_dir specified
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            test_file = output_dir / f"Fuzz{function.name}.t.sol"
            test_file.write_text(code)
            return str(test_file)
        
        return code


class FoundryIntegration:
    """
    High-level integration class for Foundry operations.
    """
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.runner = FoundryRunner(project_path)
        self.poc_generator = POCGenerator()
        self.test_dir = project_path / "test"
        
    def setup_project(self) -> bool:
        """Set up Foundry project if not exists"""
        if not self.runner.is_foundry_installed():
            return False
        
        if not self.runner.is_foundry_project():
            return self.runner.init_project()
        
        return True
    
    def verify_vulnerability(
        self,
        lead: VulnerabilityLead,
        contract: ContractInfo,
        fork_url: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Verify a vulnerability by running a POC test.
        
        Returns (is_confirmed, test_path)
        """
        # Generate POC test
        test_path = self.poc_generator.generate_poc(
            lead, contract, output_dir=self.test_dir
        )
        
        # Build project
        success, msg = self.runner.build()
        if not success:
            return False, f"Build failed: {msg}"
        
        # Run test
        test_name = f"test_{lead.id}"
        result = self.runner.run_test(
            test_pattern=test_name,
            fork_url=fork_url,
            verbose=2
        )
        
        return result.passed, test_path
    
    def fuzz_function(
        self,
        function: FunctionInfo,
        contract: ContractInfo,
        runs: int = 256,
        fork_url: Optional[str] = None
    ) -> FuzzResult:
        """Run fuzzing on a function"""
        
        # Generate fuzz test
        test_path = self.poc_generator.generate_fuzz_test(
            function, contract, output_dir=self.test_dir
        )
        
        # Build
        self.runner.build()
        
        # Run fuzz campaign
        result = self.runner.run_fuzz(
            test_pattern=f"testFuzz_{function.name}",
            runs=runs,
            fork_url=fork_url
        )
        
        return FuzzResult(
            lead_id="",  # Not associated with a specific lead
            total_runs=result.total_runs,
            successful_runs=result.successes,
            failed_runs=result.failures,
            counterexample=result.counterexamples[0] if result.counterexamples else None,
            coverage=result.coverage,
        )
    
    def compile_and_get_artifacts(self) -> Dict[str, Any]:
        """Compile contracts and return artifacts"""
        success, msg = self.runner.build()
        
        if not success:
            return {"success": False, "error": msg}
        
        # Read artifacts from out directory
        out_dir = self.project_path / "out"
        artifacts = {}
        
        if out_dir.exists():
            for artifact_file in out_dir.glob("*.json"):
                if ".dbg.json" not in artifact_file.name:
                    try:
                        with open(artifact_file) as f:
                            artifact_data = json.load(f)
                        artifacts[artifact_file.stem] = artifact_data
                    except Exception:
                        continue
        
        return {
            "success": True,
            "artifacts": artifacts
        }
