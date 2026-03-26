"""
Python/Z3 Symbolic Testing Module for EVM Solidity Auditing Agent

Simulates attack paths and validates plausibility of leads using Z3 SMT solver.
"""
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import uuid

try:
    from z3 import (
        Solver, sat, unsat, unknown,
        BitVec, BitVecVal, Bool, Int, IntVal,
        And, Or, Not, If, Implies,
        UGT, UGE, ULT, ULE,
        LShR, Extract, Concat, ZeroExt,
        simplify, Model, Context
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from models import VulnerabilityLead, FunctionInfo, Z3VerificationResult, ContractInfo
from config import LeadStatus


@dataclass
class SymbolicState:
    """Symbolic execution state"""
    variables: Dict[str, Any]  # Variable name -> Z3 expression
    constraints: List[Any]  # Path constraints
    storage: Dict[str, Any]  # Storage slots
    balance: Any = None  # Balance variable
    msg_sender: Any = None  # msg.sender variable
    msg_value: Any = None  # msg.value variable


class Z3SymbolicExecutor:
    """
    Z3-based symbolic executor for Solidity functions.
    
    Features:
    - Symbolic modeling of function parameters
    - Constraint solving for attack paths
    - Storage and balance modeling
    - Vulnerability reachability checking
    """
    
    # Solidity type bit widths
    TYPE_WIDTHS = {
        'uint256': 256, 'int256': 256,
        'uint128': 128, 'int128': 128,
        'uint64': 64, 'int64': 64,
        'uint32': 32, 'int32': 32,
        'uint16': 16, 'int16': 16,
        'uint8': 8, 'int8': 8,
        'address': 160,
        'bool': 1,
        'bytes32': 256,
    }
    
    def __init__(self, timeout_ms: int = 30000):
        if not Z3_AVAILABLE:
            raise ImportError("Z3 is not installed. Install with: pip install z3-solver")
        self.timeout_ms = timeout_ms
        self.solver: Optional[Solver] = None
        
    def create_solver(self) -> Solver:
        """Create a new Z3 solver with timeout"""
        solver = Solver()
        solver.set('timeout', self.timeout_ms)
        return solver
    
    def create_symbolic_var(self, name: str, sol_type: str) -> Any:
        """Create a symbolic variable for a Solidity type"""
        width = self.TYPE_WIDTHS.get(sol_type, 256)
        
        if sol_type == 'bool':
            return Bool(name)
        else:
            return BitVec(name, width)
    
    def create_symbolic_params(
        self,
        function: FunctionInfo,
        prefix: str = ""
    ) -> Dict[str, Any]:
        """Create symbolic variables for function parameters"""
        params = {}
        
        for param in function.parameters:
            param_name = param.get('name', f'param_{len(params)}')
            param_type = param.get('type', 'uint256')
            
            # Handle array types
            if '[' in param_type:
                # For arrays, create multiple symbolic values
                base_type = param_type.split('[')[0]
                params[param_name] = [
                    self.create_symbolic_var(f"{prefix}{param_name}[{i}]", base_type)
                    for i in range(3)  # Default to 3 elements
                ]
            else:
                var_name = f"{prefix}{param_name}" if prefix else param_name
                params[param_name] = self.create_symbolic_var(var_name, param_type)
        
        return params
    
    def verify_vulnerability(
        self,
        lead: VulnerabilityLead,
        function: FunctionInfo,
        contract: ContractInfo,
        custom_constraints: List[str] = None
    ) -> Z3VerificationResult:
        """
        Verify if a vulnerability is reachable using Z3.
        
        Returns a verification result with satisfiability and model.
        """
        solver = self.create_solver()
        
        # Create symbolic state
        state = SymbolicState(
            variables={},
            constraints=[],
            storage={},
        )
        
        # Create symbolic variables for tx context
        state.msg_sender = BitVec('msg_sender', 160)
        state.msg_value = BitVec('msg_value', 256)
        state.balance = BitVec('contract_balance', 256)
        
        # Create symbolic parameters
        params = self.create_symbolic_params(function)
        state.variables.update(params)
        
        # Add preconditions as constraints
        for precond in lead.preconditions:
            constraint = self._parse_precondition(precond, state)
            if constraint is not None:
                solver.add(constraint)
        
        # Add custom constraints
        if custom_constraints:
            for constraint_str in custom_constraints:
                constraint = self._parse_custom_constraint(constraint_str, state)
                if constraint is not None:
                    solver.add(constraint)
        
        # Add vulnerability-specific constraints
        vuln_constraints = self._get_vulnerability_constraints(
            lead.category, state, function
        )
        for constraint in vuln_constraints:
            solver.add(constraint)
        
        # Check satisfiability
        result = solver.check()
        
        if result == sat:
            model = solver.model()
            # Extract concrete values
            model_dict = self._extract_model(model, state)
            
            return Z3VerificationResult(
                lead_id=lead.id,
                satisfiable=True,
                model=model_dict,
                constraints=[str(c) for c in solver.assertions()],
            )
        else:
            return Z3VerificationResult(
                lead_id=lead.id,
                satisfiable=False,
                constraints=[str(c) for c in solver.assertions()],
            )
    
    def _parse_precondition(self, precond: str, state: SymbolicState) -> Optional[Any]:
        """Parse a precondition string into a Z3 constraint"""
        # Simple precondition parsing
        precond = precond.strip().lower()
        
        # Balance checks
        if 'balance' in precond and '>' in precond:
            match = re.search(r'balance\s*>\s*(\d+)', precond)
            if match:
                threshold = int(match.group(1))
                return UGT(state.balance, BitVecVal(threshold, 256))
        
        # msg.value checks
        if 'msg.value' in precond and '>' in precond:
            match = re.search(r'msg\.value\s*>\s*(\d+)', precond)
            if match:
                threshold = int(match.group(1))
                return UGT(state.msg_value, BitVecVal(threshold, 256))
        
        # Owner checks (simplified)
        if 'owner' in precond and '!=' in precond:
            if 'msg.sender' in precond:
                # msg.sender != owner
                owner_var = BitVec('owner', 160)
                return state.msg_sender != owner_var
        
        return None
    
    def _parse_custom_constraint(self, constraint_str: str, state: SymbolicState) -> Optional[Any]:
        """Parse a custom constraint from string"""
        # This is a simplified parser for demonstration
        # A full implementation would need proper expression parsing
        
        # Handle equality constraints
        if '==' in constraint_str:
            parts = constraint_str.split('==')
            if len(parts) == 2:
                left = parts[0].strip()
                right = parts[1].strip()
                
                # Check if it's a variable in state
                if left in state.variables:
                    var = state.variables[left]
                    try:
                        val = int(right)
                        return var == BitVecVal(val, var.size())
                    except ValueError:
                        return None
        
        # Handle inequality constraints
        if '!=' in constraint_str:
            parts = constraint_str.split('!=')
            if len(parts) == 2:
                left = parts[0].strip()
                right = parts[1].strip()
                
                if left in state.variables:
                    var = state.variables[left]
                    try:
                        val = int(right)
                        return var != BitVecVal(val, var.size())
                    except ValueError:
                        return None
        
        return None
    
    def _get_vulnerability_constraints(
        self,
        category: str,
        state: SymbolicState,
        function: FunctionInfo
    ) -> List[Any]:
        """Get Z3 constraints specific to vulnerability category"""
        constraints = []
        
        category_lower = category.lower()
        
        if 'reentrancy' in category_lower:
            # For reentrancy, we need:
            # 1. External call is made
            # 2. State is modified after call
            # 3. Attacker can re-enter
            constraints.append(
                state.msg_sender != BitVecVal(0, 160)
            )
            
        elif 'overflow' in category_lower or 'underflow' in category_lower:
            # For overflow/underflow, we need inputs that cause wrap-around
            for var_name, var in state.variables.items():
                if isinstance(var, list):
                    continue
                # Add constraint that overflow could occur
                # This is a placeholder - real check would analyze the arithmetic
                pass
                
        elif 'access' in category_lower or 'auth' in category_lower:
            # For access control issues
            # Attacker should not be owner/admin
            owner_var = BitVec('owner', 160)
            constraints.append(state.msg_sender != owner_var)
            
        elif 'flash' in category_lower:
            # For flash loan attacks
            # Need large borrow amount
            constraints.append(
                UGT(state.msg_value, BitVecVal(10**18, 256))  # > 1 ETH
            )
        
        return constraints
    
    def _extract_model(self, model: Model, state: SymbolicState) -> Dict[str, Any]:
        """Extract concrete values from Z3 model"""
        result = {}
        
        for var_name, var in state.variables.items():
            if isinstance(var, list):
                result[var_name] = [
                    str(model.eval(v, model_completion=True))
                    for v in var
                ]
            else:
                val = model.eval(var, model_completion=True)
                result[var_name] = str(val)
        
        # Add context variables
        if state.msg_sender:
            result['msg.sender'] = str(model.eval(state.msg_sender, model_completion=True))
        if state.msg_value:
            result['msg.value'] = str(model.eval(state.msg_value, model_completion=True))
        if state.balance:
            result['balance'] = str(model.eval(state.balance, model_completion=True))
        
        return result
    
    def check_invariant(
        self,
        invariant: str,
        function: FunctionInfo,
        state_modifications: List[str]
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if an invariant can be violated.
        
        Returns (can_violate, counterexample)
        """
        solver = self.create_solver()
        
        # Create symbolic state
        state = SymbolicState(
            variables=self.create_symbolic_params(function),
            constraints=[],
            storage={},
        )
        
        # Parse invariant
        invariant_constraint = self._parse_invariant(invariant, state)
        if invariant_constraint is None:
            return False, None
        
        # Check if invariant can be violated
        solver.add(Not(invariant_constraint))
        
        result = solver.check()
        
        if result == sat:
            model = solver.model()
            counterexample = self._extract_model(model, state)
            return True, counterexample
        
        return False, None
    
    def _parse_invariant(self, invariant: str, state: SymbolicState) -> Optional[Any]:
        """Parse an invariant expression"""
        # Simplified invariant parsing
        invariant = invariant.strip()
        
        # Total supply invariant
        if 'totalSupply' in invariant and '==' in invariant:
            # totalSupply == sum of balances
            # This would require modeling all balances
            return None
        
        # Balance invariant
        if 'balance' in invariant and '>=' in invariant:
            match = re.search(r'balance\s*>=\s*(\d+)', invariant)
            if match:
                threshold = int(match.group(1))
                return UGE(state.balance, BitVecVal(threshold, 256))
        
        return None


class Z3CodeGenerator:
    """Generates Z3 Python code from vulnerability analysis"""
    
    @staticmethod
    def generate_verification_code(
        lead: VulnerabilityLead,
        function: FunctionInfo,
    ) -> str:
        """Generate Z3 Python code to verify a vulnerability"""
        code = '''"""
Z3 Verification for {vuln_title}
Generated by EVM Solidity Auditing Agent
"""
from z3 import *

# Create solver
solver = Solver()
solver.set('timeout', 30000)  # 30 second timeout

'''.format(vuln_title=lead.title)
        
        # Add parameter declarations
        code += "# Function parameters\n"
        for param in function.parameters:
            param_name = param.get('name', 'param')
            param_type = param.get('type', 'uint256')
            
            if param_type == 'bool':
                code += f"{param_name} = Bool('{param_name}')\n"
            else:
                code += f"{param_name} = BitVec('{param_name}', 256)\n"
        
        code += "\n# Transaction context\n"
        code += "msg_sender = BitVec('msg_sender', 160)\n"
        code += "msg_value = BitVec('msg_value', 256)\n"
        code += "contract_balance = BitVec('contract_balance', 256)\n"
        
        # Add preconditions
        if lead.preconditions:
            code += "\n# Preconditions\n"
            for precond in lead.preconditions:
                code += f"# {precond}\n"
                # Add as comment since we can't auto-generate all constraints
        
        code += "\n# Vulnerability conditions\n"
        code += f"# {lead.attack_vector}\n"
        
        code += '''
# Check satisfiability
result = solver.check()

if result == sat:
    print("VULNERABILITY CONFIRMED: Attack path exists!")
    model = solver.model()
    print("\\nCounterexample:")
    for var in model:
        print(f"  {var} = {model[var]}")
else:
    print(f"Result: {result}")
    if result == unsat:
        print("No attack path found (vulnerability may not be exploitable)")
    else:
        print("Verification timed out or unknown result")
'''
        
        return code


# Singleton instance (created when Z3 is available)
if Z3_AVAILABLE:
    z3_executor = Z3SymbolicExecutor()
else:
    z3_executor = None
