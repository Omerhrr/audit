"""
Code Parsing & Call Graph Module for EVM Solidity Auditing Agent

Parses Solidity code and libraries, generates call graphs and workflow mapping.
Handles proxy + implementation contracts (fork mode).
"""
import re
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field

from models import (
    ContractInfo, FunctionInfo, CallGraph, CallEdge, SourceLocation
)
from config import CACHE_DIR


@dataclass
class ParseResult:
    """Result of parsing a contract file"""
    success: bool
    contracts: List[ContractInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    file_path: str = ""


class SolidityParser:
    """
    Parser for Solidity source files.
    
    Features:
    - Parse individual files and entire directories
    - Extract contract structures, functions, events, etc.
    - Build call graphs from function interactions
    - Handle proxy contracts and inheritance
    """
    
    # Regex patterns for Solidity parsing
    CONTRACT_PATTERN = re.compile(
        r'(contract|interface|library|abstract\s+contract)\s+(\w+)'
        r'(?:\s+is\s+([\w,\s]+))?'  # inheritance
        r'\s*\{',
        re.MULTILINE
    )
    
    FUNCTION_PATTERN = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)'
        r'(?:\s+(public|private|internal|external))?'
        r'(?:\s+(view|pure|payable|nonpayable))?'
        r'(?:\s+returns\s*\(([^)]*)\))?'
        r'(?:\s+(?:virtual|override))?',
        re.MULTILINE
    )
    
    MODIFIER_PATTERN = re.compile(
        r'modifier\s+(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )
    
    EVENT_PATTERN = re.compile(
        r'event\s+(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )
    
    ERROR_PATTERN = re.compile(
        r'error\s+(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )
    
    STATE_VAR_PATTERN = re.compile(
        r'(public|private|internal)\s+(?:immutable\s+)?'
        r'(?:mapping\([^)]+\)\s*=>\s*)?'
        r'(\w+(?:\[\d*\])*)\s+(\w+)',
        re.MULTILINE
    )
    
    IMPORT_PATTERN = re.compile(
        r'import\s+(?:"([^"]+)"|\'([^\']+)\')',
        re.MULTILINE
    )
    
    INTERNAL_CALL_PATTERN = re.compile(
        r'(?:self\.)?(\w+)\s*\(',
        re.MULTILINE
    )
    
    EXTERNAL_CALL_PATTERN = re.compile(
        r'(?:([\w.]+)\.(\w+)\s*\(|'
        r'(\w+)\s*\(\s*\{)',
        re.MULTILINE
    )
    
    def __init__(self, solc_path: Optional[str] = None):
        self.solc_path = solc_path or self._find_solc()
        self._cache: Dict[str, ParseResult] = {}
        
    def _find_solc(self) -> Optional[str]:
        """Find solc executable"""
        try:
            result = subprocess.run(['which', 'solc'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def parse_file(self, file_path: Path, use_solc: bool = False) -> ParseResult:
        """Parse a single Solidity file"""
        if str(file_path) in self._cache:
            return self._cache[str(file_path)]
        
        if not file_path.exists():
            return ParseResult(
                success=False,
                errors=[f"File not found: {file_path}"],
                file_path=str(file_path)
            )
        
        try:
            source_code = file_path.read_text(encoding='utf-8')
        except Exception as e:
            return ParseResult(
                success=False,
                errors=[f"Error reading file: {e}"],
                file_path=str(file_path)
            )
        
        # Try solc-based parsing first if available
        if use_solc and self.solc_path:
            result = self._parse_with_solc(file_path, source_code)
            if result.success:
                self._cache[str(file_path)] = result
                return result
        
        # Fallback to regex-based parsing
        result = self._parse_with_regex(file_path, source_code)
        self._cache[str(file_path)] = result
        return result
    
    def parse_directory(self, directory: Path, 
                        use_solc: bool = False) -> List[ParseResult]:
        """Parse all Solidity files in a directory"""
        results = []
        
        # Find all Solidity files
        sol_files = list(directory.rglob("*.sol"))
        
        for sol_file in sol_files:
            # Skip common non-source directories
            if any(part in str(sol_file) for part in ['node_modules', 'lib', 'test', 'mock']):
                continue
            result = self.parse_file(sol_file, use_solc)
            results.append(result)
        
        return results
    
    def _parse_with_solc(self, file_path: Path, source_code: str) -> ParseResult:
        """Parse using solc compiler for accurate AST"""
        try:
            # Create combined JSON input
            input_json = {
                "language": "Solidity",
                "sources": {
                    str(file_path): {
                        "content": source_code
                    }
                },
                "settings": {
                    "outputSelection": {
                        "*": {
                            "*": ["ast"]
                        }
                    }
                }
            }
            
            result = subprocess.run(
                [self.solc_path, '--standard-json'],
                input=json.dumps(input_json),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return ParseResult(
                    success=False,
                    errors=[f"Solc error: {result.stderr}"],
                    file_path=str(file_path)
                )
            
            output = json.loads(result.stdout)
            contracts = self._extract_from_ast(output, str(file_path), source_code)
            
            return ParseResult(
                success=True,
                contracts=contracts,
                imports=self._extract_imports(source_code),
                file_path=str(file_path)
            )
            
        except subprocess.TimeoutExpired:
            return ParseResult(
                success=False,
                errors=["Solc timeout"],
                file_path=str(file_path)
            )
        except Exception as e:
            return ParseResult(
                success=False,
                errors=[f"Solc parsing error: {e}"],
                file_path=str(file_path)
            )
    
    def _extract_from_ast(self, output: Dict, file_path: str, 
                          source_code: str) -> List[ContractInfo]:
        """Extract contract info from solc AST output"""
        contracts = []
        
        for source_name, source_data in output.get('sources', {}).items():
            ast = source_data.get('ast', {})
            for node in ast.get('nodes', []):
                if node.get('nodeType') in ('ContractDefinition',):
                    contract = self._parse_contract_node(node, file_path, source_code)
                    contracts.append(contract)
        
        return contracts
    
    def _parse_contract_node(self, node: Dict, file_path: str, 
                             source_code: str) -> ContractInfo:
        """Parse a contract definition node from AST"""
        name = node.get('name', 'Unknown')
        kind = node.get('contractKind', 'contract')
        
        # Get inheritance
        inherits = []
        for base in node.get('baseContracts', []):
            base_name = base.get('baseName', {}).get('name', '')
            if base_name:
                inherits.append(base_name)
        
        contract = ContractInfo(
            name=name,
            file_path=file_path,
            kind=kind,
            inherits=inherits,
        )
        
        # Parse contract body
        for child in node.get('nodes', []):
            node_type = child.get('nodeType')
            
            if node_type == 'FunctionDefinition':
                func = self._parse_function_node(child, source_code)
                if func.name:  # Skip constructor/fallback/receive
                    func.contract = name
                    contract.functions.append(func)
                    
            elif node_type == 'VariableDeclaration':
                if child.get('stateVariable', False):
                    contract.variables.append({
                        'name': child.get('name', ''),
                        'type': child.get('typeName', {}).get('name', 'unknown'),
                        'visibility': child.get('visibility', 'internal'),
                        'constant': child.get('constant', False),
                        'mutable': not child.get('constant', False),
                    })
                    
            elif node_type == 'EventDefinition':
                contract.events.append({
                    'name': child.get('name', ''),
                    'parameters': self._parse_parameters(child.get('parameters', {})),
                })
                
            elif node_type == 'ModifierDefinition':
                contract.modifiers.append({
                    'name': child.get('name', ''),
                    'parameters': self._parse_parameters(child.get('parameters', {})),
                })
                
            elif node_type == 'ErrorDefinition':
                contract.errors.append({
                    'name': child.get('name', ''),
                    'parameters': self._parse_parameters(child.get('parameters', {})),
                })
        
        # Check for proxy patterns
        contract.is_proxy = self._detect_proxy_pattern(contract, source_code)
        
        return contract
    
    def _parse_function_node(self, node: Dict, source_code: str) -> FunctionInfo:
        """Parse a function definition node"""
        name = node.get('name', '')
        visibility = node.get('visibility', 'public')
        
        # Determine mutability
        mutability = 'nonpayable'
        if node.get('stateMutability'):
            mutability = node.get('stateMutability')
        elif node.get('pure'):
            mutability = 'pure'
        elif node.get('view'):
            mutability = 'view'
        elif node.get('payable'):
            mutability = 'payable'
        
        # Get parameters
        parameters = self._parse_parameters(node.get('parameters', {}))
        
        # Get return parameters
        returns = self._parse_parameters(node.get('returnParameters', {}))
        
        # Get modifiers
        modifiers = [
            m.get('modifierName', {}).get('name', '')
            for m in node.get('modifiers', [])
        ]
        
        # Check virtual/override
        is_virtual = node.get('virtual', False)
        is_override = len(node.get('overrides', [])) > 0
        implemented = node.get('implemented', True)
        
        # Get location
        src = node.get('src', '0:0:0').split(':')
        start_line = self._get_line_number(source_code, int(src[0])) if src else 0
        
        return FunctionInfo(
            name=name,
            contract="",  # Set by caller
            visibility=visibility,
            mutability=mutability,
            parameters=parameters,
            returns=returns,
            modifiers=modifiers,
            location=SourceLocation(
                file_path="",  # Set by caller
                start_line=start_line,
                end_line=start_line + 1,
            ),
            is_virtual=is_virtual,
            is_override=is_override,
            implemented=implemented,
        )
    
    def _parse_parameters(self, params_node: Dict) -> List[Dict[str, str]]:
        """Parse function parameters"""
        params = []
        for param in params_node.get('parameters', []):
            if param.get('nodeType') == 'VariableDeclaration':
                param_type = 'unknown'
                type_name = param.get('typeName', {})
                if type_name.get('nodeType') == 'ElementaryTypeName':
                    param_type = type_name.get('name', 'unknown')
                elif type_name.get('nodeType') == 'UserDefinedTypeName':
                    param_type = type_name.get('namePath', 'unknown')
                elif type_name.get('nodeType') == 'ArrayTypeName':
                    base_type = type_name.get('baseType', {}).get('name', 'unknown')
                    param_type = f"{base_type}[]"
                
                params.append({
                    'name': param.get('name', ''),
                    'type': param_type,
                })
        return params
    
    def _get_line_number(self, source_code: str, char_offset: int) -> int:
        """Get line number from character offset"""
        return source_code[:char_offset].count('\n') + 1
    
    def _parse_with_regex(self, file_path: Path, source_code: str) -> ParseResult:
        """Parse using regex patterns (fallback)"""
        contracts = []
        imports = self._extract_imports(source_code)
        
        # Find all contracts
        for match in self.CONTRACT_PATTERN.finditer(source_code):
            kind_str, name, inherits_str = match.groups()
            kind = kind_str.replace('abstract ', '').strip()
            
            inherits = []
            if inherits_str:
                inherits = [i.strip() for i in inherits_str.split(',')]
            
            # Find contract body
            start_pos = match.end()
            body = self._extract_brace_block(source_code, start_pos - 1)
            
            contract = ContractInfo(
                name=name,
                file_path=str(file_path),
                kind=kind,
                inherits=inherits,
                imports=imports,
            )
            
            # Parse functions
            for func_match in self.FUNCTION_PATTERN.finditer(body):
                func = self._parse_function_regex(func_match, name, str(file_path))
                contract.functions.append(func)
            
            # Parse events
            for event_match in self.EVENT_PATTERN.finditer(body):
                contract.events.append({
                    'name': event_match.group(1),
                    'parameters': self._parse_param_string(event_match.group(2)),
                })
            
            # Parse errors
            for error_match in self.ERROR_PATTERN.finditer(body):
                contract.errors.append({
                    'name': error_match.group(1),
                    'parameters': self._parse_param_string(error_match.group(2)),
                })
            
            # Check for proxy pattern
            contract.is_proxy = self._detect_proxy_pattern(contract, body)
            
            contracts.append(contract)
        
        return ParseResult(
            success=True,
            contracts=contracts,
            imports=imports,
            file_path=str(file_path)
        )
    
    def _parse_function_regex(self, match, contract_name: str, 
                              file_path: str) -> FunctionInfo:
        """Parse function from regex match"""
        name = match.group(1)
        params_str = match.group(2) or ""
        visibility = match.group(3) or "public"
        mutability = match.group(4) or "nonpayable"
        returns_str = match.group(5) or ""
        
        return FunctionInfo(
            name=name,
            contract=contract_name,
            visibility=visibility,
            mutability=mutability,
            parameters=self._parse_param_string(params_str),
            returns=self._parse_param_string(returns_str),
        )
    
    def _parse_param_string(self, params_str: str) -> List[Dict[str, str]]:
        """Parse parameter string into list"""
        params = []
        if not params_str.strip():
            return params
        
        for param in params_str.split(','):
            param = param.strip()
            if not param:
                continue
            
            parts = param.split()
            if len(parts) >= 2:
                params.append({
                    'type': parts[0],
                    'name': parts[-1],
                })
            elif len(parts) == 1:
                params.append({
                    'type': parts[0],
                    'name': '',
                })
        
        return params
    
    def _extract_imports(self, source_code: str) -> List[str]:
        """Extract import statements"""
        imports = []
        for match in self.IMPORT_PATTERN.finditer(source_code):
            import_path = match.group(1) or match.group(2)
            if import_path:
                imports.append(import_path)
        return imports
    
    def _extract_brace_block(self, source: str, start: int) -> str:
        """Extract content between matching braces"""
        if start >= len(source) or source[start] != '{':
            return ""
        
        depth = 1
        pos = start + 1
        
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        
        return source[start + 1:pos - 1]
    
    def _detect_proxy_pattern(self, contract: ContractInfo, 
                              source_code: str) -> bool:
        """Detect if contract is a proxy"""
        proxy_indicators = [
            'delegatecall',
            'implementation',
            '_implementation',
            'upgradeTo',
            'proxy',
            'fallback',
            'Proxy',
            'EIP1967',
            'ERC1967',
        ]
        
        source_lower = source_code.lower()
        for indicator in proxy_indicators:
            if indicator.lower() in source_lower:
                return True
        
        return False
    
    def build_call_graph(self, contracts: List[ContractInfo],
                         source_files: Dict[str, str] = None) -> CallGraph:
        """Build call graph from contracts"""
        call_graph = CallGraph()
        
        # Build function index
        function_index = {}
        for contract in contracts:
            for func in contract.functions:
                key = f"{contract.name}.{func.name}"
                function_index[key] = func
                if func.visibility in ('public', 'external'):
                    call_graph.entry_points.add(key)
        
        # Analyze each function for calls
        if source_files:
            for contract in contracts:
                source_code = source_files.get(contract.file_path, "")
                if not source_code:
                    continue
                
                for func in contract.functions:
                    caller_key = f"{contract.name}.{func.name}"
                    call_graph.nodes.add(caller_key)
                    
                    # Extract function body and find calls
                    calls = self._extract_function_calls(
                        source_code, contract.name, func.name
                    )
                    
                    for call_type, callee in calls:
                        edge = CallEdge(
                            caller=caller_key,
                            callee=callee,
                            call_type=call_type,
                        )
                        call_graph.add_edge(edge)
        
        return call_graph
    
    def _extract_function_calls(self, source_code: str, 
                                contract_name: str,
                                function_name: str) -> List[Tuple[str, str]]:
        """Extract function calls from source"""
        calls = []
        
        # Find function body
        func_pattern = re.compile(
            rf'function\s+{re.escape(function_name)}\s*\([^)]*\)'
            r'[^{{]*\{{',
            re.MULTILINE
        )
        
        match = func_pattern.search(source_code)
        if not match:
            return calls
        
        body_start = match.end()
        body = self._extract_brace_block(source_code, body_start - 1)
        
        # Find internal calls
        for call_match in self.INTERNAL_CALL_PATTERN.finditer(body):
            callee_name = call_match.group(1)
            if callee_name not in ('require', 'assert', 'revert', 'emit', 'return', 'if', 'for', 'while'):
                calls.append(('internal', f"{contract_name}.{callee_name}"))
        
        # Find external calls
        for ext_match in re.finditer(r'(\w+)\.(\w+)\s*\(', body):
            target = ext_match.group(1)
            method = ext_match.group(2)
            if target not in ('address', 'this', 'block', 'msg', 'tx'):
                calls.append(('external', f"{target}.{method}"))
        
        # Find delegatecalls
        if 'delegatecall' in body:
            calls.append(('delegatecall', 'unknown.delegatecall'))
        
        return calls


class ProxyResolver:
    """Resolves proxy contracts and their implementations"""
    
    def __init__(self, web3_provider: Optional[str] = None):
        self.web3_provider = web3_provider
        
    def resolve_implementation(self, proxy_address: str, 
                               proxy_contract: ContractInfo) -> Optional[str]:
        """Resolve the implementation address for a proxy"""
        # Common proxy storage slots
        implementation_slots = [
            '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',  # EIP-1967
            '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3',  # OpenZeppelin
            '0x',  # Beacon proxy
        ]
        
        # TODO: Implement actual resolution via web3
        # For now, return None
        return None
    
    def get_implementation_slot(self, proxy_contract: ContractInfo) -> Optional[str]:
        """Determine the implementation storage slot"""
        # Analyze contract for known patterns
        return None


# Singleton parser instance
solidity_parser = SolidityParser()
