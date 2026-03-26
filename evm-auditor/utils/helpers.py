"""
Utility functions for EVM Solidity Auditing Agent
"""
import os
import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any


def check_command_available(command: str) -> bool:
    """Check if a command is available in PATH"""
    try:
        result = subprocess.run(
            ['which', command],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_solc_version() -> Optional[str]:
    """Get installed solc version"""
    try:
        result = subprocess.run(
            ['solc', '--version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            match = re.search(r'Version:\s*(\S+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def get_foundry_version() -> Optional[str]:
    """Get installed Foundry version"""
    try:
        result = subprocess.run(
            ['forge', '--version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_slither_version() -> Optional[str]:
    """Get installed Slither version"""
    try:
        import slither
        return getattr(slither, '__version__', 'unknown')
    except ImportError:
        return None


def get_z3_version() -> Optional[str]:
    """Get installed Z3 version"""
    try:
        import z3
        return z3.get_version_string()
    except ImportError:
        return None


def find_solidity_files(directory: Path) -> List[Path]:
    """Find all Solidity files in a directory"""
    sol_files = []
    for pattern in ['**/*.sol']:
        for file_path in directory.glob(pattern):
            # Skip common non-source directories
            if any(part in str(file_path) for part in ['node_modules', 'lib', '.git']):
                continue
            sol_files.append(file_path)
    return sorted(sol_files)


def extract_contract_names(source_code: str) -> List[str]:
    """Extract contract names from Solidity source"""
    pattern = r'\b(?:contract|interface|library)\s+(\w+)'
    return re.findall(pattern, source_code)


def extract_imports(source_code: str) -> List[str]:
    """Extract import statements from Solidity source"""
    pattern = r'import\s+(?:"([^"]+)"|\'([^\']+)\')'
    imports = []
    for match in re.finditer(pattern, source_code):
        imports.append(match.group(1) or match.group(2))
    return imports


def calculate_cyclomatic_complexity(source_code: str) -> int:
    """Calculate rough cyclomatic complexity for Solidity code"""
    # Count decision points
    patterns = [
        r'\bif\s*\(',
        r'\belse\s+if\s*\(',
        r'\bfor\s*\(',
        r'\bwhile\s*\(',
        r'\bdo\s*\{',
        r'\bcase\s+',
        r'\?\s*:',  # ternary operator
        r'&&',
        r'\|\|',
    ]
    
    complexity = 1  # Base complexity
    for pattern in patterns:
        complexity += len(re.findall(pattern, source_code))
    
    return complexity


def format_gas(gas: int) -> str:
    """Format gas value for display"""
    if gas >= 1_000_000:
        return f"{gas / 1_000_000:.2f}M"
    elif gas >= 1_000:
        return f"{gas / 1_000:.2f}K"
    else:
        return str(gas)


def format_address(address: str) -> str:
    """Format Ethereum address for display"""
    if not address:
        return ""
    address = address.lower()
    if address.startswith('0x'):
        return f"{address[:6]}...{address[-4:]}"
    return address


def wei_to_eth(wei: int) -> float:
    """Convert Wei to ETH"""
    return wei / 1e18


def eth_to_wei(eth: float) -> int:
    """Convert ETH to Wei"""
    return int(eth * 1e18)


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

