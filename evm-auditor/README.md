# EVM Solidity Auditing Agent

A **Python-based** desktop security auditing tool with deep Solidity/EVM reasoning, attacker mindset, Z3 verification, Slither static analysis, Foundry POCs/fuzzing, and automated reporting.

## Features

### 🔍 **Multi-Source Input**
- Local directory of contracts (`contracts/` or `src/`)
- GitHub repository URL
- Deployed proxy + implementation addresses
- Etherscan API integration
- Alchemy API integration

### 🧠 **AI-Powered Analysis**
- **Model Brain / LLM Reasoning**: Core reasoning engine with attacker mindset
- Generates, ranks, and triages vulnerability leads
- Creates Foundry POC test cases
- Suggests Z3 constraints for symbolic verification
- Drafts professional bug reports

### 📊 **Analysis Modules**
- **Code Parsing & Call Graph**: Parses Solidity code, generates call graphs
- **Slither Static Analysis**: Detects common vulnerabilities
- **Z3 Symbolic Testing**: Validates attack paths symbolically
- **Foundry POC & Fuzzing**: Definitive bug verification

### 📝 **Output & Reports**
- Verified bug reports (Markdown / PDF / JSON)
- Foundry POCs for each confirmed bug
- Session memory with leads, tests, fuzz results

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Desktop UI (PySide6)                     │
│  • Drag & drop projects • Session management • Terminal     │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Session Management                         │
│  • Persistent storage • Lead tracking • Progress tracking   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                 Code Parsing & Call Graph                    │
│  • Solidity parsing • Call graphs • Proxy detection         │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Model Brain / LLM                          │
│  • Lead generation • Ranking • POC creation • Reports       │
└──────┬─────────────────────────────────────────┬────────────┘
       │                                         │
┌──────▼──────┐  ┌───────────────┐  ┌───────────▼───────────┐
│   Slither   │  │  Z3 Symbolic  │  │    Foundry POC &      │
│   Static    │  │    Testing    │  │       Fuzzing         │
│  Analysis   │  │               │  │                       │
└──────┬──────┘  └───────┬───────┘  └───────────┬───────────┘
       │                 │                      │
       └─────────────────┼──────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                      Reporting                               │
│  • Markdown • PDF • JSON reports with POCs and mitigations  │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- **Python 3.11+** (required)
- **Foundry** (optional, for POC testing)
- **Slither** (optional, for static analysis)
- **Z3 Solver** (optional, for symbolic verification)

### Install Dependencies

```bash
# Clone the repository
cd evm-auditor

# Install Python dependencies
pip install -r requirements.txt

# Install Foundry (optional)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Slither (optional)
pip install slither-analyzer

# Install Z3 (optional)
pip install z3-solver
```

### Verify Installation

```bash
# Check dependencies
python main.py --check-deps
```

## Usage

### Quick Start

```bash
# Start everything (LLM service + GUI)
./start.sh

# Or start manually:

# Terminal 1: Start LLM service
python llm-service/llm_service.py --port 3030

# Terminal 2: Start GUI
python main.py
```

### Command Line Options

```bash
# Show help
python main.py --help

# Check dependencies
python main.py --check-deps

# Run in headless mode
python main.py --headless --project ./my-contracts

# Run with specific options
python main.py \
    --headless \
    --project ./my-contracts \
    --output ./reports \
    --model glm-4-plus \
    --llm-port 3030 \
    --max-iterations 20
```

### CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--project, -p` | Path to Solidity project | - |
| `--output, -o` | Output directory for reports | `./reports` |
| `--model, -m` | LLM model to use | `glm-4-plus` |
| `--llm-port` | Port for LLM API service | `3030` |
| `--no-slither` | Disable Slither analysis | - |
| `--no-z3` | Disable Z3 verification | - |
| `--no-foundry` | Disable Foundry POCs | - |
| `--headless` | Run without GUI | - |
| `--max-iterations` | Max audit iterations | `10` |

## LLM Service

The LLM service is a Python HTTP server that provides AI-powered analysis:

```bash
# Start LLM service
python llm-service/llm_service.py --port 3030

# With specific provider
python llm-service/llm_service.py --port 3030 --provider openai
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/models` | GET | List available models |
| `/api/chat` | POST | Chat completion |

### Provider Configuration

Set environment variables for API keys:

```bash
# For OpenAI
export OPENAI_API_KEY="sk-..."

# For Z-AI
export ZAI_API_KEY="..."
```

If no API key is set, the service uses a mock provider for testing.

## Project Structure

```
evm-auditor/
├── main.py                    # Main entry point
├── config.py                  # Configuration
├── models.py                  # Data models
├── requirements.txt           # Dependencies
│
├── modules/
│   ├── ui/                    # PySide6 GUI
│   │   └── main_window.py
│   ├── session/               # Session management
│   │   └── manager.py
│   ├── parser/                # Solidity parsing
│   │   └── code_parser.py
│   ├── model/                 # LLM reasoning
│   │   └── llm_service.py
│   ├── slither/               # Static analysis
│   │   └── analyzer.py
│   ├── z3_solver/             # Symbolic execution
│   │   └── symbolic.py
│   ├── foundry/               # POC & fuzzing
│   │   └── test_runner.py
│   ├── reporting/             # Report generation
│   │   └── generator.py
│   └── audit/                 # Continuous auditing
│       └── continuous.py
│
└── llm-service/               # LLM API service
    └── llm_service.py
```

## Module Details

### 1. UI Module (`modules/ui/`)
PySide6-based desktop interface with:
- Contract tree view
- Vulnerability leads table
- Source code viewer
- Terminal output
- AI chat interface

### 2. Session Management (`modules/session/`)
Persistent JSON storage for:
- Session state
- Contracts and call graphs
- Vulnerability leads
- Test results
- Reports

### 3. Code Parsing (`modules/parser/`)
- Regex-based Solidity parsing
- Solc AST parsing (when available)
- Call graph generation
- Proxy contract detection

### 4. Model Brain (`modules/model/`)
LLM-powered analysis:
- Vulnerability detection
- Lead ranking
- POC generation
- Report drafting

### 5. Slither Integration (`modules/slither/`)
- Static vulnerability detection
- Pattern-based analysis
- Detector configuration

### 6. Z3 Symbolic Testing (`modules/z3_solver/`)
- Attack path verification
- Counterexample generation
- Invariant checking

### 7. Foundry Integration (`modules/foundry/`)
- POC test generation
- Fuzzing campaigns
- Fork mode testing

### 8. Reporting (`modules/reporting/`)
- Markdown reports
- PDF generation
- JSON export

### 9. Continuous Auditing (`modules/audit/`)
- Iterative analysis
- Unexplored path detection
- Progress tracking

## Configuration

Edit `config.py` to customize:

```python
# Model settings
model_name = "glm-4-plus"

# Slither settings
slither_enabled = True

# Foundry settings
foundry_fuzz_runs = 256

# Z3 settings
z3_timeout_ms = 30000
```

## Security Focus

The agent specializes in:
- ✅ Reentrancy attacks
- ✅ Access control vulnerabilities
- ✅ Flash loan exploits
- ✅ Price manipulation
- ✅ Integer overflow/underflow
- ✅ Front-running / MEV
- ✅ Proxy vulnerabilities
- ✅ Logic errors
- ✅ Oracle manipulation

## Example Output

### Console Output
```
[1/7] Creating session for: ./my-contracts
[2/7] Parsing contracts...
       Found: Token (contract)
       Found: Vault (contract)
       Total contracts: 2
[3/7] Connecting to LLM service...
[4/7] Running Slither analysis...
       Token: 2 leads
       Vault: 5 leads
[5/7] Running LLM analysis...
       Token: 3 leads
       Vault: 4 leads
[6/7] Verifying leads with Z3...
       Reentrancy in withdraw: SATISFIABLE
[7/7] Generating reports...
       Report saved: ./reports/audit_report.md

Analysis Complete
Total Contracts: 2
Total Leads: 14
High Confidence: 5
  Critical: 1
  High: 2
  Medium: 2
```

### Sample Report
```markdown
# Reentrancy Vulnerability in Vault.withdraw()

| Field | Value |
|-------|-------|
| Severity | Critical |
| Confidence | 85% |
| Status | Confirmed |

## Description
The withdraw function makes an external call before updating state...

## Attack Vector
An attacker can recursively call withdraw before state updates...

## POC Code
```solidity
function test_reentrancy() public {
    // Attack implementation
}
```

## Mitigation
Implement the checks-effects-interactions pattern...
```

## Troubleshooting

### LLM Service Won't Start
```bash
# Check if port is in use
lsof -i :3030

# Try different port
python llm-service/llm_service.py --port 3031
```

### No Contracts Found
- Ensure `.sol` files are in `contracts/` or `src/` directory
- Check file permissions
- Verify Solidity syntax

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## License

MIT License

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
