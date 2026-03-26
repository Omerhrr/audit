#!/bin/bash
# EVM Solidity Auditing Agent - Run Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}EVM Solidity Auditing Agent${NC}"
echo -e "${GREEN}========================================${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

# Check if in venv or suggest creating one
if [[ -z "${VIRTUAL_ENV}" ]]; then
    echo -e "${YELLOW}Note: Not running in virtual environment${NC}"
    echo -e "${YELLOW}Consider running: python3 -m venv venv && source venv/bin/activate${NC}"
fi

# Install dependencies if needed
if [[ ! -d "venv" ]] && [[ "$1" == "--install" ]]; then
    echo -e "${GREEN}Installing dependencies...${NC}"
    pip install -r requirements.txt
fi

# Check for Foundry
if command -v forge &> /dev/null; then
    echo -e "${GREEN}Foundry: Installed${NC}"
else
    echo -e "${YELLOW}Foundry: Not found (optional)${NC}"
fi

# Check for Slither
if python3 -c "import slither" 2>/dev/null; then
    echo -e "${GREEN}Slither: Installed${NC}"
else
    echo -e "${YELLOW}Slither: Not found (optional)${NC}"
fi

# Check for Z3
if python3 -c "import z3" 2>/dev/null; then
    echo -e "${GREEN}Z3: Installed${NC}"
else
    echo -e "${YELLOW}Z3: Not found (optional)${NC}"
fi

echo ""
echo -e "${GREEN}Starting application...${NC}"

# Run the application
cd "$(dirname "$0")"
python3 main.py "$@"
