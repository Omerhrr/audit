#!/bin/bash
# EVM Solidity Auditing Agent - Full Launch Script
# Starts the Python LLM service and the Python GUI

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "EVM Solidity Auditing Agent"
echo "========================================"
echo ""

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "Shutting down services..."
    if [ ! -z "$LLM_PID" ]; then
        kill $LLM_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

# Default port
LLM_PORT=${LLM_PORT:-3030}

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required"
    exit 1
fi

# Kill any existing process on the port
echo "Checking port $LLM_PORT..."
fuser -k $LLM_PORT/tcp 2>/dev/null || true
sleep 1

# Check if dependencies are installed
echo "Checking dependencies..."
python3 -c "import aiohttp, httpx" 2>/dev/null || {
    echo "Installing required dependencies..."
    pip install aiohttp httpx
}

# Start LLM service
echo "Starting LLM service on port $LLM_PORT..."
python3 llm-service/llm_service.py --port $LLM_PORT &
LLM_PID=$!

# Wait for LLM service to start
echo "Waiting for LLM service..."
for i in {1..10}; do
    if curl -s "http://localhost:$LLM_PORT/health" > /dev/null 2>&1; then
        echo "LLM service is ready!"
        break
    fi
    sleep 1
done

# Start Python GUI
echo "Starting Python GUI..."
python3 main.py --llm-port $LLM_PORT "$@"

# Cleanup when done
cleanup
