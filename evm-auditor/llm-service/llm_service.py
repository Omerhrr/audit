"""
LLM Service for EVM Solidity Auditing Agent

A Python-based LLM API service that provides chat completions
for security analysis. Supports multiple backends.

Usage:
    python llm_service.py --port 3030
    
Environment Variables:
    ZAI_API_KEY      - API key for Z-AI services
    OPENAI_API_KEY   - OpenAI API key
    ANTHROPIC_API_KEY - Anthropic API key
"""
import asyncio
import json
import os
import sys
import logging
from typing import Optional, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from datetime import datetime
import argparse

# HTTP Server
try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# HTTP Client
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ChatMessage:
    """Chat message structure"""
    role: str  # system, user, assistant
    content: str
    
    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatRequest:
    """Incoming chat request"""
    messages: List[ChatMessage]
    model: str = "glm-4-plus"
    temperature: float = 0.1
    max_tokens: int = 8192
    stream: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChatRequest':
        messages = [
            ChatMessage(role=m.get("role", "user"), content=m.get("content", ""))
            for m in data.get("messages", [])
        ]
        return cls(
            messages=messages,
            model=data.get("model", "glm-4-plus"),
            temperature=data.get("temperature", 0.1),
            max_tokens=data.get("max_tokens", 8192),
            stream=data.get("stream", False),
        )


@dataclass
class ChatResponse:
    """Chat completion response"""
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "usage": self.usage,
        }


# =============================================================================
# LLM Provider Interface
# =============================================================================

class LLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    async def complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> ChatResponse:
        """Generate a completion"""
        pass
    
    @abstractmethod
    async def stream_complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncGenerator[str, None]:
        """Stream a completion"""
        pass
    
    @abstractmethod
    def get_available_models(self) -> List[Dict[str, str]]:
        """Get list of available models"""
        pass


# =============================================================================
# Z-AI Provider (using HTTP API)
# =============================================================================

class ZAIProvider(LLMProvider):
    """
    Z-AI provider using HTTP API.
    This connects to the z-ai-web-dev-sdk service or direct API.
    """
    
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://api.z.ai/v1"):
        self.api_key = api_key or os.getenv("ZAI_API_KEY", "")
        self.base_url = base_url
        self.timeout = 120.0
        
    async def complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> ChatResponse:
        """Generate a completion via HTTP API"""
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx is required for ZAIProvider. Install with: pip install httpx")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            try:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return ChatResponse(
                    content=content,
                    model=data.get("model", model),
                    usage=data.get("usage", {}),
                )
            except httpx.HTTPError as e:
                logger.error(f"ZAI API error: {e}")
                raise
    
    async def stream_complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncGenerator[str, None]:
        """Stream completion via HTTP API"""
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx is required")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }
            
            try:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                content = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                                if content:
                                    yield content
                            except json.JSONDecodeError:
                                continue
            except httpx.HTTPError as e:
                logger.error(f"ZAI streaming error: {e}")
                raise
    
    def get_available_models(self) -> List[Dict[str, str]]:
        return [
            {"id": "glm-4-plus", "name": "GLM-4 Plus", "provider": "z-ai"},
            {"id": "glm-4", "name": "GLM-4", "provider": "z-ai"},
            {"id": "glm-4-flash", "name": "GLM-4 Flash", "provider": "z-ai"},
        ]


# =============================================================================
# OpenAI Provider
# =============================================================================

class OpenAIProvider(LLMProvider):
    """OpenAI API provider"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = "https://api.openai.com/v1"
        self.timeout = 120.0
        
    async def complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> ChatResponse:
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx is required")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            
            content = data["choices"][0]["message"]["content"]
            return ChatResponse(
                content=content,
                model=data.get("model", model),
                usage=data.get("usage", {}),
            )
    
    async def stream_complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncGenerator[str, None]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }
            
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            content = data["choices"][0].get("delta", {}).get("content", "")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
    
    def get_available_models(self) -> List[Dict[str, str]]:
        return [
            {"id": "gpt-4o", "name": "GPT-4o", "provider": "openai"},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "provider": "openai"},
            {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "provider": "openai"},
        ]


# =============================================================================
# OpenRouter Provider
# =============================================================================

class OpenRouterProvider(LLMProvider):
    """OpenRouter API provider - aggregates multiple LLM providers"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = "https://openrouter.ai/api/v1"
        self.timeout = 180.0
        
    async def complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> ChatResponse:
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx is required")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://github.com/evm-auditor",
                "X-Title": "EVM Solidity Auditor",
            }
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            try:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return ChatResponse(
                    content=content,
                    model=data.get("model", model),
                    usage=data.get("usage", {}),
                )
            except httpx.HTTPError as e:
                logger.error(f"OpenRouter API error: {e}")
                raise
    
    async def stream_complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncGenerator[str, None]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://github.com/evm-auditor",
                "X-Title": "EVM Solidity Auditor",
            }
            
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }
            
            try:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                content = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                                if content:
                                    yield content
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue
            except httpx.HTTPError as e:
                logger.error(f"OpenRouter streaming error: {e}")
                raise
    
    def get_available_models(self) -> List[Dict[str, str]]:
        return [
            # OpenAI models via OpenRouter
            {"id": "openai/gpt-4o", "name": "GPT-4o (OpenRouter)", "provider": "openrouter"},
            {"id": "openai/gpt-4-turbo", "name": "GPT-4 Turbo (OpenRouter)", "provider": "openrouter"},
            {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini (OpenRouter)", "provider": "openrouter"},
            # Anthropic models via OpenRouter
            {"id": "anthropic/claude-3.5-sonnet", "name": "Claude 3.5 Sonnet (OpenRouter)", "provider": "openrouter"},
            {"id": "anthropic/claude-3-opus", "name": "Claude 3 Opus (OpenRouter)", "provider": "openrouter"},
            # Meta models via OpenRouter
            {"id": "meta-llama/llama-3.1-70b-instruct", "name": "Llama 3.1 70B (OpenRouter)", "provider": "openrouter"},
            {"id": "meta-llama/llama-3.1-405b-instruct", "name": "Llama 3.1 405B (OpenRouter)", "provider": "openrouter"},
            # Google models via OpenRouter
            {"id": "google/gemini-pro-1.5", "name": "Gemini Pro 1.5 (OpenRouter)", "provider": "openrouter"},
            # DeepSeek models
            {"id": "deepseek/deepseek-chat", "name": "DeepSeek Chat (OpenRouter)", "provider": "openrouter"},
            {"id": "deepseek/deepseek-coder", "name": "DeepSeek Coder (OpenRouter)", "provider": "openrouter"},
            # Mistral models
            {"id": "mistralai/mistral-large", "name": "Mistral Large (OpenRouter)", "provider": "openrouter"},
        ]


# =============================================================================
# Mock Provider (for testing)
# =============================================================================

class MockProvider(LLMProvider):
    """Mock provider for testing without API calls"""
    
    async def complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> ChatResponse:
        # Simulate analysis response
        last_message = messages[-1].content if messages else ""
        
        mock_response = '''
Based on the provided Solidity code analysis, I have identified the following potential vulnerabilities:

{
    "vulnerabilities": [
        {
            "title": "Potential Reentrancy Vulnerability",
            "category": "reentrancy",
            "description": "The function makes an external call before updating state, which could allow reentrancy attacks.",
            "severity": "High",
            "confidence": 0.85,
            "affected_functions": ["withdraw"],
            "attack_vector": "An attacker can recursively call the vulnerable function before state updates complete",
            "preconditions": ["Contract must have sufficient balance", "Attacker must have a fallback function"],
            "attack_steps": ["1. Attacker calls withdraw()", "2. Contract sends ETH to attacker", "3. Attacker's fallback re-enters withdraw()", "4. State not yet updated, allowing double withdrawal"],
            "impact": "Potential theft of all contract funds"
        }
    ]
}
'''
        
        await asyncio.sleep(0.5)  # Simulate API latency
        
        return ChatResponse(
            content=mock_response,
            model=model,
            usage={"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
        )
    
    async def stream_complete(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncGenerator[str, None]:
        response = await self.complete(messages, model, temperature, max_tokens)
        # Stream word by word
        words = response.content.split()
        for word in words:
            yield word + " "
            await asyncio.sleep(0.02)
    
    def get_available_models(self) -> List[Dict[str, str]]:
        return [
            {"id": "mock-model", "name": "Mock Model (Testing)", "provider": "mock"},
        ]


# =============================================================================
# LLM Service
# =============================================================================

class LLMService:
    """
    Main LLM service that routes requests to appropriate providers.
    """
    
    # System prompt for security auditing
    AUDITOR_SYSTEM_PROMPT = """You are an expert Solidity security auditor with deep EVM knowledge and an attacker mindset. 
Your role is to identify vulnerabilities, suggest attack vectors, and help verify potential exploits.

You have extensive experience with:
- Reentrancy attacks, flash loan exploits, price manipulation
- Access control vulnerabilities, privilege escalation
- Integer overflow/underflow, precision loss
- Front-running, MEV vulnerabilities
- Logic errors, state inconsistencies
- Proxy vulnerabilities, upgrade patterns
- Oracle manipulation, cross-chain issues
- Gas griefing, DoS vectors

Always think like an attacker: "How can I exploit this? What conditions need to be met?"
Be thorough but avoid false positives. Provide concrete attack scenarios.

When analyzing code, output findings in JSON format when appropriate:
{
    "vulnerabilities": [
        {
            "title": "...",
            "category": "...",
            "description": "...",
            "severity": "Critical|High|Medium|Low|Informational",
            "confidence": 0.0-1.0,
            "affected_functions": ["..."],
            "attack_vector": "...",
            "preconditions": ["..."],
            "attack_steps": ["..."],
            "impact": "..."
        }
    ]
}
"""
    
    def __init__(self, provider: Optional[LLMProvider] = None):
        self.provider = provider or self._get_default_provider()
        self.conversation_histories: Dict[str, List[ChatMessage]] = {}
    
    def _get_default_provider(self) -> LLMProvider:
        """Get the default provider based on available API keys"""
        if os.getenv("OPENROUTER_API_KEY"):
            logger.info("Using OpenRouter provider")
            return OpenRouterProvider()
        elif os.getenv("OPENAI_API_KEY"):
            logger.info("Using OpenAI provider")
            return OpenAIProvider()
        elif os.getenv("ZAI_API_KEY"):
            logger.info("Using Z-AI provider")
            return ZAIProvider()
        else:
            logger.warning("No API key found, using mock provider for testing")
            return MockProvider()
    
    def _ensure_system_prompt(self, messages: List[ChatMessage]) -> List[ChatMessage]:
        """Ensure system prompt is present"""
        has_system = any(m.role == "system" for m in messages)
        if has_system:
            return messages
        return [ChatMessage(role="system", content=self.AUDITOR_SYSTEM_PROMPT)] + messages
    
    async def complete(self, request: ChatRequest) -> ChatResponse:
        """Process a chat completion request"""
        messages = self._ensure_system_prompt(request.messages)
        
        logger.info(f"Processing chat request: model={request.model}, messages={len(messages)}")
        
        response = await self.provider.complete(
            messages=messages,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        
        logger.info(f"Response generated: {len(response.content)} chars")
        return response
    
    async def stream_complete(self, request: ChatRequest) -> AsyncGenerator[str, None]:
        """Process a streaming chat completion request"""
        messages = self._ensure_system_prompt(request.messages)
        
        logger.info(f"Processing streaming request: model={request.model}")
        
        async for chunk in self.provider.stream_complete(
            messages=messages,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        ):
            yield chunk
    
    def get_available_models(self) -> List[Dict[str, str]]:
        """Get list of available models"""
        return self.provider.get_available_models()


# =============================================================================
# HTTP Server
# =============================================================================

def create_app(service: LLMService) -> 'web.Application':
    """Create the aiohttp application"""
    if not AIOHTTP_AVAILABLE:
        raise RuntimeError("aiohttp is required. Install with: pip install aiohttp")
    
    app = web.Application()
    
    # CORS middleware
    @web.middleware
    async def cors_middleware(request: web.Request, handler):
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            try:
                response = await handler(request)
            except web.HTTPException as ex:
                response = web.Response(
                    status=ex.status,
                    text=ex.text,
                )
            except Exception as e:
                logger.exception("Request handler error")
                response = web.json_response(
                    {"error": str(e)},
                    status=500,
                )
        
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response
    
    app.middlewares.append(cors_middleware)
    
    # Routes
    async def handle_health(request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "ok",
            "service": "evm-auditor-llm-service",
            "timestamp": datetime.now().isoformat(),
        })
    
    async def handle_models(request: web.Request) -> web.Response:
        """Get available models"""
        models = service.get_available_models()
        return web.json_response({"models": models})
    
    async def handle_chat(request: web.Request) -> web.Response:
        """Handle chat completion"""
        try:
            data = await request.json()
            chat_request = ChatRequest.from_dict(data)
            
            if chat_request.stream:
                # Streaming response
                response = web.StreamResponse(
                    status=200,
                    headers={
                        "Content-Type": "text/event-stream",
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                    }
                )
                await response.prepare(request)
                
                async for chunk in service.stream_complete(chat_request):
                    data_str = json.dumps({"content": chunk})
                    await response.write(f"data: {data_str}\n\n".encode())
                
                await response.write(b"data: [DONE]\n\n")
                return response
            else:
                # Non-streaming response
                response = await service.complete(chat_request)
                return web.json_response(response.to_dict())
                
        except Exception as e:
            logger.exception("Chat handler error")
            return web.json_response({"error": str(e)}, status=500)
    
    app.router.add_get("/", handle_health)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/api/models", handle_models)
    app.router.add_post("/api/chat", handle_chat)
    
    return app


def run_server(port: int = 3030, provider: str = "auto"):
    """Run the LLM service HTTP server"""
    if not AIOHTTP_AVAILABLE:
        print("Error: aiohttp is required. Install with: pip install aiohttp")
        sys.exit(1)
    
    # Check if port is already in use
    import socket
    original_port = port
    max_attempts = 5
    
    for attempt in range(max_attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result != 0:  # Port is available
            break
        else:
            if attempt == 0:
                print(f"[WARNING] Port {port} is already in use")
            port += 1
            if attempt == max_attempts - 1:
                print(f"[ERROR] Could not find available port after {max_attempts} attempts")
                print(f"[INFO] Kill existing process with: fuser -k {original_port}/tcp")
                sys.exit(1)
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║         EVM Auditor - LLM Service (Python)                ║
║                                                           ║
║  Security-focused LLM API for Solidity auditing          ║
║  Port: {port}                                               ║
╚═══════════════════════════════════════════════════════════╝
""")
    
    if port != original_port:
        print(f"[INFO] Using alternative port {port} (original {original_port} was in use)")
    
    # Create provider based on argument
    if provider == "mock":
        llm_provider = MockProvider()
    elif provider == "openai":
        llm_provider = OpenAIProvider()
    elif provider == "openrouter":
        llm_provider = OpenRouterProvider()
    elif provider == "zai":
        llm_provider = ZAIProvider()
    else:
        llm_provider = None  # Auto-detect
    
    service = LLMService(provider=llm_provider)
    app = create_app(service)
    
    print(f"[LLM Service] Server running on http://localhost:{port}")
    print(f"[LLM Service] Endpoints:")
    print(f"  POST /api/chat    - Chat completion")
    print(f"  GET  /api/models  - List available models")
    print(f"  GET  /health      - Health check")
    print("")
    
    web.run_app(app, host="0.0.0.0", port=port, print=None)


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="EVM Auditor LLM Service - Python-based LLM API for security analysis"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=3030,
        help="Port to run the service on (default: 3030)"
    )
    parser.add_argument(
        "--provider",
        choices=["auto", "mock", "openai", "openrouter", "zai"],
        default="auto",
        help="LLM provider to use (default: auto-detect). Options: auto, mock, openai, openrouter, zai"
    )
    
    args = parser.parse_args()
    run_server(port=args.port, provider=args.provider)
