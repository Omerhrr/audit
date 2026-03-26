"""
Model Brain / LLM Reasoning Module for EVM Solidity Auditing Agent

Core reasoning engine that generates, ranks, and triages leads.
Guides Python/Z3, Foundry, fuzzing, and reporting.

This module connects to the Python LLM service for AI-powered analysis.
"""
import json
import httpx
from typing import Optional, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime
import uuid
import os

from models import (
    ContractInfo, CallGraph, VulnerabilityLead, FunctionInfo
)
from config import ModelProvider, Severity, LeadStatus


@dataclass
class ChatMessage:
    """Chat message for LLM interaction"""
    role: str  # system, user, assistant
    content: str
    
    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


class LLMClient:
    """
    Client for LLM API interactions.
    Connects to the Python LLM service.
    """
    
    def __init__(self, api_base_url: str = "http://localhost:3030"):
        self.api_base_url = api_base_url
        self.timeout = 180.0  # 3 minutes for long analysis
        
    async def chat_completion(
        self,
        messages: List[ChatMessage],
        model: str = "glm-4-plus",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        stream: bool = False
    ) -> str:
        """Send chat completion request to LLM service"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload = {
                "messages": [m.to_dict() for m in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": stream,
            }
            
            try:
                response = await client.post(
                    f"{self.api_base_url}/api/chat",
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                return data.get("content", "")
            except httpx.HTTPError as e:
                raise Exception(f"LLM API error: {e}")
    
    async def stream_completion(
        self,
        messages: List[ChatMessage],
        model: str = "glm-4-plus",
        temperature: float = 0.1,
        max_tokens: int = 8192
    ) -> AsyncGenerator[str, None]:
        """Stream chat completion response"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
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
                    f"{self.api_base_url}/api/chat",
                    json=payload
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                content = data.get("content", "")
                                if content:
                                    yield content
                            except json.JSONDecodeError:
                                continue
            except httpx.HTTPError as e:
                raise Exception(f"LLM streaming error: {e}")
    
    async def get_available_models(self) -> List[Dict[str, str]]:
        """Get list of available models"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(f"{self.api_base_url}/api/models")
                response.raise_for_status()
                data = response.json()
                return data.get("models", [])
            except httpx.HTTPError:
                return []
    
    async def health_check(self) -> bool:
        """Check if LLM service is healthy"""
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                response = await client.get(f"{self.api_base_url}/health")
                return response.status_code == 200
            except httpx.HTTPError:
                return False


class ModelBrain:
    """
    Core reasoning engine for vulnerability detection and analysis.
    
    Features:
    - Attacker mindset reasoning
    - Lead generation and ranking
    - Test template generation
    - Report drafting
    - Continuous audit guidance
    """
    
    # System prompts for different analysis modes
    ANALYSIS_PROMPT = """You are an expert Solidity security auditor with deep EVM knowledge and an attacker mindset. 
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

When analyzing code, provide your findings in structured JSON format when appropriate."""

    LEAD_GENERATION_PROMPT = """Based on the provided Solidity code, identify potential vulnerabilities.

For each potential vulnerability, provide:
1. VULNERABILITY TYPE: The category of the issue
2. LOCATION: Contract and function affected  
3. DESCRIPTION: What the issue is
4. ATTACK VECTOR: How an attacker could exploit it
5. PRECONDITIONS: What conditions must be met
6. IMPACT: Potential consequences
7. CONFIDENCE: Your confidence level (high/medium/low)
8. SEVERITY: Critical/High/Medium/Low/Informational

Format your response as structured JSON when possible."""

    RANKING_PROMPT = """Rank the following vulnerability leads by:
1. Likelihood of exploitation
2. Potential impact
3. Ease of exploitation
4. Detection confidence

Provide a numerical score (1-10) for each and an overall priority ranking."""

    POC_GENERATION_PROMPT = """Generate a Foundry test case to verify the following vulnerability.
Include:
1. Setup: Deploy contracts and configure state
2. Attack: Execute the exploit
3. Assertion: Verify the vulnerability was exploited
4. Comments: Explain each step

Use Solidity syntax compatible with Foundry."""
    
    def __init__(self, llm_client: LLMClient, model: str = "glm-4-plus"):
        self.llm = llm_client
        self.model = model
        self.conversation_history: List[ChatMessage] = []
        self._initialized = False
        
    async def initialize(self) -> bool:
        """Initialize and check connection to LLM service"""
        if self._initialized:
            return True
            
        is_healthy = await self.llm.health_check()
        if not is_healthy:
            raise ConnectionError(
                f"Cannot connect to LLM service at {self.llm.api_base_url}. "
                "Please start the service with: python llm-service/llm_service.py"
            )
        
        self._initialized = True
        return True
        
    def reset_conversation(self):
        """Reset conversation history"""
        self.conversation_history = []
    
    async def analyze_contract(
        self,
        contract: ContractInfo,
        source_code: str,
        context: str = ""
    ) -> List[VulnerabilityLead]:
        """
        Analyze a contract for potential vulnerabilities.
        
        Returns a list of vulnerability leads.
        """
        # Build contract info string
        contract_info = f"""
Contract: {contract.name}
Type: {contract.kind}
Inherits: {', '.join(contract.inherits) or 'None'}

Functions ({len(contract.functions)}):
{self._format_functions(contract.functions)}

State Variables ({len(contract.variables)}):
{self._format_variables(contract.variables)}

Events ({len(contract.events)}):
{self._format_events(contract.events)}
"""
        
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Analyze the following Solidity contract for security vulnerabilities:

{contract_info}

Source Code:
```solidity
{source_code}
```

{context}

Focus on:
1. Access control issues
2. State manipulation vectors
3. External call vulnerabilities
4. Logic errors
5. Edge cases
6. Reentrancy possibilities
7. Integer overflow/underflow
8. Front-running opportunities

Provide your analysis in the following JSON format:
{{
    "vulnerabilities": [
        {{
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
        }}
    ]
}}

If no vulnerabilities are found, return {{"vulnerabilities": []}}
""")
        ]
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
        except Exception as e:
            print(f"LLM analysis error: {e}")
            return []
        
        # Parse response and create leads
        leads = self._parse_vulnerability_response(response, contract)
        return leads
    
    def _format_functions(self, functions: List[FunctionInfo]) -> str:
        """Format functions for prompt"""
        if not functions:
            return "  None"
        lines = []
        for f in functions[:20]:  # Limit to avoid token limits
            params = ", ".join(f"{p.get('type', 'unknown')} {p.get('name', '')}".strip() for p in f.parameters)
            lines.append(f"  - {f.name}({params}) [{f.visibility}] [{f.mutability}]")
        if len(functions) > 20:
            lines.append(f"  ... and {len(functions) - 20} more")
        return "\n".join(lines)
    
    def _format_variables(self, variables: List[Dict]) -> str:
        """Format variables for prompt"""
        if not variables:
            return "  None"
        lines = []
        for v in variables[:15]:
            lines.append(f"  - {v.get('type', 'unknown')} {v.get('name', '')} [{v.get('visibility', 'internal')}]")
        if len(variables) > 15:
            lines.append(f"  ... and {len(variables) - 15} more")
        return "\n".join(lines)
    
    def _format_events(self, events: List[Dict]) -> str:
        """Format events for prompt"""
        if not events:
            return "  None"
        return "\n".join(f"  - {e.get('name', 'unknown')}" for e in events[:10])
    
    def _parse_vulnerability_response(
        self,
        response: str,
        contract: ContractInfo
    ) -> List[VulnerabilityLead]:
        """Parse LLM response into vulnerability leads"""
        leads = []
        
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
            else:
                # No JSON found
                data = {"vulnerabilities": []}
            
            for vuln in data.get('vulnerabilities', []):
                lead = VulnerabilityLead(
                    id=str(uuid.uuid4())[:8],
                    title=vuln.get('title', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    severity=self._parse_severity(vuln.get('severity', 'Medium')),
                    status=LeadStatus.NEW,
                    confidence=float(vuln.get('confidence', 0.5)),
                    affected_contracts=[contract.name],
                    affected_functions=vuln.get('affected_functions', []),
                    detection_method='llm',
                    category=vuln.get('category', ''),
                    attack_vector=vuln.get('attack_vector', ''),
                    preconditions=vuln.get('preconditions', []),
                    attack_steps=vuln.get('attack_steps', []),
                    impact=vuln.get('impact', ''),
                    tags=['llm-analysis'],
                )
                leads.append(lead)
                
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            # Try to extract information from plain text
            if 'vulnerability' in response.lower() or 'issue' in response.lower():
                lead = VulnerabilityLead(
                    id=str(uuid.uuid4())[:8],
                    title="Potential Issue (Manual Review Required)",
                    description=response[:500],
                    severity=Severity.INFORMATIONAL,
                    status=LeadStatus.NEW,
                    confidence=0.3,
                    affected_contracts=[contract.name],
                    detection_method='llm',
                    category='needs-review',
                )
                leads.append(lead)
        except Exception as e:
            print(f"Error parsing vulnerability response: {e}")
        
        return leads
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to enum"""
        if isinstance(severity_str, Severity):
            return severity_str
            
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'informational': Severity.INFORMATIONAL,
            'info': Severity.INFORMATIONAL,
            'gas': Severity.GAS,
            'gas optimization': Severity.GAS,
        }
        return severity_map.get(str(severity_str).lower(), Severity.MEDIUM)
    
    async def rank_leads(
        self,
        leads: List[VulnerabilityLead],
        context: str = ""
    ) -> List[VulnerabilityLead]:
        """
        Rank vulnerability leads by priority.
        Updates confidence scores based on LLM assessment.
        """
        if not leads:
            return leads
        
        # Build summary for ranking
        leads_summary = []
        for i, lead in enumerate(leads):
            leads_summary.append({
                "index": i,
                "title": lead.title,
                "category": lead.category,
                "severity": lead.severity.value,
                "affected_functions": lead.affected_functions,
                "attack_vector": lead.attack_vector[:200] if lead.attack_vector else "",
                "current_confidence": lead.confidence,
            })
        
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Rank the following vulnerability leads by exploitability and impact:

{json.dumps(leads_summary, indent=2)}

{context}

For each lead, provide:
1. Priority score (1-10, where 10 is most critical)
2. Brief reasoning for the score
3. Recommended next steps

Return as JSON array:
[
    {{
        "index": 0,
        "priority_score": 8,
        "reasoning": "...",
        "next_steps": "..."
    }}
]

Only output the JSON array, no additional text.
""")
        ]
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
            
            # Parse rankings
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start >= 0 and json_end > json_start:
                rankings = json.loads(response[json_start:json_end])
                
                for ranking in rankings:
                    idx = ranking.get('index')
                    if isinstance(idx, int) and 0 <= idx < len(leads):
                        # Update confidence based on priority
                        priority = ranking.get('priority_score', 5)
                        leads[idx].confidence = min(1.0, priority / 10.0)
                        leads[idx].notes.append(f"LLM Ranking: {ranking.get('reasoning', '')}")
                        leads[idx].status = LeadStatus.RANKED
                        
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            print(f"Error parsing rankings: {e}")
        
        # Sort by confidence
        leads.sort(key=lambda x: x.confidence, reverse=True)
        return leads
    
    async def generate_foundry_poc(
        self,
        lead: VulnerabilityLead,
        contract: ContractInfo,
        source_code: str
    ) -> str:
        """
        Generate a Foundry test case for a vulnerability lead.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Generate a Foundry test case to verify this vulnerability:

**Vulnerability:** {lead.title}
**Category:** {lead.category}
**Severity:** {lead.severity.value}
**Description:** {lead.description}
**Attack Vector:** {lead.attack_vector}
**Preconditions:** {json.dumps(lead.preconditions)}
**Attack Steps:** {json.dumps(lead.attack_steps)}

**Contract:** {contract.name}

```solidity
{source_code[:5000]}  // Truncated if too long
```

Generate a complete Foundry test file that:
1. Sets up the necessary contracts and state
2. Executes the attack
3. Asserts that the vulnerability was exploited

Requirements:
- Use pragma solidity ^0.8.0;
- Import from "forge-std/Test.sol";
- Include detailed comments explaining each step
- The test should be named test_{lead.category.replace('-', '_')}_{lead.id}

Output ONLY the Solidity test code, wrapped in ```solidity ... ``` markers.
""")
        ]
        
        try:
            response = await self.llm.chat_completion(
                messages, 
                model=self.model,
                max_tokens=4096
            )
            
            # Extract code block if present
            if '```solidity' in response:
                start = response.find('```solidity') + 11
                end = response.find('```', start)
                if end > start:
                    return response[start:end].strip()
            elif '```' in response:
                start = response.find('```') + 3
                end = response.find('```', start)
                if end > start:
                    code = response[start:end].strip()
                    if 'function test' in code or 'contract' in code:
                        return code
            
            return response
            
        except Exception as e:
            print(f"Error generating POC: {e}")
            return f"// POC generation failed: {e}"
    
    async def generate_z3_constraints(
        self,
        lead: VulnerabilityLead,
        function: FunctionInfo,
        source_code: str
    ) -> str:
        """
        Generate Z3 Python constraints for symbolic verification.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Generate Z3 Python code to verify if this vulnerability is reachable:

**Vulnerability:** {lead.title}
**Function:** {function.name}
**Signature:** {function.signature()}
**Attack Vector:** {lead.attack_vector}
**Preconditions:** {json.dumps(lead.preconditions)}

Generate Z3 Python code that:
1. Models the function parameters as symbolic variables
2. Encodes the preconditions as constraints
3. Checks if the attack state is reachable
4. Returns a counterexample if the vulnerability exists

Use the z3 library. Output only the Python code wrapped in ```python ... ``` markers.
""")
        ]
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
            
            # Extract code block if present
            if '```python' in response:
                start = response.find('```python') + 9
                end = response.find('```', start)
                if end > start:
                    return response[start:end].strip()
            elif '```' in response:
                start = response.find('```') + 3
                end = response.find('```', start)
                if end > start:
                    return response[start:end].strip()
            
            return response
            
        except Exception as e:
            print(f"Error generating Z3 constraints: {e}")
            return f"# Z3 constraint generation failed: {e}"
    
    async def suggest_fuzz_inputs(
        self,
        function: FunctionInfo,
        vulnerability_hints: List[str]
    ) -> Dict[str, Any]:
        """
        Suggest fuzz input strategies for a function.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Suggest fuzz testing strategies for this function:

**Function:** {function.name}
**Signature:** {function.signature()}
**Visibility:** {function.visibility}
**Mutability:** {function.mutability}
**Parameters:** {json.dumps(function.parameters)}

**Potential Vulnerability Hints:** {json.dumps(vulnerability_hints)}

Provide fuzz strategies as JSON:
{{
    "edge_cases": ["list of input combinations to test"],
    "boundary_values": ["list of boundary conditions"],
    "invariant_checks": ["state invariants to verify after execution"],
    "ghost_variables": ["additional variables to track during fuzzing"],
    "suggested_runs": 1000,
    "vm_assume_conditions": ["conditions to add via vm.assume()"]
}}

Output only the JSON object.
""")
        ]
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
            
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
                
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing fuzz suggestions: {e}")
        
        return {
            "edge_cases": [],
            "boundary_values": [],
            "invariant_checks": [],
            "suggested_runs": 256,
            "ghost_variables": [],
            "vm_assume_conditions": []
        }
    
    async def draft_report(
        self,
        lead: VulnerabilityLead,
        poc_code: str = ""
    ) -> Dict[str, str]:
        """
        Draft a vulnerability report.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Draft a professional security vulnerability report:

**Title:** {lead.title}
**Category:** {lead.category}
**Severity:** {lead.severity.value}
**Confidence:** {lead.confidence:.0%}

**Description:** {lead.description}

**Attack Vector:** {lead.attack_vector}
**Preconditions:** {json.dumps(lead.preconditions)}
**Attack Steps:** {json.dumps(lead.attack_steps)}
**Impact:** {lead.impact}

**Affected Contracts:** {json.dumps(lead.affected_contracts)}
**Affected Functions:** {json.dumps(lead.affected_functions)}

**POC Code:**
```
{poc_code[:2000] if poc_code else 'No POC available'}
```

Generate a report in this JSON format:
{{
    "title": "Clear vulnerability title",
    "description": "Detailed technical description",
    "impact": "What could happen if exploited",
    "likelihood": "How likely exploitation is (High/Medium/Low)",
    "recommendation": "How to fix the vulnerability",
    "mitigation": "Specific code changes needed",
    "references": ["Related CVEs or standards"]
}}

Output only the JSON object.
""")
        ]
        
        try:
            response = await self.llm.chat_completion(
                messages, 
                model=self.model,
                max_tokens=4096
            )
            
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
                
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing report draft: {e}")
        
        return {
            "title": lead.title,
            "description": lead.description,
            "impact": lead.impact,
            "likelihood": "Medium",
            "recommendation": "Review the identified vulnerability and implement appropriate fixes",
            "mitigation": "To be determined after further analysis",
            "references": []
        }
    
    async def identify_unexplored_paths(
        self,
        contracts: List[ContractInfo],
        call_graph: CallGraph,
        analyzed_functions: List[str]
    ) -> List[str]:
        """
        Identify unexplored code paths for continuous auditing.
        """
        all_functions = set()
        for contract in contracts:
            for func in contract.functions:
                key = f"{contract.name}.{func.name}"
                all_functions.add(key)
        
        # Add call graph nodes
        if call_graph:
            all_functions.update(call_graph.nodes)
        
        # Find unexplored
        analyzed_set = set(analyzed_functions)
        unexplored = all_functions - analyzed_set
        
        # Prioritize by entry points and call depth
        entry_unexplored = []
        other_unexplored = []
        
        if call_graph:
            entry_unexplored = [f for f in unexplored if f in call_graph.entry_points]
            other_unexplored = [f for f in unexplored if f not in call_graph.entry_points]
        else:
            other_unexplored = list(unexplored)
        
        return entry_unexplored + other_unexplored
    
    async def ask_question(
        self,
        question: str,
        context: str = ""
    ) -> str:
        """
        Ask a general question about the codebase or vulnerabilities.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
        ]
        
        # Add conversation history
        for msg in self.conversation_history[-10:]:  # Keep last 10 messages
            messages.append(msg)
        
        # Add context and question
        if context:
            messages.append(ChatMessage(
                role="user", 
                content=f"Context:\n{context}\n\nQuestion: {question}"
            ))
        else:
            messages.append(ChatMessage(role="user", content=question))
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
            
            # Update conversation history
            self.conversation_history.append(ChatMessage(role="user", content=question))
            self.conversation_history.append(ChatMessage(role="assistant", content=response))
            
            return response
            
        except Exception as e:
            return f"Error getting response: {e}"
    
    async def analyze_function(
        self,
        contract: ContractInfo,
        function: FunctionInfo,
        source_code: str
    ) -> List[VulnerabilityLead]:
        """
        Analyze a specific function for vulnerabilities.
        """
        messages = [
            ChatMessage(role="system", content=self.ANALYSIS_PROMPT),
            ChatMessage(role="user", content=f"""
Analyze this specific function for security vulnerabilities:

**Contract:** {contract.name}
**Function:** {function.name}
**Signature:** {function.signature()}
**Visibility:** {function.visibility}
**Mutability:** {function.mutability}
**Modifiers:** {json.dumps(function.modifiers)}

```solidity
{source_code}
```

Focus on:
1. Access control issues in this function
2. State manipulation possibilities
3. Reentrancy if external calls are made
4. Integer overflow/underflow
5. Logic errors specific to this function

Provide findings in JSON format:
{{
    "vulnerabilities": [
        {{
            "title": "...",
            "category": "...",
            "description": "...",
            "severity": "High|Medium|Low|Informational",
            "confidence": 0.0-1.0,
            "affected_functions": ["{function.name}"],
            "attack_vector": "...",
            "preconditions": ["..."],
            "attack_steps": ["..."],
            "impact": "..."
        }}
    ]
}}
""")
        ]
        
        try:
            response = await self.llm.chat_completion(messages, model=self.model)
            return self._parse_vulnerability_response(response, contract)
        except Exception as e:
            print(f"Error analyzing function: {e}")
            return []


# Factory function for creating ModelBrain with default settings
def create_model_brain(
    api_base_url: str = "http://localhost:3030",
    model: str = "glm-4-plus"
) -> ModelBrain:
    """Create a ModelBrain instance with default settings"""
    client = LLMClient(api_base_url=api_base_url)
    return ModelBrain(llm_client=client, model=model)
