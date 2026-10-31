"""
LLM API key patterns for all major providers.
Each pattern includes the regex, provider name, and severity.
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class SecretPattern:
    name: str
    provider: str
    regex: str
    severity: str  # HIGH, MEDIUM
    description: str


PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="openai_api_key",
        provider="OpenAI",
        regex=r"sk-[a-zA-Z0-9]{48}",
        severity="HIGH",
        description="OpenAI API key",
    ),
    SecretPattern(
        name="openai_project_key",
        provider="OpenAI",
        regex=r"sk-proj-[a-zA-Z0-9\-_]{48,}",
        severity="HIGH",
        description="OpenAI project API key",
    ),
    SecretPattern(
        name="anthropic_api_key",
        provider="Anthropic",
        regex=r"sk-ant-api\d{2}-[a-zA-Z0-9\-_]{93}AA",
        severity="HIGH",
        description="Anthropic/Claude API key",
    ),
    SecretPattern(
        name="azure_openai_key",
        provider="Azure OpenAI",
        regex=r"[a-f0-9]{32}",
        severity="MEDIUM",
        description="Azure OpenAI API key (32-char hex — verify context)",
    ),
    SecretPattern(
        name="azure_openai_endpoint_key",
        provider="Azure OpenAI",
        regex=r"(?i)(azure[_\-]?openai[_\-]?key|AZURE_OPENAI_API_KEY)\s*[=:]\s*['\"]?([a-zA-Z0-9+/=]{32,})['\"]?",
        severity="HIGH",
        description="Azure OpenAI key in env var assignment",
    ),
    SecretPattern(
        name="huggingface_token",
        provider="Hugging Face",
        regex=r"hf_[a-zA-Z0-9]{34,}",
        severity="HIGH",
        description="Hugging Face API token",
    ),
    SecretPattern(
        name="cohere_api_key",
        provider="Cohere",
        regex=r"[a-zA-Z0-9]{40}",
        severity="MEDIUM",
        description="Cohere API key (40-char — verify context)",
    ),
    SecretPattern(
        name="google_ai_key",
        provider="Google AI / Gemini",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="HIGH",
        description="Google AI / Gemini API key",
    ),
    SecretPattern(
        name="mistral_api_key",
        provider="Mistral AI",
        regex=r"(?i)(mistral[_\-]?api[_\-]?key|MISTRAL_API_KEY)\s*[=:]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
        severity="HIGH",
        description="Mistral AI API key in env var assignment",
    ),
    SecretPattern(
        name="generic_llm_key_assignment",
        provider="Generic",
        regex=r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*['\"]([a-zA-Z0-9+/=\-_]{20,})['\"]",
        severity="MEDIUM",
        description="Generic API key or token assignment",
    ),
]


# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".yaml", ".yml", ".json",
    ".sh", ".bash", ".zsh",
    ".tf", ".tfvars",
    ".rb", ".go", ".java", ".cs",
    ".php", ".rs", ".swift",
    ".toml", ".ini", ".cfg", ".conf",
    ".ipynb",
}

# Paths to always ignore
IGNORE_PATHS = {
    ".git", "node_modules", "__pycache__", ".venv",
    "venv", "env", ".env.example", "dist", "build",
    ".mypy_cache", ".pytest_cache", "*.min.js",
}
