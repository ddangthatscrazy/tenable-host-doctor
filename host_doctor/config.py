"""Environment configuration for Host Doctor."""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Configuration from environment variables and defaults."""

    # LLM Configuration (for agent)
    SCAN_DOCTOR_MODEL: str = os.getenv(
        "SCAN_DOCTOR_MODEL", "anthropic/claude-sonnet-4-20250514"
    )
    SCAN_DOCTOR_API_BASE: Optional[str] = os.getenv("SCAN_DOCTOR_API_BASE")

    # OpenAI
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")

    # Anthropic
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")

    # Tenable API (for scan creation only)
    TIO_ACCESS_KEY: Optional[str] = os.getenv("TIO_ACCESS_KEY")
    TIO_SECRET_KEY: Optional[str] = os.getenv("TIO_SECRET_KEY")

    # Agent settings
    AGENT_MAX_ITERATIONS: int = int(os.getenv("AGENT_MAX_ITERATIONS", "15"))
    AGENT_VERBOSE: bool = os.getenv("AGENT_VERBOSE", "false").lower() == "true"

    @classmethod
    def has_llm_config(cls) -> bool:
        """Check if LLM configuration is available."""
        if "ollama" in cls.SCAN_DOCTOR_MODEL.lower():
            return True  # Ollama doesn't need API key

        if "openai" in cls.SCAN_DOCTOR_MODEL.lower():
            return cls.OPENAI_API_KEY is not None

        if "anthropic" in cls.SCAN_DOCTOR_MODEL.lower():
            return cls.ANTHROPIC_API_KEY is not None

        # Default to checking for any API key
        return cls.OPENAI_API_KEY is not None or cls.ANTHROPIC_API_KEY is not None

    @classmethod
    def has_tenable_api_config(cls) -> bool:
        """Check if Tenable API configuration is available."""
        return cls.TIO_ACCESS_KEY is not None and cls.TIO_SECRET_KEY is not None


# Singleton instance
config = Config()
