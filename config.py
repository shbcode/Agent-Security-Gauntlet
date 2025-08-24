"""
Configuration module for the Adversarial Review Board (ARB).

Centralizes all ARB settings and environment variable handling.
"""

import os
from typing import Optional


class ARBConfig:
    """Configuration settings for the Adversarial Review Board."""
    
    # LLM Integration Settings - ENABLED BY DEFAULT
    ARB_LLM: bool = os.getenv("ARB_LLM", "on").lower() == "on"  # DEFAULT: ON
    ARB_JURORS: int = int(os.getenv("ARB_JURORS", "3"))  # DEFAULT: 3 jurors
    ARB_VOTE_TIMEOUT_S: float = float(os.getenv("ARB_VOTE_TIMEOUT_S", "2.0"))
    ARB_LLM_MODEL: str = os.getenv("ARB_LLM_MODEL", "gpt-4o-mini")
    
    # Security Thresholds
    STATIC_SCORE_THRESHOLD: int = int(os.getenv("ARB_STATIC_THRESHOLD", "2"))
    LLM_RISK_THRESHOLD: int = int(os.getenv("ARB_LLM_THRESHOLD", "2"))
    
    # Fallback Settings
    MAX_CONSECUTIVE_DENIALS: int = int(os.getenv("ARB_MAX_DENIALS", "2"))
    FALLBACK_FIXTURE: str = os.getenv("ARB_FALLBACK_FIXTURE", "safe_store.html")
    
    # Allowed Tools and Domains
    ALLOWED_DOMAINS: set = {"localhost", "127.0.0.1"}
    ALLOWED_TOOLS: set = {"read_page", "extract_text", "fetch_and_extract"}
    
    @classmethod
    def get_settings(cls) -> dict:
        """Get current ARB settings as a dictionary."""
        return {
            "llm_enabled": cls.ARB_LLM,
            "juror_count": cls.ARB_JURORS,
            "vote_timeout": cls.ARB_VOTE_TIMEOUT_S,
            "llm_model": cls.ARB_LLM_MODEL,
            "static_threshold": cls.STATIC_SCORE_THRESHOLD,
            "llm_threshold": cls.LLM_RISK_THRESHOLD,
            "max_denials": cls.MAX_CONSECUTIVE_DENIALS,
            "fallback_fixture": cls.FALLBACK_FIXTURE
        }
    
    @classmethod
    def is_llm_available(cls) -> bool:
        """Check if LLM functionality is available."""
        if not cls.ARB_LLM:
            return False
        
        # Check for API keys - be more permissive
        api_keys = [
            os.getenv("OPENAI_API_KEY"),
            os.getenv("ANTHROPIC_API_KEY"), 
            os.getenv("AZURE_OPENAI_API_KEY")
        ]
        
        # If ARB_LLM is explicitly set to "on", assume LLM is available
        # This allows for demo mode or when API keys are set elsewhere
        if os.getenv("ARB_LLM", "").lower() == "on":
            return True
            
        return any(key for key in api_keys)
    
    @classmethod
    def get_effective_juror_count(cls) -> int:
        """Get the actual number of jurors that will be used."""
        if not cls.is_llm_available():
            return 0
        return min(cls.ARB_JURORS, 3)  # Cap at 3 jurors


# Global configuration instance
config = ARBConfig()


def get_arb_settings() -> dict:
    """Get current ARB configuration settings."""
    return config.get_settings()


def is_llm_enabled() -> bool:
    """Check if LLM functionality is enabled and available."""
    return config.is_llm_available()


def get_juror_count() -> int:
    """Get the effective number of jurors."""
    return config.get_effective_juror_count()


if __name__ == "__main__":
    # Configuration test
    print("ARB Configuration:")
    print(f"LLM Enabled: {config.ARB_LLM}")
    print(f"LLM Available: {config.is_llm_available()}")
    print(f"Jurors: {config.get_effective_juror_count()}")
    print(f"Settings: {config.get_settings()}")
