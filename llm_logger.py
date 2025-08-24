"""
LLM Logger for tracking actual LLM calls and responses.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMLogger:
    """Logger for LLM interactions."""
    
    def __init__(self, log_file: str = "llm_interactions.log"):
        self.log_file = log_file
        self.session_logs = []
        
    def log_llm_call(self, juror_id: str, prompt: str, response: str, 
                     response_time_ms: int, model: str = "mock") -> None:
        """Log an LLM interaction."""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "juror_id": juror_id,
            "model": model,
            "prompt_length": len(prompt),
            "prompt_preview": prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "response": response,
            "response_time_ms": response_time_ms,
            "is_mock": model == "mock"
        }
        
        self.session_logs.append(log_entry)
        
        # Also log to file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Print to console for immediate visibility
        print(f"🤖 LLM CALL: {juror_id} -> {response[:100]}...")
        
    def get_session_logs(self) -> List[Dict[str, Any]]:
        """Get all logs from current session."""
        return self.session_logs
    
    def clear_session(self) -> None:
        """Clear session logs."""
        self.session_logs = []
    
    def export_session_logs(self) -> str:
        """Export session logs as JSON string."""
        return json.dumps({
            "session_start": datetime.now().isoformat(),
            "total_calls": len(self.session_logs),
            "logs": self.session_logs
        }, indent=2)

# Global logger instance
_global_logger = LLMLogger()

def get_llm_logger() -> LLMLogger:
    """Get the global LLM logger."""
    return _global_logger

def log_llm_interaction(juror_id: str, prompt: str, response: str, 
                       response_time_ms: int, model: str = "mock") -> None:
    """Log an LLM interaction using the global logger."""
    _global_logger.log_llm_call(juror_id, prompt, response, response_time_ms, model)

if __name__ == "__main__":
    # Test the logger
    logger = LLMLogger("test_llm.log")
    logger.log_llm_call(
        "test_juror", 
        "Test prompt for security analysis",
        '{"risk_score": 3, "rationale": "Test response"}',
        1500,
        "gpt-4o-mini"
    )
    print("Logger test complete")
