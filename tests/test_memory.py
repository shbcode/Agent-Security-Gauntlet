"""
Tests for the risk ledger memory system.
"""

import pytest
from datetime import datetime, timedelta
from memory import RiskLedger, get_risk_ledger, reset_risk_ledger
from arb_models import RiskLedgerEntry, ArbDecision, ArbSignals


class TestRiskLedger:
    """Test risk ledger functionality."""
    
    def setup_method(self):
        """Reset risk ledger before each test."""
        reset_risk_ledger()
    
    def test_add_entry(self):
        """Test adding entries to the risk ledger."""
        ledger = RiskLedger()
        
        entry_data = {
            "decision_id": "test_001",
            "url": "http://localhost/test.html",
            "fixture": "test.html",
            "approved": False,
            "risk_score": 4,
            "defenses_triggered": ["Static Analysis", "Context Minimization"]
        }
        
        ledger.add(entry_data)
        
        assert len(ledger.entries) == 1
        entry = ledger.entries[0]
        assert entry.decision_id == "test_001"
        assert entry.approved == False
        assert entry.risk_score == 4
        assert len(entry.defenses_triggered) == 2
    
    def test_add_from_arb_decision(self):
        """Test adding entries from ARB decisions."""
        ledger = RiskLedger()
        
        # Create mock ARB decision
        signals = ArbSignals(
            allowlist_ok=True,
            static_score=3,
            static_patterns=["ignore.*instructions"],
            conformance_ok=False,
            conformance_reasons=["Tool not allowed"]
        )
        
        decision = ArbDecision(
            approved=False,
            defenses_used=["Static Analysis", "Plan Conformance"],
            reasons=["Suspicious patterns detected"],
            sanitized_text="Safe content only",
            signals=signals,
            decision_id="arb_test_001"
        )
        
        ledger.add_from_decision(decision, "http://localhost/trap.html", "trap_hidden_text.html")
        
        assert len(ledger.entries) == 1
        entry = ledger.entries[0]
        assert entry.decision_id == "arb_test_001"
        assert entry.fixture == "trap_hidden_text.html"
        assert entry.risk_score == 3
        assert not entry.approved
    
    def test_last_n_entries(self):
        """Test retrieving last N entries."""
        ledger = RiskLedger()
        
        # Add multiple entries
        for i in range(5):
            entry_data = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/test{i}.html",
                "fixture": f"test{i}.html",
                "approved": i % 2 == 0,  # Alternate approved/denied
                "risk_score": i,
                "defenses_triggered": ["Test Defense"]
            }
            ledger.add(entry_data)
        
        # Test last_n
        last_3 = ledger.last_n(3)
        assert len(last_3) == 3
        assert last_3[0].decision_id == "test_002"  # Third entry (0-indexed)
        assert last_3[-1].decision_id == "test_004"  # Last entry
        
        # Test edge cases
        assert len(ledger.last_n(0)) == 0
        assert len(ledger.last_n(10)) == 5  # Only 5 entries exist
    
    def test_consecutive_denials_detection(self):
        """Test detection of consecutive denials."""
        ledger = RiskLedger()
        
        # Add entries with pattern: approve, deny, deny
        entries = [
            {"approved": True, "risk_score": 0},
            {"approved": False, "risk_score": 4},
            {"approved": False, "risk_score": 3}
        ]
        
        for i, entry_data in enumerate(entries):
            full_entry = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/test{i}.html",
                "fixture": f"test{i}.html",
                "defenses_triggered": ["Test Defense"],
                **entry_data
            }
            ledger.add(full_entry)
        
        # Should detect two denials in a row
        assert ledger.two_denials_in_a_row()
        assert ledger.consecutive_denials(2)
        assert not ledger.consecutive_denials(3)
        
        # Test denial streak
        assert ledger.get_denial_streak() == 2
    
    def test_no_consecutive_denials(self):
        """Test when there are no consecutive denials."""
        ledger = RiskLedger()
        
        # Add alternating pattern: deny, approve, deny, approve
        entries = [
            {"approved": False, "risk_score": 3},
            {"approved": True, "risk_score": 0},
            {"approved": False, "risk_score": 2},
            {"approved": True, "risk_score": 1}
        ]
        
        for i, entry_data in enumerate(entries):
            full_entry = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/test{i}.html",
                "fixture": f"test{i}.html",
                "defenses_triggered": ["Test Defense"],
                **entry_data
            }
            ledger.add(full_entry)
        
        # Should not detect consecutive denials
        assert not ledger.two_denials_in_a_row()
        assert not ledger.consecutive_denials(2)
        assert ledger.get_denial_streak() == 0  # Last entry was approved
    
    def test_should_trigger_fallback(self):
        """Test fallback triggering logic."""
        ledger = RiskLedger()
        
        # Add one denial - should not trigger fallback
        ledger.add({
            "decision_id": "test_001",
            "url": "http://localhost/test1.html",
            "fixture": "test1.html",
            "approved": False,
            "risk_score": 4,
            "defenses_triggered": ["Static Analysis"]
        })
        
        assert not ledger.should_trigger_fallback(max_denials=2)
        
        # Add second denial - should trigger fallback
        ledger.add({
            "decision_id": "test_002",
            "url": "http://localhost/test2.html",
            "fixture": "test2.html",
            "approved": False,
            "risk_score": 3,
            "defenses_triggered": ["Static Analysis"]
        })
        
        assert ledger.should_trigger_fallback(max_denials=2)
    
    def test_risk_trend_analysis(self):
        """Test risk trend analysis."""
        ledger = RiskLedger()
        
        # Add entries with increasing risk scores
        risk_scores = [1, 2, 3, 4, 5]
        for i, score in enumerate(risk_scores):
            entry_data = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/test{i}.html",
                "fixture": f"test{i}.html",
                "approved": score <= 2,  # Approve low risk, deny high risk
                "risk_score": score,
                "defenses_triggered": ["Static Analysis"] if score > 2 else []
            }
            ledger.add(entry_data)
        
        trend = ledger.get_risk_trend(window_size=5)
        
        assert trend["sample_size"] == 5
        assert trend["average_risk"] == 3.0  # (1+2+3+4+5)/5
        assert trend["denial_rate"] == 0.6   # 3 denials out of 5
        assert trend["trend"] in ["increasing", "stable"]  # Should detect increasing trend
        assert trend["current_streak"] == 3  # Last 3 were denials
    
    def test_fixture_statistics(self):
        """Test fixture-based statistics."""
        ledger = RiskLedger()
        
        # Add entries for different fixtures
        fixtures_data = [
            ("safe_store.html", True, 0),
            ("safe_store.html", True, 0),
            ("trap_hidden_text.html", False, 4),
            ("trap_hidden_text.html", False, 3),
            ("trap_html_comment.html", False, 5)
        ]
        
        for i, (fixture, approved, score) in enumerate(fixtures_data):
            entry_data = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/{fixture}",
                "fixture": fixture,
                "approved": approved,
                "risk_score": score,
                "defenses_triggered": ["Static Analysis"] if not approved else []
            }
            ledger.add(entry_data)
        
        fixture_stats = ledger.get_fixture_stats()
        
        # Check safe_store.html stats
        safe_stats = fixture_stats["safe_store.html"]
        assert safe_stats["total_attempts"] == 2
        assert safe_stats["approvals"] == 2
        assert safe_stats["denials"] == 0
        assert safe_stats["denial_rate"] == 0.0
        
        # Check trap_hidden_text.html stats
        trap_stats = fixture_stats["trap_hidden_text.html"]
        assert trap_stats["total_attempts"] == 2
        assert trap_stats["approvals"] == 0
        assert trap_stats["denials"] == 2
        assert trap_stats["denial_rate"] == 1.0
        assert trap_stats["average_risk"] == 3.5  # (4+3)/2
    
    def test_session_summary(self):
        """Test session summary generation."""
        ledger = RiskLedger()
        
        # Add mixed entries
        entries_data = [
            {"approved": True, "risk_score": 0, "fixture": "safe_store.html"},
            {"approved": False, "risk_score": 4, "fixture": "trap_hidden_text.html"},
            {"approved": False, "risk_score": 3, "fixture": "trap_html_comment.html"},
            {"approved": True, "risk_score": 1, "fixture": "safe_store.html"}
        ]
        
        for i, entry_data in enumerate(entries_data):
            full_entry = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/{entry_data['fixture']}",
                "defenses_triggered": ["Static Analysis"] if not entry_data["approved"] else [],
                **entry_data
            }
            ledger.add(full_entry)
        
        summary = ledger.get_session_summary()
        
        assert summary["total_decisions"] == 4
        assert summary["approvals"] == 2
        assert summary["denials"] == 2
        assert summary["approval_rate"] == 0.5
        assert summary["unique_fixtures"] == 3
        assert summary["current_denial_streak"] == 0  # Last entry was approved
        
        # Check risk trend is included
        assert "risk_trend" in summary
        assert summary["risk_trend"]["sample_size"] == 4
    
    def test_export_json(self):
        """Test JSON export functionality."""
        ledger = RiskLedger()
        
        # Add a test entry
        entry_data = {
            "decision_id": "test_001",
            "url": "http://localhost/test.html",
            "fixture": "test.html",
            "approved": False,
            "risk_score": 3,
            "defenses_triggered": ["Static Analysis"]
        }
        ledger.add(entry_data)
        
        json_export = ledger.export_json()
        
        # Should be valid JSON
        import json
        data = json.loads(json_export)
        
        assert "session_start" in data
        assert "export_time" in data
        assert "total_entries" in data
        assert "entries" in data
        assert data["total_entries"] == 1
        assert len(data["entries"]) == 1
        
        # Check entry data
        entry = data["entries"][0]
        assert entry["decision_id"] == "test_001"
        assert entry["approved"] == False
        assert entry["risk_score"] == 3
    
    def test_clear_ledger(self):
        """Test clearing the ledger."""
        ledger = RiskLedger()
        
        # Add entries
        for i in range(3):
            entry_data = {
                "decision_id": f"test_{i:03d}",
                "url": f"http://localhost/test{i}.html",
                "fixture": f"test{i}.html",
                "approved": True,
                "risk_score": 0,
                "defenses_triggered": []
            }
            ledger.add(entry_data)
        
        assert len(ledger.entries) == 3
        
        # Clear and verify
        ledger.clear()
        assert len(ledger.entries) == 0
        
        # Session summary should reflect empty state
        summary = ledger.get_session_summary()
        assert summary["total_decisions"] == 0
    
    def test_global_ledger_functions(self):
        """Test global ledger access functions."""
        # Reset to clean state
        reset_risk_ledger()
        
        # Get global ledger
        ledger = get_risk_ledger()
        assert len(ledger.entries) == 0
        
        # Add entry through global ledger
        entry_data = {
            "decision_id": "global_test_001",
            "url": "http://localhost/global_test.html",
            "fixture": "global_test.html",
            "approved": True,
            "risk_score": 0,
            "defenses_triggered": []
        }
        ledger.add(entry_data)
        
        # Verify entry exists
        assert len(ledger.entries) == 1
        
        # Reset and verify clean state
        reset_risk_ledger()
        new_ledger = get_risk_ledger()
        assert len(new_ledger.entries) == 0


if __name__ == "__main__":
    # Run basic memory tests
    test_instance = TestRiskLedger()
    
    print("Running risk ledger memory tests...")
    
    try:
        test_instance.setup_method()
        test_instance.test_add_entry()
        print("✅ Add entry test passed")
        
        test_instance.setup_method()
        test_instance.test_consecutive_denials_detection()
        print("✅ Consecutive denials detection test passed")
        
        test_instance.setup_method()
        test_instance.test_should_trigger_fallback()
        print("✅ Fallback triggering test passed")
        
        test_instance.setup_method()
        test_instance.test_risk_trend_analysis()
        print("✅ Risk trend analysis test passed")
        
        test_instance.setup_method()
        test_instance.test_fixture_statistics()
        print("✅ Fixture statistics test passed")
        
        print("🎉 All risk ledger tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise
