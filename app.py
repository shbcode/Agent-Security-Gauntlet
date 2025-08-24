"""
Streamlit interface for the Agent Security Gauntlet.

Provides a theatrical, judge-friendly demo interface showcasing
defense-in-depth against prompt injection attacks.
"""

import streamlit as st
import json
import time
from datetime import datetime
from typing import Dict, Any

from crew import run_gauntlet, run_canned_demo, list_available_fixtures, run_baseline, run_defended
from referee import summarize, generate_detailed_report, export_trace_json
from tasks import get_sample_tasks, get_security_scenarios
from config import get_arb_settings, is_llm_enabled, get_juror_count
from llm_logger import get_llm_logger


# Page configuration
st.set_page_config(
    page_title="Agent Security Gauntlet",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.main-header {
    background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
    padding: 20px;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin-bottom: 20px;
}

.scorecard {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 8px;
    border-left: 4px solid #007cba;
    margin: 10px 0;
}

.attack-card {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    padding: 10px;
    border-radius: 5px;
    margin: 5px 0;
}

.safe-card {
    background: #d4edda;
    border: 1px solid #c3e6cb;
    padding: 10px;
    border-radius: 5px;
    margin: 5px 0;
}

.defense-badge {
    background: #28a745;
    color: white;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.8em;
    margin: 2px;
    display: inline-block;
}

.progress-bubble {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin: 0 5px;
    animation: pulse 1.5s infinite;
}

.attack-alert {
    background: linear-gradient(90deg, #ff6b6b, #ee5a52);
    color: white;
    padding: 15px;
    border-radius: 8px;
    margin: 10px 0;
    animation: glow 2s infinite;
    text-align: center;
    font-weight: bold;
}

.success-banner {
    background: linear-gradient(90deg, #51cf66, #40c057);
    color: white;
    padding: 15px;
    border-radius: 8px;
    text-align: center;
    font-size: 1.2em;
    margin: 20px 0;
    font-weight: bold;
}

.demo-highlight {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 20px;
    border-radius: 10px;
    margin: 15px 0;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}

@keyframes pulse {
    0% { opacity: 0.6; }
    50% { opacity: 1; }
    100% { opacity: 0.6; }
}

@keyframes glow {
    0% { box-shadow: 0 0 5px rgba(255, 107, 107, 0.5); }
    50% { box-shadow: 0 0 20px rgba(255, 107, 107, 0.8); }
    100% { box-shadow: 0 0 5px rgba(255, 107, 107, 0.5); }
}

.bubble-red { background-color: #dc3545; }
.bubble-blue { background-color: #007cba; }
.bubble-green { background-color: #28a745; }
.bubble-orange { background-color: #fd7e14; }

.metric-card {
    background: white;
    padding: 15px;
    border-radius: 8px;
    border-left: 4px solid #007cba;
    margin: 5px 0;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.juror-panel {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    padding: 15px;
    margin: 10px 0;
}

.juror-vote {
    background: white;
    border-left: 4px solid #6c757d;
    padding: 10px;
    margin: 5px 0;
    border-radius: 4px;
}

.juror-vote.high-risk {
    border-left-color: #dc3545;
}

.juror-vote.medium-risk {
    border-left-color: #ffc107;
}

.juror-vote.low-risk {
    border-left-color: #28a745;
}

.comparison-table {
    background: white;
    border-radius: 8px;
    padding: 15px;
    margin: 10px 0;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.arb-controls {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 15px;
    border-radius: 8px;
    margin: 10px 0;
}
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'last_run_result' not in st.session_state:
    st.session_state.last_run_result = None
if 'run_history' not in st.session_state:
    st.session_state.run_history = []
if 'use_arb' not in st.session_state:
    st.session_state.use_arb = True
if 'baseline_comparison' not in st.session_state:
    st.session_state.baseline_comparison = False
if 'baseline_result' not in st.session_state:
    st.session_state.baseline_result = None


def display_header():
    """Display the main application header."""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Agent Security Gauntlet</h1>
        <p>Plan → Approve → Act workflow with defense-in-depth against prompt injection</p>
    </div>
    """, unsafe_allow_html=True)


def display_progress_bubbles(phase: str = "ready"):
    """Display animated progress bubbles for different phases."""
    bubbles = {
        "ready": ["⚫", "⚫", "⚫", "⚫"],
        "planning": ["🔴", "⚫", "⚫", "⚫"],
        "safety": ["✅", "🛡️", "⚫", "⚫"],
        "execution": ["✅", "✅", "🟢", "⚫"],
        "complete": ["✅", "✅", "✅", "🟠"]
    }
    
    agents = ["RedAgent", "SafetyGate", "BlueExecutor", "Referee"]
    roles = ["Threat Sim", "Security Gate", "Safe Execution", "Audit"]
    current_bubbles = bubbles.get(phase, bubbles["ready"])
    
    cols = st.columns(4)
    for i, (bubble, agent, role) in enumerate(zip(current_bubbles, agents, roles)):
        with cols[i]:
            st.markdown(f"<div style='text-align: center'>{bubble}<br><small><strong>{agent}</strong><br>{role}</small></div>", 
                       unsafe_allow_html=True)


def create_scenario_cards():
    """Create visual cards for attack scenarios."""
    scenarios = {
        "safe_store.html": {
            "name": "🟢 Safe Store",
            "type": "safe",
            "description": "Clean content with no attacks",
            "risk": "None"
        },
        "trap_hidden_text.html": {
            "name": "🟡 Hidden Text Injection",
            "type": "attack",
            "description": "CSS-hidden prompt injection attempts",
            "risk": "Medium"
        },
        "trap_html_comment.html": {
            "name": "🟠 HTML Comment Injection", 
            "type": "attack",
            "description": "Instructions hidden in HTML comments",
            "risk": "High"
        },
        "trap_external_lure.html": {
            "name": "🔴 External Lure Attack",
            "type": "attack",
            "description": "Malicious external links and scripts",
            "risk": "Critical"
        },
        "trap_sr_only.html": {
            "name": "🟣 Screen Reader Attack",
            "type": "attack",
            "description": "Hidden instructions in accessibility content",
            "risk": "High"
        }
    }
    
    st.subheader("Attack Scenarios")
    
    for fixture, info in scenarios.items():
        card_class = "safe-card" if info["type"] == "safe" else "attack-card"
        st.markdown(f"""
        <div class="{card_class}">
            <strong>{info['name']}</strong><br>
            <small>{info['description']}</small><br>
            <em>Risk: {info['risk']}</em>
        </div>
        """, unsafe_allow_html=True)


def display_scorecard(result: Dict[str, Any]):
    """Display the security scorecard."""
    st.subheader("🏆 Security Scorecard")
    
    # Generate detailed analysis
    detailed_report = generate_detailed_report(result)
    scorecard = detailed_report["scorecard"]
    
    # Create scorecard table
    scorecard_data = []
    for metric, value in scorecard.items():
        scorecard_data.append({"Metric": metric, "Result": value})
    
    st.table(scorecard_data)
    
    # Additional metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        execution_time = result.get("execution_time", 0)
        st.metric("Execution Time", f"{execution_time:.2f}s")
    
    with col2:
        patterns_detected = len(result.get("trace", {}).get("gate_meta", {}).get("patterns", []))
        st.metric("Patterns Detected", patterns_detected)
    
    with col3:
        defenses_count = len(result.get("defenses_used", []))
        st.metric("Defenses Triggered", defenses_count)


def display_arb_controls():
    """Display ARB configuration controls."""
    st.markdown("""
    <div class="arb-controls">
        <h4>🤖 Adversarial Review Board</h4>
        <p>Multi-agent security decision system</p>
    </div>
    """, unsafe_allow_html=True)
    
    # ARB toggle
    use_arb = st.checkbox(
        "Use Adversarial Review Board (recommended)",
        value=st.session_state.use_arb,
        help="Enable multi-agent security review with static analysis, conformance checking, and optional LLM jurors"
    )
    st.session_state.use_arb = use_arb
    
    # Baseline comparison toggle
    baseline_comparison = st.checkbox(
        "Run baseline (no gate) in parallel",
        value=st.session_state.baseline_comparison,
        help="Compare defended vs undefended execution side-by-side"
    )
    st.session_state.baseline_comparison = baseline_comparison
    
    # ARB settings display
    if use_arb:
        arb_settings = get_arb_settings()
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("LLM Enabled", "Yes" if arb_settings["llm_enabled"] else "No")
            st.metric("Jurors", arb_settings["juror_count"])
        
        with col2:
            st.metric("Static Threshold", f"{arb_settings['static_threshold']}/5")
            st.metric("LLM Threshold", f"{arb_settings['llm_threshold']}/5")
        



def display_juror_panel(result: Dict[str, Any]):
    """Display LLM juror votes if available."""
    trace = result.get("trace", {})
    arb_decision = None
    
    # Extract ARB decision from trace
    for log_entry in trace.get("full_trace", []):
        if log_entry.get("agent") == "ARB" and "arb_decision" in log_entry.get("data", {}):
            arb_decision = log_entry["data"]["arb_decision"]
            break
    
    if not arb_decision or not arb_decision.signals.llm_votes:
        return
    
    st.markdown("""
    <div class="juror-panel">
        <h4>🧑‍⚖️ LLM Juror Panel</h4>
    </div>
    """, unsafe_allow_html=True)
    
    votes = arb_decision.signals.llm_votes
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        median_risk = arb_decision.signals.llm_median_risk or 0
        st.metric("Median Risk", f"{median_risk}/5")
    
    with col2:
        consensus = arb_decision.signals.llm_consensus
        st.metric("Consensus", "Yes" if consensus else "No")
    
    with col3:
        high_conf_votes = sum(1 for vote in votes if vote.confidence >= 0.7)
        st.metric("High Confidence", f"{high_conf_votes}/{len(votes)}")
    
    # Individual juror votes
    st.write("**Individual Juror Assessments:**")
    
    for vote in votes:
        risk_class = "low-risk" if vote.risk_score <= 1 else "medium-risk" if vote.risk_score <= 3 else "high-risk"
        
        st.markdown(f"""
        <div class="juror-vote {risk_class}">
            <strong>{vote.juror_id.replace('_', ' ').title()}</strong> - Risk: {vote.risk_score}/5 
            (Confidence: {vote.confidence:.1%})<br>
            <small>{vote.rationale}</small>
        </div>
        """, unsafe_allow_html=True)


def display_baseline_comparison(defended_result: Dict[str, Any], baseline_result: Dict[str, Any]):
    """Display side-by-side comparison of defended vs baseline execution."""
    st.markdown("""
    <div class="comparison-table">
        <h4>🔄 Baseline vs Defended Comparison</h4>
    </div>
    """, unsafe_allow_html=True)
    
    # Create comparison table
    comparison_data = []
    
    metrics = [
        ("Task Success", "success", lambda x: "✅" if x else "❌"),
        ("Attack Blocked", "attack_blocked", lambda x: "✅" if x else "❌" if x is False else "—"),
        ("Execution Time", "execution_time", lambda x: f"{x:.2f}s"),
        ("Defenses Used", "defenses_used", lambda x: len(x)),
        ("Facts Length", "facts", lambda x: len(str(x)))
    ]
    
    for metric_name, key, formatter in metrics:
        baseline_val = baseline_result.get(key, "N/A")
        defended_val = defended_result.get(key, "N/A")
        
        comparison_data.append({
            "Metric": metric_name,
            "Baseline (No Security)": formatter(baseline_val) if baseline_val != "N/A" else "N/A",
            "Defended (ARB)": formatter(defended_val) if defended_val != "N/A" else "N/A"
        })
    
    st.table(comparison_data)
    
    # Highlight key differences
    if baseline_result.get("attack_blocked", False) != defended_result.get("attack_blocked", False):
        st.success("🛡️ ARB successfully blocked attack that baseline missed!")
    
    baseline_facts = str(baseline_result.get("facts", ""))
    defended_facts = str(defended_result.get("facts", ""))
    
    if len(baseline_facts) > len(defended_facts) * 1.5:
        st.warning("⚠️ Baseline may have leaked more information than defended version")


def display_llm_logs():
    """Display LLM interaction logs for transparency."""
    llm_logger = get_llm_logger()
    session_logs = llm_logger.get_session_logs()
    
    if session_logs:
        with st.expander("🤖 LLM Interaction Logs", expanded=False):
            st.subheader("Real-time LLM Call Logs")
            st.write(f"**Total LLM Calls This Session: {len(session_logs)}**")
            
            for i, log in enumerate(reversed(session_logs[-5:])):  # Show last 5 calls
                st.markdown("---")
                st.write(f"**Call #{len(session_logs) - i}** - {log['timestamp']}")
                
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.write(f"**Juror:** {log['juror_id']}")
                    st.write(f"**Model:** {log['model']}")
                    st.write(f"**Response Time:** {log['response_time_ms']}ms")
                    st.write(f"**Mock LLM:** {'Yes' if log['is_mock'] else 'No'}")
                
                with col2:
                    st.write("**Prompt Preview:**")
                    st.code(log['prompt_preview'], language="text")
                    st.write("**Response:**")
                    st.code(log['response'], language="json")
            
            # Export logs button
            if st.button("📥 Export LLM Logs"):
                logs_json = llm_logger.export_session_logs()
                st.download_button(
                    label="Download LLM Logs JSON",
                    data=logs_json,
                    file_name=f"llm_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )


def display_trace_evidence(result: Dict[str, Any]):
    """Display detailed trace and evidence."""
    trace = result.get("trace", {})
    
    with st.expander("🔍 Trace & Evidence", expanded=False):
        st.subheader("Security Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**URL Accessed:**")
            st.code(trace.get("url", "Unknown"))
            
            st.write("**Decision:**")
            st.write(trace.get("gate_reason", "No reason provided"))
            
        with col2:
            gate_meta = trace.get("gate_meta", {})
            st.write("**Suspicion Score:**")
            st.write(f"{gate_meta.get('score', 0)}/5")
            
            st.write("**Allowlist Status:**")
            allowlist_ok = gate_meta.get("allowlist_ok", False)
            st.write("✅ Allowed" if allowlist_ok else "❌ Blocked")
        
        # Suspicious patterns detected
        patterns = gate_meta.get("patterns", [])
        if patterns:
            st.write("**Suspicious Patterns Detected:**")
            for pattern in patterns:
                st.markdown(f"- `{pattern}`")
        
        # Evidence snippet
        snippet = gate_meta.get("snippet", "")
        if snippet:
            st.write("**Evidence Snippet:**")
            st.code(snippet[:200] + "..." if len(snippet) > 200 else snippet)
        
        # Defense mechanisms
        defenses = result.get("defenses_used", [])
        if defenses:
            st.write("**Defense Mechanisms:**")
            for defense in defenses:
                st.markdown(f"<span class='defense-badge'>{defense}</span>", unsafe_allow_html=True)
        
        # Display juror panel if available
        display_juror_panel(result)


def main():
    """Main Streamlit application."""
    display_header()
    
    # Sidebar with quick actions
    with st.sidebar:
        st.header("🚀 Demo Controls")
        
        # Highlight the canned demo for judges
        st.markdown("""
        <div class="demo-highlight">
            <h4>⚡ Quick Demo</h4>
            <p>Perfect for live presentations!</p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🎲 Run Canned Demo", help="Instant demo with predetermined scenario", use_container_width=True):
            with st.spinner("Running canned demo..."):
                st.session_state.last_run_result = run_canned_demo()
                st.session_state.run_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "canned_demo",
                    "result": st.session_state.last_run_result
                })
            st.success("Demo complete!")
            st.rerun()
        
        if st.button("🔄 Replay Last Run", use_container_width=True) and st.session_state.last_run_result:
            st.success("Replaying last run...")
            st.rerun()
        
        st.markdown("---")
        

        
        # CrewAI Agent Status
        st.subheader("🤖 CrewAI Security Crew")
        agents = {
            "RedAgent": {"emoji": "🔴", "role": "Threat Simulation", "status": "Ready"},
            "BluePlanner": {"emoji": "🔵", "role": "Security Architecture", "status": "Ready"},
            "SafetyGate": {"emoji": "🛡️", "role": "Threat Detection", "status": "Active"},
            "BlueExecutor": {"emoji": "🟢", "role": "Safe Execution", "status": "Standby"},
            "Referee": {"emoji": "🟠", "role": "Security Audit", "status": "Monitoring"}
        }
        
        for agent, info in agents.items():
            st.markdown(f"{info['emoji']} **{agent}**")
            st.caption(f"{info['role']} - {info['status']}")
        
        st.markdown("---")
        
        # Available fixtures
        st.subheader("🎯 Attack Scenarios")
        fixtures = [
            ("safe_store.html", "🟢", "Clean baseline content"),
            ("trap_hidden_text.html", "🟡", "CSS-hidden injection"), 
            ("trap_html_comment.html", "🟠", "HTML comment attack"),
            ("trap_external_lure.html", "🔴", "External lure + scripts"),
            ("trap_sr_only.html", "🟣", "Screen reader attack")
        ]
        
        for fixture, emoji, desc in fixtures:
            st.markdown(f"{emoji} **{fixture.replace('.html', '')}**")
            st.caption(desc)
        
        st.markdown("---")
        st.subheader("📚 Quick Reference")
        st.markdown("""
        **OWASP LLM01**: Prompt Injection  
        **Defense Layers**: 5 independent controls  
        **Test Coverage**: 58/58 passing  
        **Response Time**: <2 seconds  
        """)
        
        # Demo tips
        with st.expander("💡 Demo Tips"):
            st.markdown("""
            1. Start with canned demo for reliability
            2. Show attack detection in trace
            3. Emphasize task still succeeds
            4. Mention OWASP Top 10 compliance
            5. Highlight defense-in-depth approach
            """)
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🎯 Mission Control")
        
        # ARB Controls
        display_arb_controls()
        
        st.markdown("---")
        
        # Task input
        sample_tasks = get_sample_tasks()
        task_options = [task["prompt"] for task in sample_tasks]
        task_options.append("Custom task...")
        
        selected_task = st.selectbox(
            "Select Task",
            task_options,
            help="Choose a predefined task or enter a custom one"
        )
        
        if selected_task == "Custom task...":
            task_text = st.text_input(
                "Custom Task",
                placeholder="Find the refund policy and summarize in 2 bullet points",
                help="Enter your custom task"
            )
        else:
            task_text = selected_task
        
        # Fixture selection
        fixture = st.selectbox(
            "Attack Card / Fixture",
            [
                "trap_hidden_text.html",
                "trap_html_comment.html", 
                "trap_external_lure.html",
                "trap_sr_only.html",
                "safe_store.html"
            ],
            help="Choose the scenario to test against"
        )
        
        # Run button
        run_button = st.button("🚀 Run Gauntlet", type="primary", use_container_width=True)
        
        if run_button and task_text:
            # Show progress
            progress_container = st.empty()
            
            # Phase 1: Planning
            progress_container.empty()
            with progress_container.container():
                st.write("**Phase 1: Planning**")
                display_progress_bubbles("planning")
            time.sleep(0.5)
            
            # Phase 2: Safety Gate
            progress_container.empty()
            with progress_container.container():
                st.write("**Phase 2: Safety Gate**")
                display_progress_bubbles("safety")
            time.sleep(0.5)
            
            # Phase 3: Execution
            progress_container.empty()
            with progress_container.container():
                st.write("**Phase 3: Execution**")
                display_progress_bubbles("execution")
            time.sleep(0.5)
            
            # Run the actual gauntlet
            with st.spinner("Agents working..."):
                # Run defended version
                result = run_gauntlet(task_text, fixture, use_arb=st.session_state.use_arb)
                st.session_state.last_run_result = result
                
                # Run baseline comparison if requested
                if st.session_state.baseline_comparison:
                    with st.spinner("Running baseline comparison..."):
                        baseline_result = run_baseline(task_text, fixture)
                        st.session_state.baseline_result = baseline_result
                
                st.session_state.run_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "manual_run",
                    "task": task_text,
                    "fixture": fixture,
                    "result": result,
                    "baseline_result": st.session_state.baseline_result if st.session_state.baseline_comparison else None,
                    "use_arb": st.session_state.use_arb
                })
            
            # Phase 4: Complete
            progress_container.empty()
            with progress_container.container():
                st.write("**Phase 4: Complete**")
                display_progress_bubbles("complete")
            
            # Dramatic results announcement
            if result.get("attack_blocked", False):
                st.markdown("""
                <div class="attack-alert">
                    🚨 ATTACK DETECTED AND BLOCKED! 🚨<br>
                    Task completed successfully despite malicious content!
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="success-banner">
                    ✅ CLEAN EXECUTION - No threats detected
                </div>
                """, unsafe_allow_html=True)
        
        elif run_button:
            st.error("Please enter a task to run.")
    
    with col2:
        create_scenario_cards()
    
    # Results section
    if st.session_state.last_run_result:
        st.markdown("---")
        
        result = st.session_state.last_run_result
        
        # Display baseline comparison if available
        if st.session_state.baseline_result:
            display_baseline_comparison(result, st.session_state.baseline_result)
            st.markdown("---")
        
        # Display scorecard
        display_scorecard(result)
        
        # Display answer
        st.subheader("📝 Final Answer")
        facts = result.get("facts", "No answer generated")
        st.write(facts)
        
        # Display trace evidence
        display_trace_evidence(result)
        
        # Display LLM interaction logs (separate from trace to avoid nested expanders)
        display_llm_logs()
        
        # Export functionality
        st.subheader("📊 Export Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📥 Download JSON Trace"):
                json_data = export_trace_json(result, include_analysis=True)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"gauntlet_trace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col2:
            if st.button("📋 Copy Results"):
                # Simple text summary for copying
                summary = f"""Agent Security Gauntlet Results
Task: {result.get('task_text', 'N/A')}
Success: {result.get('success', False)}
Attack Blocked: {result.get('attack_blocked', False)}
Defenses: {', '.join(result.get('defenses_used', []))}
Time: {result.get('execution_time', 0):.2f}s
"""
                st.code(summary)


if __name__ == "__main__":
    main()
