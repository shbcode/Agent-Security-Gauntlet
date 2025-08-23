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

from crew import run_gauntlet, run_canned_demo, list_available_fixtures
from referee import summarize, generate_detailed_report, export_trace_json
from tasks import get_sample_tasks, get_security_scenarios


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

@keyframes pulse {
    0% { opacity: 0.6; }
    50% { opacity: 1; }
    100% { opacity: 0.6; }
}

.bubble-red { background-color: #dc3545; }
.bubble-blue { background-color: #007cba; }
.bubble-green { background-color: #28a745; }
.bubble-orange { background-color: #fd7e14; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'last_run_result' not in st.session_state:
    st.session_state.last_run_result = None
if 'run_history' not in st.session_state:
    st.session_state.run_history = []


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
        "safety": ["✅", "🔵", "⚫", "⚫"],
        "execution": ["✅", "✅", "🟢", "⚫"],
        "complete": ["✅", "✅", "✅", "🟠"]
    }
    
    labels = ["Planner", "SafetyGate", "Executor", "Referee"]
    current_bubbles = bubbles.get(phase, bubbles["ready"])
    
    cols = st.columns(4)
    for i, (bubble, label) in enumerate(zip(current_bubbles, labels)):
        with cols[i]:
            st.markdown(f"<div style='text-align: center'>{bubble}<br><small>{label}</small></div>", 
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


def display_trace_evidence(result: Dict[str, Any]):
    """Display detailed trace and evidence."""
    trace = result.get("trace", {})
    
    with st.expander("🔍 Trace & Evidence", expanded=False):
        st.subheader("Security Gate Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**URL Accessed:**")
            st.code(trace.get("url", "Unknown"))
            
            st.write("**Gate Decision:**")
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


def main():
    """Main Streamlit application."""
    display_header()
    
    # Sidebar with quick actions
    with st.sidebar:
        st.header("Quick Actions")
        
        if st.button("🎲 Run Canned Demo", help="Instant demo with predetermined scenario"):
            with st.spinner("Running canned demo..."):
                st.session_state.last_run_result = run_canned_demo()
                st.session_state.run_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "canned_demo",
                    "result": st.session_state.last_run_result
                })
            st.success("Demo complete!")
            st.rerun()
        
        if st.button("🔄 Replay Last Run") and st.session_state.last_run_result:
            st.success("Replaying last run...")
            st.rerun()
        
        st.markdown("---")
        
        # Available fixtures
        st.subheader("Available Fixtures")
        fixtures = [
            "safe_store.html",
            "trap_hidden_text.html", 
            "trap_html_comment.html",
            "trap_external_lure.html"
        ]
        
        for fixture in fixtures:
            emoji = "🟢" if "safe" in fixture else "🔴"
            st.write(f"{emoji} {fixture}")
        
        st.markdown("---")
        
        # Statistics
        if st.session_state.run_history:
            st.subheader("Session Stats")
            total_runs = len(st.session_state.run_history)
            successful_blocks = sum(1 for run in st.session_state.run_history 
                                  if run["result"].get("attack_blocked", False))
            st.metric("Total Runs", total_runs)
            st.metric("Attacks Blocked", successful_blocks)
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🎯 Mission Control")
        
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
                result = run_gauntlet(task_text, fixture)
                st.session_state.last_run_result = result
                st.session_state.run_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "manual_run",
                    "task": task_text,
                    "fixture": fixture,
                    "result": result
                })
            
            # Phase 4: Complete
            progress_container.empty()
            with progress_container.container():
                st.write("**Phase 4: Complete**")
                display_progress_bubbles("complete")
            
            st.success("🎉 Gauntlet run complete!")
        
        elif run_button:
            st.error("Please enter a task to run.")
    
    with col2:
        create_scenario_cards()
    
    # Results section
    if st.session_state.last_run_result:
        st.markdown("---")
        
        result = st.session_state.last_run_result
        
        # Display scorecard
        display_scorecard(result)
        
        # Display answer
        st.subheader("📝 Final Answer")
        facts = result.get("facts", "No answer generated")
        st.write(facts)
        
        # Display trace evidence
        display_trace_evidence(result)
        
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
