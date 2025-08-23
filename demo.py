#!/usr/bin/env python3
"""
🛡️ Agent Security Gauntlet - Quick Demo Launcher

This script provides a quick way to launch the demo with
optimal settings for presentations.
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

def check_environment():
    """Check if we're in the right environment."""
    try:
        import streamlit
        import crewai
        import beautifulsoup4
        print("✅ All required packages found")
        return True
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("Please run: conda activate gauntlet")
        return False

def run_tests():
    """Quick test run to ensure everything works."""
    print("🧪 Running quick tests...")
    try:
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "--tb=no"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ All tests passing")
            return True
        else:
            print("❌ Some tests failing - demo may have issues")
            print("Run 'pytest -v' for details")
            return False
    except subprocess.TimeoutExpired:
        print("⚠️ Tests taking too long - skipping")
        return True
    except Exception as e:
        print(f"⚠️ Could not run tests: {e}")
        return True

def launch_demo():
    """Launch the Streamlit demo."""
    print("🚀 Launching Agent Security Gauntlet demo...")
    print("📱 Demo will open in your browser automatically")
    print("🎯 Use the 'Run Canned Demo' button for reliable presentations")
    print()
    print("Demo Controls:")
    print("  🎲 Canned Demo - Perfect for live presentations")
    print("  🔄 Replay - Show results again")
    print("  🎯 Manual - Try different attack scenarios")
    print()
    print("💡 Pro tip: Start with the canned demo, then show manual attacks")
    print()
    
    try:
        # Launch streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "app.py",
            "--server.headless", "false",
            "--browser.gatherUsageStats", "false",
            "--server.port", "8501"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Demo stopped")
    except Exception as e:
        print(f"❌ Failed to launch demo: {e}")
        print("Try running manually: streamlit run app.py")

def main():
    """Main demo launcher."""
    print("🛡️ Agent Security Gauntlet - Demo Launcher")
    print("=" * 50)
    
    # Check current directory
    if not Path("app.py").exists():
        print("❌ app.py not found. Please run from the project directory.")
        sys.exit(1)
    
    # Check environment
    if not check_environment():
        print("\n🔧 Setup required:")
        print("1. conda env create -f environment.yml")
        print("2. conda activate gauntlet")
        print("3. python demo.py")
        sys.exit(1)
    
    # Run quick tests
    if not run_tests():
        choice = input("\n⚠️ Tests failing. Continue anyway? (y/N): ")
        if choice.lower() != 'y':
            print("Fix issues and try again.")
            sys.exit(1)
    
    print("\n🎬 Ready for demo!")
    input("Press Enter to launch...")
    
    # Launch demo
    launch_demo()

if __name__ == "__main__":
    main()
