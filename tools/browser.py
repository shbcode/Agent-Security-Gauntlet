"""
Browser tools for the Agent Security Gauntlet.

Provides safe, local-only web content access with built-in security controls.
"""

from pathlib import Path
import sys
import os

# Add parent directory to path for safety_gate import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safety_gate import sanitize


def fetch_local(url: str) -> str:
    """
    Fetch content from a local fixture file.
    
    Maps URLs like http://localhost/filename.html to fixtures/html/filename.html
    
    Args:
        url: URL to fetch (should be localhost)
        
    Returns:
        HTML content as string
        
    Raises:
        FileNotFoundError: If fixture file doesn't exist
    """
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Extract filename from URL
    if "/" in url:
        filename = url.split("/")[-1]
    else:
        filename = url
    
    # Default to safe store if no filename
    if not filename or filename == "":
        filename = "safe_store.html"
    
    # Ensure .html extension
    if not filename.endswith(".html"):
        filename += ".html"
    
    # Construct path to fixture
    fixture_path = Path("fixtures/html") / filename
    
    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture not found: {fixture_path}")
    
    try:
        content = fixture_path.read_text(encoding="utf-8")
        return content
    except Exception as e:
        raise RuntimeError(f"Failed to read fixture {fixture_path}: {e}")


def extract_text(html: str) -> str:
    """
    Extract safe, visible text from HTML content.
    
    Uses the safety gate's sanitization to remove scripts, hidden content,
    and other potential attack vectors.
    
    Args:
        html: Raw HTML content
        
    Returns:
        Sanitized visible text
    """
    if not html:
        return ""
    
    try:
        result = sanitize(html)
        return result["safe_text"]
    except Exception as e:
        # Fallback to empty string if sanitization fails
        print(f"Warning: Text extraction failed: {e}")
        return ""


def get_page_title(html: str) -> str:
    """
    Extract page title from HTML content safely.
    
    Args:
        html: Raw HTML content
        
    Returns:
        Page title or "Untitled" if not found
    """
    if not html:
        return "Untitled"
    
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()
        return "Untitled"
    except Exception:
        return "Untitled"


def list_available_fixtures() -> list[str]:
    """
    List all available HTML fixtures.
    
    Returns:
        List of fixture filenames
    """
    fixtures_dir = Path("fixtures/html")
    if not fixtures_dir.exists():
        return []
    
    try:
        return [f.name for f in fixtures_dir.glob("*.html")]
    except Exception:
        return []


# CrewAI tool definitions
def fetch_and_extract(url: str) -> str:
    """
    Combined tool for CrewAI: fetch local content and extract safe text.
    
    This is the main tool that agents will use to safely access web content.
    
    Args:
        url: URL to fetch (localhost only)
        
    Returns:
        Safe, extracted text content
    """
    try:
        html = fetch_local(url)
        text = extract_text(html)
        title = get_page_title(html)
        
        return f"Page Title: {title}\n\nContent:\n{text}"
    except Exception as e:
        return f"Error accessing {url}: {e}"


if __name__ == "__main__":
    # Simple test
    print("Testing browser tools...")
    
    # Test fixture listing
    fixtures = list_available_fixtures()
    print(f"Available fixtures: {fixtures}")
    
    # Test with safe content
    try:
        html = "<html><head><title>Test</title></head><body><h1>Safe Content</h1><p>This is visible.</p></body></html>"
        text = extract_text(html)
        print(f"Extracted text: {text}")
        
        title = get_page_title(html)
        print(f"Page title: {title}")
    except Exception as e:
        print(f"Test failed: {e}")
