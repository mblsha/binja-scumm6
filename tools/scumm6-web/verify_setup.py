#!/usr/bin/env python3
"""
Verify the Flask app setup without requiring Flask to be installed.
"""

import os
import sys
from pathlib import Path

def verify_file_structure():
    """Verify all required files exist."""
    print("Checking file structure...")
    
    required_files = [
        "app.py",
        "requirements.txt",
        "README.md",
        "run.sh",
        "templates/index.html",
        "test_app.py"
    ]
    
    current_dir = Path(__file__).parent
    all_exist = True
    
    for file_path in required_files:
        full_path = current_dir / file_path
        exists = full_path.exists()
        status = "✓" if exists else "✗"
        print(f"  {status} {file_path}")
        if not exists:
            all_exist = False
    
    return all_exist

def verify_app_structure():
    """Verify app.py has the expected structure."""
    print("\nChecking app.py structure...")
    
    app_path = Path(__file__).parent / "app.py"
    if not app_path.exists():
        print("  ✗ app.py not found")
        return False
    
    with open(app_path, 'r') as f:
        content = f.read()
    
    # Check for key components
    checks = [
        ("Flask app creation", "app = Flask(__name__)"),
        ("DataProvider class", "class DataProvider"),
        ("ScriptComparison class", "class ScriptComparison"),
        ("Main route", "@app.route('/')"),
        ("API routes", "@app.route('/api/"),
        ("Template rendering", "render_template('index.html')"),
    ]
    
    all_found = True
    for name, pattern in checks:
        found = pattern in content
        status = "✓" if found else "✗"
        print(f"  {status} {name}")
        if not found:
            all_found = False
    
    return all_found

def verify_html_template():
    """Verify the HTML template structure."""
    print("\nChecking HTML template...")
    
    template_path = Path(__file__).parent / "templates" / "index.html"
    if not template_path.exists():
        print("  ✗ templates/index.html not found")
        return False
    
    with open(template_path, 'r') as f:
        content = f.read()
    
    # Check for key elements
    checks = [
        ("Page title", "<title>SCUMM6 Disassembly Comparison</title>"),
        ("Script list container", 'id="scriptList"'),
        ("Diff panels", 'class="diff-panel"'),
        ("JavaScript functionality", "async function loadScripts()"),
        ("API calls", "fetch('/api/scripts')"),
    ]
    
    all_found = True
    for name, pattern in checks:
        found = pattern in content
        status = "✓" if found else "✗"
        print(f"  {status} {name}")
        if not found:
            all_found = False
    
    return all_found

def verify_requirements():
    """Check requirements.txt."""
    print("\nChecking requirements.txt...")
    
    req_path = Path(__file__).parent / "requirements.txt"
    if not req_path.exists():
        print("  ✗ requirements.txt not found")
        return False
    
    with open(req_path, 'r') as f:
        content = f.read()
    
    required_packages = ["Flask", "Flask-CORS"]
    
    for package in required_packages:
        found = package in content
        status = "✓" if found else "✗"
        print(f"  {status} {package}")
    
    return True

def main():
    """Run all verifications."""
    print("=== SCUMM6 Flask Web App Verification ===\n")
    
    results = []
    results.append(("File structure", verify_file_structure()))
    results.append(("App structure", verify_app_structure()))
    results.append(("HTML template", verify_html_template()))
    results.append(("Requirements", verify_requirements()))
    
    print("\n=== Summary ===")
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n✓ All verifications passed!")
        print("\nTo run the web app:")
        print("  1. cd tools/scumm6-web")
        print("  2. pip install -r requirements.txt")
        print("  3. python app.py")
        print("\nThen open http://localhost:5000 in your browser.")
    else:
        print("\n✗ Some verifications failed.")
        print("Please check the issues above.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())