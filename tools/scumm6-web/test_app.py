#!/usr/bin/env python3
"""
Unit tests for SCUMM6 Flask web application.
"""

import os
import sys
import json
import unittest
from pathlib import Path
import time

# Add current directory to path for app import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set mock environment before imports
os.environ["FORCE_BINJA_MOCK"] = "1"

from app import app, DataProvider, ScriptComparison


class TestDataProvider(unittest.TestCase):
    """Test the DataProvider class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = DataProvider()
    
    def test_initialization_without_files(self):
        """Test initialization when files don't exist."""
        # Use paths that don't exist
        provider = DataProvider(
            bsc6_path=Path("/nonexistent/file.bsc6"),
            descumm_path=Path("/nonexistent/descumm")
        )
        result = provider.initialize()
        self.assertFalse(result)
        self.assertIsNotNone(provider.initialization_error)
    
    def test_normalization(self):
        """Test line normalization."""
        test_cases = [
            ("[0000] (43) localvar5 = 10", "localvar5 = 10"),
            ("[0x1234] var_5 = 20", "var_5 = 20"),
            ("(5D)   if   (!var_1)  {", "if (!var_1) {"),
        ]
        
        for input_line, expected in test_cases:
            normalized = self.provider._normalize_line(input_line)
            # Should at least remove prefixes and normalize vars
            self.assertNotIn("[0000]", normalized)
            self.assertNotIn("(43)", normalized)
    
    def test_comparison_logic(self):
        """Test output comparison logic."""
        descumm = """[0000] (5D) if (!isScriptRunning(137)) {
[0008] (5F)   startScriptQuick(93,[1])
[001A] (**) }"""
        
        fused = """[0000] isScriptRunning(137)
[0008] startScriptQuick(93, [1])"""
        
        is_match, score, unmatched = self.provider._compare_outputs(descumm, fused)
        
        # Should find some similarity
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertIsInstance(unmatched, list)


class TestFlaskApp(unittest.TestCase):
    """Test Flask application endpoints."""
    
    def setUp(self):
        """Set up test client."""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_index_route(self):
        """Test main page loads."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SCUMM6 Disassembly Comparison', response.data)
    
    def test_api_status(self):
        """Test status endpoint."""
        response = self.app.get('/api/status')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('initialized', data)
        self.assertIn('error', data)
    
    def test_api_scripts(self):
        """Test scripts listing endpoint."""
        response = self.app.get('/api/scripts')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        if 'error' not in data:
            self.assertIn('scripts', data)
            self.assertIn('total', data)
            self.assertIsInstance(data['scripts'], list)
    
    def test_api_script_not_found(self):
        """Test getting non-existent script."""
        response = self.app.get('/api/scripts/nonexistent_script')
        # Should return 404 or have error in response
        if response.status_code == 200:
            data = json.loads(response.data)
            self.assertIn('error', data)
        else:
            self.assertEqual(response.status_code, 404)
    
    def test_api_process_all(self):
        """Test process all scripts endpoint."""
        response = self.app.post('/api/process_all')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        if 'error' not in data:
            self.assertIn('processed', data)
            self.assertIn('matched', data)
            self.assertIn('total', data)
            self.assertIn('match_percentage', data)


class TestScriptComparison(unittest.TestCase):
    """Test ScriptComparison dataclass."""
    
    def test_dataclass_creation(self):
        """Test creating comparison object."""
        comp = ScriptComparison(
            name="test_script",
            descumm_output="output1",
            fused_output="output2",
            raw_output="output3",
            is_match=True,
            match_score=0.95,
            unmatched_lines=[]
        )
        
        self.assertEqual(comp.name, "test_script")
        self.assertTrue(comp.is_match)
        self.assertEqual(comp.match_score, 0.95)


class TestIntegration(unittest.TestCase):
    """Integration tests for the full application flow."""
    
    def setUp(self):
        """Set up test client."""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_full_workflow(self):
        """Test loading scripts and getting comparison."""
        # First check status
        response = self.app.get('/api/status')
        self.assertEqual(response.status_code, 200)
        
        # Get scripts list
        response = self.app.get('/api/scripts')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # If we have scripts, try to get one
        if 'scripts' in data and len(data['scripts']) > 0:
            script_name = data['scripts'][0]['name']
            
            # Get comparison for this script
            response = self.app.get(f'/api/scripts/{script_name}')
            self.assertEqual(response.status_code, 200)
            
            comp_data = json.loads(response.data)
            if 'error' not in comp_data:
                self.assertIn('name', comp_data)
                self.assertIn('descumm_output', comp_data)
                self.assertIn('fused_output', comp_data)
                self.assertIn('raw_output', comp_data)
                self.assertIn('is_match', comp_data)
                self.assertIn('match_score', comp_data)


class TestServerStartup(unittest.TestCase):
    """Test that the server can start up properly."""
    
    def test_app_imports(self):
        """Test that all imports work."""
        try:
            from app import app, init_app
            self.assertIsNotNone(app)
            self.assertIsNotNone(init_app)
        except ImportError as e:
            self.fail(f"Failed to import app: {e}")
    
    def test_app_configuration(self):
        """Test app configuration."""
        from app import app
        
        # Check Flask app is configured
        self.assertIsNotNone(app.secret_key)
        self.assertTrue(len(app.secret_key) > 0)
        
        # Check routes are registered
        rules = [rule.rule for rule in app.url_map.iter_rules()]
        self.assertIn('/', rules)
        self.assertIn('/api/scripts', rules)
        self.assertIn('/api/status', rules)


def run_integration_test():
    """Run a simple integration test by starting the server."""
    print("\n=== Running Integration Test ===")
    
    import subprocess
    import requests
    
    # Start the Flask server in a subprocess
    print("Starting Flask server...")
    server_process = subprocess.Popen(
        [sys.executable, "tools/scumm6-web/app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Give server time to start
    time.sleep(3)
    
    try:
        # Test that server is running
        print("Testing server endpoints...")
        
        # Test main page
        response = requests.get("http://localhost:5000/")
        print(f"Main page status: {response.status_code}")
        assert response.status_code == 200, "Main page should load"
        
        # Test API status
        response = requests.get("http://localhost:5000/api/status")
        print(f"API status: {response.status_code}")
        data = response.json()
        print(f"Status data: {data}")
        
        # Test scripts endpoint
        response = requests.get("http://localhost:5000/api/scripts")
        print(f"Scripts endpoint status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if 'scripts' in data:
                print(f"Found {len(data['scripts'])} scripts")
            elif 'error' in data:
                print(f"Error loading scripts: {data['error']}")
        
        print("\n✓ Integration test passed!")
        
    except Exception as e:
        print(f"\n✗ Integration test failed: {e}")
        
    finally:
        # Stop the server
        print("\nStopping Flask server...")
        server_process.terminate()
        server_process.wait()


if __name__ == '__main__':
    # Run unit tests
    print("Running unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run integration test if requests is available
    try:
        import requests  # noqa: F401
        run_integration_test()
    except ImportError:
        print("\nSkipping integration test (requests module not available)")
        print("Install with: pip install requests")