#!/usr/bin/env python3
"""
Launcher Verification
Tests that launcher.py correctly parses arguments and dispatches to appropriate functions.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import launcher

class TestLauncher(unittest.TestCase):
    
    @patch('launcher.run_dashboard')
    def test_dashboard_command(self, mock_run_dashboard):
        """Test 'dashboard' command dispatch"""
        test_args = ['launcher.py', 'dashboard', '--host', '127.0.0.1', '--port', '9999', '--token', 'secret']
        with patch.object(sys, 'argv', test_args):
            launcher.main()
            
        mock_run_dashboard.assert_called_once()
        call_args = mock_run_dashboard.call_args[1]
        self.assertEqual(call_args['host'], '127.0.0.1')
        self.assertEqual(call_args['port'], 9999)
        self.assertEqual(call_args['token'], 'secret')
        print("✅ Launcher 'dashboard' command dispatch verified")

    @patch('launcher.PKIManager')
    def test_init_pki_command(self, mock_pki_class):
        """Test 'init-pki' command dispatch"""
        # Configure mock to return values expected by unpack
        mock_pki_class.return_value.generate_root_ca.return_value = ('cert', 'key')
        
        test_args = ['launcher.py', 'init-pki', '--ca-name', 'Test CA']
        with patch.object(sys, 'argv', test_args):
            launcher.main()
            
        mock_pki_class.return_value.generate_root_ca.assert_called_once()
        print("✅ Launcher 'init-pki' command dispatch verified")

    @patch('launcher.SecureAgent')
    def test_agent_command(self, mock_agent_class):
        """Test 'agent' command dispatch"""
        # Mock pathlib.Path.exists to return True
        with patch('pathlib.Path.exists', return_value=True):
            test_args = ['launcher.py', 'agent', '--agent-id', 'test-agent', '--server', 'localhost']
            with patch.object(sys, 'argv', test_args):
                launcher.main()
                
        mock_agent_class.assert_called_once()
        print("✅ Launcher 'agent' command dispatch verified")

if __name__ == '__main__':
    print("🧪 Verifying Launcher Functionality...")
    unittest.main(verbosity=2)
