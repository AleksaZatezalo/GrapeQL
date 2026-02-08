"""
GrapeQL Configuration File Support
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Load GrapeQL settings from .grapeql.yaml configuration file.
             Allows users to define defaults without long CLI arguments.
"""

import os
import yaml
from typing import Dict, List, Optional, Any


class ConfigLoader:
    """
    Load and manage GrapeQL configuration from .grapeql.yaml or grapeql.conf files.

    Configuration file format (.grapeql.yaml):
        api: https://api.example.com/graphql
        modules:
          - fingerprint
          - info
          - injection
        auth: "Bearer token123"
        auth-type: "Bearer"
        proxy: "localhost:8080"
        test-cases: /custom/test/cases
        log-file: scan.log
        report: report.md
        report-format: markdown

    Precedence: CLI args > .grapeql.yaml in cwd > .grapeql.yaml in home dir
    """

    def __init__(self):
        self.config: Dict[str, Any] = {}

    def load_config(self, explicit_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file.

        Args:
            explicit_path: Optional path to config file. If None, searches for
                          .grapeql.yaml in cwd and home directory.

        Returns:
            Dictionary of configuration values.
        """
        config_files = []

        if explicit_path:
            config_files.append(explicit_path)
        else:
            # Search for config files in order of precedence
            cwd_config = os.path.join(os.getcwd(), ".grapeql.yaml")
            home_config = os.path.join(os.path.expanduser("~"), ".grapeql.yaml")
            config_files = [cwd_config, home_config]

        for config_file in config_files:
            if os.path.isfile(config_file):
                return self._parse_config(config_file)

        return {}

    @staticmethod
    def _parse_config(path: str) -> Dict[str, Any]:
        """Parse a YAML configuration file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                return {}
            return data
        except Exception as e:
            print(f"[!] Error loading config file {path}: {e}")
            return {}

    @staticmethod
    def merge_with_args(config: Dict[str, Any], args: Any) -> Any:
        """
        Merge configuration file defaults with CLI arguments.
        CLI arguments take precedence over config file.

        Args:
            config: Configuration dictionary from file
            args: Parsed CLI arguments (argparse Namespace)

        Returns:
            Updated arguments with config file defaults applied
        """
        # List of argument names to consider for merging
        config_keys = {
            "api": "api",
            "modules": "modules",
            "auth": "auth",
            "auth-type": "auth_type",
            "auth_type": "auth_type",
            "cookie": "cookie",
            "proxy": "proxy",
            "username": "username",
            "password": "password",
            "log-file": "log_file",
            "log_file": "log_file",
            "report": "report",
            "report-format": "report_format",
            "report_format": "report_format",
            "test-cases": "test_cases",
            "test_cases": "test_cases",
            "schema-file": "schema_file",
            "schema_file": "schema_file",
            "listener-ip": "listener_ip",
            "listener_ip": "listener_ip",
            "listener-port": "listener_port",
            "listener_port": "listener_port",
            "ai-key": "ai_key",
            "ai_key": "ai_key",
            "ai-message": "ai_message",
            "ai_message": "ai_message",
            "include": "include",
        }

        for config_key, arg_key in config_keys.items():
            # Use config value if CLI argument not explicitly provided
            config_value = config.get(config_key)
            if config_value is not None:
                current_arg_value = getattr(args, arg_key, None)

                # Only override if arg not provided or is default
                if current_arg_value is None:
                    setattr(args, arg_key, config_value)
                elif isinstance(current_arg_value, list) and isinstance(
                    config_value, list
                ):
                    # For list args (modules, include), merge only if default
                    if not current_arg_value:
                        setattr(args, arg_key, config_value)

        return args
