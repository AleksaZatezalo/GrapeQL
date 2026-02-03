"""
GrapeQL Test Case Loader
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Loads test case definitions from a directory of YAML files.
             Each module has its own subdirectory under the test_cases root.

Directory layout expected:

    test_cases/
    ├── fingerprint/
    │   └── engines.yaml
    ├── injection/
    │   ├── sqli.yaml
    │   └── command.yaml
    ├── info/
    │   └── checks.yaml
    └── dos/
        └── attacks.yaml
"""

import os
import glob
from typing import Dict, List, Any, Optional

import yaml


class TestCaseLoader:
    """
    Discovers and loads YAML test case files for a given module.

    Usage:
        loader = TestCaseLoader("/path/to/test_cases")
        sqli_cases  = loader.load_module("injection")    # merges all YAMLs in injection/
        dos_cases   = loader.load_module("dos")
        single_file = loader.load_file("injection/sqli.yaml")
    """

    def __init__(self, test_cases_dir: str):
        """
        Args:
            test_cases_dir: Root directory containing per-module subdirectories.
        """
        self.root = os.path.abspath(test_cases_dir)
        if not os.path.isdir(self.root):
            raise FileNotFoundError(
                f"Test cases directory not found: {self.root}"
            )

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def load_module(self, module_name: str) -> List[Dict[str, Any]]:
        """
        Load and merge all YAML files under ``<root>/<module_name>/``.

        Each YAML file is expected to have a top-level ``test_cases`` key
        containing a list of test case dicts.  Files are merged in sorted
        filename order.

        Args:
            module_name: Subdirectory name (e.g. "injection", "dos").

        Returns:
            Merged list of test case dicts.
        """
        module_dir = os.path.join(self.root, module_name)
        if not os.path.isdir(module_dir):
            return []

        merged: List[Dict[str, Any]] = []
        for yaml_path in sorted(glob.glob(os.path.join(module_dir, "*.yaml"))):
            merged.extend(self._parse_file(yaml_path))
        for yaml_path in sorted(glob.glob(os.path.join(module_dir, "*.yml"))):
            merged.extend(self._parse_file(yaml_path))
        return merged

    def load_file(self, relative_path: str) -> List[Dict[str, Any]]:
        """
        Load a single YAML file by path relative to the root.

        Args:
            relative_path: e.g. "injection/sqli.yaml"

        Returns:
            List of test case dicts from that file.
        """
        full_path = os.path.join(self.root, relative_path)
        return self._parse_file(full_path)

    def available_modules(self) -> List[str]:
        """Return names of subdirectories that contain at least one YAML file."""
        modules = []
        for entry in sorted(os.listdir(self.root)):
            subdir = os.path.join(self.root, entry)
            if os.path.isdir(subdir):
                yamls = glob.glob(os.path.join(subdir, "*.yaml")) + glob.glob(
                    os.path.join(subdir, "*.yml")
                )
                if yamls:
                    modules.append(entry)
        return modules

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_file(path: str) -> List[Dict[str, Any]]:
        """Parse a single YAML file and return its test_cases list."""
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            print(f"[!] YAML parse error in {path}: {exc}")
            return []

        if not isinstance(data, dict):
            return []

        cases = data.get("test_cases", [])
        if not isinstance(cases, list):
            return []
        return cases
