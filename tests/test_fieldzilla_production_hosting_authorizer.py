"""Include the production-hosting safety contract in required central regression."""

import importlib.util
from pathlib import Path
import unittest


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    path = Path(__file__).resolve().parents[1] / "actions/fieldzilla-production-hosting/test_authorize.py"
    spec = importlib.util.spec_from_file_location("fieldzilla_production_authorizer_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
