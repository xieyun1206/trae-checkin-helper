#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_tests.py — 运行全部单元测试（无网络依赖）。

用法：python3 tests/run_tests.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

if __name__ == "__main__":
    suite = unittest.TestLoader().discover(
        os.path.dirname(os.path.abspath(__file__)), pattern="test_*.py"
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
