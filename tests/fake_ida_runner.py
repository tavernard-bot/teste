# -*- coding: utf-8 -*-
"""Imita a linha de comando do IDA (-A -c -L.. -S.. dll) usando o IDA falso."""
import os
import runpy
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
modo = os.environ.get("FAKE_MODE", "")
script = [a[2:] for a in sys.argv if a.startswith("-S")][0].strip('"')
dll = sys.argv[-1]
if modo == "hang" and "lento" in os.path.basename(dll):
    time.sleep(600)
if modo == "crash" and "quebra" in os.path.basename(dll):
    sys.exit(3)
import mock_ida  # noqa: E402
mock_ida.install()
runpy.run_path(script, run_name="__main__")
