#!/bin/sh
exec python3 "$(dirname "$0")/fake_ida_runner.py" "$@"
