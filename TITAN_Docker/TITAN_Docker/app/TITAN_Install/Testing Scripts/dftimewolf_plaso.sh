#!/bin/bash
# While in the poetry shell, execute dftimewolf upload_ts
. $(cd /opt/dftimewolf ; ~/.local/share/pypoetry/venv/bin/poetry env info --path)/bin/activate && python /opt/dftimewolf/dftimewolf_plaso.py
