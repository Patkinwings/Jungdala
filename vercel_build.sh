#!/bin/bash
set -x  # This will print each command as it's executed
pip freeze  # This will show all installed packages
pip uninstall -y psycopg2 psycopg2-binary
pip install -r requirements.txt
pip freeze  # This will show installed packages after our installation