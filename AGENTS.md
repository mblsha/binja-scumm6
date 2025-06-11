# Instructions for Codex agents

This repository uses GitHub Actions to run automated checks. To reproduce these checks locally before submitting code, follow the steps below from the repository root.

1. Install dependencies (only required once):

   ```bash
   python -m pip install -e .[dev]
   ```

2. (Optional) Download demo data so tests have something to run against:

   ```bash
   curl -L -o DOTTDEMO.ZIP https://archive.org/download/DayOfTheTentacleDemo/DOTTDEMO.ZIP || echo "Demo download failed, tests will be skipped"
   if [ -f DOTTDEMO.ZIP ]; then
       unzip -q DOTTDEMO.ZIP
       python converter/cli.py DOTTDEMO.000 DOTTDEMO.001 -o DOTTDEMO.bsc6 || echo "Demo conversion failed, tests will be skipped"
   fi
   ```

3. Run the checkers **in the following order**:

   ```bash
   ruff check
   bash run_mypy.sh
   pytest --cov=src --cov-report=xml --cov-report=term
   ```

Ensure all commands complete successfully before committing your changes.
