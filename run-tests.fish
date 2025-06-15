#!/usr/bin/env fish

# Run all tests for the scumm6 project
# Based on binja_helpers_tmp/run-tests.fish

function build_and_run
    echo "🔍 Running ruff..."
    ruff check .
    
    echo "🔍 Running mypy..."
    bash scripts/run_mypy.sh
    
    echo "🧪 Running pytest with coverage..."
    python scripts/run_pytest_direct.py
    
    echo "✅ All checks passed!"
end

# Run once
build_and_run

# Watch for changes and re-run if fswatch is available
if type -q fswatch
    echo "👀 Watching for file changes (Ctrl+C to stop)..."
    while fswatch -1 .
        clear
        echo "🔄 Files changed, re-running tests..."
        build_and_run
        sleep 1
    end
else
    echo "💡 Install fswatch to automatically re-run tests on file changes"
end