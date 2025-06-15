#!/usr/bin/env fish

# Run all tests for the scumm6 project
# Based on binja_helpers_tmp/run-tests.fish

function build_and_run
    set -l fix_mode $argv[1]

    echo "🔍 Running ruff..."
    if test "$fix_mode" = "--fix"
        ruff check --fix .
    else
        ruff check .
    end

    echo "🔍 Running mypy..."
    echo "  Running mypy with real Binary Ninja (if available)..."
    bash scripts/run_mypy.sh
    if test $status -ne 0
        echo "❌ mypy failed with real Binary Ninja"
    end

    echo "  Running mypy with mocked Binary Ninja..."
    env FORCE_BINJA_MOCK=1 bash scripts/run_mypy.sh
    if test $status -ne 0
        echo "❌ mypy failed with mocked Binary Ninja"
    end

    echo "🧪 Running pytest..."
    python scripts/run_pytest_direct.py

    echo "✅ All checks passed!"
end

# Parse command line arguments
set -l fix_mode ""
set -l run_once false

for arg in $argv
    switch $arg
        case "--fix"
            set fix_mode "--fix"
        case "--once"
            set run_once true
        case "-h" "--help"
            echo "Usage: $argv[0] [--fix] [--once] [--help]"
            echo "  --fix   Automatically fix ruff issues"
            echo "  --once  Run tests once and exit (don't watch for changes)"
            echo "  --help  Show this help message"
            exit 0
    end
end

# Run once
build_and_run $fix_mode

# Watch for changes and re-run if fswatch is available (unless --once specified)
if not test "$run_once" = true
    if type -q fswatch
        echo "👀 Watching for file changes (Ctrl+C to stop)..."
        while fswatch -1 .
            clear
            echo "🔄 Files changed, re-running tests..."
            build_and_run $fix_mode
            sleep 1
        end
    else
        echo "💡 Install fswatch to automatically re-run tests on file changes"
        echo "💡 Use --once to run tests only once"
    end
end
