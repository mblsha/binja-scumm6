#!/usr/bin/env fish

# Run all tests for the scumm6 project
# Based on binja_helpers_tmp/run-tests.fish

function build_and_run
    set -l fix_mode $argv[1]
    set -l failures

    echo "🔍 Running ruff..."
    if test "$fix_mode" = "--fix"
        uv run ruff check --fix .
    else
        uv run ruff check .
    end
    if test $status -ne 0
        set -a failures "ruff"
    end

    echo "🔍 Running mypy..."
    set -l mypy_failed false
    echo "  Running mypy with real Binary Ninja (if available)..."
    uv run bash scripts/run_mypy.sh
    if test $status -ne 0
        echo "❌ mypy failed with real Binary Ninja"
        set mypy_failed true
    end

    echo "  Running mypy with mocked Binary Ninja..."
    env FORCE_BINJA_MOCK=1 uv run bash scripts/run_mypy.sh
    if test $status -ne 0
        echo "❌ mypy failed with mocked Binary Ninja"
        set mypy_failed true
    end
    
    if test "$mypy_failed" = true
        set -a failures "mypy"
    end

    echo "🧪 Running pytest..."
    uv run python scripts/run_pytest_direct.py
    if test $status -ne 0
        set -a failures "pytest"
    end

    # Report final status
    if test (count $failures) -eq 0
        echo "Done running tests! ✅ All tests passed"
    else
        echo "Done running tests! ❌ Failures in: "(string join ", " $failures)
    end
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
