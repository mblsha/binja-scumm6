#!/usr/bin/env fish

# Parse command line arguments
set -l list_only false
set -l include_binja false

for arg in $argv
    switch $arg
        case --list -l
            set list_only true
        case --binja
            set include_binja true
        case --help -h
            echo "Usage: list-project-files.fish [options]"
            echo ""
            echo "Options:"
            echo "  --list, -l    Just list filenames instead of passing to files-to-prompt"
            echo "  --binja       Include files from local Binary Ninja Python API"
            echo "  --help, -h    Show this help message"
            exit 0
        case '*'
            echo "Unknown option: $arg"
            exit 1
    end
end

# Define exclusions
set -l exclusions \
    --exclude scummvm-tools \
    --exclude binja_helpers_tmp/sc62015

# Get all files using fd, respecting .gitignore and custom exclusions
set -l files (fd --type f $exclusions .)

# Add Binary Ninja Python API files if requested
if test "$include_binja" = true
    # Check if Binary Ninja Python API directory exists
    set -l binja_api_path "$HOME/Applications/Binary Ninja.app/Contents/Resources/python"
    if test -d "$binja_api_path"
        # Define allow-list of Binary Ninja files
        set -l binja_allowlist \
            "binaryninja/__init__.py" \
            "binaryninja/architecture.py" \
            "binaryninja/binaryview.py" \
            "binaryninja/lowlevelil.py" \
            "binaryninja/enums.py"

        # Add each allowed file if it exists
        for file in $binja_allowlist
            set -l full_path "$binja_api_path/$file"
            if test -f "$full_path"
                set files $files $full_path
            end
        end
    end
end

if test "$list_only" = true
    # Just list the files
    for file in $files
        echo $file
    end
else
    # Pass files to files-to-prompt --cxml (default behavior)
    files-to-prompt --cxml $files
end
