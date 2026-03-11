#!/usr/bin/env bash
set -euo pipefail

# Prepares Shannon for scanning a target project.
# Creates a symlink in Shannon's repos/ directory and validates the environment.
#
# Required environment variables:
#   SHANNON_PATH       - Path to the Shannon installation directory
#   TARGET_REPO_PATH   - Path to the target repository to scan
#   TARGET_REPO_NAME   - Name to use for the repo within Shannon
#
# Returns 0 on success, 1 on failure (errors written to stderr).

# --- Validate required environment variables ---

if [[ -z "${SHANNON_PATH:-}" ]]; then
    echo "Error: SHANNON_PATH is not set. Set it to the Shannon installation directory." >&2
    exit 1
fi

if [[ -z "${TARGET_REPO_PATH:-}" ]]; then
    echo "Error: TARGET_REPO_PATH is not set. Set it to the target repository path." >&2
    exit 1
fi

if [[ -z "${TARGET_REPO_NAME:-}" ]]; then
    echo "Error: TARGET_REPO_NAME is not set. Set it to the desired repo name for Shannon." >&2
    exit 1
fi

# --- Resolve paths ---

SHANNON_PATH="$(cd "$SHANNON_PATH" && pwd)"
TARGET_REPO_PATH="$(cd "$TARGET_REPO_PATH" && pwd)"

# --- Validate Shannon installation ---

if [[ ! -x "$SHANNON_PATH/shannon" ]]; then
    echo "Error: Shannon binary not found or not executable at $SHANNON_PATH/shannon" >&2
    echo "Ensure Shannon is properly installed and the binary has execute permissions." >&2
    exit 1
fi

echo "Shannon installation validated at: $SHANNON_PATH" >&2

# --- Validate Docker is running ---

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is not installed. Shannon requires Docker to run." >&2
    echo "Install Docker: https://docs.docker.com/get-docker/" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running. Start Docker and try again." >&2
    exit 1
fi

echo "Docker is running." >&2

# --- Validate target repository ---

if [[ ! -d "$TARGET_REPO_PATH" ]]; then
    echo "Error: Target repository not found: $TARGET_REPO_PATH" >&2
    exit 1
fi

if [[ ! -d "$TARGET_REPO_PATH/.git" ]]; then
    echo "Warning: Target path does not appear to be a git repository: $TARGET_REPO_PATH" >&2
    echo "Shannon may require a git repository for source analysis." >&2
fi

# --- Create repos directory if needed ---

REPOS_DIR="$SHANNON_PATH/repos"
if [[ ! -d "$REPOS_DIR" ]]; then
    mkdir -p "$REPOS_DIR"
    echo "Created repos directory: $REPOS_DIR" >&2
fi

# --- Create or update symlink ---

LINK_PATH="$REPOS_DIR/$TARGET_REPO_NAME"

if [[ -L "$LINK_PATH" ]]; then
    # Symlink exists — check if it points to the right place
    existing_target="$(readlink "$LINK_PATH" || true)"
    if [[ "$existing_target" == "$TARGET_REPO_PATH" ]]; then
        echo "Symlink already exists and points to correct target." >&2
    else
        rm "$LINK_PATH"
        ln -s "$TARGET_REPO_PATH" "$LINK_PATH"
        echo "Updated symlink: $LINK_PATH -> $TARGET_REPO_PATH" >&2
    fi
elif [[ -e "$LINK_PATH" ]]; then
    echo "Error: $LINK_PATH already exists and is not a symlink. Remove it manually." >&2
    exit 1
else
    ln -s "$TARGET_REPO_PATH" "$LINK_PATH"
    echo "Created symlink: $LINK_PATH -> $TARGET_REPO_PATH" >&2
fi

# --- Summary ---

echo "Shannon setup complete." >&2
echo "  Shannon path : $SHANNON_PATH" >&2
echo "  Repo link    : $LINK_PATH -> $TARGET_REPO_PATH" >&2
echo "  Repo name    : $TARGET_REPO_NAME" >&2

exit 0
