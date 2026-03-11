#!/usr/bin/env bash
set -uo pipefail

# Tests for scripts/detect-stack.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECT_STACK="$SCRIPT_DIR/../scripts/detect-stack.sh"

source "$SCRIPT_DIR/test-helpers.sh"

echo "  Testing: detect-stack.sh"

# Ensure the script exists and is executable
if [[ ! -f "$DETECT_STACK" ]]; then
    echo "  ERROR: detect-stack.sh not found at $DETECT_STACK"
    exit 1
fi
chmod +x "$DETECT_STACK"

# ============================================================
# Test: Node.js project detection
# ============================================================
test_nodejs_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/node-project"
    mkdir -p "$project_dir/src"

    cat > "$project_dir/package.json" <<'FIXTURE'
{
  "name": "test-app",
  "version": "1.0.0",
  "main": "src/index.js",
  "dependencies": {
    "express": "^4.18.0"
  }
}
FIXTURE
    echo "const express = require('express');" > "$project_dir/src/index.js"
    touch "$project_dir/package-lock.json"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "nodejs: output is valid JSON"
    assert_json_array_contains "$output" "languages" "javascript" "nodejs: detects javascript language"
    assert_json_array_contains "$output" "frameworks" "express" "nodejs: detects express framework"
    assert_json_value "$output" "package_manager" "npm" "nodejs: detects npm as package manager"
    assert_json_value "$output" "has_dockerfile" "false" "nodejs: no dockerfile detected"
    assert_json_array_contains "$output" "entry_points" "src/index.js" "nodejs: detects entry point"

    teardown_test_dir
}

# ============================================================
# Test: Python project detection
# ============================================================
test_python_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/python-project"
    mkdir -p "$project_dir/src"

    cat > "$project_dir/requirements.txt" <<'FIXTURE'
django==4.2
djangorestframework==3.14
gunicorn==21.2.0
FIXTURE
    echo "print('hello')" > "$project_dir/src/main.py"
    echo "print('app')" > "$project_dir/manage.py"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "python: output is valid JSON"
    assert_json_array_contains "$output" "languages" "python" "python: detects python language"
    assert_json_array_contains "$output" "frameworks" "django" "python: detects django framework"
    assert_json_value "$output" "package_manager" "pip" "python: detects pip as package manager"
    assert_json_array_contains "$output" "entry_points" "manage.py" "python: detects manage.py entry point"

    teardown_test_dir
}

# ============================================================
# Test: PHP project detection
# ============================================================
test_php_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/php-project"
    mkdir -p "$project_dir/public"

    cat > "$project_dir/composer.json" <<'FIXTURE'
{
  "name": "test/app",
  "require": {
    "laravel/framework": "^10.0"
  }
}
FIXTURE
    echo "<?php echo 'hello'; ?>" > "$project_dir/index.php"
    echo "<?php echo 'public'; ?>" > "$project_dir/public/index.php"
    touch "$project_dir/artisan"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "php: output is valid JSON"
    assert_json_array_contains "$output" "languages" "php" "php: detects php language"
    assert_json_array_contains "$output" "frameworks" "laravel" "php: detects laravel framework"
    assert_json_value "$output" "package_manager" "composer" "php: detects composer as package manager"
    assert_json_array_contains "$output" "entry_points" "public/index.php" "php: detects public/index.php entry point"
    assert_json_array_contains "$output" "entry_points" "artisan" "php: detects artisan entry point"

    teardown_test_dir
}

# ============================================================
# Test: Go project detection
# ============================================================
test_go_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/go-project"
    mkdir -p "$project_dir/cmd/server"

    cat > "$project_dir/go.mod" <<'FIXTURE'
module github.com/example/app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
)
FIXTURE
    echo 'package main' > "$project_dir/main.go"
    echo 'package main' > "$project_dir/cmd/server/main.go"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "go: output is valid JSON"
    assert_json_array_contains "$output" "languages" "go" "go: detects go language"
    assert_json_array_contains "$output" "frameworks" "gin" "go: detects gin framework"
    assert_json_value "$output" "package_manager" "go" "go: detects go as package manager"
    assert_json_array_contains "$output" "entry_points" "main.go" "go: detects main.go entry point"

    teardown_test_dir
}

# ============================================================
# Test: Mixed project (Node.js + Docker)
# ============================================================
test_mixed_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/mixed-project"
    mkdir -p "$project_dir/src"

    cat > "$project_dir/package.json" <<'FIXTURE'
{
  "name": "mixed-app",
  "dependencies": {
    "react": "^18.0.0",
    "next": "^14.0.0"
  }
}
FIXTURE
    echo "export default function Home() {}" > "$project_dir/src/index.js"
    touch "$project_dir/Dockerfile"
    touch "$project_dir/docker-compose.yml"
    touch "$project_dir/yarn.lock"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "mixed: output is valid JSON"
    assert_json_array_contains "$output" "languages" "javascript" "mixed: detects javascript"
    assert_json_array_contains "$output" "frameworks" "react" "mixed: detects react"
    assert_json_array_contains "$output" "frameworks" "nextjs" "mixed: detects nextjs"
    assert_json_value "$output" "has_dockerfile" "true" "mixed: detects Dockerfile"
    assert_json_value "$output" "has_docker_compose" "true" "mixed: detects docker-compose"
    assert_json_value "$output" "package_manager" "yarn" "mixed: detects yarn from lock file"

    teardown_test_dir
}

# ============================================================
# Test: Empty directory
# ============================================================
test_empty_directory() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/empty-project"
    mkdir -p "$project_dir"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "empty: output is valid JSON"
    assert_json_value "$output" "package_manager" "null" "empty: package_manager is null"
    assert_json_value "$output" "has_dockerfile" "false" "empty: no dockerfile"
    assert_json_value "$output" "has_docker_compose" "false" "empty: no docker-compose"
    assert_json_array_length "$output" "languages" "0" "empty: no languages detected"
    assert_json_array_length "$output" "frameworks" "0" "empty: no frameworks detected"
    assert_json_array_length "$output" "entry_points" "0" "empty: no entry points detected"

    teardown_test_dir
}

# ============================================================
# Test: Invalid directory returns error
# ============================================================
test_invalid_directory() {
    local exit_code=0
    bash "$DETECT_STACK" "/nonexistent/path/that/does/not/exist" 2>/dev/null || exit_code=$?
    assert_equals "1" "$exit_code" "invalid_dir: exits with code 1 for missing directory"
}

# ============================================================
# Test: TypeScript project via tsconfig.json
# ============================================================
test_typescript_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/ts-project"
    mkdir -p "$project_dir/src"

    cat > "$project_dir/package.json" <<'FIXTURE'
{
  "name": "ts-app",
  "dependencies": {
    "@nestjs/core": "^10.0.0"
  }
}
FIXTURE
    echo '{}' > "$project_dir/tsconfig.json"
    echo "console.log('hello');" > "$project_dir/src/main.ts"
    touch "$project_dir/pnpm-lock.yaml"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "typescript: output is valid JSON"
    assert_json_array_contains "$output" "languages" "typescript" "typescript: detects typescript"
    assert_json_array_contains "$output" "frameworks" "nestjs" "typescript: detects nestjs"
    assert_json_value "$output" "package_manager" "pnpm" "typescript: detects pnpm from lock file"
    assert_json_array_contains "$output" "entry_points" "src/main.ts" "typescript: detects src/main.ts entry point"

    teardown_test_dir
}

# ============================================================
# Test: Python with Poetry
# ============================================================
test_python_poetry_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/poetry-project"
    mkdir -p "$project_dir"

    cat > "$project_dir/pyproject.toml" <<'FIXTURE'
[tool.poetry]
name = "my-app"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.100.0"
FIXTURE
    touch "$project_dir/poetry.lock"
    echo "print('main')" > "$project_dir/app.py"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "poetry: output is valid JSON"
    assert_json_array_contains "$output" "languages" "python" "poetry: detects python"
    assert_json_array_contains "$output" "frameworks" "fastapi" "poetry: detects fastapi"
    assert_json_value "$output" "package_manager" "poetry" "poetry: detects poetry as package manager"
    assert_json_array_contains "$output" "entry_points" "app.py" "poetry: detects app.py entry point"

    teardown_test_dir
}

# ============================================================
# Test: Dockerfile in subdirectory
# ============================================================
test_dockerfile_in_subdir() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/docker-sub-project"
    mkdir -p "$project_dir/deploy"

    echo "FROM node:18" > "$project_dir/deploy/Dockerfile"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "docker_subdir: output is valid JSON"
    assert_json_value "$output" "has_dockerfile" "true" "docker_subdir: detects Dockerfile in subdirectory"

    teardown_test_dir
}

# ============================================================
# Test: Ruby project detection
# ============================================================
test_ruby_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/ruby-project"
    mkdir -p "$project_dir"

    cat > "$project_dir/Gemfile" <<'FIXTURE'
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg'
FIXTURE
    echo "puts 'hello'" > "$project_dir/app.rb"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "ruby: output is valid JSON"
    assert_json_array_contains "$output" "languages" "ruby" "ruby: detects ruby language"
    assert_json_array_contains "$output" "frameworks" "rails" "ruby: detects rails framework"
    assert_json_value "$output" "package_manager" "bundler" "ruby: detects bundler as package manager"

    teardown_test_dir
}

# ============================================================
# Test: Rust project detection
# ============================================================
test_rust_project() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/rust-project"
    mkdir -p "$project_dir/src"

    cat > "$project_dir/Cargo.toml" <<'FIXTURE'
[package]
name = "my-app"
version = "0.1.0"
edition = "2021"
FIXTURE
    echo "fn main() {}" > "$project_dir/src/main.rs"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "rust: output is valid JSON"
    assert_json_array_contains "$output" "languages" "rust" "rust: detects rust language"
    assert_json_value "$output" "package_manager" "cargo" "rust: detects cargo as package manager"
    assert_json_array_contains "$output" "entry_points" "src/main.rs" "rust: detects src/main.rs entry point"

    teardown_test_dir
}

# ============================================================
# Test: Compose variants (compose.yml, compose.yaml)
# ============================================================
test_compose_yaml_variant() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/compose-project"
    mkdir -p "$project_dir"

    touch "$project_dir/compose.yaml"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "compose_variant: output is valid JSON"
    assert_json_value "$output" "has_docker_compose" "true" "compose_variant: detects compose.yaml"

    teardown_test_dir
}

# ============================================================
# Test: package.json main field as entry point
# ============================================================
test_package_json_main_field() {
    setup_test_dir
    local project_dir="$TEST_TEMP_DIR/main-field-project"
    mkdir -p "$project_dir/lib"

    cat > "$project_dir/package.json" <<'FIXTURE'
{
  "name": "lib-app",
  "main": "lib/entry.js",
  "dependencies": {}
}
FIXTURE
    echo "module.exports = {};" > "$project_dir/lib/entry.js"

    local output
    output="$(bash "$DETECT_STACK" "$project_dir")"

    assert_valid_json "$output" "main_field: output is valid JSON"
    assert_json_array_contains "$output" "entry_points" "lib/entry.js" "main_field: detects main field entry point"

    teardown_test_dir
}

# --- Run all tests ---

test_nodejs_project
test_python_project
test_php_project
test_go_project
test_mixed_project
test_empty_directory
test_invalid_directory
test_typescript_project
test_python_poetry_project
test_dockerfile_in_subdir
test_ruby_project
test_rust_project
test_compose_yaml_variant
test_package_json_main_field

print_summary
