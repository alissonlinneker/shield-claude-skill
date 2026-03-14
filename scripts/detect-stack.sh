#!/usr/bin/env bash
set -euo pipefail

# Detects the technology stack of a project directory.
# Outputs JSON with languages, frameworks, package manager, Docker presence,
# and entry points.
#
# Usage: detect-stack.sh <project-path>

PROJECT_PATH="${1:-.}"

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: directory not found: $PROJECT_PATH" >&2
    exit 1
fi

PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

# --- Helpers ---

json_array() {
    local items=("$@")
    if [[ ${#items[@]} -eq 0 ]]; then
        printf '[]'
        return
    fi
    printf '['
    local first=true
    for item in "${items[@]}"; do
        [[ "$first" == "true" ]] && first=false || printf ','
        printf '"%s"' "$item"
    done
    printf ']'
}

# --- Language Detection ---

detect_languages() {
    local langs=()
    local seen=()

    add_lang() {
        local lang="$1"
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$lang" ]] && return
        done
        seen+=("$lang")
        langs+=("$lang")
    }

    # Check by file extensions (search only first 3 directory levels for speed)
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.js' -not -path '*/node_modules/*' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "javascript"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.ts' -not -path '*/node_modules/*' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "typescript"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.py' -not -path '*/.git/*' -not -path '*/venv/*' -not -path '*/.venv/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "python"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.php' -not -path '*/vendor/*' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "php"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.go' -not -path '*/vendor/*' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "go"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.java' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "java"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.rb' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "ruby"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 -name '*.rs' -not -path '*/.git/*' -not -path '*/target/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "rust"
    fi
    if find "$PROJECT_PATH" -maxdepth 3 \( -name '*.cs' -o -name '*.csproj' \) -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .; then
        add_lang "csharp"
    fi

    # Infer language from package.json if JS frameworks are likely
    [[ -f "$PROJECT_PATH/package.json" ]] && add_lang "javascript"

    # Config-file-based detection
    [[ -f "$PROJECT_PATH/tsconfig.json" ]] && add_lang "typescript"
    [[ -f "$PROJECT_PATH/requirements.txt" || -f "$PROJECT_PATH/pyproject.toml" || -f "$PROJECT_PATH/setup.py" ]] && add_lang "python"
    [[ -f "$PROJECT_PATH/composer.json" ]] && add_lang "php"
    [[ -f "$PROJECT_PATH/go.mod" ]] && add_lang "go"
    [[ -f "$PROJECT_PATH/Gemfile" ]] && add_lang "ruby"
    [[ -f "$PROJECT_PATH/Cargo.toml" ]] && add_lang "rust"

    json_array "${langs[@]+"${langs[@]}"}"
}

# --- Framework Detection ---

detect_frameworks() {
    local frameworks=()
    local seen=()

    add_fw() {
        local fw="$1"
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$fw" ]] && return
        done
        seen+=("$fw")
        frameworks+=("$fw")
    }

    # package.json dependencies
    if [[ -f "$PROJECT_PATH/package.json" ]]; then
        local pkg_content
        pkg_content="$(cat "$PROJECT_PATH/package.json" 2>/dev/null || true)"

        check_pkg_dep() {
            local dep_name="$1"
            local fw_name="$2"
            if echo "$pkg_content" | grep -q "\"$dep_name\""; then
                add_fw "$fw_name"
            fi
        }

        check_pkg_dep "express" "express"
        check_pkg_dep "fastify" "fastify"
        check_pkg_dep "koa" "koa"
        check_pkg_dep "hapi" "hapi"
        check_pkg_dep "nestjs" "nestjs"
        check_pkg_dep "@nestjs/core" "nestjs"
        check_pkg_dep "next" "nextjs"
        check_pkg_dep "nuxt" "nuxtjs"
        check_pkg_dep "react" "react"
        check_pkg_dep "vue" "vue"
        check_pkg_dep "angular" "angular"
        check_pkg_dep "@angular/core" "angular"
        check_pkg_dep "svelte" "svelte"
        check_pkg_dep "gatsby" "gatsby"
        check_pkg_dep "remix" "remix"
        check_pkg_dep "astro" "astro"
        check_pkg_dep "electron" "electron"
    fi

    # Python frameworks
    local py_deps=""
    if [[ -f "$PROJECT_PATH/requirements.txt" ]]; then
        py_deps="$(cat "$PROJECT_PATH/requirements.txt" 2>/dev/null || true)"
    fi
    if [[ -f "$PROJECT_PATH/pyproject.toml" ]]; then
        py_deps="$py_deps $(cat "$PROJECT_PATH/pyproject.toml" 2>/dev/null || true)"
    fi
    if [[ -n "$py_deps" ]]; then
        echo "$py_deps" | grep -qi "django" && add_fw "django"
        echo "$py_deps" | grep -qi "flask" && add_fw "flask"
        echo "$py_deps" | grep -qi "fastapi" && add_fw "fastapi"
        echo "$py_deps" | grep -qi "starlette" && add_fw "starlette"
        echo "$py_deps" | grep -qi "tornado" && add_fw "tornado"
        echo "$py_deps" | grep -qi "aiohttp" && add_fw "aiohttp"
    fi

    # PHP frameworks (composer.json)
    if [[ -f "$PROJECT_PATH/composer.json" ]]; then
        local composer_content
        composer_content="$(cat "$PROJECT_PATH/composer.json" 2>/dev/null || true)"
        echo "$composer_content" | grep -q "laravel/framework" && add_fw "laravel"
        echo "$composer_content" | grep -q "symfony/" && add_fw "symfony"
        echo "$composer_content" | grep -q "slim/slim" && add_fw "slim"
        echo "$composer_content" | grep -q "cakephp/cakephp" && add_fw "cakephp"
    fi

    # Go frameworks
    if [[ -f "$PROJECT_PATH/go.mod" ]]; then
        local go_content
        go_content="$(cat "$PROJECT_PATH/go.mod" 2>/dev/null || true)"
        echo "$go_content" | grep -q "github.com/gin-gonic/gin" && add_fw "gin"
        echo "$go_content" | grep -q "github.com/labstack/echo" && add_fw "echo"
        echo "$go_content" | grep -q "github.com/gofiber/fiber" && add_fw "fiber"
        echo "$go_content" | grep -q "github.com/gorilla/mux" && add_fw "gorilla"
    fi

    # Ruby frameworks
    if [[ -f "$PROJECT_PATH/Gemfile" ]]; then
        local gem_content
        gem_content="$(cat "$PROJECT_PATH/Gemfile" 2>/dev/null || true)"
        echo "$gem_content" | grep -q "'rails'" && add_fw "rails"
        echo "$gem_content" | grep -q '"rails"' && add_fw "rails"
        echo "$gem_content" | grep -q "'sinatra'" && add_fw "sinatra"
        echo "$gem_content" | grep -q '"sinatra"' && add_fw "sinatra"
    fi

    # Java frameworks
    if [[ -f "$PROJECT_PATH/pom.xml" ]]; then
        local pom_content
        pom_content="$(cat "$PROJECT_PATH/pom.xml" 2>/dev/null || true)"
        echo "$pom_content" | grep -q "spring-boot" && add_fw "spring-boot"
        echo "$pom_content" | grep -q "quarkus" && add_fw "quarkus"
    fi
    if [[ -f "$PROJECT_PATH/build.gradle" ]] || [[ -f "$PROJECT_PATH/build.gradle.kts" ]]; then
        local gradle_content
        gradle_content="$(cat "$PROJECT_PATH"/build.gradle* 2>/dev/null || true)"
        echo "$gradle_content" | grep -q "spring-boot" && add_fw "spring-boot"
        echo "$gradle_content" | grep -q "quarkus" && add_fw "quarkus"
    fi

    json_array "${frameworks[@]+"${frameworks[@]}"}"
}

# --- Package Manager Detection ---

detect_package_manager() {
    # Check lock files first (most definitive)
    if [[ -f "$PROJECT_PATH/pnpm-lock.yaml" ]]; then
        echo "pnpm"
    elif [[ -f "$PROJECT_PATH/yarn.lock" ]]; then
        echo "yarn"
    elif [[ -f "$PROJECT_PATH/package-lock.json" ]]; then
        echo "npm"
    elif [[ -f "$PROJECT_PATH/bun.lockb" ]]; then
        echo "bun"
    elif [[ -f "$PROJECT_PATH/package.json" ]]; then
        echo "npm"
    elif [[ -f "$PROJECT_PATH/Pipfile.lock" ]] || [[ -f "$PROJECT_PATH/Pipfile" ]]; then
        echo "pipenv"
    elif [[ -f "$PROJECT_PATH/poetry.lock" ]] || grep -q '\[tool.poetry\]' "$PROJECT_PATH/pyproject.toml" 2>/dev/null; then
        echo "poetry"
    elif [[ -f "$PROJECT_PATH/requirements.txt" ]] || [[ -f "$PROJECT_PATH/setup.py" ]] || [[ -f "$PROJECT_PATH/pyproject.toml" ]]; then
        echo "pip"
    elif [[ -f "$PROJECT_PATH/composer.lock" ]] || [[ -f "$PROJECT_PATH/composer.json" ]]; then
        echo "composer"
    elif [[ -f "$PROJECT_PATH/Gemfile.lock" ]] || [[ -f "$PROJECT_PATH/Gemfile" ]]; then
        echo "bundler"
    elif [[ -f "$PROJECT_PATH/pom.xml" ]]; then
        echo "maven"
    elif [[ -f "$PROJECT_PATH/build.gradle" ]] || [[ -f "$PROJECT_PATH/build.gradle.kts" ]]; then
        echo "gradle"
    elif ls "$PROJECT_PATH"/*.csproj 1>/dev/null 2>&1 || ls "$PROJECT_PATH"/*.sln 1>/dev/null 2>&1; then
        echo "dotnet"
    elif [[ -f "$PROJECT_PATH/go.mod" ]]; then
        echo "go"
    elif [[ -f "$PROJECT_PATH/Cargo.lock" ]] || [[ -f "$PROJECT_PATH/Cargo.toml" ]]; then
        echo "cargo"
    else
        echo "null"
    fi
}

# --- All Package Managers Detection (polyglot support) ---

detect_all_package_managers() {
    local managers=()
    local seen=()

    add_pm() {
        local pm="$1"
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$pm" ]] && return
        done
        seen+=("$pm")
        managers+=("$pm")
    }

    # JavaScript ecosystem
    [[ -f "$PROJECT_PATH/pnpm-lock.yaml" ]] && add_pm "pnpm"
    [[ -f "$PROJECT_PATH/yarn.lock" ]] && add_pm "yarn"
    [[ -f "$PROJECT_PATH/package-lock.json" ]] && add_pm "npm"
    [[ -f "$PROJECT_PATH/bun.lockb" ]] && add_pm "bun"
    # Only add npm as fallback if package.json exists but no specific JS lock file
    if [[ -f "$PROJECT_PATH/package.json" ]]; then
        local has_js_pm=false
        for s in "${seen[@]+"${seen[@]}"}"; do
            case "$s" in pnpm|yarn|npm|bun) has_js_pm=true ;; esac
        done
        [[ "$has_js_pm" == "false" ]] && add_pm "npm"
    fi

    # Python ecosystem
    if [[ -f "$PROJECT_PATH/Pipfile.lock" ]] || [[ -f "$PROJECT_PATH/Pipfile" ]]; then
        add_pm "pipenv"
    fi
    if [[ -f "$PROJECT_PATH/poetry.lock" ]] || grep -q '\[tool.poetry\]' "$PROJECT_PATH/pyproject.toml" 2>/dev/null; then
        add_pm "poetry"
    fi
    if [[ -f "$PROJECT_PATH/requirements.txt" ]] || [[ -f "$PROJECT_PATH/setup.py" ]] || [[ -f "$PROJECT_PATH/pyproject.toml" ]]; then
        add_pm "pip"
    fi

    # PHP
    { [[ -f "$PROJECT_PATH/composer.lock" ]] || [[ -f "$PROJECT_PATH/composer.json" ]]; } && add_pm "composer"

    # Ruby
    { [[ -f "$PROJECT_PATH/Gemfile.lock" ]] || [[ -f "$PROJECT_PATH/Gemfile" ]]; } && add_pm "bundler"

    # JVM
    [[ -f "$PROJECT_PATH/pom.xml" ]] && add_pm "maven"
    { [[ -f "$PROJECT_PATH/build.gradle" ]] || [[ -f "$PROJECT_PATH/build.gradle.kts" ]]; } && add_pm "gradle"

    # .NET
    if ls "$PROJECT_PATH"/*.csproj 1>/dev/null 2>&1 || ls "$PROJECT_PATH"/*.sln 1>/dev/null 2>&1; then
        add_pm "dotnet"
    fi

    # Go
    [[ -f "$PROJECT_PATH/go.mod" ]] && add_pm "go"

    # Rust
    { [[ -f "$PROJECT_PATH/Cargo.lock" ]] || [[ -f "$PROJECT_PATH/Cargo.toml" ]]; } && add_pm "cargo"

    json_array "${managers[@]+"${managers[@]}"}"
}

# --- Docker Detection ---

detect_docker() {
    [[ -f "$PROJECT_PATH/Dockerfile" ]] || find "$PROJECT_PATH" -maxdepth 2 -name 'Dockerfile*' -not -path '*/.git/*' -print -quit 2>/dev/null | grep -q .
}

detect_docker_compose() {
    [[ -f "$PROJECT_PATH/docker-compose.yml" ]] || \
    [[ -f "$PROJECT_PATH/docker-compose.yaml" ]] || \
    [[ -f "$PROJECT_PATH/compose.yml" ]] || \
    [[ -f "$PROJECT_PATH/compose.yaml" ]]
}

# --- Entry Points Detection ---

detect_entry_points() {
    local entries=()
    local patterns=(
        "src/index.ts" "src/index.js" "src/index.mjs"
        "src/main.ts" "src/main.js" "src/main.py"
        "src/app.ts" "src/app.js" "src/app.py"
        "index.ts" "index.js" "index.php"
        "app.ts" "app.js" "app.py" "app.php"
        "main.ts" "main.js" "main.py" "main.go"
        "server.ts" "server.js" "server.py"
        "manage.py" "wsgi.py" "asgi.py"
        "cmd/main.go" "cmd/server/main.go"
        "src/main.rs" "src/lib.rs"
        "public/index.php"
        "artisan"
    )

    for pattern in "${patterns[@]}"; do
        if [[ -f "$PROJECT_PATH/$pattern" ]]; then
            entries+=("$pattern")
        fi
    done

    # Also check package.json main/entry fields
    if [[ -f "$PROJECT_PATH/package.json" ]]; then
        local main_field
        main_field="$(grep -o '"main"[[:space:]]*:[[:space:]]*"[^"]*"' "$PROJECT_PATH/package.json" 2>/dev/null | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
        if [[ -n "$main_field" ]] && [[ -f "$PROJECT_PATH/$main_field" ]]; then
            local already_found=false
            for e in "${entries[@]+"${entries[@]}"}"; do
                [[ "$e" == "$main_field" ]] && already_found=true && break
            done
            [[ "$already_found" == "false" ]] && entries+=("$main_field")
        fi
    fi

    json_array "${entries[@]+"${entries[@]}"}"
}

# --- Main Output ---

detected_langs="$(detect_languages)"
detected_fws="$(detect_frameworks)"
pkg_manager="$(detect_package_manager)"
all_pkg_managers="$(detect_all_package_managers)"
has_dockerfile=$(detect_docker && echo "true" || echo "false")
has_compose=$(detect_docker_compose && echo "true" || echo "false")
detected_entries="$(detect_entry_points)"

printf '{\n'
printf '  "languages": %s,\n' "$detected_langs"
printf '  "frameworks": %s,\n' "$detected_fws"
printf '  "package_manager": %s,\n' "$(if [[ "$pkg_manager" == "null" ]]; then echo "null"; else printf '"%s"' "$pkg_manager"; fi)"
printf '  "all_package_managers": %s,\n' "$all_pkg_managers"
printf '  "has_dockerfile": %s,\n' "$has_dockerfile"
printf '  "has_docker_compose": %s,\n' "$has_compose"
printf '  "entry_points": %s\n' "$detected_entries"
printf '}\n'
