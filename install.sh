#!/usr/bin/env bash
# Shield — Security Orchestrator
# Install script for required and optional dependencies
# https://github.com/alissonlinneker/shield-claude-skill

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
INSTALLED=0
SKIPPED=0
FAILED=0
TOOLS_STATUS=()

print_banner() {
    echo -e "${BOLD}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║          Shield — Install Script          ║"
    echo "║       Security Orchestrator v0.1.0        ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

detect_os() {
    case "$(uname -s)" in
        Darwin*)  OS="macos" ;;
        Linux*)   OS="linux" ;;
        *)        OS="unknown" ;;
    esac
    echo "$OS"
}

detect_linux_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v snap &>/dev/null; then
        echo "snap"
    else
        echo "unknown"
    fi
}

check_command() {
    command -v "$1" &>/dev/null
}

record_status() {
    local tool="$1"
    local status="$2"
    local note="${3:-}"
    TOOLS_STATUS+=("${tool}|${status}|${note}")
}

install_jq() {
    log_info "Checking jq (JSON processor — required)..."
    if check_command jq; then
        local version
        version=$(jq --version 2>/dev/null || echo "unknown")
        log_success "jq already installed (${version})"
        record_status "jq" "installed" "${version}"
        ((SKIPPED++))
        return
    fi

    log_info "Installing jq..."
    if [[ "$OS" == "macos" ]] && check_command brew; then
        if brew install jq 2>/dev/null; then
            log_success "jq installed via Homebrew"
            record_status "jq" "installed" "via brew"
            ((INSTALLED++))
            return
        fi
    fi

    if [[ "$OS" == "linux" ]]; then
        if check_command apt-get; then
            if sudo apt-get install -y jq 2>/dev/null; then
                log_success "jq installed via apt"
                record_status "jq" "installed" "via apt"
                ((INSTALLED++))
                return
            fi
        elif check_command dnf; then
            if sudo dnf install -y jq 2>/dev/null; then
                log_success "jq installed via dnf"
                record_status "jq" "installed" "via dnf"
                ((INSTALLED++))
                return
            fi
        fi
    fi

    log_error "Could not install jq. This is required. Install manually: https://jqlang.github.io/jq/download/"
    record_status "jq" "missing" "REQUIRED — install manually"
    ((FAILED++))
}

install_semgrep() {
    log_info "Checking Semgrep (SAST engine)..."
    if check_command semgrep; then
        local version
        version=$(semgrep --version 2>/dev/null || echo "unknown")
        log_success "Semgrep already installed (${version})"
        record_status "Semgrep" "installed" "${version}"
        ((SKIPPED++))
        return
    fi

    log_info "Installing Semgrep..."
    if [[ "$OS" == "macos" ]] && check_command brew; then
        if brew install semgrep 2>/dev/null; then
            log_success "Semgrep installed via Homebrew"
            record_status "Semgrep" "installed" "via brew"
            ((INSTALLED++))
            return
        fi
    fi

    if check_command pip3; then
        if pip3 install semgrep 2>/dev/null; then
            log_success "Semgrep installed via pip3"
            record_status "Semgrep" "installed" "via pip3"
            ((INSTALLED++))
            return
        fi
    elif check_command pip; then
        if pip install semgrep 2>/dev/null; then
            log_success "Semgrep installed via pip"
            record_status "Semgrep" "installed" "via pip"
            ((INSTALLED++))
            return
        fi
    fi

    log_error "Could not install Semgrep. Install manually: https://semgrep.dev/docs/getting-started/"
    record_status "Semgrep" "missing" "install manually"
    ((FAILED++))
}

install_gitleaks() {
    log_info "Checking gitleaks (secrets scanner)..."
    if check_command gitleaks; then
        local version
        version=$(gitleaks version 2>/dev/null || echo "unknown")
        log_success "gitleaks already installed (${version})"
        record_status "gitleaks" "installed" "${version}"
        ((SKIPPED++))
        return
    fi

    log_info "Installing gitleaks..."
    if [[ "$OS" == "macos" ]] && check_command brew; then
        if brew install gitleaks 2>/dev/null; then
            log_success "gitleaks installed via Homebrew"
            record_status "gitleaks" "installed" "via brew"
            ((INSTALLED++))
            return
        fi
    fi

    if [[ "$OS" == "linux" ]]; then
        if check_command snap; then
            if sudo snap install gitleaks 2>/dev/null; then
                log_success "gitleaks installed via snap"
                record_status "gitleaks" "installed" "via snap"
                ((INSTALLED++))
                return
            fi
        fi

        # Try downloading binary from GitHub releases
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64)  arch="x64" ;;
            aarch64) arch="arm64" ;;
        esac
        log_info "Attempting to download gitleaks binary for linux/${arch}..."
        local latest_url="https://github.com/gitleaks/gitleaks/releases/latest"
        if check_command curl; then
            local download_url
            download_url=$(curl -sI "$latest_url" | grep -i "^location:" | awk '{print $2}' | tr -d '\r')
            if [[ -n "$download_url" ]]; then
                local tag
                tag=$(basename "$download_url")
                local bin_url="https://github.com/gitleaks/gitleaks/releases/download/${tag}/gitleaks_${tag#v}_linux_${arch}.tar.gz"
                if curl -sL "$bin_url" | tar xz -C /tmp gitleaks 2>/dev/null; then
                    sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
                    sudo chmod +x /usr/local/bin/gitleaks
                    log_success "gitleaks installed from GitHub releases"
                    record_status "gitleaks" "installed" "via binary"
                    ((INSTALLED++))
                    return
                fi
            fi
        fi
    fi

    log_error "Could not install gitleaks. Install manually: https://github.com/gitleaks/gitleaks#installing"
    record_status "gitleaks" "missing" "install manually"
    ((FAILED++))
}

install_trivy() {
    log_info "Checking Trivy (container/IaC scanner)..."
    if check_command trivy; then
        local version
        version=$(trivy --version 2>/dev/null | head -1 || echo "unknown")
        log_success "Trivy already installed (${version})"
        record_status "Trivy" "installed" "${version}"
        ((SKIPPED++))
        return
    fi

    log_info "Installing Trivy..."
    if [[ "$OS" == "macos" ]] && check_command brew; then
        if brew install trivy 2>/dev/null; then
            log_success "Trivy installed via Homebrew"
            record_status "Trivy" "installed" "via brew"
            ((INSTALLED++))
            return
        fi
    fi

    if [[ "$OS" == "linux" ]]; then
        if check_command apt-get; then
            log_info "Adding Aqua Security repository..."
            if sudo apt-get install -y wget apt-transport-https gnupg lsb-release 2>/dev/null && \
               wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null && \
               echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list && \
               sudo apt-get update 2>/dev/null && \
               sudo apt-get install -y trivy 2>/dev/null; then
                log_success "Trivy installed via apt"
                record_status "Trivy" "installed" "via apt"
                ((INSTALLED++))
                return
            fi
        fi

        if check_command snap; then
            if sudo snap install trivy 2>/dev/null; then
                log_success "Trivy installed via snap"
                record_status "Trivy" "installed" "via snap"
                ((INSTALLED++))
                return
            fi
        fi
    fi

    log_warn "Could not install Trivy. This is optional. Install manually: https://trivy.dev/"
    record_status "Trivy" "missing" "optional — install manually"
    ((FAILED++))
}

check_docker() {
    log_info "Checking Docker (required for Shannon pentest)..."
    if check_command docker; then
        if docker info &>/dev/null; then
            log_success "Docker is installed and running"
            record_status "Docker" "installed" "running"
        else
            log_warn "Docker is installed but not running. Start Docker to use Shannon."
            record_status "Docker" "installed" "not running"
        fi
        ((SKIPPED++))
    else
        log_warn "Docker is not installed. Required for autonomous pentesting (Shannon)."
        log_warn "Install from: https://www.docker.com/get-started"
        record_status "Docker" "missing" "optional — needed for Shannon"
        ((FAILED++))
    fi
}

install_shannon() {
    log_info "Checking Shannon (autonomous pentest engine)..."
    local shannon_dir="${HOME}/shannon"

    if [[ -d "$shannon_dir" ]]; then
        log_success "Shannon already cloned at ${shannon_dir}"
        record_status "Shannon" "installed" "${shannon_dir}"
        ((SKIPPED++))
        return
    fi

    echo ""
    echo -e "${YELLOW}Shannon is the autonomous penetration testing engine.${NC}"
    echo -e "It requires Docker and will be cloned to ${BOLD}${shannon_dir}${NC}"
    echo ""
    read -rp "Clone Shannon now? [y/N] " response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        if check_command git; then
            if git clone https://github.com/KeygraphHQ/shannon.git "$shannon_dir" 2>/dev/null; then
                log_success "Shannon cloned to ${shannon_dir}"
                record_status "Shannon" "installed" "${shannon_dir}"
                ((INSTALLED++))
            else
                log_error "Failed to clone Shannon"
                record_status "Shannon" "missing" "clone failed"
                ((FAILED++))
            fi
        else
            log_error "git is not installed. Cannot clone Shannon."
            record_status "Shannon" "missing" "git not found"
            ((FAILED++))
        fi
    else
        log_info "Skipping Shannon. You can clone it later:"
        log_info "  git clone https://github.com/KeygraphHQ/shannon.git ~/shannon"
        record_status "Shannon" "skipped" "user declined"
        ((SKIPPED++))
    fi
}

check_pip_audit() {
    log_info "Checking pip-audit (Python dependency auditor)..."
    if check_command pip-audit; then
        log_success "pip-audit is available"
        record_status "pip-audit" "installed" ""
        ((SKIPPED++))
    else
        if check_command pip3; then
            log_info "Installing pip-audit..."
            if pip3 install pip-audit 2>/dev/null; then
                log_success "pip-audit installed via pip3"
                record_status "pip-audit" "installed" "via pip3"
                ((INSTALLED++))
            else
                log_warn "Could not install pip-audit. Optional for Python projects."
                record_status "pip-audit" "missing" "optional"
                ((FAILED++))
            fi
        else
            log_info "pip3 not found — pip-audit skipped (only needed for Python projects)"
            record_status "pip-audit" "skipped" "no pip3"
            ((SKIPPED++))
        fi
    fi
}

check_node() {
    log_info "Checking Node.js / npm (JS dependency auditor)..."
    if check_command npm; then
        local version
        version=$(npm --version 2>/dev/null || echo "unknown")
        log_success "npm is available (${version})"
        record_status "npm" "installed" "${version}"
    else
        log_info "npm not found — skipping (only needed for Node.js projects)"
        record_status "npm" "skipped" "not needed if no JS"
    fi
    ((SKIPPED++))
}

check_composer() {
    log_info "Checking Composer (PHP dependency auditor)..."
    if check_command composer; then
        local version
        version=$(composer --version 2>/dev/null | head -1 || echo "unknown")
        log_success "Composer is available (${version})"
        record_status "Composer" "installed" "${version}"
    else
        log_info "Composer not found — skipping (only needed for PHP projects)"
        record_status "Composer" "skipped" "not needed if no PHP"
    fi
    ((SKIPPED++))
}

print_summary() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║            Installation Summary           ║${NC}"
    echo -e "${BOLD}╠═══════════════════════════════════════════╣${NC}"
    printf "${BOLD}║ %-15s %-12s %-13s ║${NC}\n" "Tool" "Status" "Note"
    echo -e "${BOLD}╠═══════════════════════════════════════════╣${NC}"

    for entry in "${TOOLS_STATUS[@]}"; do
        IFS='|' read -r tool status note <<< "$entry"
        local color
        case "$status" in
            installed) color="$GREEN" ;;
            missing)   color="$RED" ;;
            skipped)   color="$YELLOW" ;;
            *)         color="$NC" ;;
        esac
        printf "║ %-15s ${color}%-12s${NC} %-13s ║\n" "$tool" "$status" "$note"
    done

    echo -e "${BOLD}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Installed:${NC} ${INSTALLED}   ${YELLOW}Skipped/Present:${NC} ${SKIPPED}   ${RED}Missing:${NC} ${FAILED}"
    echo ""

    if [[ "$FAILED" -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}All tools are ready. Run /shield full to start your first scan.${NC}"
    else
        echo -e "${YELLOW}${BOLD}Some optional tools are missing. Shield will run with available tools.${NC}"
        echo -e "Install missing tools for broader coverage."
    fi
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    print_banner

    OS=$(detect_os)
    log_info "Detected OS: ${OS}"

    if [[ "$OS" == "unknown" ]]; then
        log_error "Unsupported operating system: $(uname -s)"
        log_error "Shield supports macOS and Linux."
        exit 1
    fi

    if [[ "$OS" == "macos" ]] && ! check_command brew; then
        log_warn "Homebrew not found. Some tools may need manual installation."
        log_warn "Install Homebrew: https://brew.sh"
    fi

    echo ""

    # Required dependencies
    install_jq
    echo ""

    # Core tools
    install_semgrep
    echo ""
    install_gitleaks
    echo ""
    install_trivy
    echo ""

    # Docker and Shannon
    check_docker
    echo ""
    install_shannon
    echo ""

    # Language-specific auditors
    check_pip_audit
    echo ""
    check_node
    echo ""
    check_composer

    # Summary
    print_summary
}

main "$@"
