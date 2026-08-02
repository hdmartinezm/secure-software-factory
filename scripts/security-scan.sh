#!/bin/bash
# =============================================================================
# EFEX Secure Software Factory - Universal Security Scanner
# =============================================================================
# This script runs all security scans and works on ANY CI/CD platform:
# - GitHub Actions
# - Azure DevOps
# - AWS CodeBuild/CodePipeline
# - GitLab CI
# - Jenkins
# - CircleCI
# - Local development
#
# Usage: ./scripts/security-scan.sh [vulnerable|remediated] [--soft-fail] [--skip-iac]
#
# Examples:
#   ./scripts/security-scan.sh vulnerable      # Scan vulnerable code (expects failures)
#   ./scripts/security-scan.sh remediated      # Scan remediated code (expects pass)
#   ./scripts/security-scan.sh                 # Defaults to remediated
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SOFT_FAIL=false
SKIP_IAC=false

# Parse scenario (first positional argument)
SCENARIO="${1:-remediated}"
if [[ "$SCENARIO" == "--"* ]]; then
    # First arg is a flag, default to remediated
    SCENARIO="remediated"
else
    shift 2>/dev/null || true
fi

# Validate scenario
if [[ "$SCENARIO" != "vulnerable" && "$SCENARIO" != "remediated" ]]; then
    echo "Usage: $0 [vulnerable|remediated] [--soft-fail] [--skip-iac]"
    echo ""
    echo "Scenarios:"
    echo "  vulnerable  - Scan vulnerable/ folder (expects security failures)"
    echo "  remediated  - Scan remediated/ folder (expects clean pass)"
    exit 1
fi

# Set paths based on scenario
APP_DIR="$ROOT_DIR/$SCENARIO/app"
INFRA_DIR="$ROOT_DIR/$SCENARIO/infra"
DOCKERFILE="$ROOT_DIR/$SCENARIO/Dockerfile"
EVIDENCE_DIR="${ROOT_DIR}/evidence/${SCENARIO}"

# Parse remaining arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --soft-fail) SOFT_FAIL=true; shift ;;
        --skip-iac) SKIP_IAC=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Colors (disabled if not TTY)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log_header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        echo "Install with: $2"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
mkdir -p "$EVIDENCE_DIR"

echo -e "${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║           EFEX Secure Software Factory - Security Scanner            ║"
echo "║                     Platform-Agnostic Pipeline                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Configuration:"
echo "  Scenario: $SCENARIO"
echo "  App directory: $APP_DIR"
echo "  Infra directory: $INFRA_DIR"
echo "  Dockerfile: $DOCKERFILE"
echo "  Evidence output: $EVIDENCE_DIR"
echo "  Soft fail mode: $SOFT_FAIL"
echo "  Skip IaC: $SKIP_IAC"
echo ""

# Track failures
FAILED_CHECKS=()

# -----------------------------------------------------------------------------
# Tool Version Check
# -----------------------------------------------------------------------------
log_header "Checking Required Tools"

TOOLS_OK=true
check_tool "gitleaks" "brew install gitleaks" || TOOLS_OK=false
check_tool "semgrep" "pip install semgrep" || TOOLS_OK=false
check_tool "trivy" "brew install trivy" || TOOLS_OK=false

if [ "$SKIP_IAC" = false ]; then
    check_tool "checkov" "pip install checkov" || TOOLS_OK=false
fi

if [ "$TOOLS_OK" = false ]; then
    echo -e "\n${RED}Some required tools are missing. Install them and retry.${NC}"
    exit 1
fi

log_success "All required tools are installed"

# -----------------------------------------------------------------------------
# Layer 1: Secrets Detection (Gitleaks)
# -----------------------------------------------------------------------------
log_header "Layer 1: Secrets Detection (Gitleaks)"

GITLEAKS_REPORT="$EVIDENCE_DIR/gitleaks.sarif"

if gitleaks detect \
    --source "$APP_DIR" \
    --no-git \
    --config "$ROOT_DIR/.gitleaks.toml" \
    --report-format sarif \
    --report-path "$GITLEAKS_REPORT" \
    --exit-code 0 2>/dev/null; then

    # Check if findings exist
    if [ -f "$GITLEAKS_REPORT" ]; then
        SECRETS_COUNT=$(jq '[.runs[].results[]] | length' "$GITLEAKS_REPORT" 2>/dev/null || echo "0")
    else
        SECRETS_COUNT=0
    fi

    if [ "$SECRETS_COUNT" -gt 0 ]; then
        log_error "Found $SECRETS_COUNT hardcoded secrets"
        FAILED_CHECKS+=("secrets")
    else
        log_success "No hardcoded secrets detected"
    fi
else
    log_error "Gitleaks scan failed"
    FAILED_CHECKS+=("secrets")
fi

# -----------------------------------------------------------------------------
# Layer 2: SAST - Static Application Security Testing (Semgrep)
# -----------------------------------------------------------------------------
log_header "Layer 2: SAST Analysis (Semgrep)"

SEMGREP_REPORT="$EVIDENCE_DIR/semgrep.sarif"

if semgrep scan \
    --config auto \
    --config "$ROOT_DIR/.semgrep/" \
    --sarif \
    --output "$SEMGREP_REPORT" \
    --error \
    "$APP_DIR" 2>/dev/null; then
    log_success "No high-severity vulnerabilities found"
else
    SAST_EXIT=$?
    if [ -f "$SEMGREP_REPORT" ]; then
        SAST_COUNT=$(jq '[.runs[].results[] | select(.level == "error")] | length' "$SEMGREP_REPORT" 2>/dev/null || echo "0")
        log_error "Found $SAST_COUNT high-severity findings (SQL injection, command injection, etc.)"
    else
        log_error "Semgrep scan failed with exit code $SAST_EXIT"
    fi
    FAILED_CHECKS+=("sast")
fi

# -----------------------------------------------------------------------------
# Layer 3: SCA - Software Composition Analysis (Trivy)
# -----------------------------------------------------------------------------
log_header "Layer 3: Dependency Scan (Trivy SCA)"

TRIVY_REPORT="$EVIDENCE_DIR/trivy-sca.sarif"

if trivy fs \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --format sarif \
    --output "$TRIVY_REPORT" \
    "$APP_DIR" 2>/dev/null; then
    log_success "No HIGH/CRITICAL CVEs in dependencies"
else
    if [ -f "$TRIVY_REPORT" ]; then
        CVE_COUNT=$(jq '[.runs[].results[]] | length' "$TRIVY_REPORT" 2>/dev/null || echo "0")
        log_error "Found $CVE_COUNT vulnerable dependencies"
    else
        log_error "Trivy scan failed"
    fi
    FAILED_CHECKS+=("sca")
fi

# -----------------------------------------------------------------------------
# Layer 4: IaC - Infrastructure as Code Security (Checkov)
# -----------------------------------------------------------------------------
if [ "$SKIP_IAC" = false ] && [ -d "$INFRA_DIR" ]; then
    log_header "Layer 4: Infrastructure Security (Checkov)"

    CHECKOV_REPORT="$EVIDENCE_DIR/checkov.sarif"

    if checkov \
        --directory "$INFRA_DIR" \
        --framework terraform \
        --output-file-path "$EVIDENCE_DIR" \
        --output sarif \
        --soft-fail 2>/dev/null; then

        if [ -f "$EVIDENCE_DIR/results_sarif.sarif" ]; then
            mv "$EVIDENCE_DIR/results_sarif.sarif" "$CHECKOV_REPORT"
            IAC_FAILED=$(jq '[.runs[].results[] | select(.level == "error")] | length' "$CHECKOV_REPORT" 2>/dev/null || echo "0")

            if [ "$IAC_FAILED" -gt 0 ]; then
                log_error "Found $IAC_FAILED infrastructure misconfigurations"
                FAILED_CHECKS+=("iac")
            else
                log_success "Infrastructure configuration is secure"
            fi
        else
            log_success "Infrastructure configuration is secure"
        fi
    else
        log_error "Checkov scan failed"
        FAILED_CHECKS+=("iac")
    fi
else
    log_warn "Skipping IaC scan (--skip-iac or no $INFRA_DIR directory)"
fi

# -----------------------------------------------------------------------------
# Layer 5: Container Security (Trivy + Dockerfile lint)
# -----------------------------------------------------------------------------
if [ -f "$DOCKERFILE" ]; then
    log_header "Layer 5: Container Security"

    # Check for USER directive
    if grep -q "^USER" "$DOCKERFILE"; then
        if grep -q "^USER root" "$DOCKERFILE"; then
            log_error "Dockerfile runs as root user"
            FAILED_CHECKS+=("container")
        else
            log_success "Dockerfile uses non-root user"
        fi
    else
        log_error "Dockerfile missing USER directive (runs as root)"
        FAILED_CHECKS+=("container")
    fi

    # Check for HEALTHCHECK
    if grep -q "^HEALTHCHECK" "$DOCKERFILE"; then
        log_success "Dockerfile has HEALTHCHECK"
    else
        log_warn "Dockerfile missing HEALTHCHECK (recommended)"
    fi
else
    log_warn "Dockerfile not found at $DOCKERFILE"
fi

# -----------------------------------------------------------------------------
# Security Gate Decision
# -----------------------------------------------------------------------------
echo ""
log_header "Security Gate"

REPORT_FILE="$EVIDENCE_DIR/scan-summary.json"
cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total_checks": 5,
  "failed_checks": ${#FAILED_CHECKS[@]},
  "failed": [$(printf '"%s",' "${FAILED_CHECKS[@]}" | sed 's/,$//')]
}
EOF

if [ ${#FAILED_CHECKS[@]} -eq 0 ]; then
    echo -e "${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                    ✅ SECURITY GATE: PASSED                           ║"
    echo "║                                                                       ║"
    echo "║  All security checks passed. Code is safe to merge/deploy.            ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                    ❌ SECURITY GATE: FAILED                           ║"
    echo "║                                                                       ║"
    printf "║  Failed checks: %-52s ║\n" "${FAILED_CHECKS[*]}"
    echo "║                                                                       ║"
    echo "║  Review findings in: evidence/scan-results/                           ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if [ "$SOFT_FAIL" = true ]; then
        log_warn "Soft-fail mode enabled - exiting with 0"
        exit 0
    else
        exit 1
    fi
fi
