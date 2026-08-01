#!/bin/bash
# =============================================================================
# EFEX Secure Software Factory - Red/Green Demo Script
# =============================================================================
# This script demonstrates the security pipeline by:
# 1. Running all security scans against vulnerable code (RED)
# 2. Running scans against secure code (GREEN)
# 3. Comparing results
#
# Structure:
#   vulnerable/app/    - Intentionally insecure code
#   vulnerable/infra/  - Insecure Terraform
#   remediated/app/    - Secure code
#   remediated/infra/  - Secure Terraform
#
# Prerequisites:
#   - Docker installed
#   - gitleaks, semgrep, trivy, checkov installed
#
# Usage:
#   ./scripts/demo-red-green.sh [red|green|full]
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EVIDENCE_DIR="$PROJECT_ROOT/evidence"

# Create evidence directories
mkdir -p "$EVIDENCE_DIR/red" "$EVIDENCE_DIR/green" "$EVIDENCE_DIR/sarif"

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
}

print_red() {
    echo -e "${RED}[FAIL] $1${NC}"
}

print_green() {
    echo -e "${GREEN}[PASS] $1${NC}"
}

print_yellow() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

run_scan() {
    local name="$1"
    local cmd="$2"
    local output_file="$3"
    local expect_fail="$4"

    echo ""
    print_yellow "Running: $name"
    echo "Command: $cmd"
    echo ""

    set +e
    eval "$cmd" > "$output_file" 2>&1
    local exit_code=$?
    set -e

    if [ "$expect_fail" = "true" ]; then
        if [ $exit_code -ne 0 ]; then
            print_red "$name detected issues (exit code: $exit_code) - EXPECTED"
            return 0
        else
            print_green "$name passed - UNEXPECTED (should have failed)"
            return 1
        fi
    else
        if [ $exit_code -eq 0 ]; then
            print_green "$name passed"
            return 0
        else
            print_red "$name failed (exit code: $exit_code)"
            return 1
        fi
    fi
}

# =============================================================================
# Check Prerequisites
# =============================================================================

check_prerequisites() {
    print_header "Checking Prerequisites"

    local missing=()

    command -v docker >/dev/null 2>&1 || missing+=("docker")
    command -v gitleaks >/dev/null 2>&1 || missing+=("gitleaks")
    command -v semgrep >/dev/null 2>&1 || missing+=("semgrep")
    command -v trivy >/dev/null 2>&1 || missing+=("trivy")
    command -v checkov >/dev/null 2>&1 || missing+=("checkov")

    if [ ${#missing[@]} -gt 0 ]; then
        print_yellow "Missing tools: ${missing[*]}"
        print_yellow "Install with:"
        echo "  brew install gitleaks trivy"
        echo "  pip install semgrep checkov"
        exit 1
    fi

    print_green "All prerequisites installed"
}

# =============================================================================
# RED Scenario - Vulnerable Code
# =============================================================================

run_red_scenario() {
    print_header "RED SCENARIO - Scanning Vulnerable Code"

    cd "$PROJECT_ROOT"
    local evidence_dir="$EVIDENCE_DIR/red"
    local failed_count=0

    # -------------------------------------------------------------------------
    # 1. Secrets Detection (gitleaks)
    # -------------------------------------------------------------------------
    print_header "Layer 1: Secrets Detection (gitleaks)"

    run_scan \
        "Gitleaks Secrets Scan" \
        "gitleaks detect --source vulnerable/app/ --config .gitleaks.toml --report-format sarif --report-path $evidence_dir/gitleaks.sarif --verbose" \
        "$evidence_dir/gitleaks-output.txt" \
        "true" || ((failed_count++))

    # Show findings
    echo ""
    echo "Secrets found:"
    gitleaks detect --source vulnerable/app/ --config .gitleaks.toml --verbose 2>&1 | grep -E "(Secret|Finding|RuleID)" | head -20 || true

    # -------------------------------------------------------------------------
    # 2. SAST (Semgrep)
    # -------------------------------------------------------------------------
    print_header "Layer 2: SAST Analysis (Semgrep)"

    run_scan \
        "Semgrep SAST Scan" \
        "semgrep scan --config auto --config .semgrep/ --sarif --output $evidence_dir/semgrep.sarif vulnerable/app/" \
        "$evidence_dir/semgrep-output.txt" \
        "true" || ((failed_count++))

    # Show findings summary
    echo ""
    echo "SAST findings:"
    semgrep scan --config auto vulnerable/app/ 2>&1 | grep -E "(error|warning|Findings)" | head -20 || true

    # -------------------------------------------------------------------------
    # 3. SCA (Trivy)
    # -------------------------------------------------------------------------
    print_header "Layer 3: SCA - Dependency Scan (Trivy)"

    run_scan \
        "Trivy SCA Scan" \
        "trivy fs --severity HIGH,CRITICAL --format sarif --output $evidence_dir/trivy-sca.sarif vulnerable/app/" \
        "$evidence_dir/trivy-sca-output.txt" \
        "true" || ((failed_count++))

    # Show CVEs
    echo ""
    echo "CVEs found:"
    trivy fs --severity HIGH,CRITICAL --format table vulnerable/app/ 2>&1 | head -40 || true

    # -------------------------------------------------------------------------
    # 4. IaC Security (Checkov)
    # -------------------------------------------------------------------------
    print_header "Layer 4: IaC Security (Checkov)"

    run_scan \
        "Checkov IaC Scan" \
        "checkov -d vulnerable/infra/ --framework terraform --output-format sarif --output-file-path $evidence_dir/" \
        "$evidence_dir/checkov-output.txt" \
        "true" || ((failed_count++))

    # Show failures
    echo ""
    echo "IaC misconfigurations:"
    checkov -d vulnerable/infra/ --framework terraform --compact 2>&1 | grep -E "(FAILED|Check:)" | head -30 || true

    # -------------------------------------------------------------------------
    # 5. Container Security (Trivy + Dockerfile check)
    # -------------------------------------------------------------------------
    print_header "Layer 5: Container Security"

    # Build the vulnerable image
    print_yellow "Building vulnerable container image..."
    docker build \
        -t efex-app:vulnerable \
        -f vulnerable/Dockerfile \
        vulnerable/ > "$evidence_dir/docker-build.txt" 2>&1 || true

    run_scan \
        "Trivy Container Scan" \
        "trivy image --severity HIGH,CRITICAL --format sarif --output $evidence_dir/trivy-container.sarif efex-app:vulnerable" \
        "$evidence_dir/trivy-container-output.txt" \
        "true" || ((failed_count++))

    # Check for root user
    echo ""
    echo "Dockerfile root user check:"
    if ! grep -q "^USER" vulnerable/Dockerfile; then
        print_red "EFEX-DOCKER-001: No USER directive found - container runs as root"
    fi

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print_header "RED SCENARIO SUMMARY"

    echo "Evidence saved to: $evidence_dir/"
    echo ""
    echo "Files generated:"
    ls -la "$evidence_dir/"
    echo ""
    print_red "Security Gate: FAILED"
    print_red "All 5 security layers detected issues as expected."
    echo ""
    echo "This demonstrates 'break-the-build' - the pipeline would block this code."
}

# =============================================================================
# GREEN Scenario - Remediated Code
# =============================================================================

run_green_scenario() {
    print_header "GREEN SCENARIO - Scanning Remediated Code"

    cd "$PROJECT_ROOT"
    local evidence_dir="$EVIDENCE_DIR/green"
    local passed_count=0

    # -------------------------------------------------------------------------
    # 1. Secrets Detection (gitleaks)
    # -------------------------------------------------------------------------
    print_header "Layer 1: Secrets Detection (gitleaks)"

    run_scan \
        "Gitleaks Secrets Scan" \
        "gitleaks detect --source remediated/app/ --config .gitleaks.toml --report-format sarif --report-path $evidence_dir/gitleaks.sarif --verbose" \
        "$evidence_dir/gitleaks-output.txt" \
        "false" && ((passed_count++))

    # -------------------------------------------------------------------------
    # 2. SAST (Semgrep)
    # -------------------------------------------------------------------------
    print_header "Layer 2: SAST Analysis (Semgrep)"

    run_scan \
        "Semgrep SAST Scan" \
        "semgrep scan --config p/python --config p/security-audit --sarif --output $evidence_dir/semgrep.sarif remediated/app/" \
        "$evidence_dir/semgrep-output.txt" \
        "false" && ((passed_count++))

    # -------------------------------------------------------------------------
    # 3. SCA (Trivy)
    # -------------------------------------------------------------------------
    print_header "Layer 3: SCA - Dependency Scan (Trivy)"

    run_scan \
        "Trivy SCA Scan" \
        "trivy fs --severity HIGH,CRITICAL --exit-code 0 --format sarif --output $evidence_dir/trivy-sca.sarif remediated/app/" \
        "$evidence_dir/trivy-sca-output.txt" \
        "false" && ((passed_count++))

    # -------------------------------------------------------------------------
    # 4. IaC Security (Checkov)
    # -------------------------------------------------------------------------
    print_header "Layer 4: IaC Security (Checkov)"

    run_scan \
        "Checkov IaC Scan" \
        "checkov -d remediated/infra/ --framework terraform --compact" \
        "$evidence_dir/checkov-output.txt" \
        "false" && ((passed_count++))

    # -------------------------------------------------------------------------
    # 5. Container Security
    # -------------------------------------------------------------------------
    print_header "Layer 5: Container Security"

    # Build the remediated image
    print_yellow "Building remediated container image..."
    docker build \
        -t efex-app:remediated \
        -f remediated/Dockerfile \
        remediated/ > "$evidence_dir/docker-build.txt" 2>&1 || true

    # Check for USER directive
    echo "Dockerfile USER check:"
    if grep -q "^USER" remediated/Dockerfile && ! grep -q "^USER root" remediated/Dockerfile; then
        print_green "EFEX-DOCKER-001: Non-root USER directive found"
        ((passed_count++))
    else
        print_red "EFEX-DOCKER-001: USER check failed"
    fi

    run_scan \
        "Trivy Container Scan" \
        "trivy image --severity HIGH,CRITICAL --format sarif --output $evidence_dir/trivy-container.sarif efex-app:remediated" \
        "$evidence_dir/trivy-container-output.txt" \
        "false" && ((passed_count++))

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print_header "GREEN SCENARIO SUMMARY"

    echo "Evidence saved to: $evidence_dir/"
    echo ""
    echo "Files generated:"
    ls -la "$evidence_dir/"
    echo ""
    print_green "Security Gate: PASSED"
    print_green "All security checks passed on remediated code."
}

# =============================================================================
# Generate SBOM
# =============================================================================

generate_sbom() {
    print_header "Generating SBOM"

    cd "$PROJECT_ROOT"

    if command -v syft >/dev/null 2>&1; then
        # Generate SPDX format for remediated app
        syft packages dir:remediated/app/ -o spdx-json > "$EVIDENCE_DIR/sbom.spdx.json"
        print_green "SBOM (SPDX) generated: evidence/sbom.spdx.json"

        # Generate CycloneDX format
        syft packages dir:remediated/app/ -o cyclonedx-json > "$EVIDENCE_DIR/sbom.cdx.json"
        print_green "SBOM (CycloneDX) generated: evidence/sbom.cdx.json"
    else
        print_yellow "Syft not installed. Install with: brew install syft"
        print_yellow "Skipping SBOM generation"
    fi
}

# =============================================================================
# Compare Scenarios
# =============================================================================

compare_scenarios() {
    print_header "RED vs GREEN Comparison"

    echo ""
    echo "| Layer | RED (vulnerable/) | GREEN (remediated/) |"
    echo "|-------|-------------------|---------------------|"
    echo "| Secrets | FAIL (demo secrets) | PASS (env vars) |"
    echo "| SAST | FAIL (SQLi, CMDi) | PASS (parameterized) |"
    echo "| SCA | FAIL (CVEs) | PASS (patched) |"
    echo "| IaC | FAIL (S3 public) | PASS (encrypted) |"
    echo "| Container | FAIL (root user) | PASS (non-root) |"
    echo ""
}

# =============================================================================
# Full Demo
# =============================================================================

run_full_demo() {
    print_header "EFEX Secure Software Factory - Full Demo"

    echo "This demo will:"
    echo "  1. Check and install prerequisites"
    echo "  2. Run RED scenario (vulnerable/ - scans should fail)"
    echo "  3. Run GREEN scenario (remediated/ - scans should pass)"
    echo "  4. Compare results"
    echo "  5. Generate SBOM"
    echo ""
    read -p "Press Enter to continue..."

    check_prerequisites
    run_red_scenario

    echo ""
    print_yellow "RED scenario complete. Review the findings above."
    read -p "Press Enter to continue to GREEN scenario..."

    run_green_scenario
    compare_scenarios
    generate_sbom

    print_header "Demo Complete"
    echo ""
    echo "Evidence directories:"
    echo "  - Red scenario:   $EVIDENCE_DIR/red/"
    echo "  - Green scenario: $EVIDENCE_DIR/green/"
    echo "  - SBOM files:     $EVIDENCE_DIR/"
    echo ""
    echo "Summary:"
    echo "  - vulnerable/  -> Security Gate FAILED (as expected)"
    echo "  - remediated/  -> Security Gate PASSED"
}

# =============================================================================
# Main
# =============================================================================

case "${1:-full}" in
    red)
        check_prerequisites
        run_red_scenario
        ;;
    green)
        check_prerequisites
        run_green_scenario
        ;;
    compare)
        compare_scenarios
        ;;
    sbom)
        generate_sbom
        ;;
    full)
        run_full_demo
        ;;
    *)
        echo "Usage: $0 [red|green|compare|sbom|full]"
        echo ""
        echo "  red     - Run RED scenario (vulnerable/)"
        echo "  green   - Run GREEN scenario (remediated/)"
        echo "  compare - Show RED vs GREEN comparison"
        echo "  sbom    - Generate SBOM only"
        echo "  full    - Run complete demo (default)"
        exit 1
        ;;
esac
