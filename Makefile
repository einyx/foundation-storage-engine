.PHONY: all build test clean security-check install-security-tools

# Build variables
BINARY_NAME=s3proxy-go
GO=go
GOFLAGS=-v

all: security-check test build

build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

test:
	$(GO) test $(GOFLAGS) ./...

clean:
	$(GO) clean
	rm -f $(BINARY_NAME)
	rm -f gosec-report.json
	rm -f trivy-results.json

# Security scanning targets
security-check: gitleaks gosec trivy semgrep

gitleaks:
	@echo "Running Gitleaks secret scanning..."
	@command -v gitleaks >/dev/null 2>&1 || (echo "gitleaks not installed. Run: make install-security-tools" && exit 1)
	gitleaks detect --config=.gitleaks.toml --verbose

gosec:
	@echo "Running Gosec security scanning..."
	@command -v gosec >/dev/null 2>&1 || (echo "gosec not installed. Run: make install-security-tools" && exit 1)
	gosec -fmt json -out gosec-report.json ./...
	@echo "Gosec report saved to gosec-report.json"

trivy:
	@echo "Running Trivy vulnerability scanning..."
	@command -v trivy >/dev/null 2>&1 || (echo "trivy not installed. Run: make install-security-tools" && exit 1)
	trivy fs --security-checks vuln,config,secret .

semgrep:
	@echo "Running Semgrep static analysis..."
	@command -v semgrep >/dev/null 2>&1 || (echo "semgrep not installed. Run: make install-security-tools" && exit 1)
	semgrep --config=.semgrep.yml --config=auto .

# Pre-commit setup
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	@command -v pre-commit >/dev/null 2>&1 || (echo "pre-commit not installed. Run: pip install pre-commit" && exit 1)
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-run:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files

# Install security tools
install-security-tools:
	@echo "Installing security tools..."
	# Gitleaks
	@echo "Installing gitleaks..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install gitleaks; \
	else \
		go install github.com/gitleaks/gitleaks/v8@latest; \
	fi
	# Gosec
	@echo "Installing gosec..."
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	# Trivy
	@echo "Installing trivy..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install aquasecurity/trivy/trivy; \
	else \
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
	fi
	# Semgrep
	@echo "Installing semgrep..."
	@if command -v pip3 >/dev/null 2>&1; then \
		pip3 install semgrep; \
	else \
		echo "Python pip3 required for semgrep installation"; \
	fi
	# Pre-commit
	@echo "Installing pre-commit..."
	@if command -v pip3 >/dev/null 2>&1; then \
		pip3 install pre-commit; \
	else \
		echo "Python pip3 required for pre-commit installation"; \
	fi
	# Nancy for dependency scanning
	@echo "Installing nancy..."
	go install github.com/sonatype-nexus-community/nancy@latest
	# Hadolint for Dockerfile linting
	@echo "Installing hadolint..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install hadolint; \
	else \
		echo "Visit https://github.com/hadolint/hadolint for installation instructions"; \
	fi

# Generate security baseline
generate-secrets-baseline:
	@echo "Generating secrets baseline..."
	@command -v detect-secrets >/dev/null 2>&1 || pip3 install detect-secrets
	detect-secrets scan > .secrets.baseline

# Run all checks
check: test security-check

# Quick security scan (faster, for development)
quick-scan: gitleaks gosec

# Full security scan (comprehensive, for CI/CD)
full-scan: security-check pre-commit-run