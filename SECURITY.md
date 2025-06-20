# Security Scanning Setup

This project implements comprehensive security scanning using multiple tools to ensure code quality and security.

## Security Tools

### 1. Gitleaks
- **Purpose**: Detect and prevent secrets in git repos
- **Config**: `.gitleaks.toml`
- **Usage**: `make gitleaks`

### 2. Gosec
- **Purpose**: Go security checker
- **Usage**: `make gosec`
- **Output**: `gosec-report.json`

### 3. Trivy
- **Purpose**: Vulnerability scanner for containers and filesystems
- **Config**: `.trivyignore`
- **Usage**: `make trivy`

### 4. Semgrep
- **Purpose**: Static analysis tool
- **Config**: `.semgrep.yml`
- **Usage**: `make semgrep`

### 5. Pre-commit Hooks
- **Config**: `.pre-commit-config.yaml`
- **Includes**:
  - Gitleaks for secret scanning
  - Go formatting and linting
  - Detect-secrets baseline
  - File fixes and checks

## Quick Start

1. **Install all security tools**:
   ```bash
   make install-security-tools
   ```

2. **Set up pre-commit hooks**:
   ```bash
   make pre-commit-install
   ```

3. **Generate secrets baseline**:
   ```bash
   make generate-secrets-baseline
   ```

## Running Security Scans

### Quick scan (development):
```bash
make quick-scan
```

### Full security scan:
```bash
make security-check
```

### All checks (test + security):
```bash
make check
```

### Manual pre-commit run:
```bash
make pre-commit-run
```

## GitHub Actions Integration

The `.github/workflows/security.yml` workflow runs automatically on:
- Push to main/develop branches
- Pull requests
- Weekly schedule (Sunday midnight)

It includes:
- Gitleaks secret scanning
- Gosec security analysis
- Trivy vulnerability scanning
- Semgrep static analysis
- CodeQL analysis
- Dependency vulnerability checks
- License compliance
- SBOM generation

## Security Best Practices

1. **Never commit secrets** - Use environment variables or secret management tools
2. **Run pre-commit hooks** - Catches issues before they're committed
3. **Review security reports** - Check GitHub Security tab regularly
4. **Keep dependencies updated** - Use `go mod tidy` and update regularly
5. **Follow secure coding practices** - See `.semgrep.yml` for common patterns to avoid

## Handling Security Issues

1. **If a secret is detected**:
   - Immediately revoke the compromised credential
   - Remove from git history if needed
   - Update `.gitleaks.toml` allowlist if false positive

2. **If vulnerabilities are found**:
   - Review the severity and impact
   - Update dependencies if patches available
   - Add to `.trivyignore` if risk accepted (with justification)

3. **For false positives**:
   - Update tool configurations to exclude
   - Document the reason for exclusion
   - Regularly review exclusions

## Local Development

Before pushing code:
```bash
# Run quick security scan
make quick-scan

# Run full test suite
make test

# Or run everything
make all
```

## Additional Resources

- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Gosec Documentation](https://github.com/securego/gosec)
- [Trivy Documentation](https://aquasecurity.github.io/trivy)
- [Semgrep Documentation](https://semgrep.dev/docs)
- [Pre-commit Documentation](https://pre-commit.com)