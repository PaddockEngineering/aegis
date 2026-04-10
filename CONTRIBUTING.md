# Contributing to Aegis

Aegis is an automated Linux shield defense framework. Every contribution must strengthen the shield — no regressions, no new attack surface, no bloat.

## Security-First Principles

All contributions must follow these rules without exception:

1. **No command injection** — Always use `subprocess.run()` with explicit argument lists. Never `shell=True`.
2. **No hardcoded secrets** — No passwords, API keys, or credentials in code.
3. **No unsafe execution** — No `eval()`, `exec()`, or `os.system()` with user input.
4. **Safe file permissions** — Configs `0o644`, scripts `0o755`, sensitive files `0o640`.
5. **Input validation** — Validate all user input before use.
6. **Backup before modify** — Always create timestamped backups before changing system files.
7. **Error containment** — Catch exceptions, don't expose system internals to stdout.
8. **Idempotency** — Re-running any module must not break an already-configured system.

## Before You Start

- Check existing issues and PRs to avoid duplicate work.
- For major changes, open an issue to discuss the approach first.
- Ensure your changes don't cause interference or performance degradation.
- Test on a clean VM or container.

## Making Changes

1. **Fork the repository**
   ```bash
   gh repo fork PaddockEngineering/aegis --clone
   cd aegis
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-shield-module
   ```

3. **Write secure, idempotent code**
   - Implement `install()`, `configure()`, `check()`, `status()`
   - Add an `is_already_configured()` guard to avoid re-applying settings
   - Include proper error handling and descriptive docstrings

4. **Test your changes**
   ```bash
   python3 -m py_compile tools/your_module.py
   sudo ./setup.py --help  # Verify it loads
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: add <module> shield layer

   - What it defends against
   - Security considerations
   - Testing performed"
   ```

## Adding a New Shield Module

1. **Create the module** in `tools/new_shield.py`:
   ```python
   def install():
       """Install the defense tool."""
       from utils.apt import install_package
       return install_package("package-name")

   def configure():
       """Apply hardened configuration."""
       # Check if already configured (idempotency)
       # Backup existing config
       # Write hardened config
       # Enable and start service
       # Verify configuration
       return True

   def check():
       """Check if tool is installed."""
       from utils.system import command_exists
       return command_exists("tool")

   def status():
       """Report shield status."""
       return "Shield active" if check() else "Shield offline"
   ```

2. **Add to `config/tools.json`**

3. **Import and handle in `setup.py`**

4. **Update `README.md`** — place the module in the correct defense layer

5. **Test on a clean system** before submitting

## Submitting a Pull Request

### PR Checklist

```markdown
## Summary
Brief description of the shield module or fix.

## Security Checklist
- [ ] No shell=True or command injection risks
- [ ] No hardcoded secrets
- [ ] Safe file permissions
- [ ] Backups created before system file modifications
- [ ] Idempotent — safe to re-run
- [ ] Input validated
- [ ] Error handling included

## Testing
- [ ] Tested on clean Debian/Ubuntu system
- [ ] No performance degradation
- [ ] Existing modules unaffected
- [ ] Module works with --all and --status flags
```

## Reporting Security Issues

**Do not** open a public issue for security vulnerabilities. Email the maintainers directly with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Code Style

- **Python 3.8+** with modern conventions
- **Descriptive names** — no abbreviations
- **Comments explain "why"**, not "what"
- **Docstrings** on all functions
- **Line length** under 100 characters where possible

---

Aegis defends. Every contribution should make it defend better.
