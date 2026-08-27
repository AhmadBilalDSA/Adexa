# Contributing to ADEXA

Thank you for your interest in contributing to **ADEXA — Adaptive Exploit Repair and Verification Framework**.

ADEXA is an open cybersecurity research project focused on adaptive security testing, exploit repair, verification, dataset development, and evaluation.

Contributions are welcome from developers, cybersecurity students, penetration testers, researchers, and anyone interested in security automation.

> [!WARNING]
> **AUTHORIZED SECURITY TESTING ONLY**
>
> All contributions, testing, demonstrations, and experiments involving ADEXA must be performed only in controlled environments or against systems for which you have explicit authorization.

---

## Ways to Contribute

You can contribute to ADEXA in several areas.

### Code

Examples include:

- improving the adaptive execution loop,
- improving the CLI,
- improving repair strategy selection,
- adding unit tests,
- improving error handling,
- improving logging,
- improving the web backend,
- improving the experimental binary-analysis components,
- or fixing bugs.

### Dataset

The `dataset/` directory contains the SQL injection dataset-generation and verification pipeline.

Useful contributions include:

- adding new validated corruption cases,
- improving failure classification,
- improving dataset validation,
- improving duplicate detection,
- improving verifier reliability,
- adding dataset-quality metrics,
- and improving held-out evaluation methodology.

### Research

ADEXA is also a research project.

Research contributions may include:

- evaluating ADEXA on previously unseen test cases,
- comparing ADEXA against baseline approaches,
- studying payload-repair diversity,
- improving repair strategy taxonomy,
- investigating additional vulnerability classes,
- and proposing safer or more reliable verification methods.

### Documentation

Documentation contributions are highly valuable.

Examples include:

- improving installation instructions,
- improving the DVWA laboratory setup guide,
- documenting modules,
- improving diagrams,
- fixing unclear explanations,
- and adding examples.

---

## Getting Started

### 1. Fork the Repository

Fork the ADEXA repository on GitHub.

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR-USERNAME/Adexa.git
cd Adexa
```

### 3. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Create a Branch

Create a separate branch for your change.

```bash
git checkout -b feature/your-feature-name
```

Examples:

```bash
git checkout -b fix/cli-error-handling
```

```bash
git checkout -b dataset/add-sqli-corruptions
```

```bash
git checkout -b docs/improve-dvwa-setup
```

---

## Development Guidelines

Keep contributions focused and easy to review.

Prefer:

- small, clear changes,
- descriptive variable and function names,
- comments where behavior is not obvious,
- reusable code,
- and minimal unrelated modifications.

Avoid mixing several unrelated changes into one pull request.

For example, do not combine:

```text
CLI redesign
+
dataset changes
+
backend refactor
+
documentation rewrite
```

into one pull request.

Submit them separately where possible.

---

## Testing

Before submitting a pull request, test your changes.

For relevant Python code, make sure the modified modules can run without syntax errors.

You can use:

```bash
python3 -m compileall .
```

For dataset-related changes, run the relevant validation or verification scripts.

Examples:

```bash
python3 dataset/validate_dataset.py
```

```bash
python3 dataset/test_verifier.py
```

For ADEXA benchmark-related changes:

```bash
python3 benchmark_adexa.py
```

Testing requirements may vary depending on the part of the project being modified.

---

## Security Testing Rules

ADEXA is a security-testing framework, so contributions must follow responsible-testing practices.

Do not submit:

- credentials,
- API keys,
- access tokens,
- private session cookies,
- real customer data,
- unauthorized target information,
- private infrastructure details,
- or secrets of any kind.

Do not test contributions against systems without authorization.

Preferred environments include:

- DVWA,
- intentionally vulnerable applications,
- local laboratories,
- CTF environments,
- and systems explicitly authorized for security testing.

---

## Dataset Contribution Guidelines

Dataset quality is more important than dataset size.

New dataset entries should:

- represent a meaningful failure case,
- use a consistent failure classification,
- use an appropriate repair strategy,
- contain a valid repaired candidate,
- avoid unnecessary duplicates,
- and be suitable for controlled verification.

Do not submit thousands of automatically generated entries without validation.

For large dataset contributions, open an Issue first so the methodology can be discussed before submitting the data.

---

## Adding a New Vulnerability Class

ADEXA currently focuses primarily on SQL injection.

If you want to propose support for another vulnerability class such as XSS, SSRF, or command injection, please open an Issue before implementing a large module.

The proposal should describe:

- the vulnerability class,
- the proposed input format,
- how failure would be detected,
- possible repair strategies,
- how success could be safely verified,
- and how the module would integrate with the existing adaptive loop.

This helps keep ADEXA's architecture consistent.

---

## Commit Messages

Use short and descriptive commit messages.

Good examples:

```text
Improve SQLi failure classification
```

```text
Add unit tests for repair memory
```

```text
Fix timeout handling in web backend
```

```text
Document DVWA setup
```

Avoid messages such as:

```text
update
```

```text
fix stuff
```

```text
changes
```

---

## Submitting a Pull Request

Before opening a pull request:

1. Make sure your branch is up to date.
2. Test the affected functionality.
3. Remove temporary files and debugging output.
4. Check that no secrets are included.
5. Keep the pull request focused on one main change.

Your pull request should explain:

- **What changed**
- **Why the change is useful**
- **How it was tested**
- **Any limitations or remaining work**

Screenshots or terminal output are welcome when they help explain the change.

---

## Issues

Before starting work on a larger feature, check the existing Issues.

Useful labels will include:

- `good first issue`
- `help wanted`
- `bug`
- `documentation`
- `dataset`
- `enhancement`
- `research`

If you want to work on an open Issue, leave a comment so other contributors know that it is being worked on.

---

## Good First Contributions

If you are new to ADEXA, good starting tasks include:

- improving documentation,
- adding unit tests,
- improving CLI messages,
- adding validated SQLi test cases,
- improving benchmark output,
- fixing small bugs,
- or improving dataset-validation checks.

Look for Issues labeled:

**`good first issue`**

---

## Questions and Ideas

If you are unsure whether an idea fits ADEXA, open an Issue and describe it before writing a large amount of code.

Discussion is encouraged.

---

## License

By contributing to ADEXA, you agree that your contributions will be distributed under the same license as the project.

See the [`LICENSE`](LICENSE) file for details.

---

## Responsible Use

ADEXA is intended for cybersecurity research, education, controlled laboratory environments, and authorized security testing.

**Do not use ADEXA against systems without explicit permission.**
