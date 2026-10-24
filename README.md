# DevOps Repository Auditor

**Muhammad Talha — I220839**

## Quick Start — Commands Only

```bash
# 1. Clone the repository
git clone https://github.com/MTalhaAli47/devops-repo-auditor.git
cd devops-repo-auditor

# 2. Create and activate a virtual environment (Linux/macOS/WSL)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Configure your Gemini API key
cp .env.example .env
# Edit .env and set GEMINI_API_KEY to your own key.
# GEMINI_MODEL=gemini-3.1-flash-lite

# 5. Run automated tests
python -m pytest -q

# 6. Check Python syntax and sample report
python -m py_compile agent.py tools.py prompts.py
python -m json.tool sample_report.json

# 7. Audit a public GitHub repository
python agent.py --repo https://github.com/heamnathbaskar/awstraining-vulnerable-app --output report.json

# 8. Validate the generated report
python -m json.tool report.json
```

**Windows PowerShell:** Replace the virtual-environment commands with:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Configure `.env` with your own Gemini API key before running a live audit. Never commit `.env` or share your API key.


















# intro

An AI-powered Python CLI agent that audits public GitHub repositories for DevOps and software-delivery security issues. It uses an LLM-driven tool loop to inspect repository files and Git history, then produces a structured JSON report.

## Features

- Audits CI/CD workflows, Dockerfiles, infrastructure-as-code, dependencies, exposed secrets, permissions, and Git history.
- Dynamically selects tools to investigate findings.
- Redacts detected secret values from findings.
- Generates JSON reports with severity, evidence, and remediation recommendations.
- Never executes repository code, installs target-repository dependencies, or modifies the audited repository.

## Requirements

- Python 3.11+
- Git
- A Google Gemini API key

## Installation

Clone the repository:

```bash
git clone https://github.com/MTalhaAli47/devops-repo-auditor.git
cd devops-repo-auditor
```

### Linux / macOS / WSL

On Ubuntu or Debian-based WSL:

```bash
sudo apt update
sudo apt install -y python3-full python3-venv git

python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Install dependencies

With the virtual environment activated:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Configuration

1. Get your own Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey).
2. Create a local `.env` file from the example.

Linux / macOS / WSL:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

3. Open `.env` and add your API key:

```dotenv
GEMINI_API_KEY=your_actual_api_key_here
GEMINI_MODEL=gemini-3.1-flash-lite
```

Replace `your_actual_api_key_here` with your own key. Do not include quotes or share the key publicly. Keep `.env` private; never commit it to Git.

## Run an Audit

Audit a public GitHub repository:

```bash
python agent.py --repo https://github.com/OWNER/REPOSITORY.git --output report.json
```

Example:

```bash
python agent.py --repo https://github.com/heamnathbaskar/awstraining-vulnerable-app --output report.json
```

Validate the generated JSON:

```bash
python -m json.tool report.json
```

Each report contains a `repository` field and a `violations` array. Findings include `rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and `recommendation`.

Severity levels are `critical`, `high`, `medium`, and `low`. File paths and line numbers may be `null` when not applicable or unavailable.

## Run Tests

Run the automated tests:

```bash
python -m pytest -q
```

Check Python syntax:

```bash
python -m py_compile agent.py tools.py prompts.py
```

Validate the included sample report:

```bash
python -m json.tool sample_report.json
```

Unit tests do not require a live API audit. A live audit requires a valid API key, network access, model availability, and sufficient API quota.

## Project Structure

```text
devops-repo-auditor/
├── agent.py
├── tools.py
├── llm_client.py
├── prompts.py
├── tests/
│   ├── test_agent.py
│   ├── test_llm_client.py
│   └── test_tools.py
├── requirements.txt
├── .env.example
├── sample_report.json
└── README.md
```

## Limitations

- Designed for public GitHub repositories accessible over HTTPS.
- Results depend on repository evidence and model analysis; manual verification is recommended.
- Static auditing cannot guarantee that a repository is secure.
