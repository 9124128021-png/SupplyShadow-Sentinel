# SupplyShadow Sentinel

A mini-project web dashboard for software supply-chain security. It scans Python dependencies for:

- Typosquatting using Levenshtein similarity
- PyPI package existence
- Known vulnerabilities using the OSV API
- A simple explainable risk score
- Exportable JSON scan report

## Run locally

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Demo

Click **Load sample** and then **Run full scan**. The sample includes `requesrs`, which is intentionally similar to `requests` to demonstrate the typosquatting detector.

## Project flow

requirements.txt → parser → typosquatting engine → PyPI verification → OSV lookup → risk scoring → dashboard/report.

## Important

This is an academic prototype, not a replacement for enterprise software composition analysis. The trusted-package list and scoring model should be expanded for production use.
