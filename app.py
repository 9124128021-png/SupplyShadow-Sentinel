from flask import Flask, render_template, request, jsonify
import requests
import re
from urllib.parse import urlparse

app = Flask(__name__)

POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "tensorflow", "boto3", "colorama",
    "cryptography", "scikit-learn", "flask", "django", "fastapi",
    "urllib3", "matplotlib", "scipy", "sqlalchemy", "pytest", "pillow",
    "beautifulsoup4", "setuptools", "pip", "pyyaml", "jinja2", "werkzeug"
]


def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca != cb)))
        prev = cur
    return prev[-1]


def typo_match(name):
    name = name.lower()
    if name in POPULAR_PACKAGES:
        return None
    candidates = []
    for trusted in POPULAR_PACKAGES:
        d = levenshtein(name, trusted)
        if d <= 2:
            candidates.append((d, trusted))
    return sorted(candidates)[0][1] if candidates else None


def pypi_info(name):
    try:
        r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=7)
        if r.status_code == 200:
            data = r.json()
            info = data.get("info", {})
            return {"exists": True, "version": info.get("version"), "summary": info.get("summary") or ""}
        return {"exists": False}
    except requests.RequestException as e:
        return {"exists": None, "error": str(e)}


def osv_vulns(name, version=None):
    payload = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except requests.RequestException:
        pass
    return []


def parse_line(line):
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http://", "https://")):
        return None, None
    m = re.match(r"^([A-Za-z0-9_.-]+)", line)
    if not m:
        return None, None
    name = m.group(1)
    vm = re.search(r"==\s*([A-Za-z0-9.+!_-]+)", line)
    return name, vm.group(1) if vm else None


def scan(requirements):
    results = []
    for raw in requirements.splitlines():
        name, version = parse_line(raw)
        if not name:
            continue
        typo = typo_match(name)
        pypi = pypi_info(name)
        vulns = osv_vulns(name, version)
        score = 0
        reasons = []
        if typo:
            score += 65; reasons.append(f"Name closely resembles trusted package '{typo}'")
        if pypi.get("exists") is False:
            score += 25; reasons.append("Package was not found on PyPI")
        if vulns:
            score += min(50, 25 + len(vulns) * 8); reasons.append(f"{len(vulns)} OSV vulnerability record(s) found")
        if pypi.get("exists") is True and not typo and not vulns:
            score = 5
        score = min(score, 100)
        risk = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        results.append({
            "package": name, "version": version or "Unpinned", "typosquatting": typo,
            "pypi": pypi, "vulnerabilities": vulns, "score": score,
            "risk": risk, "reasons": reasons
        })
    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    requirements = data.get("requirements", "")
    if not requirements.strip():
        return jsonify({"error": "Add at least one dependency."}), 400
    results = scan(requirements)
    counts = {k: sum(1 for r in results if r["risk"] == k) for k in ["Critical", "High", "Medium", "Low"]}
    return jsonify({"results": results, "summary": {"total": len(results), **counts}})


@app.post("/api/quick-check")
def quick_check():
    data = request.get_json(silent=True) or {}
    name = (data.get("package") or "").strip()
    if not name:
        return jsonify({"error": "Enter a package name."}), 400
    results = scan(name)
    return jsonify(results[0] if results else {"error": "Unable to parse package."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
