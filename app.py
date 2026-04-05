"""
Phishing Detector — Flask Backend
Run with: python app.py
"""

from flask import Flask, request, jsonify, render_template
from analyzer import analyze_url, analyze_email
import traceback
import os

app = Flask(__name__)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze/url", methods=["POST"])
def api_analyze_url():
    try:
        data = request.get_json()
        url = (data or {}).get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        result = analyze_url(url)
        return jsonify(_serialize(result))

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/email", methods=["POST"])
def api_analyze_email():
    try:
        data = request.get_json()
        headers = (data or {}).get("headers", "").strip()
        if not headers:
            return jsonify({"error": "No email headers provided"}), 400

        result = analyze_email(headers)
        return jsonify(_serialize(result))

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "tool": "PhishGuard v1.0"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(result):
    return {
        "target": result.target,
        "analysis_type": result.analysis_type,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "recommendations": result.recommendations,
        "metadata": result.metadata,
        "indicators": [
            {
                "name": ind.name,
                "severity": ind.severity,
                "description": ind.description,
                "points": ind.points,
            }
            for ind in result.indicators
        ],
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🛡️  PhishGuard running at http://localhost:{port}\n")
    app.run(debug=True, host="0.0.0.0", port=port)
