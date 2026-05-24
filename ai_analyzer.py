import os
import json
import requests

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

def analyze_with_ai(header_results, tls_results):
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return None

    # build a clean summary of findings to send to Gemini
    header_summary = []
    for r in header_results:
        header_summary.append({
            "header": r["header"],
            "status": r["status"],
            "severity": r["severity"],
            "value": r.get("value")
        })

    tls_summary = []
    if tls_results and not tls_results.get("error"):
        for finding in tls_results.get("findings", []):
            tls_summary.append({
                "check": finding["check"],
                "status": finding["status"],
                "detail": finding["detail"]
            })

    prompt = f"""
    You are an application security engineer. Review these scan results and respond ONLY in JSON.

    Headers: {json.dumps([{"header": r["header"], "status": r["status"], "severity": r["severity"]} for r in header_results], indent=2)}

    TLS issues: {json.dumps([f["check"] + ": " + f["status"] for f in tls_results.get("findings", [])] if tls_results and not tls_results.get("error") else [], indent=2)}

    Respond ONLY in this exact JSON format, no markdown:
    {{"summary": "2-3 sentence security assessment", "false_positives": ["list any headers flagged but not needed"], "top_fixes": ["fix 1", "fix 2", "fix 3"], "confidence": 0.0}}
    """

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [
                    {"parts": [{"text": prompt}]}
                ]
            },
            timeout=30
        )

        data = response.json()
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]

        # strip markdown fences if Gemini adds them anyway
        clean = raw_text.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1]
            clean = clean.rsplit("```", 1)[0]

        result = json.loads(clean)
        return result

    except Exception as e:
        print(f"AI analysis failed: {e}")
        return None
