import json
import logging
import os
import traceback

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify

from detect import analyze, build_explanation

load_dotenv()

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

_model = None
if GEMINI_API_KEY:
    import google.generativeai as genai
    genai.configure(api_key=GEMINI_API_KEY)
    _model = genai.GenerativeModel("gemini-3.5-flash")

SYSTEM_PROMPT = """You are a phishing detection assistant for students. You will be given a \
suspicious message and a list of red flags already detected by a rule engine. \
Decide the final risk assessment and respond with ONLY valid JSON, no other text, matching \
this exact schema:

{
  "score": <integer 0-100>,
  "label": "Safe" | "Suspicious" | "High Risk",
  "red_flags": [{"category": str, "matched": str, "reason": str}],
  "explanation": <one short paragraph summarizing overall why this message got this label>,
  "next_action": <one short sentence of concrete advice>
}

Score bands: 0-29 Safe, 30-64 Suspicious, 65-100 High Risk. You may adjust the rule engine's \
flags/score/reasons if you find they misjudged the message, and you may add flags the rule \
engine missed. Keep reasons short (one sentence each), explanation to 1-2 sentences, and \
next_action concrete and actionable for a student."""


def classify_with_ai(message, rule_result):
    user_prompt = (
        f"Message:\n{message}\n\n"
        f"Rule engine detected these red flags:\n{json.dumps(rule_result['red_flags'], indent=2)}\n"
        f"Rule engine score: {rule_result['score']} ({rule_result['label']})\n\n"
        "Return the final JSON assessment now."
    )
    response = _model.generate_content(
        f"{SYSTEM_PROMPT}\n\n{user_prompt}",
        generation_config={"response_mime_type": "application/json"},
        request_options={"timeout": 25},
    )
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    result = json.loads(raw)
    if not result.get("explanation"):
        result["explanation"] = build_explanation(result.get("label", ""), result.get("red_flags", []))
    return result


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    rule_result = analyze(message)

    if _model:
        try:
            ai_result = classify_with_ai(message, rule_result)
            ai_result["source"] = "ai"
            return jsonify(ai_result)
        except Exception as e:
            app.logger.error("Gemini classification failed:\n%s", traceback.format_exc())
            rule_result["source"] = "rules-fallback"
            rule_result["ai_error"] = str(e)
            return jsonify(rule_result)

    rule_result["source"] = "rules-fallback"
    return jsonify(rule_result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
