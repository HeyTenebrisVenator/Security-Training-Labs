from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from markupsafe import escape
import re
import json
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "comments.json"

WAF_ENABLED_DEFAULT = True
WAF_RULES = [
    {
        "id": "xss-script-tag",
        "description": "Blocks tag <script>",
        "pattern": r"<\s*/?\s*script\b",
        "severity": "high",
    },
    {
        "id": "xss-event-handler",
        "description": "Blocks atributos onerror/onload/onclick/etc",
        "pattern": r"\bon[a-zA-Z]{2,}\s*=",
        "severity": "high",
    },
    {
        "id": "xss-javascript-uri",
        "description": "Blocks javascript: em links/src",
        "pattern": r"javascript\s*:",
        "severity": "high",
    },
    {
        "id": "xss-dangerous-tags",
        "description": "Blocks tags comuns em payloads XSS",
        "pattern": r"<\s*(iframe|object|embed|svg|math|img|video|audio|body|details|marquee)\b",
        "severity": "medium",
    },
    {
        "id": "xss-expression-eval",
        "description": "Blocks eval/alert/prompt/confirm/document.cookie",
        "pattern": r"\b(eval|alert|prompt|confirm)\s*\(|document\s*\.\s*cookie",
        "severity": "medium",
    },
    {
        "id": "xss-encoded-angle",
        "description": "Blocks alguns encodings comuns de < e >",
        "pattern": r"(%3c|%3e|&lt;|&gt;|&#x?0*3c;|&#x?0*3e;)",
        "severity": "medium",
    },
]


def load_comments():
    if not DB_FILE.exists():
        return []
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_comments(comments):
    DB_FILE.write_text(json.dumps(comments, indent=2, ensure_ascii=False), encoding="utf-8")


def waf_enabled():
    value = request.args.get("waf", "1" if WAF_ENABLED_DEFAULT else "0")
    return value not in ("0", "false", "False", "off", "OFF")


def normalize_for_waf(value: str) -> str:
    if value is None:
        return ""
    normalized = value
    replacements = {
        "%3C": "<", "%3c": "<", "%253C": "%3C", "%253c": "%3c",
        "%3E": ">", "%3e": ">", "%253E": "%3E", "%253e": "%3e",
        "%22": '"', "%27": "'", "+": " ",
    }
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    return normalized


def inspect_waf(value: str):
    normalized = normalize_for_waf(value)
    matches = []
    for rule in WAF_RULES:
        if re.search(rule["pattern"], normalized, flags=re.IGNORECASE):
            matches.append(rule)
    return matches


def waf_check_or_block(*values):
    if not waf_enabled():
        return None
    all_matches = []
    for value in values:
        all_matches.extend(inspect_waf(value or ""))
    if all_matches:
        unique = {m["id"]: m for m in all_matches}.values()
        return render_template(
            "blocked.html",
            rules=list(unique),
            original_values=values,
            waf_enabled=waf_enabled(),
        ), 403
    return None


def unsafe_response(html: str):
    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["X-Lab-Warning"] = "Intentionally vulnerable XSS laboratory"
    return response


@app.route("/")
def index():
    return render_template("index.html", waf_enabled=waf_enabled(), rules=WAF_RULES)


@app.route("/reflected-get")
def reflected_get():
    q = request.args.get("q", "")
    blocked = waf_check_or_block(q)
    if blocked:
        return blocked
    html = render_template("reflected_get.html", q=q, waf_enabled=waf_enabled())
    return unsafe_response(html)


@app.route("/form-injection", methods=["GET", "POST"])
def form_injection():
    name = ""
    bio = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        bio = request.form.get("bio", "")
        blocked = waf_check_or_block(name, bio)
        if blocked:
            return blocked
    return unsafe_response(render_template("form_injection.html", name=name, bio=bio, waf_enabled=waf_enabled()))


@app.route("/comment-xss", methods=["GET", "POST"])
def comment_xss():
    comments = load_comments()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        comment = request.form.get("comment", "")
        blocked = waf_check_or_block(author, comment)
        if blocked:
            return blocked
        comments.append({
            "author": author,
            "comment": comment,
            "created_at": datetime.utcnow().isoformat() + "Z",
        })
        save_comments(comments)
        return redirect(url_for("comment_xss"))
    return unsafe_response(render_template("comment_xss.html", comments=comments, waf_enabled=waf_enabled()))


@app.route("/comment-xss/reset", methods=["POST"])
def reset_comments():
    save_comments([])
    return redirect(url_for("comment_xss"))


@app.route("/dom-xss")
def dom_xss():
    return render_template("dom_xss.html", waf_enabled=waf_enabled())


@app.route("/href-xss")
def href_xss():
    next_url = request.args.get("next", "https://example.com")
    label = request.args.get("label", "Clique aqui")
    blocked = waf_check_or_block(next_url, label)
    if blocked:
        return blocked
    return unsafe_response(render_template("href_xss.html", next_url=next_url, label=label, waf_enabled=waf_enabled()))


@app.route("/src-xss")
def src_xss():
    image_url = request.args.get("image", "/static/img/missing.png")
    alt = request.args.get("alt", "Imagem do laboratório")
    blocked = waf_check_or_block(image_url, alt)
    if blocked:
        return blocked
    return unsafe_response(render_template("src_xss.html", image_url=image_url, alt=alt, waf_enabled=waf_enabled()))


@app.route("/attribute-xss")
def attribute_xss():
    value = request.args.get("value", "demo")
    blocked = waf_check_or_block(value)
    if blocked:
        return blocked
    return unsafe_response(render_template("attribute_xss.html", value=value, waf_enabled=waf_enabled()))


@app.route("/safe-examples")
def safe_examples():
    q = request.args.get("q", "")
    return render_template("safe_examples.html", q=q, escaped_q=escape(q), waf_enabled=waf_enabled())


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    blocked = waf_check_or_block(q)
    if blocked:
        return jsonify({"blocked": True, "reason": "simulated_waf"}), 403
    return jsonify({"query": q, "message": f"Resultado para: {q}"})


@app.route("/health")
def health():
    return jsonify({"ok": True, "lab": "xss-professional-lab"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
