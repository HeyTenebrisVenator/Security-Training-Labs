# Professional XSS Security Lab

A deliberately vulnerable local web application designed to test XSS scanners, payloads, injection contexts, and simulated WAF bypass techniques.

> Use only in isolated or controlled environments. This project intentionally contains vulnerabilities.

## Installation

```bash
cd xss_professional_lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open:

http://127.0.0.1:5000

## Main Endpoints

- /reflected-get?q=...
- /form-injection
- /comment-xss
- /dom-xss
- /href-xss
- /src-xss
- /attribute-xss
- /safe-examples
- /api/search

## Simulated WAF

The laboratory includes a simple educational WAF that blocks common XSS payload patterns. It can be disabled per request using:

?waf=0

## Injection Contexts

- Reflected XSS
- Stored XSS
- DOM-Based XSS
- HTML Context
- Attribute Context
- HREF Injection
- SRC Injection
- API Reflection

This laboratory is intended for security research, training, and scanner validation.
