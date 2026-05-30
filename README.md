# Security Training Labs

A collection of intentionally vulnerable web applications and security training environments designed for research, education, vulnerability assessment, and scanner validation.

## Overview

This repository contains multiple security laboratories covering common web application vulnerabilities and security misconfigurations.

The primary goal is to provide realistic environments for:

* Security training
* Bug bounty practice
* Vulnerability research
* Payload development
* Scanner validation
* False-positive analysis
* Security automation testing

## Included Labs

| Lab                | Description                                               |
| ------------------ | --------------------------------------------------------- |
| XSS Lab            | Reflected, Stored, DOM, HREF, SRC, and Blind XSS          |
| SQL Injection Lab  | Error-based and Time-based SQLi simulation                |
| SSRF Lab           | Internal resource access and metadata endpoint simulation |
| SSTI Lab           | Server-Side Template Injection scenarios                  |
| File Upload Lab    | Upload validation bypasses and dangerous file handling    |
| Open Redirect Lab  | Redirect validation weaknesses                            |
| XXE Lab            | XML External Entity testing environments                  |
| RCE Lab            | Remote Code Execution training scenarios                  |
| Business Logic Lab | Workflow and logic flaw exercises                         |
| BAC/IDOR Lab       | Authorization and object access control weaknesses        |
| GraphQL Lab        | GraphQL enumeration and security testing                  |
| Exposure Lab       | Information disclosure and sensitive file exposure        |

## Objectives

These laboratories were created to help researchers understand:

* Vulnerability discovery
* Exploitation techniques
* Detection methodologies
* Payload behavior
* WAF bypasses
* Security controls
* Scanner limitations
* False positive reduction

## Repository Structure

```text
labs/
├── xss/
├── sqli/
├── ssrf/
├── ssti/
├── file_upload/
├── open_redirect/
├── xxe/
├── rce/
├── business_logic/
├── bac/
├── graphql/
└── exposures/
```

## Features

Most labs include:

* Multiple vulnerability variations
* Realistic application workflows
* Logging systems
* Simulated WAF protections
* Security headers
* Challenge difficulty levels
* Educational documentation
* Sample payloads

## Usage

Clone the repository:

```bash
git clone https://github.com/your-username/security-training-labs.git
cd security-training-labs
```

Navigate to a specific laboratory:

```bash
cd labs/xss
```

Install requirements:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

## Scanner Validation

These labs are particularly useful for validating:

* Reconnaissance tools
* Web vulnerability scanners
* Custom security modules
* Fuzzers
* Detection engines
* Machine learning classifiers
* Security research projects

## Educational Purpose

All laboratories in this repository are intentionally vulnerable and should only be deployed in isolated environments.

Do not expose these applications to the public Internet.

## Contributing

Contributions are welcome.

Possible contributions include:

* New vulnerability scenarios
* Additional challenge levels
* WAF bypass exercises
* Security header configurations
* Documentation improvements
* New training environments

## License

This project is intended for educational and security research purposes only.
