# Vendor Risk Assessment Tool

A Python-based cybersecurity project that evaluates third-party vendors using questionnaire responses, external exposure signals, vulnerability findings, and business impact factors to generate explainable risk scores.

## Overview

This project simulates a security review workflow. Instead of relying on a simple checklist, it combines multiple security and business inputs into a single assessment that is easier to review, compare, and defend.

The goal was to build something relevant to real-world cybersecurity analyst, security risk, GRC, and third-party risk work.

### Single-vendor assessment

![Single vendor risk report](assets/single-vendor-report.png)

### Multi-vendor ranking

![Multi-vendor risk ranking](assets/multi-vendor-ranking.png)

## Features

- Evaluates questionnaire responses using weighted security control scoring
- Assesses external exposure signals that expand the vendor's attack surface
- Analyzes vulnerability findings that increase exploitability risk
- Applies impact multipliers and contextual amplification factors
- Produces an explainable report with key drivers and recommendations
- Compares multiple vendors in batch mode and ranks them by risk
- Exports single-vendor assessments to markdown for reporting

## Cybersecurity Concepts Demonstrated

This project highlights several core cybersecurity concepts used in vendor and third-party risk analysis:

- **Access control risk:** evaluates weaknesses like missing MFA or SSO support
- **Data protection risk:** considers encryption and handling of sensitive data
- **Compliance risk:** accounts for missing audit evidence or weak assurance posture
- **Incident history risk:** incorporates past incidents and transparency into scoring
- **Attack surface awareness:** external exposure contributes to vendor risk
- **Vulnerability-based risk:** known weaknesses increase exploitability and urgency
- **Business impact analysis:** vendors with privileged access, sensitive data access, or operational dependency create higher downstream risk
- **Risk-based decision making:** outputs support escalation, review, or approval decisions
- **Explainable security reporting:** reports show why a vendor scored the way it did, not just the final number

## How It Works

The final score is driven by four main inputs:

1. **Questionnaire controls**  
   Weighted questions evaluate vendors across categories like access control, data protection, compliance, and incident history.

2. **External exposure**  
   Accounts for whether the vendor has risky or unnecessary internet-facing exposure.

3. **Vulnerabilities**  
   Adds risk based on known security weaknesses and patching concerns.

4. **Impact and amplifications**  
   Adjusts the score based on business criticality and contextual risk factors such as privileged access, sensitive data handling, and operational dependency.

## CLI Usage

### Run a single vendor assessment

```bash
python -m src.main --vendor data/vendor1.json
```

### Export a markdown report
```bash
python -m src.main --vendor data/vendor1.json --export-md reports/vendor_report.md
```

### Compare multiple vendors
```bash
python -m src.main --folder data/multivendor

