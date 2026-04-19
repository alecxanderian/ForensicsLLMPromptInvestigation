#

Alec C
Embry-Riddle Aeronautical University

AI Prompt Injection Forensics

This project simulates a vulnerable AI system and performs a digital forensic investigation on prompt-based attacks. The goal is to analyze how adversarial prompts can bypass safeguards and extract sensitive information from large language models.

---

## Overview

Modern AI systems can be manipulated using prompt injection attacks instead of traditional exploits. This project recreates that scenario by:

- Building a vulnerable LLM application
- Simulating attacker behavior using crafted prompts
- Logging all interactions as forensic evidence
- Analyzing logs to detect attacks and data leaks

---

## Features

- Vulnerable LLM system (Flask + Ollama + Phi3)
- Simulated confidential data exposure
- Automated multi-session attack generation
- Structured forensic logging (JSONL format)
- Attack classification and tagging
- Investigation scripts for:
  - Pattern detection
  - Leak confirmation
  - Timeline reconstruction
  - Summary reporting

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/alecxanderian/AI-Prompt-Injection-Forensics.git
cd AI-Prompt-Injection-Forensics

pip install -r requirements.txt

sudo apt install ollama
ollama run phi3
run:
python3 victim_vuln_app.py

then run attack.py to gather chatlog events

python3 master_investigation_report.py
