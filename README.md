# Capstone1

# AI-Assisted Tier-1 SOC Triage Assistant for Wazuh

## General Information

* **Project Title:** AI-Assisted Tier-1 SOC Triage Assistant for Wazuh

---

## Points of Contact

| Position | Name | Student ID | Phone Number | E-mail |
| :--- | :--- | :--- | :--- | :--- |
| **Industry Client** | [to be confirmed] | | | |
| **Supervisor** | Siti Hajar Khairuddin | | | 112972@sd.taylors.edu.my |
| **Project Member (CS1)** | Lau Hui Henk (Cybersecurity Student 1) | 0365791 | 0143381245 | huihenklau05@gmail.com |
| **Project Member (CS2)** | Arvin Raj (Cybersecurity Student 2) | | 0167081295 | |
| **Project Member (AI1)** | Chua Weng Hong (AI Student 1) | 0366751 | 0162978223 | chuawenghong2@gmail.com |
| **Project Member (AI2)** | Zhang Junyi (AI Student 2) | 0374235 | 0107622557 | vezq52431821z@gmail.com |
| **Project Member (AI3)** | Aryan Raj (AI Student 3) | | 0108241295 | |

---

## Executive Summary

Security Operations Centres (SOCs) receive more alerts than analysts can investigate carefully. The first look at each alert, known as Tier-1 triage, is repetitive, slow and easy to get wrong when workloads are high. This project builds an AI-assisted Tier-1 triage assistant for Wazuh, an open-source security monitoring platform.

When Wazuh raises an alert, the system collects the related logs, extracts indicators such as IP addresses and file hashes, and checks them against threat-intelligence services and a host inventory. A large language model (LLM), accessed through a hosted API, then reads this evidence and writes a structured triage report containing a verdict, the matching MITRE ATT&CK technique, the supporting evidence and a recommended action. A validator rejects any report that breaks the required format or cites evidence that does not exist. A web console shows the report to a human analyst, who approves or rejects the action. The system never acts on its own, and containment is simulated and logged.

The team will build and test the system in an isolated lab with two attack scenarios, SSH credential attacks on Linux and PowerShell living-off-the-land activity on Windows. It will be evaluated on about 80 labelled alerts against three baselines. This document sets out the problem, the objectives, the functionality, the scope, the 16-week plan and the team organisation.

---

## Project Purpose

### 1. Problem Statement

SOC analysts must validate the alerts raised by monitoring tools such as SIEM platforms. In a qualitative study with 21 practitioners from seven SOCs, Alahmadi et al. (2022) found that most alarms analysts regarded as false positives were benign triggers, meaning real detections that are explained by legitimate activity in the organisation. They also found that alarm validation is a tedious, human-centred task that can lead to alarm burnout and desensitisation. When analysts become desensitised, genuine attacks risk being treated as noise.

Slow detection and response is costly. IBM’s 2025 study reported a global mean time to identify and contain a breach of 241 days and an average breach cost of US$4.44 million (Kapko, 2025). Shortening the time between an alert and a correct decision is a practical way to reduce the damage of an intrusion, and Tier-1 triage is the first step at which time is lost.

LLMs are an active area of cybersecurity research: a systematic review analysed 127 papers on their use in security tasks (Xu et al., 2024). LLMs can read varied log text and write explanations, which suits triage. However, their output can be unreliable, and attacker-controlled text inside logs can try to manipulate them. A triage assistant therefore needs evidence checking, restricted read-only tools and human approval before any action. What is still needed is evidence of how well such a design performs on Wazuh alerts, compared with a human analyst and with simple baselines.

**Problem statement:** How can an LLM agent perform Tier-1 triage of Wazuh alerts accurately, quickly and with verifiable evidence, while keeping a human analyst in control of every action? The proposed computing-based approach combines automated log collection, threat-intelligence enrichment, an LLM agent with a fixed set of read-only tools, a report validator and a human-in-the-loop console, and measures the result on labelled lab alerts.

---

## Project Objectives

* **Objective 1:** Design and develop an automated pipeline that ingests Wazuh alerts, collects the related logs and enriches indicators with threat intelligence, producing a triage report for each alert in a median time of under 60 seconds.
* **Objective 2:** Implement an LLM-based triage agent, with structured JSON output and read-only tools, that assigns a verdict (true positive, false positive or escalate) and a MITRE ATT&CK technique to each alert, targeting at least 80% accuracy and 90% recall on malicious alerts in a 60-alert test set.
* **Objective 3:** Develop validation guardrails (JSON schema check, evidence-citation check and prompt-injection handling) so that at most 5% of the claims in a report lack supporting evidence.
* **Objective 4:** Develop a human-in-the-loop web console in which an analyst reviews the evidence and approves or rejects the recommended action, with every decision stored in an audit log.
* **Objective 5:** Evaluate the system against three baselines (Wazuh rule level, the same LLM without enrichment, and a human analyst) on about 80 labelled alerts from two attack scenarios, reporting accuracy, groundedness, consistency, time and cost.

---

## Proposed Functionality

| No. | Proposed Functionality | Problems Solved / Opportunities |
| :---: | :--- | :--- |
| **1** | Alert ingestion from Wazuh | Wazuh alerts arrive as raw, rule-centred JSON that an analyst must read and interpret by hand. |
| **2** | Log collection around each alert | Analysts spend time finding the related events on the same host and user before they can judge an alert. |
| **3** | Indicator extraction (IPs, hashes, domains, usernames) | Removes manual copying of indicators and gives the model a clean list of what to check. |
| **4** | Threat-intelligence enrichment (AbuseIPDB, VirusTotal) with caching | Replaces manual look-ups; caching keeps the free-tier rate limits from blocking runs. |
| **5** | Host and owner lookup from an asset CSV file | The same alert has a different risk on a server than on a test machine; context supports the verdict. |
| **6** | LLM triage agent with fixed read-only tools and a 6-step limit | Automates the first-look reasoning while keeping behaviour bounded, testable and unable to change any system. |
| **7** | Structured triage report (verdict, MITRE technique, evidence list, recommended action) | Gives consistent, comparable reports that can be scored against labels. |
| **8** | Report validator (schema check, evidence-ID check, retry) | Reduces unsupported or invented claims before an analyst sees the report. |
| **9** | Analyst console with Approve and Reject buttons | Keeps a human in control; nothing is acted on without approval. |
| **10** | Audit log and simulated containment | Records who decided what and when, without any risk of acting on a real host. |
| **11** | Template incident summary generated from the report fields | Saves analysts from writing the first incident summary from scratch. |
| **12** | Replay mode that runs the pipeline on stored alerts | Makes results repeatable and allows a demo without the lab or the internet. |
| **13** | Evaluation harness (accuracy, recall, groundedness, consistency, time, cost) | Turns performance claims into measured results against baselines. |

---

## Assumptions

* **A1.** A hosted LLM API with tool calling and JSON output stays available, and its cost stays within the team’s budget. This is reasonable because only about 80 alerts are processed, and cost per alert is recorded as a metric.
* **A2.** The free tiers of AbuseIPDB and VirusTotal are enough, because look-ups are cached and the number of alerts is small.
* **A3.** At least one team member has an x86-64 computer with 16 GB of RAM to host the Wazuh lab and the Windows and Linux victim machines, while other members run the backend and console on their own laptops. Wazuh’s prebuilt virtual machine image is understood to target x86-64 processors; this will be confirmed in week 1.
* **A4.** All attacks are run only against the team’s own virtual machines on an isolated network, and no real personal data or production system is used.
* **A5.** Wazuh raises usable alerts for both scenarios. Where it does not, the cybersecurity students write custom rules.
* **A6.** Two team members can label about 80 alerts between weeks 3 and 7 by following a written labelling guide.
* **A7.** The project runs for 16 weeks, and each member can contribute about 5 hours a week (about 385 hours in total).

---

## Project Description, Scope and Management Milestones

### Project Description

* **Approach:** The project follows an iterative build-and-measure approach. The team first builds an isolated lab with Wazuh and victim machines and generates alerts from two scenarios: SSH credential attacks (MITRE ATT&CK T1110 Brute Force and T1078 Valid Accounts) and PowerShell living-off-the-land activity (T1059.001, T1105 and T1027) (MITRE, n.d.). Two team members label each alert independently to create a ground-truth dataset of about 80 alerts, half malicious and half benign look-alikes. Twenty alerts are used to develop prompts and 60 are locked as a test set.
* **Solution:** The solution is a Python backend with five stages:
  1. Alert ingestion and log collection;
  2. Indicator extraction and cached enrichment from AbuseIPDB, VirusTotal and a host inventory file;
  3. A triage agent that calls a hosted LLM through a tool-calling API, with structured JSON output, a fixed set of read-only tools and a six-step limit;
  4. A validator that checks the JSON schema and that every claim cites an evidence ID; and
  5. A web console where an analyst approves or rejects the recommended action, with every decision stored in an audit log. A replay mode runs the pipeline on stored alerts so that results are repeatable.
* **Customers and Benefits:** The intended users are Tier-1 SOC analysts and small security teams that lack the staff to review every alert. The expected benefits are faster first-look triage, consistent and evidence-cited reports, and analysts who spend their time on decisions instead of data gathering. The project also produces a labelled alert dataset and a measured evaluation that others can reuse.

### Scope

* **Who:** A team of five students (three AI, two cybersecurity) under a project supervisor. The intended users are SOC analysts; fellow students act as analysts in the analyst-time study.
* **What is in scope:** Two attack scenarios (SSH credential attack, PowerShell living-off-the-land); a Wazuh lab with Linux and Windows victim machines; threat-intelligence enrichment from two APIs; a hosted LLM triage agent with a report validator; an analyst console with an audit log and simulated containment; a template incident summary; and an evaluation with baselines.
* **What is out of scope:** Ransomware, lateral-movement and data-exfiltration scenarios; Active Directory integration (replaced by a host CSV file); real containment actions on any host; legal mapping of incidents to regulations such as PDPA or GDPR; production deployment; and training or fine-tuning an LLM.
* **Where:** The lab runs on the team’s own computers on an isolated host-only network. The LLM is reached through a hosted API, and the console runs locally.
* **When:** 16 weeks, with three gates:
  * **Gate 1 (end of week 7):** One scenario works end to end and 40 alerts are labelled.
  * **Gate 2 (end of week 11):** Feature freeze.
  * **Gate 3 (end of week 14):** Results frozen.
* **Why:** To measure, on realistic alerts, whether an LLM agent can reduce Tier-1 triage effort without losing correctness or human control.
* **If the schedule slips:** One scenario, the pipeline, the report and an evaluation on 40 alerts remain a complete project.

---

## Summary of Milestones and Deliverables

| Milestone No. | Milestone | Person Responsible | Expected Duration (days) |
| :---: | :--- | :--- | :---: |
| **001** | Lab ready: Wazuh, Ubuntu and Windows victim machines, agents and LLM API access | CS1, AI1 | 14 |
| **002** | Attack scripts for both scenarios written and first alerts captured | CS1 | 14 |
| **003** | Labelling guide written; dataset v1 of 40 labelled alerts | CS2 (all label) | 35 |
| **004** | Alert collector and indicator extraction | AI2 | 21 |
| **005** | Cached threat-intelligence look-ups and host inventory | AI2 | 14 |
| **006** | Triage prompts, JSON schema and first end-to-end report (Gate 1, end of week 7) | AI1 | 28 |
| **007** | Agent loop with fixed tools and step limit; second scenario added | AI1, CS1 | 21 |
| **008** | Report validator and prompt-injection guardrails | AI2 | 21 |
| **009** | Full dataset of 80 labelled alerts locked | CS2, CS1 | 21 |
| **010** | Analyst console and audit log | AI3 | 28 |
| **011** | Template incident summary and replay mode; feature freeze (Gate 2, end of week 11) | CS2, AI3 | 14 |
| **012** | Evaluation runs: metrics, baselines and ablation | AI3, AI1 | 21 |
| **013** | Analyst-time study; results frozen (Gate 3, end of week 14) | All members | 14 |
| **014** | Final report, demo and slides | All members | 28 |

*Note: Durations overlap, so the project completes in 16 weeks (112 days). CS1 and CS2 are the cybersecurity students; AI1, AI2 and AI3 are the AI students.*

---

## Project Organization

### 1. Project Organization Structure
              ┌───────────────────────────────┐
              │       Project Supervisor      │
              │    [Siti Hajar Khairuddin]    │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐        ┌───────────────────────────────┐
              │          Project Team         │ · · ·  │        Industry Client        │
              │   5 students: 3 AI, 2 Cyber   │        │       [to be confirmed]       │
              └───────────────┬───────────────┘        └───────────────────────────────┘
                              │
  ┌──────────────┬────────────┴───┬──────────────┬──────────────┐
  ▼              ▼                ▼              ▼              ▼
┌───────────┐  ┌───────────┐    ┌───────────┐  ┌───────────┐  ┌───────────┐
│    CS1    │  │    CS2    │    │    AI1    │  │    AI2    │  │    AI3    │
│  Lau Hui  │  │ Arvin Raj │    │Chua Weng  │  │   Zhang   │  │ Aryan Raj │
│   Henk    │  │           │    │   Hong    │  │   Junyi   │  │           │
└─────┬─────┘  └─────┬─────┘    └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
│              │                │              │              │
▼              ▼                ▼              ▼              ▼
Lab & Attack    Labelling &       LLM Agent    Data Pipeline   Console &
Simulation   Threat Analysis       Lead            Lead       Evaluation
Lead           Lead                                           Lead


### 2. Roles and Responsibilities

| Name | Roles | Responsibilities |
| :--- | :--- | :--- |
| **[to be confirmed]** | Industry Client | To provide information on the key deliverables of the project and monitor project progress including providing any other assistance deemed important. |
| **Siti Hajar Khairuddin** | Project Supervisor | To provide guidance and support in term of knowledge, opinion and view throughout the entire project and to evaluating the project and provide recommendation for continuous improvement to meet the project objectives. |
| **Lau Hui Henk** | Cybersecurity Student 1: Lab and Attack Simulation Lead (CS1) | Builds and maintains the Wazuh lab and the victim machines, writes the attack scripts for both scenarios, and tunes or writes Wazuh rules so that each scenario raises usable alerts. |
| **Arvin Raj** | Cybersecurity Student 2: Labelling and Threat Analysis Lead (CS2) | Writes the labelling guide, leads the labelling and ground-truth review, maps alerts to MITRE ATT&CK techniques and drafts the incident summary template. |
| **Chua Weng Hong** | AI Student 1: LLM Agent Lead (AI1) | Designs the prompts, JSON schema and agent loop, selects the hosted model, and tunes the pipeline on the development alerts. |
| **Zhang Junyi** | AI Student 2: Data Pipeline Lead (AI2) | Builds the alert collector, indicator extraction, cached threat-intelligence look-ups and the report validator. |
| **Aryan Raj** | AI Student 3: Console and Evaluation Lead (AI3) | Builds the analyst console, audit log and replay mode, and the evaluation scripts that compute the metrics. |

*All members also label alerts, test the system and contribute to the final report, so that no single person’s judgement defines the ground truth.*

---

## Gantt Chart & Schedule

| Activity (milestones) | W1 | W2 | W3 | W4 | W5 | W6 | W7 | W8 | W9 | W10 | W11 | W12 | W13 | W14 | W15 | W16 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Lab setup (M1)** | ██ | ██ | | | | | | | | | | | | | | |
| **Attack scripts and labelling (M2-M3)** | | | ██ | ██ | ██ | ██ | ██ | | | | | | | | | |
| **Collector, intel and first report (M4-M6)** | | | | ██ | ██ | ██ | ██ | | | | | | | | | |
| **Agent, validator and 2nd scenario (M7-M9)** | | | | | | | | ██ | ██ | ██ | | | | | | |
| **Console, audit log and freeze (M10-M11)** | | | | | | | | | | ██ | ██ | | | | | |
| **Evaluation and analyst study (M12-M13)** | | | | | | | | | | | | ██ | ██ | ██ | | |
| **Report and demo (M14)** | | | | | | | | | | | | | ██ | ██ | ██ | ██ |
| **GATES** | | | | | | | **G1** | | | | **G2** | | | **G3** | | |

### Gates Definition
* **G1 (End of Week 7):** One scenario works end to end and 40 alerts are labelled.
* **G2 (End of Week 11):** Feature freeze.
* **G3 (End of Week 14):** Results frozen.

*(Note: Weeks are counted from project start).*

---

## References

* Alahmadi, B. A., Axon, L., & Martinovic, I. (2022). 99% false positives: A qualitative study of SOC analysts’ perspectives on security alarms. In *Proceedings of the 31st USENIX Security Symposium*. USENIX Association. https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi
* Kapko, M. (2025, July 30). Research shows data breach costs have reached an all-time high. *CyberScoop*. https://cyberscoop.com/ibm-cost-data-breach-2025/
* MITRE. (n.d.). *MITRE ATT&CK*. https://attack.mitre.org/
* Xu, H., Wang, S., Li, N., Wang, K., Zhao, Y., Chen, K., Yu, T., Liu, Y., & Wang, H. (2024). Large language models for cyber security: A systematic literature review. *arXiv*. https://arxiv.org/abs/2405.04760
