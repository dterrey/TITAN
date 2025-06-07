#### LATEST NEWS ####
I have been actively working on updating TITAN to the new TITAN_Docker (Docker Edition)
The whole platform will run in Docker Containers - currently up to 17 containers and growing.
You will soon be able to scale the titan processor container to the number of artifacts and hosts required to analyse which means its 100% scalable.

This is a fully AI Automated and AI Augmented DFIR Platform running custom AI. This isnt a normal AI Assistant, this is an AI Lab.

I'm still fixing the installation script so it all works flawlessly and on any machine.

#### NOTE ####

Its still a work in progress as the original TITAN worked on a VM whereas I want it to ultimately work in a DOCKER Containers. 

Thanks.

#### Special Considrations ####
This project was forked and improved on from - https://github.com/blueteam0ps/AllthingsTimesketch. 
This project leverages the following open-source projects
Timesketch
Log2timeline/Plaso
Node-RED
Hayabusa

#### AS THIS PROJECT WAS DEVELOPED UNDER THE APACHE LICENSE 2.0 ALONG WITH ALL OPEN-SOURCE PROJECTS, TITAN IS UNDER APACHE LICENSE 2.0 PROTECTION ####

#### On that note, as TITAN is currently 20000 files which is a combination of custom script developed by David Terrey (Myself) with the assistance of TITAN AI. Writing documentation for this will take some time so feel free to contact me if you have any questions. ####

License

This project is licensed under the Apache License 2.0. See the LICENSE file for more details.
NOTICE

This product, TITAN, includes custom scripts developed by [David Terrey], the creator of the platform. TITAN is designed to assist DFIR analysts and cybersecurity professionals in automating threat investigation, incident response, and forensic analysis.

Attribution: The following third-party libraries and tools are used in this project, each under their respective open-source licenses:

    GPT-2 (MIT License)
        https://github.com/openai/gpt-2
    spaCy (MIT License)
        https://github.com/explosion/spaCy
    NLTK (Apache License 2.0)
        https://www.nltk.org/
    Timesketch API Client (Apache License 2.0)
        https://github.com/google/timesketch
    Pandas (BSD 3-Clause License)
        https://github.com/pandas-dev/pandas
    Flask (BSD 3-Clause License)
        https://github.com/pallets/flask
    Zircolite (MIT License)
        https://github.com/wagga40/Zircolite

Ensure that any use, modification, or redistribution of this project includes proper attribution to [David Terrey], as per the terms of the Apache License 2.0.


________________________________________

TITAN Overview

TITAN is a modular, AI-augmented Cybersecurity Incident Response and Forensics Platform built to unify, automate, and scale modern DFIR operations. It streamlines investigations, reduces analyst fatigue, and accelerates the detection, containment, and reporting lifecycle through intelligent automation and machine learning.

TITAN offers a unified investigation workspace where analysts can collect evidence, parse data, hunt threats, enrich IOCs, correlate logs, triage alerts, and generate reports — all from one integrated platform. It supports everything from endpoint triage to reverse engineering and executive reporting, tightly aligned to MITRE ATT&CK and tailored for rapid response.

TITAN scales elastically using Docker Swarm or Kubernetes, enabling simultaneous processing of 100s–1000s of hosts or forensic images across distributed infrastructure. Its built-in SIEM engine (TITAN SIEM) uses tagging, TIP enrichment, and IOC correlation to reduce millions of raw logs to only what matters — helping responders cut through the noise and focus immediately on high-risk activity.

TITAN can also integrate with forensic tools such as X-Ways Forensics using command-line automation, case templates, and scripting to automate image parsing, hash generation, artifact export, and bookmarking — with results automatically ingested back into TITAN for enrichment, correlation, and reporting.

With built-in support for air-gapped environments, modular deployment, and automated workflows, TITAN enables fast onboarding, consistent investigation standards, and high-efficiency surge response capabilities — from one analyst to an entire response team.

________________________________________
Core Investigation Workflows

TITAN supports a standard DFIR workflow through automation and orchestration of the following steps:
1. Trigger & Data Ingestion
Log2Timeline, Velociraptor, CrowdStrike, KAPE Triage, Raw Disk Images (e01, VMDK, VHDX), X-Ways-compatible image formats
Cloud integration with Azure, Google and AWS coming soon.
Supports SIEM, EDR, and custom agents via API coming soon
2. Evidence Collection & Parsing
Artifact acquisition (memory, disk, logs, cloud), timeline generation, IOC extraction
Tools: custom tools and scripts, automated X-Ways batch jobs, and parsing of exported data from .xwf cases or bookmarks
3. Automated Analysis
Correlation, rule matching (Sigma/YARA), tagging, anomaly detection and AI analysis.
X-Ways output (hash lists, bookmarks, timelines) can be automatically fed into TITAN SIEM or timeline modules
4. Threat Classification & Enrichment
Use of ML/NLP for event tagging, TTP detection, and threat actor mapping
Real-time IOC enrichment via TIP APIs and cross-referencing with X-Ways file artifacts.
5. Response & Reporting
Playbook execution, threat containment suggestions
Auto-generated executive-level reports and technical narratives including X-Ways output
6. Manual Verification
Confirmation from Incident responder / analyst, including review of artifacts parsed via X-Ways and loaded into TITAN SIEM or linked reports

________________________________________
AI/ML Component
TITAN includes a dedicated AI/ML engine that enhances analyst workflows and decision-making using the following models:
BERT – Event classification and context understanding
T5 – Data refinement and summarisation
LLaMa 3.2 – Narrative generation and report writing
Lucy – Cyber Security Intelligence Database
MITRE ATT&CK - MITRE ATT&CK Mapping TTPs to assist with timeline generation.
Custom Neural Network – Anomaly detection, IOC pattern recognition
These models assist in reducing false positives, prioritising alerts, and generating human-readable insights, minimising time-to-decision during critical incidents.

________________________________________
Key Features, Components & Integrations

Key Features
Feature Description
IOC Extraction & Management Automated detection, enrichment, and correlation of indicators
Timeline & Artifact Analysis Custom parsing, including X-Ways artifact exports, and integration with SIEM for event correlation
Remote Agent Deployment One-click automated agent deployment on remote hosts for quick triage collection and monitoring.
Automated Playbooks Custom/standard workflows that include X-Ways case execution or output ingestion
ML-Powered Classification NLP models auto-tag events, classify threats, mapping MITRE ATT&CK TTPS, summarise findings and SIEM query generation.
Threat Intelligence TIP integration for real-time context around indicators and actors
Containerised & Scalable Deployable and scalable via Docker Swarm or Kubernetes
Executive Reports Auto-generated reports with contextual and technical breakdowns
Parallel Image Processing Supports 10s–1000s of images concurrently across hosts
TITAN SIEM
Custom OpenSearch-based SIEM to ingest and correlate logs/artifacts from X-Ways and other sources

MITRE ATT&CK Built-in MITRE ATT&CK enrichment fields enable structured analysis across all phases (Initial Access, Execution, Persistence, etc.).

________________________________________
Key Components
• TITAN Admin – Management UI, coordination, and control
• TITAN Client – Remote Endpoint orchestration (Velociraptor, CrowdStrike deployment)
• TITAN Threat – IOC management, threat correlation, API TIP integration, automated online threat hunts.
• TITAN Console – AI/ML processing, NLP tagging, automated decisions, SIEM query generation, MITRE ATT&CK Mapping Techniques.
• TITAN Sandbox – Detonation, behaviour analysis, AI assisted Reverse Engineering and static analysis.
• TITAN SIEM – Op Log and artifact analysis (including X-Ways exports) with tagging, correlation, and reporting

________________________________________
Integrations
• SIEM / Triage Collection: CrowdStrike, SentinelOne, Splunk, Microsoft Defender – Automated remote agent deployment
• Threat Intel Platforms (TIPs): Can be integrated using APIs to enrich TITAN Threat and enhance automated tagging of IOCs.
• Forensics & Triage: Velociraptor, OpenSearch, X-Ways Forensics, custom python scripts and other tools.
• Storage: MinIO, PostgreSQL, OpenSearch
• AI Libraries: HuggingFace Transformers, PyTorch, TensorFlow

________________________________________
Key Benefits of TITAN

Benefit Description
Rapid Triage & Response Reduces investigation timelines by 50–70% through automation
Analyst Efficiency Offloads repetitive tasks, enabling faster decision-making
AI-Augmented Investigation Supports analysts with intelligent classification, event tagging of IOCs within TITAN SIEM and summary generation.
Scalable Anywhere Can run on 2–4GB RAM but requires more for processing and parsing of larger artifacts, supports cloud, on-prem, and air-gapped environments
Consistency & Accuracy Standardises workflows and reduces human error
Reduced Burnout Frees analysts from manual “click work” to focus on strategic thinking
Modular & Customisable Easily tailored for specific use cases, industries, or threat profiles.
Threat Intelligence Integrated online search engine with AI intelligence that searches, extracts and stores IOCs within TITAN Threat for automated tagging and analysis.
Accelerated Onboarding TITAN’s modular, containerised design allows new analysts or response teams to get up and running quickly with prebuilt playbooks, tagging logic, and dashboards.
TITAN SIEM Reduces log volume from millions to tagged priority events. Accelerates analysis and supports MITRE ATT&CK-aligned investigations.
Auditability & Evidence Preservation All investigation steps, tags, decisions, and reports are logged and timestamped, ensuring full traceability for audits, legal reviews, or regulatory compliance.
Support for Air-Gapped Environments Designed to run offline with minimal resources, making it ideal for classified, or highly regulated environments.
Automated IOC Propagation Once identified in TITAN Threat, IOCs can be automatically tagged across new incoming logs and artifacts via TITAN SIEM, ensuring continuous coverage without rework.
Elastic Scaling for Surge Response During major incidents or threat hunts, TITAN can dynamically scale horizontally across containers/nodes to handle increased ingestion, parsing, and correlation workloads.
Unified Investigation Workspace Analysts no longer need to pivot between tools — TITAN brings endpoint triage, SIEM, TIP, AI tagging, reverse engineering, and reporting into a single investigation pane.

Additionally, TITAN will support parallel image/artefact processing by deploying multiple containers across nodes. It scales dynamically with Docker Swarm/Kubernetes, enabling analysis of 100s–1000s of hosts simultaneously—greatly improving performance and time-to-analyse.

