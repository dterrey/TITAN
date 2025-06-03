#### LATEST NEWS ####
I have been actively working on updating TITAN to the new TITANv2 (Docker Edition)
The whole platform will run in Docker Containers - currently up to 17 containers and growing.
You will soon be able to scale the titan processor container to the number of artifacts and hosts required to analyse which means its 100% scalable.
### This is NEVER SEEN BEFORE in the market ###

This is a fully AI Automated and AI Augmented DFIR Platform running custom AI. This isnt a normal AI Assistant, this is an AI Lab.

I will release it soon but as of now, its still a work in progress. 



# TITAN-X Platform: Threat Investigation and Analysis Network
Overview

TITAN-X (Threat Investigation and Analysis Network) is a cutting-edge Digital Forensics and Incident Response (DFIR) platform that leverages artificial intelligence (AI), machine learning, and automated investigation workflows. This platform assists DFIR analysts in analyzing events, detecting indicators of compromise (IOCs), and performing comprehensive threat hunting and investigation within an Elasticsearch or Timesketch environment.

The platform integrates tools like NodeRED, Timesketch, and third-party libraries to offer a seamless incident response and forensic investigation experience.
Threat Investigation and Tactical Analysis Network

Here’s an expanded version of the Key Features section, incorporating the AI network you are developing, which integrates spaCy and GPT-2 to enhance natural language processing and threat investigation within the TITAN-X platform:

# Key Features of TITAN-X

1. AI-Powered NLP Network: Integration of spaCy and GPT-2

TITAN-X leverages an advanced AI-powered network that integrates spaCy for rule-based natural language processing (NLP) and GPT-2 for more sophisticated deep learning-based understanding of complex queries. This network provides enhanced capabilities for analysts to interact with the platform in natural language, streamlining complex forensic tasks and investigations.
How the AI Network Works:

    spaCy:
        SpaCy is used for rule-based processing tasks such as tokenization, named entity recognition (NER), and part-of-speech tagging, which ensures fast and accurate parsing of structured queries. For instance, if an analyst asks "Show me all PowerShell execution events," spaCy quickly extracts and identifies the event types, commands, and timestamps needed for precise querying.
    GPT-2:
        GPT-2 brings the power of deep learning to the platform, allowing TITAN-X to process more complex or ambiguous queries, including conversational inputs. GPT-2 understands context and nuance, enabling the platform to generate responses or actions based on incomplete or vaguely defined requests. For example, when asked "What are the latest suspicious events?" GPT-2 interprets the query in the context of recent IOCs, flagged events, and related metadata.
    AI Network Collaboration:
        The spaCy and GPT-2 models work together in a hybrid network. When a query is entered, spaCy first processes the input to extract key entities and phrases, after which GPT-2 adds deeper semantic understanding and context. This results in more accurate query parsing and better handling of complex forensic tasks.

2. IOC Hunting and Tagging

    Auto-Investigation (auto_investigation.py): Automatically detects and hunts for Indicators of Compromise (IOCs) across large datasets within Timesketch and Elasticsearch. It then tags the events in Timesketch, allowing for deeper forensic investigation.
    Automated IOC Matching: Searches for IOCs, tags events that match, and generates detailed investigation reports.

3. Sigma Rule Integration

    Sigma Rule Parsing: TITAN-X integrates Sigma rules to detect suspicious activities and automatically match them to known MITRE ATT&CK tactics, techniques, and procedures (TTPs). The events are then tagged in Timesketch or Elasticsearch, providing quick access to potential threats.
    Customizable Rules: Add custom Sigma rules to extend threat detection capabilities based on your environment.

4. Automated Timeline Generation

    Log Parsing and Timeline Analysis: TITAN-X automatically processes logs and generates forensic timelines, allowing DFIR analysts to visualize and investigate incident timelines.
    Incident Correlation: Links events across different data sources, identifying common patterns and helping analysts detect multi-stage attacks.

5. Root Cause Hypothesis Generation

    AI-Driven Analysis: Based on the detected events and IOCs, TITAN-X uses AI to generate hypotheses about the root cause of an incident. The platform identifies MITRE ATT&CK techniques associated with the events and suggests potential starting points for the investigation.
    Hypothesis Summarization: Automatically summarizes findings from timelines, IOCs, and events, allowing DFIR analysts to quickly assess the situation.

6. Elasticsearch Integration

    Elasticsearch Backend: TITAN-X leverages Elasticsearch as its backend for storing and querying large datasets, making it highly scalable and efficient for handling enterprise-scale DFIR cases.
    Search and Query Events: Execute complex searches and retrieve structured results directly from Elasticsearch.

7. Timesketch Integration

    Timesketch Tagging and Querying: Seamlessly integrates with Timesketch to allow for event tagging, querying, and forensic timeline creation. The auto-investigation script (auto_investigation.py) interacts with Timesketch to automatically tag IOCs and generate event reports.
    Export to Timesketch: Analysts can export their investigation findings into Timesketch for further collaborative analysis and reporting.

8. NodeRED Integration

    Automated Workflow Processing: NodeRED automates data processing tasks such as log parsing and IOC extraction. By running collectors and ingesting logs (e.g., from Velociraptor or KAPE), it prepares the data for ingestion into TITAN-X.
    Modular Automation: Create custom automation workflows for forensic triage, data extraction, and other incident response actions.

9. Threat Intelligence Integration

    STIX, YARA, Sigma, JSON: Support for a wide range of threat intelligence formats, including STIX, YARA, Sigma, and custom JSON files, enabling analysts to load IOCs and match them against incoming events.
    Automatic Matching: Threat intelligence feeds are automatically ingested, parsed, and compared to events in the system for real-time threat detection and reporting.

10. Customizable Reports and Export Options

    IOC-Based Reports: Automatically generates detailed IOC hunt reports summarizing matched IOCs, event timelines, and potential attack paths.
    CSV Export: Export investigation findings to CSV for easy sharing and integration with other tools.
    PDF Reporting: Generate comprehensive, formatted PDF reports summarizing events, timelines, and root cause hypotheses.

11. Mitre ATT&CK Integration

    ATT&CK Mapping: All events tagged in Timesketch or Elasticsearch are mapped to MITRE ATT&CK TTPs, providing quick reference to the relevant tactics and techniques.
    Custom ATT&CK Tags: Analysts can query specific ATT&CK techniques (e.g., “List of defense evasion techniques”) and get an overview of events that map to them.

12. Scalability and Flexibility

    Large-Scale Investigations: TITAN-X is built for handling massive datasets and large-scale investigations, whether you're analyzing logs from a single system or across an entire organization.
    Customizable Architecture: The platform is modular, allowing for custom integrations, plugins, and extensions to suit specific organizational needs.

Example Use Cases:

    IOC Hunting: Automatically detects IOCs across multiple systems, tags events, and generates a detailed report for incident responders.
    Suspicious Event Investigation: Analysts can use NLP queries to investigate suspicious logon events, file executions, or command-line activity.
    Forensic Timeline Creation: Generates detailed forensic timelines for deep analysis of compromised systems.
    Root Cause Analysis: Automatically identifies potential root causes of an incident based on MITRE ATT&CK techniques and summarizes the findings.

License

This project is licensed under the Apache License 2.0. See the LICENSE file for more details.
NOTICE

This product, TITAN-X, includes software developed by [David Terrey], the creator of the platform. TITAN-X is designed to assist DFIR analysts and cybersecurity professionals in automating threat investigation, incident response, and forensic analysis.

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
