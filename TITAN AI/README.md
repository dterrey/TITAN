README

UPDATE
zircolitereport.py is a csv report of all mitreattack sigma findings

mitrecti.py is REQUIRED FOR MITRE DATABASE - what is akira, what is T1723 etc etc etc

adam.py is the current working script and adam_script.py is the backup working. Always back up working after every change and test.

event_descriptions.json is the NLG summary but is broken but not sure if I should fix it

iocs_storage.json is the saved file when upload /home/triagex/Downloads/iocs.csv or results_2134423423.json (codex hash results file)

Custom tagging of events is KEY and VERY IMPORTANT to speed up the analysis.

Need to run KAPE on a infected machine to get some test CSVs and ingest into TIMESKETCH

Need to complete Zircolite custom template in timesketch
Zircolite_TS.py is the template
ts_tagging.py is the custom JSONL tagger. 

cg.py is the codex python script
codex.py is the main codexgiggas python script - both required for codex to work.

Need to also configure to run in /opt when completed.
and modify the triage_script.sh to also update the folder directories when deploying and update with the new pip installation and deployments.

flask_cli.py is the test UI script for ADAM... Still need to be updated.


CURRENT FEATURES

Example questions you can ask:
- logon events
- logoff events
- event id 4624
- execution techniques
- persistence techniques
- show me all the threats detected
- show me defender threats
- How many events are tagged with execution?
- Show me all PowerShell events.
- Find all file deletion events.
- How many malware detection events occurred?
- What is the Windows Defender Malware Detection History Deletion?
- show me execution and persistence techniques
- show me execution and persistence techniques and export to exec_persis.csv
- upload upload /home/triagex/Downloads/ADAM/iocs.csv
- What was the last logon?
- How many malware detections were there?
- switch to timesketch
- switch to file
- show me the list of indicators and export to indicators.csv
- show me the list of tools
- show me the list of commands
- show me the list of hashes
- show me the list of IPs
- show me the list of domains
- show me the MITRE ATT&CK techniques
- show me the list of credential access and persistence techniques
- show me all initial access events
- show me all defense evasion events
- show me all command and control events
- IMPORTANT - set export <folderpath>
- codex file
- codex hash
- scan url google.com
- scan url yahoo.com
- search for iocs in timesketch and export to iocs.csv
- search for iocs in timesketch and tag iocs
- tag 4625 events or tag akira events or tag powershell events>
- generate root cause hypothesis
- export all tagged events to tagged.csv
- tag test.exe events
- run sigma hunt /home/triagex/Downloads/sigma/rules/windows
