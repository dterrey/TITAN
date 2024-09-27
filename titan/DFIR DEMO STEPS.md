ADAM DEMO

1. Victim calls about a Cyber Attack on a Workstation
2. DFIR Team questions victim about what happened.
3. DFIR gathers information about the threat seen on workstation and Initial IOCS.
4. DFIR builds IOC list and while pre containment is exercised, fast forward image is taken of the machine and sent to DFIR.

ADAM/TriageX

.E01 image or KAPE/VR Triage is sent to NodeRed
NodeRED processes the image and run Hayabusa, Zircolite, Chainsaw and Log2Timeline.
Data is then ingested into TimeSketch for investigation.
ADAM AI connects to TimeSketch and allows the following features.

1. Targeted IOC Hunts and custom tagging in TimeSketch
2. Import Mitre ATT&CK data to TimeSketch and Sigma based hunts.
3. Targeted events searching with custom tagging in TimeSketch

Once the DFIR Analyst tagged all the iocs, malicious events.

4. ADAM AI exports all tagged events to a CSV.
5. (COMING SOON) ADAM AI, builds custom report based on all tagged events. 
