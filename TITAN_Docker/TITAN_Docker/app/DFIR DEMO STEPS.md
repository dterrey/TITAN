ADAM DEMO

1. IOC Platform
2. Codex hash
3. Parse Codex button
4. titan - search for iocs in timesketch

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

Process
Log2timeline .E01 file
Mount .E01
Filehash everything
Zircolite .E01
Hayabusa / Chainsaw .E01
Unmount .E01

Titan Script to Import Zircolite Data

def handle_zircolite_import():
    # Paths to the Node.js script and data.js
    nodejs_script_path = '/home/triagex/Downloads/TITAN/extract_data.js'  # Replace with the actual path
    data_js_path = '/home/triagex/Downloads/TITAN/data.js'  # Replace with the actual path
    json_output_directory = '/home/triagex/Downloads/TITAN/zircolite'  # Same as outputDirectory in extract_data.js

titan.py
import zircolite data
