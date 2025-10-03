#  MITRE-Sigma Lookup Tool

CLI tool to lookup the MITRE mitigations and the Sigma detections for any technique
## Project Background
This project is intended to be a starting point for anyone beginning a journey in cybersecurity. This project is small in scope and only requires basic skills, but touches on critical concepts used in cybersecurity operations, threat hunting, and incident response.

**MITRE ATT&CK** is a globally accessible knowledge base of adversary tactics and techniques. Security teams use it to understand attacker behaviors, plan defenses, and map observed activity in their networks.

**Sigma** is a generic and open signature format for SIEM (Security Information and Event Management) systems. It allows security teams to define detection rules once and convert them to different SIEM formats. By linking ATT&CK techniques to Sigma rules, analysts can quickly translate threat intelligence into actionable detection logic.

Through this project, you will interact with ATT&CK data, extract useful information, and gain hands-on exposure to practical cybersecurity workflows while developing your Python and Linux skills.

This project will also include suggestions to improve, customize, and expand its features. After completing the project, consider implementing one or more of these suggestions for further learning and to make this project really standout on a resume.
## Project Specifications
Input: an ATT&CK technique ID (`T1564`) or technique name.
Output:
	Basic technique info (name, description)
	ATT&CK mitigations related to that technique
	Sigma rules that mention the technique ID

### Prerequisites
Beginner Python skills
Basic Linux skills, including familiarity with a command line text editor (e.g. `vim`) 
Basic Git/GitHub skills
Basic understanding of MITRE ATT&CK and Sigma, like their role and usefulness in cybersecurity
### Dependencies
Python 3.9+
A Linux environment with Internet access
	Note this project can be done in other systems, however all instructions are intended for Linux and may need to be modified for other environments.
## STAGE 0 - Setup Environment
The setup process has been automated with `setup.sh`, or you can follow these steps:
### 1. Create a virtual environment and activate it
```bash
python -m venv venv
source venv/bin/activate
```
### 2. Install libraries
```bash
pip install mitreattack-python pyyaml rich
```

https://mitreattack-python.readthedocs.io/en/latest/
### 3. Download an ATT&CK STIX bundle file (enterprise)
```bash
curl https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json -o enterprise-attack.json
```
### 4. Clone SigmaHQ/sigma locally
```bash
git clone https://github.com/SigmaHQ/sigma.git
```
### 5. Create a hello world program in `lookup.py`
```bash
echo -e '#!/usr/bin/env python3\nprint("hello world")' > lookup.py
```

## STAGE 1 - Libraries and to do list
- [ ] Import all the necessary libraries and components
	- [ ] `argparse, re, sys, yaml, json`
	- [ ] `Path from pathlib`
	- [ ] `Console from rich.console`
	- [ ] `Table from rich.table`
	- [ ] `Markdown from rich.mardown`
	- [ ] `MitreAttackData from mitreattack.stix20`
- [ ] Outline the tasks to complete in comments 
- [ ] Define `main()` as “hello world” program
- [ ] Use Console to make hello world green
- [ ] Setup `__name__`
## Stage 2 - Argument parsing & loading MITRE
- [ ] Define a function to parse the following arguments using `argparse`
	- [ ] `-h` and `--help` with description of program
	- [ ] `--stix` for path to enterprise STIX JSON bundle (default `enterprise-attack.json`)
	- [ ] `--sigma` for path to local Sigma repo (default `sigma`)
- [ ] Define a function to load the MITRE STIX file with `MitreAttackData()`
- [ ] Add both functions to `main()` and add descriptive console outputs.
## Stage 3 - Searching MITRE for the technique
- [ ] Define a regex to find all versions of Attack Id (with and without trailing decimal)
- [ ] Define a function put put all Attack Ids in a standard form
- [ ] Define a function to find the MITRE technique for any query
	- [ ] First look for a technique, interpreting the query as an Attack ID
	- [ ] Then as a technique name
	- [ ] Then as a portion of the technique’s description
- [ ] Define a function to print the technique’s name and description.
- [ ] Add searching and printing functions to `main()` and add descriptive console outputs.
## Stage 4 - Getting the mitigations
- [ ] Define a function to get the Mitigations for a given technique
	- [ ] First utilize `get_mitigations_mitigating_technique()`
	- [ ] If that fails, try `get_all_techniques_mitigated_by_all_mitigations()`
- [ ] Define a function to print the mitigations in a table
- [ ] Add searching and printing functions to `main()` and add descriptive console outputs.
## Stage 5 - Searching Sigma for the detections
- [ ] Define a function to get an attack id (from either the technique or the query)
- [ ] Define a function to get our sigma root as a path
- [ ] Define a function to scan sigma for the given technique attack id
	- [ ] Check each file in our sigma repo
		- [ ] Skip directories
		- [ ] Read the file
		- [ ] Check it contains the attack id
		- [ ] Extract the content depending on the file type (yml vs json)
	- [ ] Return an object with all the files, titles, and tags
- [ ] Define a function that prints the found sigma rules in a table
- [ ] Add the functions to `main()` and add descriptive console outputs.
## Post Project Ideas

- Alias the program to create a custom command that is accessible anywhere
- Handle outputting to files
- Handle bulk searches and outputs
- Integrate another open-source library mapped to MITRE ATT&CK
- Use Django to create a web interface
	- Search bar for searching, rather than command line argument
	- Host static site via cloud technology or physical server
- Improve the speed of Sigma searches 
	- maybe by applying particular data structures & algorithms
- Automatically update MITRE and Sigma (which are only accessed locally)
- Make searching by name or description “smarter” 
	- Output all techniques that partially map to description and let user choose
- Interface directly with other professional cybersecurity tools
	- MITRE Caldera - Attack platform for launching TTPs in MITRE ATT&CK
	- Metasploit - Tool for emulating attacker’s TTPs
	- Splunk - Open-source SIEM (could implement Sigma rules directly)

Implement all of these well and you likely have a project comparable to enterprise tools.