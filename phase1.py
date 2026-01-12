#!/usr/bin/env python3

# default libraries
import argparse
import re
import sys
from pathlib import Path
import yaml
import json

# library for pretty CLI output
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

console = Console()

# library for accessing MITRE ATT&CK data
from mitreattack.stix20 import MitreAttackData

# TODO: Process Arguments (Technique)

# TODO: Load MITRE Data

# TODO: Search MITRE Data for Technique

# TODO: Get Mitigations for Technique

# TODO: Search Sigma Data for Technique

# TODO: Print Name & Description (MITRE) of Technqiue

# TODO: Print Mitigations (MITRE) for Technqiue

# TODO: Print Detections (SIGMA) for Technique

def main():
	console.print("[green]hello world[/green]")

if __name__ == "__main__":
    main()
