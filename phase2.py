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

# Process Arguments (Technique)
def process_arguments():
    parser = argparse.ArgumentParser(description="Lookup the MITRE mitigations and the Sigma detections for any technique")
    parser.add_argument("query", help="ATT&CK technique ID (`T1564`) or technique name.")
    parser.add_argument("--stix", default="enterprise-attack.json", help="Path to enterprise STIX JSON bundle")
    parser.add_argument("--sigma", default="sigma", help="Path to local Sigma repo (folder)")
    return parser.parse_args()
    
# Load MITRE Data
def load_mitre_data(stix_path):
    return MitreAttackData(stix_path)

# TODO: Search MITRE Data for Technique

# TODO: Get Mitigations for Technique

# TODO: Search Sigma Data for Technique

# TODO: Print Name & Description (MITRE) of Technqiue

# TODO: Print Mitigations (MITRE) for Technqiue

# TODO: Print Detections (SIGMA) for Technique

def main():
    args = process_arguments()
    
    console.print("[bold]Loading ATT&CK data...[/bold]")
    mitre = load_mitre_data(args.stix)
    
    console.print(f"[bold]Looking up technique for:[/bold] {args.query}")

if __name__ == "__main__":
    main()
