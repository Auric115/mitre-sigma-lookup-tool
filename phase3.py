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

ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
# T\d{4}        -> Matchs "T" followed by 4 digits so from T0000 to T9999
# (?:\.\d{3})?  -> Matches "." followed by 3 digits or nothing (.000 to .999), opt.
# re.IGNORECASE -> Makes the whole thing case insensative

def normalize_attack_id(attack_id_raw: str):
    if not attack_id_raw:
        return None
    m = ATTACK_ID_RE.search(attack_id_raw)
    return m.group(0).upper() if m else None

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

# Search MITRE Data for Technique
def find_technique(mitre, query):
    # first look by ATT&CK ID
    m = ATTACK_ID_RE.search(query)
    if m:
        attack_id = m.group(0) # e.g. T0000
        tech = mitre.get_object_by_attack_id(attack_id, "attack-pattern")
        return tech
    
    # then try by name
    matches = mitre.get_objects_by_name(query, "attack-pattern")
    if matches:
        return matches[0]
        
    # then try searching the content of techniques (descriptions, metadata)
    content_matches = mitre.get_objects_by_content(query, object_type="attack-pattern", remove_revoked_deprecated=True)
    return content_matches[0] if content_matches else None

# TODO: Get Mitigations for Technique

# TODO: Search Sigma Data for Technique

# Print Name & Description (MITRE) of Technqiue
def print_technique_summary(tech):
    name = tech.get("name", "Unknown")
    attack_id = tech.get("external_references", [{}])[0].get("external_id") \
                if tech.get("external_references") else None
    console.print(Markdown(f"# {name}  \n**STIX id:** {tech.get('id')}  \n**ATT&CK id:** {attack_id}"))
    desc = tech.get("description") or tech.get("x_mitre_short_description") or "(no description)"
    console.print(Markdown("### Description"))
    console.print(desc)

# TODO: Print Mitigations (MITRE) for Technqiue

# TODO: Print Detections (SIGMA) for Technique

def main():
    args = process_arguments()
    
    console.print("[bold]Loading ATT&CK data...[/bold]")
    mitre = load_mitre_data(args.stix)
    
    console.print(f"[bold]Looking up technique for:[/bold] {args.query}")
    tech = find_technique(mitre, args.query)
    if not tech:
        console.print(f"[red]Technique '{args.query}' not found.[/red]")
        sys.exit(2)

    print_technique_summary(tech)

if __name__ == "__main__":
    main()
