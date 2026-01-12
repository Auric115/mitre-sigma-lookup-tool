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

def get_attack_id(technique, query):
    ext = technique.get("external_references", [])
    if ext:
        for e in ext:
            if e.get("external_id") and e.get("external_id").upper().startswith("T"):
                attack_id = normalize_attack_id(e.get("external_id"))
                break

    if not attack_id:
        attack_id = normalize_attack_id(query)

    if not attack_id:
        console.print("[yellow]Could not determine ATT&CK ID for technique. Sigma scan skipped.[/yellow]")
        return

    return attack_id

def get_sigma_root(sigma):
    sigma_root = Path(sigma)

    if not sigma_root.exists():
        console.print(f"[red]Sigma folder not found at {sigma_root}[/red]")
        return

    return sigma_root

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

# Get Mitigations for Technique
def get_mitigations_for_technique(mitre, technique):
    try:
        tech_stix_id = technique["id"]
        mitigations = mitre.get_mitigations_mitigating_technique(tech_stix_id)
        if isinstance(mitigations, dict):
            mitigations = [entry["object"] for entries in mitigations.values() for entry in entries]
        return mitigations
    except Exception:
        try:
            mapping = mitre.get_all_techniques_mitigated_by_all_mitigations()
            return mapping.get(technique["id"], [])
        except Exception:
            return []

# Search Sigma Data for Technique
def scan_sigma_for_technique(sigma_root: Path, attack_id: str, verbose=False):
    pattern = re.compile(re.escape(attack_id), re.IGNORECASE)
    matches = []
    
    # For each file in our sigma repo
    for p in sigma_root.rglob("*"):
        # skip directories
        if p.is_dir():
            continue
            
        # read the file
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # search for our attack id
        if not pattern.search(text):
            continue
        
        # extract content, depending on file type
        title = "(no title)"
        tags = None

        # YAML files
        if p.suffix.lower() in (".yml", ".yaml"):
            try:
                docs = list(yaml.safe_load_all(text))
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    combined = json.dumps(doc)
                    if pattern.search(combined):
                        title = doc.get("title", title)
                        tags = doc.get("tags", tags)
                        break
            except Exception:
                pass

        # JSON files
        elif p.suffix.lower() == ".json":
            try:
                j = json.loads(text)
                if isinstance(j, dict):
                    if "title" in j:
                        title = j.get("title", title)
                else:
                    for entry in j:
                        if isinstance(entry, dict):
                            if any(normalize_attack_id(str(v)) == attack_id for v in entry.values() if isinstance(v, str)):
                                title = entry.get("title", title)
                                tags = entry.get("tags", tags)
                                break
            except Exception:
                pass

        tags_str = str(tags) if tags is not None else None
        matches.append({"file": str(p), "title": title, "tags": tags_str})

        if verbose:
            console.print(f"[green]Found {attack_id} in {p}[/green]")

    return matches

# Print Name & Description (MITRE) of Technqiue
def print_technique_summary(tech):
    name = tech.get("name", "Unknown")
    attack_id = tech.get("external_references", [{}])[0].get("external_id") \
                if tech.get("external_references") else None
    console.print(Markdown(f"# {name}  \n**STIX id:** {tech.get('id')}  \n**ATT&CK id:** {attack_id}"))
    desc = tech.get("description") or tech.get("x_mitre_short_description") or "(no description)"
    console.print(Markdown("### Description"))
    console.print(desc)

# Print Mitigations (MITRE) for Technqiue
def print_mitigations(mitigations):
    # Handle None found
    if not mitigations:
        console.print("\n[bold yellow]No mitigations found in ATT&CK dataset for this technique.[/bold yellow]\n")
        return
    
    # Create table
    table = Table(title="Mitigations from ATT&CK")
    table.add_column("Mitigation Name")
    table.add_column("ATT&CK id / STIX id")
    
    # Populate table
    for m in mitigations:
        obj = m.get("object") if isinstance(m, dict) and "object" in m else m
        name = obj.get("name", "(no name)")
        ext = obj.get("external_references", [])
        ext_id = ext[0].get("external_id") if ext else obj.get("id")
        table.add_row(name, str(ext_id))
        
    # Print table
    console.print(table)

# Print Detections (SIGMA) for Technique
def print_sigma_matches(matches):
    # Handle None found
    if not matches:
        console.print("\n[bold yellow]No Sigma rules found referencing that technique in your sigma repo.[/bold yellow]\n")
        return
        
    # Create table
    table = Table(title="Sigma rules referencing technique")
    table.add_column("Title")
    table.add_column("File path", overflow="fold")
    table.add_column("Tags")
    
    # Populate table
    for m in matches:
        table.add_row(str(m.get("title")), str(m.get("file")), str(m.get("tags")))
    
    # Print table
    console.print(table)

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
    
    console.print("\n[bold]Fetching mitigations from ATT&CK...[/bold]")
    mitigations = get_mitigations_for_technique(mitre, tech)
    print_mitigations(mitigations)
    
    console.print("\n[bold]Scanning local Sigma repo for matching rules...[/bold]")
    
    attack_id = get_attack_id(tech, args.query)
    sigma_root = get_sigma_root(args.sigma)

    matches = scan_sigma_for_technique(sigma_root, attack_id)
    print_sigma_matches(matches)

if __name__ == "__main__":
    main()
