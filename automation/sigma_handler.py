import os
import glob
import re
import logging
from automation import utils
from automation import config

SIGMA_BASE_URL = "https://github.com/SigmaHQ/sigma/blob/main/rules/"

def parse_sigma_rule(file_path, rules_base_path):
    """
    Reads a single Sigma rule file and extracts key information.
    """
    rule_content = utils.load_yaml_file(file_path)
    if not rule_content:
        return None

    if not isinstance(rule_content, dict) or not all(k in rule_content for k in ['title', 'detection', 'logsource']):
        return None
    
    platform = rule_content.get('logsource', {}).get('product', 'N/A')

    if config.PLATFORM == "linux" and platform != "linux":
        return None
    
    attack_tags = []
    if 'tags' in rule_content:
        for tag in rule_content['tags']:
            match = re.search(r'attack\.t\d+(\.\d+)?', tag, flags=re.IGNORECASE)
            if match:
                technique_id = match.group(0).replace('attack.', '')
                attack_tags.append(technique_id)
    
    if not attack_tags:
        return None

    relative_path = os.path.relpath(file_path, start=rules_base_path).replace('\\', '/')
    rule_link = SIGMA_BASE_URL + relative_path

    return {
        'filepath': file_path,
        'title': rule_content.get('title'),
        'status': rule_content.get('status', 'unknown'),
        'platform': platform,
        'link': rule_link,
        'attack_tags': list(set(attack_tags))
    }

def load_and_parse_rules(path):
    """
    Scans all Sigma rule files and returns a list of parsed rules.
    """
    logging.info(f"Scanning for Sigma rules in: {path}")
    rule_files = glob.glob(os.path.join(path, '**', '*.yml'), recursive=True)
    logging.info(f"    -> Found {len(rule_files)} YAML detection files.")
    
    loaded_rules = [parse_sigma_rule(fp, path) for fp in rule_files]
    loaded_rules = [r for r in loaded_rules if r is not None] # Filter out None values
    
    logging.info(f"    -> Successfully loaded and parsed {len(loaded_rules)} valid rules with ATT&CK tags.")
    return loaded_rules