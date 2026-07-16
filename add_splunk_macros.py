"""
Splunk ESCU Filter Macro Installer

ESCU (Enterprise Security Content Updates) detection rules reference filter macros
(e.g. `linux_auditd_add_user_account_type_filter`) that must exist in Splunk's
macros.conf for the searches to run without errors. By default, these macros are
not defined, causing "macro not found" errors during detection verification.

This script:
1. Scans all ESCU detection rules for `*_filter` macro references
2. Checks which ones are already defined in macros.conf
3. Adds missing macros with a passthrough definition (`search *`)

Usage:
    python add_splunk_macros.py

Note: Requires Splunk to be installed locally. Update SPLUNK_MACROS_CONF path
if your Splunk installation is in a different location. Restart Splunk after running.
"""

import re
import os
import glob

DETECTIONS_PATH = os.path.join(os.path.dirname(__file__), "data", "repos",
                               "security_content", "detections", "endpoint")

SPLUNK_MACROS_CONF = r"C:\Program Files\Splunk\etc\system\local\macros.conf"

def find_filter_macros():
    macros = set()
    pattern = re.compile(r'`(\w+_filter)`')
    for yml_file in glob.glob(os.path.join(DETECTIONS_PATH, "*.yml")):
        with open(yml_file, "r", encoding="utf-8") as f:
            for match in pattern.finditer(f.read()):
                macros.add(match.group(1))
    return sorted(macros)

def read_existing_macros():
    existing = set()
    if os.path.exists(SPLUNK_MACROS_CONF):
        with open(SPLUNK_MACROS_CONF, "r", encoding="utf-8") as f:
            for line in f:
                m = re.match(r'\[(\w+)\]', line.strip())
                if m:
                    existing.add(m.group(1))
    return existing

def main():
    macros = find_filter_macros()
    existing = read_existing_macros()
    new_macros = [m for m in macros if m not in existing]
    print(f"Found {len(macros)} filter macros in ESCU rules")
    print(f"Already defined: {len(existing)}")
    print(f"New to add: {len(new_macros)}")
    if not new_macros:
        print("Nothing to add!")
        return
    with open(SPLUNK_MACROS_CONF, "a", encoding="utf-8") as f:
        for macro_name in new_macros:
            f.write(f"\n[{macro_name}]\ndefinition = search *\n")
    print(f"Added {len(new_macros)} macros to {SPLUNK_MACROS_CONF}")
    print("Restart Splunk for changes to take effect.")

if __name__ == "__main__":
    main()
