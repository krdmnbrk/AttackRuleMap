import os
import logging
from dotenv import load_dotenv

# Find the project root directory
# This file (config.py) -> parent is 'automation'
# The parent of 'automation' is the Project Root (e.g., 'AttackRuleMap')
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load .env early so repo paths can be overridden
dotenv_path = os.path.join(PROJECT_ROOT, '.env')
load_dotenv(dotenv_path=dotenv_path)

PLATFORM =  os.getenv("PLATFORM", "windows").lower()



# Repo base: default data/repos (managed by RepoManager); override via REPOS_BASE_PATH in .env
DEPENDENCIES_PATH = os.path.join(PROJECT_ROOT, 'dependencies')
REPOS_BASE_PATH = os.getenv("REPOS_BASE_PATH", os.path.join(PROJECT_ROOT, "data", "repos"))

SIGMA_REPO_PATH = os.getenv("SIGMA_REPO_PATH", os.path.join(REPOS_BASE_PATH, "sigma"))
ESCU_REPO_PATH = os.getenv("ESCU_REPO_PATH", os.path.join(REPOS_BASE_PATH, "security_content"))
SIGMA_RULES_PATH = os.getenv("SIGMA_RULES_PATH", os.path.join(SIGMA_REPO_PATH, "rules"))
ESCU_RULES_PATH = os.getenv("ESCU_RULES_PATH", os.path.join(ESCU_REPO_PATH, "detections"))
ATOMIC_RED_TEAM_REPO = os.getenv("ATOMIC_RED_TEAM_REPO", os.path.join(REPOS_BASE_PATH, "atomic-red-team"))
ATOMIC_TESTS_PATH = os.getenv("ATOMIC_TESTS_PATH", os.path.join(ATOMIC_RED_TEAM_REPO, "atomics"))

# --- Helpers ---
def _as_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")

# Get Splunk connection details from the .env file
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_SCHEME = os.getenv("SPLUNK_SCHEME", "https")
SPLUNK_VERIFY_CERT = _as_bool(os.getenv("SPLUNK_VERIFY_CERT"), False)
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")  # If set, token-based auth will be used
SPLUNK_SEARCH_INDEX = os.getenv("SPLUNK_SEARCH_INDEX", "main")

# Basic auth/token hints (DEBUG only - import runs before main's logging setup)
if not SPLUNK_PASSWORD and not SPLUNK_TOKEN:
    logging.getLogger(__name__).debug("Neither SPLUNK_PASSWORD nor SPLUNK_TOKEN found in .env. Splunk connection may fail.")
if SPLUNK_PASSWORD and SPLUNK_TOKEN:
    logging.getLogger(__name__).debug("Both SPLUNK_TOKEN and SPLUNK_PASSWORD are set; token auth will be preferred.")

# --- Get VM connection details from the .env file ---
VM_HOST = os.getenv("VM_HOST")
VM_HOSTNAME = os.getenv("VM_HOSTNAME", VM_HOST)
VM_USERNAME = os.getenv("VM_USERNAME")
VM_PASSWORD = os.getenv("VM_PASSWORD")
VM_SAFE_DIR = os.getenv("VM_SAFE_DIR")
VM_SSH_PORT = int(os.getenv("VM_SSH_PORT", "22"))
VM_SSH_KEY_PATH = os.getenv("VM_SSH_KEY_PATH")
# Linux only: real network interface name of the VM (e.g. enp0s3). When set, it
# overrides an Atomic test's default "interface" argument (often eth0/ens33),
# which otherwise fails with "No such device" on a differently-named NIC.
VM_INTERFACE = os.getenv("VM_INTERFACE")

if PLATFORM =="windows":
    ATOMIC_MODULE_PATH = os.getenv("ATOMIC_MODULE_PATH", r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")
    ATOMIC_ATOMICS_PATH = os.getenv("ATOMIC_ATOMICS_PATH", r"C:\AtomicRedTeam\atomics")
else:
    ATOMIC_MODULE_PATH = None
    ATOMIC_ATOMICS_PATH = os.getenv("ATOMIC_ATOMICS_PATH", os.path.join(PROJECT_ROOT, "data", "repos", "atomic-red-team", "atomics"))

# --- Proxmox settings (from .env) ---
USE_PROXMOX = _as_bool(os.getenv("USE_PROXMOX"), True)
PROXMOX_HOST = os.getenv("PROXMOX_HOST")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD")
PROXMOX_KEY_PATH = os.getenv("PROXMOX_KEY_PATH")  # Optional: SSH key instead of password
PROXMOX_PORT = int(os.getenv("PROXMOX_SSH_PORT", os.getenv("PROXMOX_PORT", "22")))
TARGET_VM_ID = os.getenv("TARGET_VM_ID")
TARGET_SNAPSHOT = os.getenv("TARGET_SNAPSHOT")

# --- Automation Settings from .env ---
# Use only explicit seconds value; legacy minutes-based var removed
SPLUNK_INDEX_WAIT_SECONDS = int(os.getenv("SPLUNK_INDEX_WAIT_SECONDS", "900"))
# Time padding around execution window when querying Splunk (seconds)
SPLUNK_TIME_PAD_SECONDS = int(os.getenv("SPLUNK_TIME_PAD_SECONDS", "300"))
# Post-test wait (seconds) before powering off VM to allow UF to forward events.
# Linux (auditd -> UF) needs longer; Windows keeps the original 30s default so its
# run duration and search window are unchanged.
_default_forward_wait = "100" if PLATFORM == "linux" else "30"
POST_EXEC_FORWARD_WAIT_SECONDS = int(os.getenv("POST_EXEC_FORWARD_WAIT_SECONDS", _default_forward_wait))
# Linux only: extra seconds added to the ESCU search window. Many ESCU rules
# aggregate over time (e.g. `bucket _time span=15m`) and need a window wider than
# a single test's ~100s. Default 900s (15m) to cover the common bucket span.
ESCU_AGG_WINDOW_SECONDS = int(os.getenv("ESCU_AGG_WINDOW_SECONDS", "900"))

# --- Per-test verification settings ---
PER_TEST_VERIFICATION = _as_bool(os.getenv("PER_TEST_VERIFICATION"), False)
PER_TEST_VERIFY_TIMEOUT_SECONDS = int(os.getenv("PER_TEST_VERIFY_TIMEOUT_SECONDS", "180"))
PER_TEST_VERIFY_POLL_INTERVAL_SECONDS = int(os.getenv("PER_TEST_VERIFY_POLL_INTERVAL_SECONDS", "15"))

# --- Strict ingestion wait (keep VM up until events observed or timeout) ---
PER_TEST_STRICT_INGESTION_WAIT = _as_bool(os.getenv("PER_TEST_STRICT_INGESTION_WAIT"), False)
PER_TEST_STRICT_MAX_WAIT_SECONDS = int(os.getenv("PER_TEST_STRICT_MAX_WAIT_SECONDS", "300"))
PER_TEST_INGESTION_POLL_INTERVAL_SECONDS = int(os.getenv("PER_TEST_INGESTION_POLL_INTERVAL_SECONDS", "10"))
# If true, abort remaining tests and leave VM running on ingestion timeout
PER_TEST_ABORT_ON_INGESTION_TIMEOUT = _as_bool(os.getenv("PER_TEST_ABORT_ON_INGESTION_TIMEOUT"), False)

# --- VM command execution timeout (seconds) ---
VM_COMMAND_TIMEOUT_SECONDS = int(os.getenv("VM_COMMAND_TIMEOUT_SECONDS", "600"))

if PLATFORM =="windows":
    ATTACK_TIDS_DEFAULT = "T1059.001,T1087.001,T1003.001"
else: 
    ATTACK_TIDS_DEFAULT = "T1059.004,T1087.001,T1222.002"

ATTACK_LIST = [t.strip().upper() for t in os.getenv("ATTACK_TIDS", ATTACK_TIDS_DEFAULT).split(",") if t.strip()]

# --- Output paths ---
# Main report: dist/ for AJAX loading by index.html.
# Only Linux gets a platform-suffixed file (separate artifact); Windows keeps the
# original un-suffixed name that index.html loads, so its behaviour is unchanged.
if PLATFORM == "linux":
    REPORT_JSON_PATH = os.path.join(PROJECT_ROOT, "dist", "attack_rule_map_linux.json")
else:
    REPORT_JSON_PATH = os.path.join(PROJECT_ROOT, "dist", "attack_rule_map.json")
# dist/ for MITRE layer and HTML (keeps root clean)
DIST_PATH = os.path.join(PROJECT_ROOT, "dist")