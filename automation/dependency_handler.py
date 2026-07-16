import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

from automation import config

# Define the repositories we depend on
REPOSITORIES = {
    "sigma": "https://github.com/SigmaHQ/sigma.git",
    "atomic-red-team": "https://github.com/redcanaryco/atomic-red-team.git",
    "escu": "https://github.com/splunk/security_content.git"
}

def check_and_update_dependencies(base_path):
    """
    Checks for the existence of dependency repositories.
    Clones them if they don't exist, or pulls the latest changes if they do.

    :param base_path: The folder where the dependency repos should reside.
    """
    print("[+] Checking and updating dependencies...")
    os.makedirs(base_path, exist_ok=True)

    for name, url in REPOSITORIES.items():
        repo_path = os.path.join(base_path, name)

        if not os.path.isdir(repo_path):
            print(f"    -> '{name}' repository not found. Cloning from {url}...")
            try:
                subprocess.run(
                    ["git", "clone", url, repo_path], 
                    check=True, capture_output=True, text=True
                )
                print(f"    -> Successfully cloned '{name}'.")
            except subprocess.CalledProcessError as e:
                print(f"    -> ERROR: Failed to clone '{name}'. Git error: {e.stderr}")
                return False
        else:
            # If directory exists but is not a git repository, treat it as a vendored copy and skip updating
            if not os.path.isdir(os.path.join(repo_path, ".git")):
                print(f"    -> '{name}' directory exists but is not a git repository. Using vendored copy (skip pull).")
                continue

            print(f"    -> '{name}' repository found. Pulling latest changes...")
            try:
                # We use -C flag to specify the repository path for git command
                subprocess.run(
                    ["git", "-C", repo_path, "pull"], 
                    check=True, capture_output=True, text=True
                )
                print(f"    -> Successfully updated '{name}'.")
            except subprocess.CalledProcessError as e:
                print(f"    -> ERROR: Failed to pull '{name}'. Git error: {e.stderr}")
                return False
    
    print("[+] Dependencies are up to date.")
    return True


def _download_file(url: str, dest_path: Path) -> bool:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url) as r, open(dest_path, 'wb') as f:
            shutil.copyfileobj(r, f)
        return True
    except Exception as e:
        print(f"    -> ERROR: Failed to download {url}: {e}")
        return False


def stage_atomic_dependencies_locally(atomic_test: dict, technique_dir: str, cache_dir: str) -> list[str]:
    """Resolves and downloads common Atomic external payloads or URL-based dependencies into a local cache.

    Returns a list of absolute local file paths that should be uploaded to the VM safe dir.
    """
    staged: list[str] = []
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    # 1) Handle explicit dependencies.source files in the atomic YAML
    for dep in (atomic_test.get('dependencies') or []):
        src = dep.get('source')
        if not src:
            continue
        local_path = Path(technique_dir) / src
        if local_path.exists():
            staged.append(str(local_path))

    # 2) Parse input_arguments defaults for URLs or PathToAtomicsFolder patterns
    for name, arg in (atomic_test.get('input_arguments') or {}).items():
        val = str(arg.get('default', '')).strip()
        if not val:
            continue
        # If URL, download to cache
        try:
            parsed = urlparse(val)
            if parsed.scheme in ('http', 'https') and parsed.netloc:
                fname = os.path.basename(parsed.path) or 'payload.bin'
                dest = cache / fname
                if _download_file(val, dest):
                    staged.append(str(dest))
                continue
        except Exception:
            pass

        # If PathToAtomicsFolder reference, try to resolve file under repo and stage
        if 'PathToAtomicsFolder' in val:
            rel = val.split('PathToAtomicsFolder', 1)[1].lstrip('/\\')
            if config.PLATFORM == "linux":
                # On Linux the atomics live at config.ATOMIC_TESTS_PATH (.../atomics),
                # and rel is already "<Txxxx>/src/...". parents[2] would overshoot to
                # the repos root, so resolve directly under ATOMIC_TESTS_PATH instead.
                full_local = Path(config.ATOMIC_TESTS_PATH) / rel
            else:
                full_local = Path(technique_dir).parents[2] / rel  # .../dependencies/atomic-red-team/atomics/<Txxxx>
            if full_local.exists():
                staged.append(str(full_local))
            else:
                # Sometimes ExternalPayloads path is up one level
                alt = Path(technique_dir).parents[2].parent / rel
                if alt.exists():
                    staged.append(str(alt))

    # 3) Heuristics: if commands reference well-known ExternalPayloads (e.g., PetitPotam.exe), try to find them in repo
    cmd = (atomic_test.get('executor') or {}).get('command', '')
    for m in re.findall(r"[A-Za-z]:\\[^\s\"']+|\b[\w\-]+\.exe\b", cmd):
        # If it's just a filename like PetitPotam.exe, locate under atomic-red-team/ExternalPayloads
        if not (':' in m or m.startswith('\\')) and m.lower().endswith('.exe'):
            repo = Path(technique_dir).parents[2]
            for cand in repo.parent.rglob(m):
                try:
                    if cand.is_file():
                        staged.append(str(cand))
                        break
                except Exception:
                    pass

    # Deduplicate
    return sorted(set(staged))