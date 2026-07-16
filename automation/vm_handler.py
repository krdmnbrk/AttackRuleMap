"""
VM lifecycle management via Proxmox over SSH.
Uses paramiko to connect to Proxmox host and run qm commands.
"""
import logging
import time
import re
import paramiko
from automation import config
import subprocess

def _get_proxmox_ssh_client():
    """
    Create and connect SSH client to Proxmox host.
    Returns client on success, None on failure.
    """
    host = config.PROXMOX_HOST
    user = config.PROXMOX_USER
    password = config.PROXMOX_PASSWORD
    key_path = config.PROXMOX_KEY_PATH
    port = config.PROXMOX_PORT

    if not host or not user:
        logging.error("PROXMOX_HOST and PROXMOX_USER must be set in .env")
        return None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=key_path,
                timeout=30,
            )
        else:
            if not password:
                logging.error("PROXMOX_PASSWORD or PROXMOX_KEY_PATH must be set in .env")
                return None
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=30,
            )
        return client
    except paramiko.AuthenticationException as e:
        logging.error(f"Proxmox SSH authentication failed: {e}")
        return None
    except paramiko.SSHException as e:
        logging.error(f"Proxmox SSH connection error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Proxmox: {e}")
        return None


def _run_proxmox_command(args, check=True):
    """
    Run a qm command on Proxmox host via SSH.
    args: list of command parts, e.g. ["rollback", "100", "Lab-Ready-v1"]
    Returns (success: bool, stdout: str, stderr: str)
    """

    
    vm_id = config.TARGET_VM_ID
    if not vm_id:
        logging.error("TARGET_VM_ID must be set in .env")
        return (False, "", "TARGET_VM_ID not configured")

    full_args = ["qm"] + args
    cmd = " ".join(full_args)
    logging.debug("Executing Proxmox command: %s", cmd)

    client = _get_proxmox_ssh_client()
    if not client:
        return (False, "", "Could not connect to Proxmox")

    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        client.close()

        if check and exit_status != 0:
            logging.error(f"Proxmox command failed (exit {exit_status}). stderr: {err}")
            return (False, out, err)
        return (exit_status == 0, out, err)
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        logging.error(f"Error running Proxmox command: {e}")
        return (False, "", str(e))


def get_vm_state():
    """Gets the current state of the VM on Proxmox (running/stopped)."""
    if config.USE_PROXMOX:  
        success, stdout, _ = _run_proxmox_command(["status", config.TARGET_VM_ID], check=False)
        if not success or not stdout:
            return "unknown"
        # qm status returns e.g. "status: running" or "status: stopped"
        match = re.search(r"status:\s*(\w+)", stdout, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return "unknown"
    else:
        result = subprocess.run(["VBoxManage", "showvminfo", config.TARGET_VM_ID, "--machinereadable"],
                        capture_output=True, text=True)
        if result.returncode != 0:
            return "unknown"
        match = re.search(r'VMState="(\w+)"', result.stdout)
        if match:
            return match.group(1).lower()
        return "unknown"
    
def ensure_vm_is_off(timeout_seconds=60):
    """
    Ensures the VM is in a stopped state.
    Returns True if the machine is or becomes stopped, False otherwise.
    """
    logging.debug("Ensuring VM is powered off...")
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        state = get_vm_state()
        logging.debug("Current VM state: %s", state)

        if state == "stopped" or state == "poweroff" or state == "aborted" or state == "saved":
            logging.debug("VM is already stopped.")
            return True
        elif state == "running":
            logging.debug("VM is running. Sending stop command...")
            if config.USE_PROXMOX:    
                success, _, err = _run_proxmox_command(["stop", config.TARGET_VM_ID])
                if not success:
                  logging.warning(f"Stop command may have failed: {err}")
            else:
                result = subprocess.run(
                    ["VBoxManage", "controlvm", config.TARGET_VM_ID, "poweroff"],
                    capture_output=True, text=True)
                if result.returncode != 0:
                    logging.warning(f"Stop command may have failed: {result.stderr}")
        else:
            logging.warning(f"VM is in state '{state}'. Waiting...")
        time.sleep(5)

    logging.error("Failed to get VM into stopped state within the timeout.")
    return False


def revert_to_snapshot():
    """Reverts the VM to the specified clean snapshot (qm rollback)."""
    snapshot = config.TARGET_SNAPSHOT
    vm_id = config.TARGET_VM_ID
    if not snapshot or not vm_id:
        logging.error("TARGET_SNAPSHOT and TARGET_VM_ID must be set in .env")
        return False
    if config.USE_PROXMOX:
        logging.debug("Reverting VM %s to snapshot '%s'...", vm_id, snapshot)
        if not ensure_vm_is_off():
            logging.error("Cannot restore snapshot because VM could not be stopped.")
            return False
        success, _, err = _run_proxmox_command(["rollback", vm_id, snapshot])
        if not success:
            logging.error(f"Snapshot rollback failed: {err}")
            return False
        logging.debug("Verifying state after snapshot rollback...")
        return ensure_vm_is_off()
    else: 
        logging.debug("Reverting VM %s to snapshot '%s' via VBoxManage...", vm_id, snapshot)
        if not ensure_vm_is_off():
            logging.error("Cannot restore snapshot because VM could not be stopped.")
            return False
        result = subprocess.run(
            ["VBoxManage", "snapshot", vm_id, "restore", snapshot],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            logging.error(f"Snapshot restore failed: {result.stderr}")
            return False
        return True

def start_vm():
    """Starts the VM on Proxmox."""
    vm_id = config.TARGET_VM_ID
    if not vm_id:
        logging.error("TARGET_VM_ID must be set in .env")
        return False
    if config.USE_PROXMOX:
        logging.debug("Starting VM %s...", vm_id)
        success, _, err = _run_proxmox_command(["start", vm_id])
        if not success:
            logging.error(f"Failed to start VM: {err}")
        return success
    else:
        logging.debug("Starting VM %s via VBoxManage...", vm_id)
        result = subprocess.run(
            ["VBoxManage", "startvm", vm_id, "--type", "headless"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            logging.error(f"Failed to start VM: {result.stderr}")
            return False
        return True
    
def stop_vm():
    """Stops the VM after test case."""
    logging.debug("Stopping VM after test case...")
    return ensure_vm_is_off()

def is_vm_ready(timeout_seconds=300):
    """
    Checks if the VM (Windows guest) is booted and SSH port is responding.
    Uses VM_HOST, VM_USERNAME, VM_PASSWORD from config (target guest, not Proxmox).
    """
    logging.debug("Waiting for VM to become ready for SSH connections...")

    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if config.VM_SSH_KEY_PATH:
                client.connect(
                    hostname=config.VM_HOST,
                    port=config.VM_SSH_PORT,
                    username=config.VM_USERNAME,
                    key_filename=config.VM_SSH_KEY_PATH,
                    timeout=10,
                    banner_timeout=30,
                )
            else:
                client.connect(
                    hostname=config.VM_HOST,
                    port=config.VM_SSH_PORT,
                    username=config.VM_USERNAME,
                    password=config.VM_PASSWORD,
                    timeout=10,
                    banner_timeout=30,
                )
            client.close()
            logging.debug("VM is ready and responding to SSH.")
            return True
        except Exception:
            logging.debug("VM not ready yet, retrying in 15 seconds...")
            time.sleep(15)

    logging.error(f"VM did not become ready within the {timeout_seconds} second timeout.")
    return False