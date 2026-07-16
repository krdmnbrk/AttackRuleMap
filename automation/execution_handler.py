import os
import logging
import re
import time
import paramiko
from automation import config
from automation import dependency_handler
from automation import atomic_handler
from automation import vm_handler


class PowerShellExecutor:
    def __init__(self):
        self.host = config.VM_HOST
        self.username = config.VM_USERNAME
        self.password = config.VM_PASSWORD
        self.port = config.VM_SSH_PORT
        self.key_path = config.VM_SSH_KEY_PATH
        self.timeout = max(30, int(config.VM_COMMAND_TIMEOUT_SECONDS))
        self._client = None

    def connect(self):
        if not self.host or not self.username:
            logging.error("VM_HOST and VM_USERNAME must be set in .env")
            return False
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.key_path:
             self._client.connect(
                 hostname=self.host, port=self.port,
                 username=self.username, key_filename=self.key_path,
                 timeout=30, banner_timeout=30,)
            else:
             self._client.connect(
                 hostname=self.host, port=self.port,
                 username=self.username, password=self.password,
                 timeout=30, banner_timeout=30,)
            return True
        except Exception as e:
            logging.error("PowerShellExecutor connect failed: %s", e)
            logging.debug("[FAIL] SSH connection to %s: %s", self.host, e)
            return False

    def disconnect(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def execute(self, command):
        if not self._client:
            if not self.connect():
                return (1, "", "Connection failed")
        try:
            full_cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\""
            transport = self._client.get_transport()
            if not transport:
                return (1, "", "SSH transport not available")
            chan = transport.open_session()
            chan.settimeout(self.timeout)
            chan.exec_command(full_cmd)
            stdout_chunks = []
            stderr_chunks = []
            start = time.time()
            while True:
                if chan.recv_ready():
                    stdout_chunks.append(chan.recv(4096))
                if chan.recv_stderr_ready():
                    stderr_chunks.append(chan.recv_stderr(4096))
                if chan.exit_status_ready():
                    break
                if time.time() - start > self.timeout:
                    try:
                        chan.close()
                    except Exception:
                        pass
                    return (124, b"".join(stdout_chunks).decode("utf-8", errors="ignore"), f"Timeout after {self.timeout}s")
                time.sleep(0.1)
            status = chan.recv_exit_status()
            stdout = b"".join(stdout_chunks).decode("utf-8", errors="ignore")
            stderr = b"".join(stderr_chunks).decode("utf-8", errors="ignore")
            return (status, stdout, stderr)
        except Exception as e:
            logging.error(f"PowerShellExecutor execute error: {e}")
            return (1, "", str(e))


def run_invoke_atomic_test(technique_id="T1059.001", test_number=1):
    executor = PowerShellExecutor()
    if not executor.connect():
        return False
    script = (
        "try { Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -ErrorAction Stop; "
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -ErrorAction Stop } catch {}; "
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
        "w32tm /resync /force; "
        "Restart-Service SplunkForwarder -Force -ErrorAction SilentlyContinue; "
        "Write-Host \"VM Current Time: $(Get-Date)\"; "
        f"Import-Module '{config.ATOMIC_MODULE_PATH}' -Force; "
        f"Invoke-AtomicTest {technique_id} -PathToAtomicsFolder '{config.ATOMIC_ATOMICS_PATH}' -TestNumbers {test_number} -TimeoutSeconds 120 -Confirm:$false"
    )
    status, stdout, stderr = executor.execute(script)
    logging.debug("[CMD] %s", script)
    logging.debug("[STDOUT] %s", stdout)
    if stderr:
        logging.debug("[STDERR] %s", stderr)
    if status == 0:
        logging.debug("[SUCCESS] Invoke-AtomicTest %s completed", technique_id)
    else:
        logging.debug("[FAIL] Invoke-AtomicTest exit code %s", status)
    executor.disconnect()
    return status == 0

def run_bash_atomic_test(technique_id="T1059.004", test_number=1):
    client = _create_ssh_client()
    if not client:
        return False
    prep_commands = (
        "sudo ntpdate -u pool.ntp.org 2>/dev/null || sudo timedatectl set-ntp true; "
        "sudo systemctl restart SplunkForwarder 2>/dev/null; "
        "echo \"VM Current Time: $(date)\"")
    status, stdout, stderr = _exec_on_vm(client, prep_commands, "bash")
    client.close()
    
    
    test_data, technique_path = atomic_handler.find_atomic_for_technique(
        technique_id, config.ATOMIC_ATOMICS_PATH
    )
    if not test_data or "atomic_tests" not in test_data:
        logging.debug("[FAIL] No atomic test data found for %s", technique_id)
        return False

    atomic_tests = test_data["atomic_tests"]
    if test_number < 1 or test_number > len(atomic_tests):
        logging.debug("[FAIL] Test number %s out of range", test_number)
        return False
    atomic_test = atomic_tests[test_number - 1]

    status, stdout, stderr = run_test_on_vm(atomic_test, technique_path)

    logging.debug("[CMD] bash atomic test %s #%s", technique_id, test_number)
    stdout = re.sub(r'\x1b\[[0-9;]*m', '', stdout) if stdout else stdout
    logging.debug("[STDOUT] %s", stdout)
    if stderr:
        logging.debug("[STDERR] %s", stderr)
    if status == 0:
        logging.debug("[SUCCESS] Bash atomic test %s completed", technique_id)
    else:
        logging.debug("[FAIL] Bash atomic test exit code %s", status)
    # Return the real exit status (like the Windows path) so the caller skips
    # detection for a test that did not run cleanly. Note: a few tests exit
    # non-zero yet still emit the execve telemetry a command-based rule matches
    # (e.g. xclip/xwd erroring on a headless VM with no X11 display); those
    # detections will no longer be counted, which is the correct, stricter behaviour.
    return status == 0


def run_simple_encoded_command():
    script = "Write-Host 'AttackRuleMap-Simulation'; Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; whoami"
    executor = PowerShellExecutor()
    if not executor.connect():
        return False
    status, stdout, stderr = executor.execute(script)
    print(f"[CMD] {script}")
    print(f"[STDOUT] {stdout}")
    if stderr:
        print(f"[STDERR] {stderr}")
    if status == 0:
        print(f"[SUCCESS] EncodedCommand simulation completed")
    else:
        print(f"[FAIL] EncodedCommand exit code {status}")
    executor.disconnect()
    return status == 0


def run_first_attack_simulation():
    if config.PLATFORM == "windows":  
        if run_invoke_atomic_test("T1059.001", 1):
            return True
        logging.debug("[FALLBACK] Invoke-AtomicTest failed, running simple EncodedCommand...")
        return run_simple_encoded_command()
    else:
        if run_bash_atomic_test("T1059.004", 1):
            return True
        return False

def run_first_attack_workflow():
    logging.debug("Starting first attack simulation workflow...")
    logging.debug("=" * 60)
    logging.debug("FIRST ATTACK SIMULATION WORKFLOW")
    logging.debug("=" * 60)
    if not vm_handler.revert_to_snapshot():
        logging.debug("[FAIL] Snapshot revert failed")
        return False
    if not vm_handler.start_vm():
        logging.debug("[FAIL] VM start failed")
        return False
    logging.debug("[WAIT] Waiting for VM to become ready...")
    if not vm_handler.is_vm_ready():
        logging.debug("[FAIL] VM did not become ready")
        return False
    logging.debug("[OK] VM is ready, triggering first attack simulation...")
    success = run_first_attack_simulation()
    logging.debug("=" * 60)
    if success:
        logging.debug("[WORKFLOW] First attack simulation completed successfully")
    else:
        logging.debug("[WORKFLOW] First attack simulation failed")
    logging.debug("=" * 60)
    return success


def _create_ssh_client():
    """Helper function to create and connect an SSH client."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        

        if config.VM_SSH_KEY_PATH:
            client.connect(
                hostname=config.VM_HOST, port=config.VM_SSH_PORT,
                username=config.VM_USERNAME, key_filename=config.VM_SSH_KEY_PATH,
                timeout=30, banner_timeout=30,)
        else:
            client.connect(
                hostname=config.VM_HOST, port=config.VM_SSH_PORT,
                username=config.VM_USERNAME, password=config.VM_PASSWORD,
                timeout=30, banner_timeout=30,)
        
        return client
    except Exception as e:
        logging.error(f"Failed to create SSH client. Exception: {e}")
        return None

def _upload_file_sftp(client, local_path, remote_path):
    """Uploads a single file to the remote VM using SFTP over the SSH connection."""
    logging.debug("    -> Uploading '%s' to '%s' via SFTP...", os.path.basename(local_path), remote_path)
    try:
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        return True
    except Exception as e:
        logging.error(f"    -> ERROR: Failed to upload file '{local_path}'. Exception: {e}")
        return False

def _build_arg_value_map(atomic_test: dict, safe_dir: str) -> dict:
    """Builds a mapping from placeholders like #{arg} to rewritten values suitable for the VM.

    - Replaces PathToAtomicsFolder references with files uploaded into safe_dir.
    - If value looks like a file path (.exe, .dll, .ps1, etc.), point it to safe_dir\filename
    """
    sep = "\\" if config.PLATFORM == "windows" else "/"
    mapping = {}
    for arg_name, arg_details in (atomic_test.get('input_arguments') or {}).items():
        default_value = str(arg_details.get('default', ''))
        # General path replacement for robust handling
        if "PathToAtomicsFolder" in default_value:
            relative_path = default_value.split("PathToAtomicsFolder", 1)[1].strip('\\/')
            # This assumes the relative path is from the root of the atomic-red-team repo
            file_name = os.path.basename(relative_path.replace('\\', '/'))
            rewritten_path = f"{safe_dir}{sep}{file_name}"
        elif any(ext in default_value.lower() for ext in ['.exe', '.dll', '.dmp', '.ps1', '.bat', '.txt', '.csv', '.zip', '.sh', '.py', '.so']):
            file_name = os.path.basename(default_value.replace('\\', '/'))
            rewritten_path = f"{safe_dir}{sep}{file_name}"
        elif config.PLATFORM == "linux" and arg_name == "interface" and config.VM_INTERFACE:
            # Atomic's default interface (eth0/ens33) often doesn't exist on the VM.
            # If VM_INTERFACE is configured, use the real NIC name instead.
            rewritten_path = config.VM_INTERFACE
        else:
            rewritten_path = default_value

        mapping[f"#{{{arg_name}}}"] = rewritten_path
    return mapping


def _apply_rewrites_to_command(cmd_text: str, arg_map: dict, safe_dir: str) -> str:
    """Apply placeholder and PathToAtomicsFolder rewrites to a command text."""
    if not cmd_text:
        return cmd_text
    out = cmd_text
    # Replace input argument placeholders
    for ph, val in arg_map.items():
        out = out.replace(ph, val)
    # Replace PathToAtomicsFolder tokens with C:\\Atomic-Tests first (canonical), then ensure any path-like
    # values referring to ExternalPayloads map to our safe_dir uploads as a fallback.
    if config.PLATFORM == "windows":
        out = out.replace('PathToAtomicsFolder', 'C:\\Atomic-Tests')
    else:
        out = out.replace('PathToAtomicsFolder', '/tmp/atomic-tests')

    return out


def _normalize_command_for_executor(command_text: str, executor_name: str) -> str:
    """PowerShell/cmd friendly inline script formatting. Joins multiline scripts safely."""
    if not command_text:
        return command_text
    # Collapse lines for inline -Command usage
    lines = [ln.strip() for ln in re.split(r"\r?\n", command_text) if ln.strip()]
    if executor_name == 'powershell':
        return '; '.join(lines)
    elif executor_name == 'cmd':
        return ' & '.join(lines)
    elif executor_name in ('bash', 'sh'):
        return '\n'.join(lines)
    return command_text


def _exec_on_vm(client, command_text: str, executor_name: str):
    """Execute the given command on VM using specified executor (powershell/cmd) with timeout."""
    # Linux only: when True, the script is sent over the channel's stdin instead
    # of being embedded in `-c "..."` (avoids inner-quote collision). See below.
    feed_via_stdin = False
    if executor_name == 'powershell':
        full_command_to_run = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command_text}\""
    elif executor_name == 'cmd':
        full_command_to_run = f"cmd /c \"{command_text}\""
    elif executor_name in ('bash', 'sh'):
        if config.PLATFORM == "windows":
            full_command_to_run = f"{executor_name} -c \"{command_text}\""
        else:
            # Linux: wrapping the script in -c "..." breaks whenever the script
            # itself contains double quotes (e.g. `if [ "$(uname)" = 'FreeBSD' ]`):
            # the inner " closes the outer " early and the shell mis-parses the
            # script (Syntax error: unexpected end of file). To stay safe we only
            # change behaviour for scripts that contain a double quote: we run
            # `sh -s` and feed the script via stdin, so there is no outer quoting
            # to collide with. Quote-free scripts keep the original -c path, so
            # the common case is byte-for-byte unchanged. Windows path untouched
            # (I cannot test it, so I did not change it without confirmation).
            if '"' in command_text:
                full_command_to_run = f"sudo {executor_name} -s"
                feed_via_stdin = True
            else:
                full_command_to_run = f"sudo {executor_name} -c \"{command_text}\""

    else:
        return (1, "", f"Unsupported executor: {executor_name}")

    timeout = max(30, int(config.VM_COMMAND_TIMEOUT_SECONDS))

    try:
        # Set up a non-blocking read with timeout on the channel
        transport = client.get_transport()
        if transport is None:
            return (1, "", "SSH transport not available")
        chan = transport.open_session()
        chan.settimeout(timeout)
        chan.exec_command(full_command_to_run)

        if feed_via_stdin:
            # Push the script into `sh -s` over stdin, then close the write side
            # so the shell sees EOF and starts executing. No outer quoting, so
            # the script's own quotes can never collide.
            chan.sendall(command_text + "\n")
            chan.shutdown_write()

        stdout_chunks = []
        stderr_chunks = []
        start_time = time.time()
        while True:
            if chan.recv_ready():
                stdout_chunks.append(chan.recv(4096))
            if chan.recv_stderr_ready():
                stderr_chunks.append(chan.recv_stderr(4096))
            if chan.exit_status_ready():
                break
            if time.time() - start_time > timeout:
                try:
                    chan.close()
                except Exception:
                    pass
                return (124, b''.join(stdout_chunks).decode('utf-8', errors='ignore'),
                        f"Command timed out after {timeout}s")
            time.sleep(0.1)

        status_code = chan.recv_exit_status()
        std_out_str = b''.join(stdout_chunks).decode('utf-8', errors='ignore')
        std_err_str = b''.join(stderr_chunks).decode('utf-8', errors='ignore')
        return (status_code, std_out_str, std_err_str)
    except Exception as e:
        logging.error(f"    -> ERROR: Failed to execute SSH command. Exception: {e}")
        return (1, "", str(e))


def run_test_on_vm(atomic_test, test_technique_path):
    """
    Handles the entire execution process for a single atomic test via SSH,
    including dependency uploads and path rewriting.
    """
    client = _create_ssh_client()
    if not client:
        return (1, "", "Could not establish SSH connection.")

    if config.PLATFORM == "windows":
        safe_dir = config.VM_SAFE_DIR or "C:\\Atomic-Tests"
    else:
        safe_dir = config.VM_SAFE_DIR or "/tmp/atomic-tests"

    
    # Ensure safe dir exists on remote
    try:
        if config.PLATFORM == "windows":
            stdin, stdout, stderr = client.exec_command(f'powershell -Command "New-Item -Path \"{safe_dir}\" -ItemType Directory -Force | Out-Null"')
        else:
            stdin, stdout, stderr = client.exec_command(f'mkdir -p {safe_dir}')

        stdout.channel.recv_exit_status()
    except Exception as e:
        logging.warning(f"    -> Could not ensure remote safe dir exists: {e}")

    # Seed C:\Atomic-Tests path as well (many atomics assume it)
    if config.PLATFORM == "windows":
        try:
            stdin, stdout, stderr = client.exec_command('powershell -Command "New-Item -Path \"C:\\Atomic-Tests\" -ItemType Directory -Force | Out-Null"')
            stdout.channel.recv_exit_status()
        except Exception as e:
            logging.debug(f"    -> Could not create C:\\Atomic-Tests: {e}")

    # --- 1. Handle Dependencies ---
    # 1a) Resolve and stage locally (download URLs / ExternalPayloads)
    local_cache = os.path.join(config.DEPENDENCIES_PATH, 'atomic-cache')
    staged_files = dependency_handler.stage_atomic_dependencies_locally(atomic_test, test_technique_path, local_cache)
    for lf in staged_files:
        try:
            remote_filename = os.path.basename(lf.replace('\\', '/'))
            remote_path_safe = f"{safe_dir.replace('\\','/')}/{remote_filename}"
            _upload_file_sftp(client, lf, remote_path_safe)
            if config.PLATFORM == "windows":
                remote_path_atomic = f"C:/Atomic-Tests/{remote_filename}"
                # also copy into C:\Atomic-Tests for tests that reference that path
                client.exec_command(f'powershell -Command "Copy-Item -Force \"{remote_path_safe}\" -Destination \"{remote_path_atomic}\""')
        except Exception as e:
            logging.warning(f"    -> Failed to upload staged file '{lf}': {e}")
    if 'dependencies' in atomic_test and atomic_test['dependencies']:
        logging.debug("Handling dependencies (file copies)...")
        for dep in atomic_test['dependencies']:
            if 'source' in dep and 'destination' in dep:
                local_dep_path = os.path.join(test_technique_path, dep['source'])
                remote_filename = os.path.basename(dep['destination'].replace('\\', '/'))
                remote_dep_path = f"{safe_dir.replace('\\', '/')}/{remote_filename}"

                if not os.path.exists(local_dep_path):
                    logging.warning(f"    -> Dependency file not found on host: {local_dep_path}. Skipping upload.")
                    continue
                _upload_file_sftp(client, local_dep_path, remote_dep_path)

    # Opportunistic: place any referenced ExternalPayloads (if copied by prepare_command replacements) into safe dir alias path
    try:
        # Create a symlink-like copy location so C:\Atomic-Tests resolves to safe_dir content when we staged files there
        # Simple approach: nothing to do here beyond creating C:\Atomic-Tests; uploads above use safe_dir
        pass
    except Exception:
        pass
    
    # --- 2. Run dependency prereq commands if defined ---
    dep_executor = atomic_test.get('dependency_executor_name', 'powershell')
    if config.PLATFORM != "windows" and dep_executor in ('powershell', 'command_prompt'):
        dep_executor = 'bash'
    arg_map = _build_arg_value_map(atomic_test, safe_dir)
    for dep in (atomic_test.get('dependencies') or []):
        prereq_cmd = dep.get('prereq_command')
        get_prereq_cmd = dep.get('get_prereq_command')
        if not prereq_cmd:
            continue

        pre_cmd = _apply_rewrites_to_command(prereq_cmd, arg_map, safe_dir)
        pre_cmd = _normalize_command_for_executor(pre_cmd, dep_executor)
        logging.debug("    -> Checking dependency prereq on VM...")
        status, so, se = _exec_on_vm(client, pre_cmd, dep_executor)
        if status == 0:
            continue

        if get_prereq_cmd:
            fix_cmd = _apply_rewrites_to_command(get_prereq_cmd, arg_map, safe_dir)
            fix_cmd = _normalize_command_for_executor(fix_cmd, dep_executor)
            logging.debug("    -> Attempting to satisfy prereq on VM...")
            status_fix, so_fix, se_fix = _exec_on_vm(client, fix_cmd, dep_executor)
            if status_fix != 0:
                client.close()
                return (1, so_fix, f"Prereq remediation failed: {se_fix}")

            # Re-check prereq
            status2, so2, se2 = _exec_on_vm(client, pre_cmd, dep_executor)
            if status2 != 0:
                client.close()
                return (1, so2, f"Prereq check still failing after remediation: {se2}")
        else:
            client.close()
            return (1, so, f"Prereq failed and no get_prereq_command provided: {se}")

    # --- 3. Prepare Command ---
    executor = atomic_test.get('executor', {})
    raw_command = executor.get('command')
    executor_name = executor.get('name')

    if not raw_command or not executor_name:
        client.close()
        return (1, "", "Command or executor name not found in atomic test definition.")
        
    arg_map = _build_arg_value_map(atomic_test, safe_dir)
    final_command = _apply_rewrites_to_command(raw_command, arg_map, safe_dir)
    final_command = _normalize_command_for_executor(final_command, executor_name)

    # --- 3. Execute Command with the correct executor ---
    logging.debug("    -> Executing on VM via SSH (Executor: %s): %s", executor_name, final_command)
    status_code, std_out_str, std_err_str = _exec_on_vm(client, final_command, executor_name)
    client.close()
    return (status_code, std_out_str, std_err_str)