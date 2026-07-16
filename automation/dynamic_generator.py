import os
import re
import sys
import json
import time
import logging
import glob

from automation import config
from automation import utils
from automation import repo_manager
from automation import report_handler
from automation import vm_handler
from automation import execution_handler
from automation import splunk_handler
from automation import atomic_handler
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.exceptions import SigmaError

# Time-boxing: Do NOT use relative time (-2m, now). Only absolute epoch timestamps.
RE_MACRO = re.compile(r"%[^%\s]+%")

# Sigma (pySigma) field names -> Splunk CIM (Common Information Model) field names
# EventCode= alanına dokunulmaz (performans için indekste kalmalı)
CIM_MAPPING = {
    # Process
    "Image=": "process_name=",
    "ParentImage=": "parent_process_name=",
    "CommandLine=": "process=",
    "OriginalFileName=": "original_file_name=",
    # User & Host
    "User=": "user=",
    "Computer=": "dest=",
    "DestinationHostname=": "dest=",
    # Network
    "DestinationIp=": "dest_ip=",
    "DestinationPort=": "dest_port=",
    "SourceIp=": "src_ip=",
    # Registry & File
    "TargetObject=": "registry_path=",
    "Details=": "registry_value_data=",
    "TargetFilename=": "file_name=",
    # PowerShell (Message alanı XML loglarında yaygın)
    "ScriptBlockText=": "Message=",
    "ScriptBlockText IN": "Message IN",
    "field=ScriptBlockText": "field=Message",
}

# GitHub raw URLs for rule links.
SIGMA_RAW_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"
# ESCU/security_content: the detections/ tree lives on the repo's DEFAULT `develop`
# branch; `master` 404s for the whole detections/ tree (verified: develop -> HTTP 200,
# master -> 404). Switched to `develop` for Linux only, the platform this PR covers and
# can verify. The existing Windows path is left on `master` unchanged — the same fix
# almost certainly applies to Windows too, but I did not change the existing Windows
# behaviour without confirmation / a way to test it.
if config.PLATFORM == "linux":
    ESCU_RAW_BASE = "https://raw.githubusercontent.com/splunk/security_content/develop"
else:
    ESCU_RAW_BASE = "https://raw.githubusercontent.com/splunk/security_content/master"


def _apply_cim_mapping(spl: str) -> str:
    """Apply CIM-compliant field name replacements for Sigma->Splunk compatibility."""
    if not spl or not isinstance(spl, str):
        return spl
    if config.PLATFORM == "linux":
        return spl
    result = spl
    for old, new in sorted(CIM_MAPPING.items(), key=lambda x: -len(x[0])):
        result = result.replace(old, new)
    return result



def _normalize_sigma_spl_for_splunk(query: str) -> str:
    """
    pySigma çıktısını Splunk için normalize eder.
    - Her zaman 'search index=*' ile başlatır (Splunk için zorunlu, tüm indeksler taranır)
    - '|' ile başlayan sorgularda 'search index=*' generating command olarak eklenir
    - pySigma newline+pipe formatını düzeltir
    """
    q = (query or "").strip()
    if not q:
        return "search index=*"
    # Tüm index= ifadelerini kaldır (sonra index=* ekleyeceğiz)
    q = re.sub(r'\bindex\s*=\s*["\']?[^"\'\s]*["\']?\s*', "", q, flags=re.I)
    q = q.strip()
    if not q:
        return "search index=*"
    # pySigma '*\n| regex' formatını ' | regex' yap
    q = re.sub(r"\s*\n\s*\|", " |", q)
    q = q.strip()
    # Zaten 'search index=*' ile başlıyorsa dokunma
    if re.match(r"search\s+index\s*=\s*\*", q, re.I):
        return q
    # 'search ' ile başlıyorsa index=* ekle
    if q.lower().startswith("search "):
        return re.sub(r"^search\s+", "search index=* ", q, count=1, flags=re.I)
    # '|' ile başlıyorsa: search index=* | ...
    if q.startswith("|"):
        return "search index=* " + q
    # Basit ifade veya '*' ile başlıyorsa
    return f"search index=* {q}"


def _cim_search_only(query: str) -> str:
    """VerificationEngine için: Sorguyu Splunk formatına getirir."""
    return _normalize_sigma_spl_for_splunk(query)


class RuleMapper:
    def __init__(self):
        self.sigma_path = config.SIGMA_RULES_PATH
        self.escu_path = config.ESCU_RULES_PATH

    @staticmethod
    def _sanitize_escu_spl(search: str) -> str:
        if not search or not isinstance(search, str):
            return "index=*"
        s = search.strip()
        s = RE_MACRO.sub("*", s)
        s = re.sub(r"\*+", "*", s)
        if not s or s == "|":
            return "index=*"
        if not s.lower().startswith(("search", "index=", "|")):
            s = f"search {s}"
        return s

    @staticmethod
    def _sigma_file_to_spl(filepath: str) -> str | None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rule_text = f.read()
            rules = SigmaCollection.from_yaml(rule_text)
            backend = SplunkBackend()
            result = backend.convert(rules)
            if isinstance(result, (list, tuple)):
                if result and isinstance(result[0], str) and result[0].strip():
                    return result[0]
            elif isinstance(result, str) and result.strip():
                return result
        except (SigmaError, Exception) as e:
            logging.warning("Sigma->SPL failed %s: %s", os.path.basename(filepath), e)
        return None

    def collect_for_technique(self, technique_id: str) -> tuple[list, list]:
        tid_upper = technique_id.upper()
        sigma_entries = []
        if os.path.isdir(self.sigma_path):
            for fp in glob.glob(os.path.join(self.sigma_path, "**", "*.yml"), recursive=True):
                doc = utils.load_yaml_file(fp)
                if not isinstance(doc, dict) or "detection" not in doc or "title" not in doc:
                    continue

                if config.PLATFORM == "linux":
                    product = doc.get("logsource", {}).get("product", "")
                    if product != "linux":
                        continue

                tags = doc.get("tags") or []
                if not isinstance(tags, list):
                    continue
                for tag in tags:
                    if isinstance(tag, str) and re.search(r"attack\.t\d+(\.\d+)?", tag, re.I):
                        tech = tag.replace("attack.", "").upper()
                        if tech == tid_upper:
                            title = doc.get("title", os.path.basename(fp))
                            spl = self._sigma_file_to_spl(fp)
                            if spl:
                                spl = _apply_cim_mapping(spl)
                                spl = _normalize_sigma_spl_for_splunk(spl)
                                rule_id = doc.get("id") or ""
                                rel_path = os.path.relpath(fp, config.SIGMA_REPO_PATH).replace("\\", "/")
                                rule_link = f"{SIGMA_RAW_BASE}/{rel_path}" if rel_path and not rel_path.startswith("..") else ""
                                sigma_entries.append({
                                    "rule_name": title,
                                    "id": rule_id,
                                    "rule_link": rule_link,
                                    "generated_spl": spl,
                                })
                            break

        escu_entries = []
        if os.path.isdir(self.escu_path):
            for fp in glob.glob(os.path.join(self.escu_path, "**", "*.yml"), recursive=True):
                doc = utils.load_yaml_file(fp)
                if not isinstance(doc, dict):
                    continue
                search = doc.get("search")
                if not search or not isinstance(search, str):
                    continue
                tags = doc.get("tags") or {}
                # Splunk security_content moved mitre_attack_id from under `tags`
                # to the top level of the YAML (commit db8c7c8, 2026-05-13), which
                # silently broke ESCU technique matching against the current repo.
                # The lookup reads the new top-level field first, then falls back to
                # the old `tags` location, so it is correct for both schemas and every
                # platform (confirmed with the maintainer). Enabled for Windows too,
                # which the current schema otherwise leaves with zero ESCU matches.
                attack_ids = doc.get("mitre_attack_id") or tags.get("mitre_attack_id") or []
                if isinstance(attack_ids, (str, int)):
                    attack_ids = [str(attack_ids)]
                if not isinstance(attack_ids, list):
                    continue
                norm = [str(x).upper() for x in attack_ids if x]
                if tid_upper not in norm:
                    continue
                title = doc.get("name") or doc.get("title") or os.path.basename(fp)
                sanitized = self._sanitize_escu_spl(search)
                if config.PLATFORM == "linux":
                    # Pipeline runs on a Windows host, so os.path.relpath returns
                    # backslashes; normalize to forward slashes so the GitHub raw URL
                    # is valid (the Sigma side already does this at ~line 166). Linux
                    # only, per the same "don't touch the Windows path" rationale above.
                    rel_path = os.path.relpath(fp, config.ESCU_REPO_PATH).replace("\\", "/")
                else:
                    rel_path = os.path.relpath(fp, config.ESCU_REPO_PATH)
                rule_link = f"{ESCU_RAW_BASE}/{rel_path}" if rel_path and not rel_path.startswith("..") else ""
                file_path = rel_path if rel_path and not rel_path.startswith("..") else fp
                escu_entries.append({
                    "rule_name": title,
                    "file_path": file_path,
                    "rule_link": rule_link,
                    "original_spl": search,
                    "sanitized_spl": sanitized,
                })

        return sigma_entries, escu_entries


class AttackEngine:
    @staticmethod
    def run_attack(technique_id: str, test_number: int = 1) -> tuple[bool, float, float]:
        """
        Run a single Atomic Test. VM revert/start must be done by caller.
        Returns (success, start_time_epoch, end_time_epoch) for strict time-boxed verification.
        """
        if not vm_handler.is_vm_ready():
            logging.warning("VM not ready for %s", technique_id)
            return False, 0.0, 0.0
        start_time = time.time()
        if config.PLATFORM == "windows":
            ok = execution_handler.run_invoke_atomic_test(technique_id, test_number)
        else:
            ok = execution_handler.run_bash_atomic_test(technique_id, test_number)
        if not ok:
            vm_handler.stop_vm()
            return False, start_time, time.time()
        wait_sec = max(30, int(config.POST_EXEC_FORWARD_WAIT_SECONDS))
        logging.debug("Waiting %s seconds for logs to reach Splunk...", wait_sec)
        time.sleep(wait_sec)
        end_time = time.time()
        vm_handler.stop_vm()
        return True, start_time, end_time


class VerificationEngine:
    def __init__(self, service):
        self.service = service

    def run(
        self,
        spl_query: str,
        rule_name: str = "",
        earliest_time: float | None = None,
        latest_time: float | None = None,
    ) -> tuple[bool, int]:
        """
        Run Splunk verification for the given SPL query.
        REQUIRES earliest_time and latest_time (epoch floats) for strict time-boxing.
        No relative time (-2m, now) - prevents cross-contamination between sequential tests.
        """
        if not spl_query or not spl_query.strip():
            return False, 0
        if earliest_time is None or latest_time is None:
            logging.error(
                "Verification requires earliest_time and latest_time (epoch). "
                "Refusing to use relative time to prevent test cross-contamination."
            )
            return False, 0
        q = spl_query.strip()
        if not q.lower().startswith(("search", "index=", "|", "tstats")):
            q = f"search {q}"
        # Strict time-boxing: absolute epoch timestamps only
        earliest = int(earliest_time)
        latest = int(latest_time)
        full = _cim_search_only(q)
        label = rule_name or "unknown"
        logging.debug("[SPL DEBUG] [%s] Query: %s | Time: %s - %s (epoch)", label, full, earliest, latest)
        try:
            job = self.service.jobs.create(
                full,
                exec_mode="blocking",
                earliest_time=str(earliest),
                latest_time=str(latest),
            )
            try:
                job.refresh()
            except Exception:
                pass
            count = int((job.content or {}).get("resultCount", 0))
            if count > 0:
                logging.info("\033[92m[+] DETECTED: %s | Count: %s\033[0m", label, count)
            else:
                logging.debug("No results for [%s]. Search Time: %s to %s (epoch)", label, earliest, latest)
            return count > 0, count
        except Exception as e:
            logging.warning("Verification search failed: %s", e)
            return False, 0


class ReportGenerator:
    @staticmethod
    def build_entry(
        technique_id: str,
        test_number: int,
        atomic_name: str,
        atomic_attack_guid: str,
        platform: str,
        sigma_list: list,
        escu_list: list,
    ) -> dict:
        return {
            "tech_id": technique_id,
            "test_number": test_number,
            "atomic_attack_guid": atomic_attack_guid,
            "atomic_attack_name": atomic_name,
            "platform": platform,
            "sigma_rules": sigma_list,
            "escu_rules": escu_list,
        }

class DynamicDetectionLab:
    def __init__(self, technique_ids: list[str] | None = None):
        self.technique_ids = [t.strip().upper() for t in (technique_ids or config.ATTACK_LIST) if t]
        self.rule_mapper = RuleMapper()
        self.attack_engine = AttackEngine()
        self.report_generator = ReportGenerator()
        self._service = None

    @property
    def service(self):
        if self._service is None:
            self._service = splunk_handler.connect_to_splunk()
        return self._service

    def run(self) -> list:
        logging.info("[*] Ensuring repos (Sigma, ESCU, Atomic Red Team)...")
        mgr = repo_manager.RepoManager()
        if not mgr.ensure_repos():
            logging.error("Repo setup failed. Aborting.")
            return []

        if not self.service:
            logging.error("Splunk connection failed.")
            return []

        verification = VerificationEngine(self.service)
        atomic_parser = atomic_handler.AtomicParser()
        report = []

        for technique_id in self.technique_ids:
            tid = technique_id.upper()
            tests = atomic_parser.get_tests_for_technique(tid, platform_filter=config.PLATFORM)
            if not tests:
                logging.info(f"========== Technique {tid} (no {config.PLATFORM} tests) ==========")
                continue

            sigma_spl_list, escu_spl_list = self.rule_mapper.collect_for_technique(tid)

            for test in tests:
                test_num = test["test_number"]
                atomic_name = test["name"]
                atomic_attack_guid = test["guid"]
                platform = ",".join(test.get("supported_platforms", []) or [])

                logging.info("========== %s | Test #%s: %s ==========", tid, test_num, atomic_name)

                sigma_results = [
                    {
                        "rule_name": r["rule_name"],
                        "id": r.get("id", ""),
                        "rule_link": r.get("rule_link", ""),
                        "generated_spl": r["generated_spl"],
                        "detected": False,
                        "log_count": 0,
                    }
                    for r in sigma_spl_list
                ]
                escu_results = [
                    {
                        "rule_name": r["rule_name"],
                        "file_path": r.get("file_path", ""),
                        "rule_link": r.get("rule_link", ""),
                        "original_spl": r["original_spl"],
                        "detected": False,
                        "log_count": 0,
                    }
                    for r in escu_spl_list
                ]

                if not vm_handler.revert_to_snapshot():
                    logging.warning("Snapshot revert failed for %s Test #%s", tid, test_num)
                    report.append(
                        self.report_generator.build_entry(
                            tid, test_num, atomic_name, atomic_attack_guid, platform,
                            sigma_results, escu_results
                        )
                    )
                    continue
                if not vm_handler.start_vm():
                    logging.warning("VM start failed for %s Test #%s", tid, test_num)
                    report.append(
                        self.report_generator.build_entry(
                            tid, test_num, atomic_name, atomic_attack_guid, platform,
                            sigma_results, escu_results
                        )
                    )
                    continue

                attack_ok, start_time, end_time = self.attack_engine.run_attack(tid, test_number=test_num)
                if not attack_ok:
                    report.append(
                        self.report_generator.build_entry(
                            tid, test_num, atomic_name, atomic_attack_guid, platform,
                            sigma_results, escu_results
                        )
                    )
                    continue

                for i, r in enumerate(sigma_spl_list):
                    detected, count = verification.run(
                        r["generated_spl"],
                        rule_name=r["rule_name"],
                        earliest_time=start_time,
                        latest_time=end_time,
                    )
                    sigma_results[i]["detected"] = detected
                    sigma_results[i]["log_count"] = count

                # Many ESCU rules aggregate over time (e.g. `bucket _time span=15m`
                # | stats ...), so they need a window wider than a single test's
                # ~100s. On Linux we widen only latest_time (push forward, never into
                # the past), so the test's own events still fall inside a full bucket
                # without pulling in earlier tests. Each test runs on a freshly
                # reverted VM, so this does not cross-contaminate.
                if config.PLATFORM == "linux":
                    escu_latest = end_time + config.ESCU_AGG_WINDOW_SECONDS
                else:
                    escu_latest = end_time
                for i, r in enumerate(escu_spl_list):
                    detected, count = verification.run(
                        r["sanitized_spl"],
                        rule_name=r["rule_name"],
                        earliest_time=start_time,
                        latest_time=escu_latest,
                    )
                    escu_results[i]["detected"] = detected
                    escu_results[i]["log_count"] = count

                report.append(
                    self.report_generator.build_entry(
                        tid, test_num, atomic_name, atomic_attack_guid, platform,
                        sigma_results, escu_results
                    )
                )

        handler = report_handler.ReportHandler()
        handler.save_report_json(report)
        return report


def run_dynamic_generator(technique_ids: list[str] | None = None) -> list:
    log_path = os.path.join(config.PROJECT_ROOT, "dynamic_generator.log")
    fh = logging.FileHandler(log_path, mode="w")
    fh.setLevel(logging.DEBUG)
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[fh, sh],
    )
    lab = DynamicDetectionLab(technique_ids=technique_ids)
    return lab.run()


if __name__ == "__main__":
    run_dynamic_generator()
