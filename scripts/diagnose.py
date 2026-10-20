#!/usr/bin/env python3
"""Read-only RED OS/Slurm inventory. No sudo, installs, network scans or secrets."""

import argparse
import datetime
import glob
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


SCRIPT_VERSION = "2026-10-20.3"


def read_text(path, limit=65536):
    try:
        return Path(path).read_text(errors="replace")[:limit].strip()
    except OSError:
        return ""


def parse_os_release(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        # Parse quoting without executing any shell content.
        try:
            words = shlex.split(value)
        except ValueError:
            words = [value]
        result[key] = " ".join(words)
    return result


def run(argv, timeout=20):
    if not shutil.which(argv[0]):
        return {"argv": argv, "rc": 127, "status": "missing", "stdout": "", "stderr": "command not found"}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C"}, check=False)
        return {"argv": argv, "rc": proc.returncode,
                "status": "ok" if proc.returncode == 0 else "failed",
                "stdout": proc.stdout[:131072], "stderr": proc.stderr[:16384],
                "stdout_truncated": len(proc.stdout) > 131072,
                "stderr_truncated": len(proc.stderr) > 16384}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "rc": 124, "status": "timeout", "stdout": "", "stderr": "timeout"}
    except OSError as exc:
        return {"argv": argv, "rc": 126, "status": "failed", "stdout": "", "stderr": str(exc)}


def memory_mib(text):
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1]) // 1024
            except (IndexError, ValueError):
                return 0
    return 0


def collect(check_repos=False):
    probes = {
        "cpu": ["lscpu", "--json"],
        "numa": ["numactl", "--hardware"],
        "block_devices": ["lsblk", "--json", "--bytes", "--output", "NAME,TYPE,SIZE,MODEL,FSTYPE,MOUNTPOINTS"],
        "filesystems": ["df", "-PT"],
        "network": ["ip", "-j", "address", "show"],
        "pci": ["lspci", "-nnk"],
        "nvidia_smi": ["nvidia-smi", "-L"],
        "nvidia_inventory": ["nvidia-smi", "--query-gpu=index,name,uuid,pci.bus_id,driver_version,memory.total", "--format=csv,noheader"],
        "nvidia_mig": ["nvidia-smi", "--query-gpu=index,mig.mode.current", "--format=csv,noheader"],
        "nvidia_topology": ["nvidia-smi", "topo", "-m"],
        "nvml": ["ldconfig", "-p"],
        "installed_packages": ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n", "slurm*", "munge*", "nvidia*", "*nvml*", "libnvidia*"],
        "slurm_hardware": ["slurmd", "-C"],
        "slurm_version": ["slurmd", "-V"],
        "controller_version": ["slurmctld", "-V"],
        "services": ["systemctl", "show", "munge.service", "slurmctld.service", "slurmd.service", "chronyd.service", "--property=Id,LoadState,ActiveState,SubState,UnitFileState"],
        "clock": ["timedatectl", "show", "--property=NTPSynchronized,Timezone"],
        "chrony": ["chronyc", "tracking"],
        "selinux": ["getenforce"],
        "firewall": ["firewall-cmd", "--list-all"],
        "slurm_account": ["getent", "passwd", "slurm"],
        "munge_account": ["getent", "passwd", "munge"],
    }
    if check_repos:
        # Only existing metadata. No refresh, new repo, transaction or download.
        probes["available_os_packages_cached"] = [
            "dnf", "--cacheonly", "--assumeno", "list", "--available",
            "slurm*", "munge*", "*nvml*", "nvidia*",
        ]
    commands = {name: run(argv) for name, argv in probes.items()}
    # ldconfig's complete cache is unnecessary; retain only GPU-related entries.
    commands["nvml"]["stdout"] = "\n".join(
        line for line in commands["nvml"]["stdout"].splitlines()
        if "libnvidia-ml" in line or "libcuda.so" in line
    )
    return {
        "schema_version": 1,
        "script_version": SCRIPT_VERSION,
        "report_kind": "hardware",
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "os_release": parse_os_release(read_text("/etc/os-release")),
        "release_text": "\n".join(filter(None, [read_text("/etc/redos-release"), read_text("/etc/redhat-release"), read_text("/etc/system-release"), read_text("/etc/os-release")])),
        "memory_total_mib": memory_mib(read_text("/proc/meminfo")),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup_controllers": read_text("/sys/fs/cgroup/cgroup.controllers").split(),
        "dmi": {name: read_text("/sys/class/dmi/id/" + name) for name in ("sys_vendor", "product_name", "board_vendor", "board_name", "bios_version")},
        "nvidia_device_files": sorted(glob.glob("/dev/nvidia*")),
        "commands": commands,
        "notes": [
            "Probe failures are recorded, not hidden; missing tools are not installed.",
            "A missing or failed nvidia-smi does not prove absence of NVIDIA hardware; compare PCI inventory.",
            "Cached package metadata may be absent/stale; no refresh was attempted.",
            "No MUNGE key, environment variables, credential files or private keys are read.",
            "This report inventories this host only; it does not certify cluster readiness.",
        ],
    }


def collect_packages():
    """Investigate RPM/DNF without starting DNF or changing package state."""
    packages = [
        "dnf", "dnf-data", "python3-dnf", "libdnf", "python3-libdnf",
        "python3-hawkey", "libsolv", "python3-libsolv", "rpm", "rpm-libs",
        "python3-rpm", "python3", "python3-libs",
        # Kernel logs localized the observed DNF SIGSEGV to librepo.so.0.
        "librepo", "python3-librepo", "libcurl", "libcurl-minimal",
        "curl", "curl-minimal", "libxml2", "openssl-libs", "glib2",
        "libgpg-error", "gpgme", "zchunk-libs", "libzstd", "zlib",
    ]
    slurm_packages = [
        "slurm", "slurm-libs", "slurm-slurmd", "slurm-slurmctld",
        "munge", "munge-libs",
    ]
    probes = {
        "rpm_version": ["rpm", "--version"],
        "package_versions": ["rpm", "-q", "--qf",
                             "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n",
                             *packages, *slurm_packages],
        # --noscripts prevents execution of RPM verification scriptlets.
        "package_integrity": ["rpm", "--verify", "--noscripts", *packages],
        "slurm_package_metadata": ["rpm", "-q", "--qf",
                                   "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n"
                                   "Vendor: %{VENDOR}\nBuild: %{BUILDTIME:date}\n"
                                   "Source RPM: %{SOURCERPM}\n",
                                   *slurm_packages],
        "slurm_package_files": ["rpm", "-ql", *slurm_packages],
        "slurm_changelog": ["rpm", "-q", "--changelog", "slurm", "slurm-libs"],
        "dnf_path_ownership": ["rpm", "-qf", "/usr/bin/dnf", "/usr/bin/python3"],
        "librepo_path_ownership": ["rpm", "-qf",
                                   "/usr/lib64/librepo.so.0", "/lib64/librepo.so.0"],
        "librepo_package_metadata": ["rpm", "-q", "--qf",
                                     "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"
                                     "Vendor: %{VENDOR}\nSource RPM: %{SOURCERPM}\n",
                                     "librepo", "libcurl", "libcurl-minimal"],
        "librepo_requirements": ["rpm", "-q", "--requires", "librepo"],
        "librepo_changelog": ["rpm", "-q", "--changelog", "librepo"],
        "librepo_elf_dependencies": ["readelf", "--dynamic", "/usr/lib64/librepo.so.0"],
        "librepo_elf_build_id": ["readelf", "--notes", "/usr/lib64/librepo.so.0"],
        "system_python": ["/usr/bin/python3", "--version"],
        "systemd_version": ["systemctl", "--version"],
        "cgroup_mounts": ["findmnt", "-rn", "-t", "cgroup,cgroup2",
                          "-o", "TARGET,FSTYPE,OPTIONS"],
        "kernel_package_faults": ["journalctl", "--dmesg", "--no-pager",
                                  "--grep=dnf|libdnf|libsolv", "--lines=30"],
    }
    commands = {name: run(argv) for name, argv in probes.items()}
    # Keep package paths relevant to Slurm rather than the entire file inventory.
    commands["slurm_package_files"]["stdout"] = "\n".join(
        line for line in commands["slurm_package_files"]["stdout"].splitlines()
        if re.search(r"cgroup|nvml|gres|slurmd|slurmctld|systemd|not installed", line, re.I)
    )
    changelog = commands["slurm_changelog"]["stdout"].splitlines()
    selected = set()
    for index, line in enumerate(changelog):
        if re.search(r"cgroup|nvml|not installed", line, re.I):
            selected.update(range(max(0, index - 2), min(len(changelog), index + 3)))
    commands["slurm_changelog"]["stdout"] = "\n".join(
        changelog[index] for index in sorted(selected)
    )
    return {
        "schema_version": 1,
        "script_version": SCRIPT_VERSION,
        "report_kind": "packages",
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "os_release": parse_os_release(read_text("/etc/os-release")),
        "python_version": platform.python_version(),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup_controllers": read_text("/sys/fs/cgroup/cgroup.controllers").split(),
        # Record names/presence only, never values or a full environment dump.
        "runtime_variable_names_present": [
            name for name in (
                "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH", "PYTHONHOME",
                "VIRTUAL_ENV", "CONDA_PREFIX",
            ) if name in os.environ
        ],
        "commands": commands,
        "notes": [
            "DNF is not started in this mode; its prior crash is not retried.",
            "RPM queries and file verification do not install or repair packages.",
            "RPM verification scriptlets are disabled with --noscripts.",
            "Missing packages, denied journal access and nonzero statuses remain visible.",
            "Empty filtered changelog output does not prove absence of a vendor backport.",
            "Package files/metadata do not by themselves certify cgroup v2 or NVML support.",
            "Optional library variants may be absent; that is not a recommendation to install them.",
            "RPM T-only output means a timestamp difference, not a content checksum mismatch.",
            "readelf only inspects ELF data; target libraries are not loaded or executed.",
            "No MUNGE keys, credentials, environment values or repository config files are read.",
        ],
    }


def collect_curl_plan():
    """Ask DNF for a cached transaction preview; --assumeno forbids applying it."""
    report = {
        "schema_version": 1,
        "script_version": SCRIPT_VERSION,
        "report_kind": "package_plan",
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "os_release": parse_os_release(read_text("/etc/os-release")),
        "requested_packages": ["curl.x86_64", "libcurl.x86_64"],
        "apply_supported": False,
        "commands": {},
        "notes": [
            "This separate mode starts DNF with --assumeno; no RPM transaction is applied.",
            "Only existing repository cache is used; metadata is not refreshed.",
            "DNF plugins are disabled and GPG verification remains enabled.",
            "The solver may propose dependencies beyond curl/libcurl; review all output.",
            "DNF exit 1 may mean expected Operation aborted; it is not a passing installation test.",
            "A timeout, SIGSEGV, missing cache or truncated output does not provide an approvable plan.",
            "The earlier --packages-only mode still never starts DNF.",
        ],
    }
    if os.geteuid() != 0:
        report["state"] = "requires_root_for_dnf_preview"
        report["error"] = "DNF upgrade demands root even with --assumeno; no command was started."
        return report
    if platform.machine() != "x86_64":
        report["state"] = "unsupported_architecture"
        return report
    # Confine DNF logs to a new private temporary directory, never edit dnf.conf.
    with tempfile.TemporaryDirectory(prefix=".slurm-dnf-plan-", dir=".") as logdir:
        argv = [
            "dnf", "--cacheonly", "--assumeno", "--noplugins",
            "--setopt=assumeyes=False", "--setopt=gpgcheck=True",
            "--setopt=logdir=" + str(Path(logdir).resolve()),
            "--setopt=logfilelevel=0",
            "upgrade", "curl.x86_64", "libcurl.x86_64",
        ]
        result = run(argv, timeout=60)
    report["commands"]["curl_transaction_preview"] = result
    report["state"] = "review_required"
    if result["rc"] < 0 or result["rc"] in (124, 126, 127):
        report["state"] = "preview_unavailable"
    return report


def save_report(report, directory="."):
    """Create a unique mode-0600 JSON; never replace an existing report."""
    hostname = re.sub(r"[^A-Za-z0-9_.-]", "_", report["hostname"])[:80] or "node"
    kind = {"packages": "packages", "package_plan": "plan"}.get(
        report.get("report_kind"), "report",
    )
    descriptor, filename = tempfile.mkstemp(
        prefix=f"slurm-{kind}-{hostname}-", suffix=".json", dir=directory,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            # Let the invoking SSH/SFTP user retrieve a report created via sudo.
            sudo_uid, sudo_gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
            if os.geteuid() == 0 and sudo_uid.isdigit() and sudo_gid.isdigit() and int(sudo_uid) > 0:
                os.fchown(output.fileno(), int(sudo_uid), int(sudo_gid))
            json.dump(report, output, indent=2, ensure_ascii=False)
            output.write("\n")
    except BaseException:
        Path(filename).unlink(missing_ok=True)
        raise
    return Path(filename)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cached-repos", action="store_true", help="inspect existing DNF metadata without refreshing it")
    mode.add_argument("--packages-only", action="store_true", help="read RPM/package diagnostics without starting DNF")
    mode.add_argument("--plan-curl-update", action="store_true", help="preview curl/libcurl update with DNF --assumeno; requires root, never applies")
    parser.add_argument("--save-report", action="store_true", help="save a new protected JSON in the current directory")
    parser.add_argument("--version", action="version", version=SCRIPT_VERSION)
    args = parser.parse_args()
    if args.plan_curl_update:
        report = collect_curl_plan()
    else:
        report = collect_packages() if args.packages_only else collect(args.cached_repos)
    if args.save_report:
        print("Отчёт сохранён:", save_report(report))
    else:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
