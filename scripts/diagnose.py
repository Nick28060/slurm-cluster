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


SCRIPT_VERSION = "2026-10-20.1"


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
            "No MUNGE keys, credentials, environment values or repository config files are read.",
        ],
    }


def save_report(report, directory="."):
    """Create a unique mode-0600 JSON; never replace an existing report."""
    hostname = re.sub(r"[^A-Za-z0-9_.-]", "_", report["hostname"])[:80] or "node"
    kind = "packages" if report.get("report_kind") == "packages" else "report"
    descriptor, filename = tempfile.mkstemp(
        prefix=f"slurm-{kind}-{hostname}-", suffix=".json", dir=directory,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
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
    parser.add_argument("--save-report", action="store_true", help="save a new protected JSON in the current directory")
    parser.add_argument("--version", action="version", version=SCRIPT_VERSION)
    args = parser.parse_args()
    report = collect_packages() if args.packages_only else collect(args.cached_repos)
    if args.save_report:
        print("Отчёт сохранён:", save_report(report))
    else:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
