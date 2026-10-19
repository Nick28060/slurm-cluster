#!/usr/bin/env python3
"""Read-only RED OS/Slurm inventory. No sudo, installs, network scans or secrets."""

import argparse
import datetime
import glob
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys


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
                "stdout": proc.stdout[:131072], "stderr": proc.stderr[:16384]}
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cached-repos", action="store_true", help="inspect existing DNF metadata without refreshing it")
    args = parser.parse_args()
    json.dump(collect(args.cached_repos), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
