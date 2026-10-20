#!/usr/bin/env python3
"""Install OS Slurm/MUNGE packages on one host and collect capability evidence.

sudo /usr/bin/python3 install_slurm_probe.py --install --target-host HOST
Use --check-only to repeat checks without a package transaction.
No permanent configuration, service enable/start, key distribution or jobs.
A temporary, isolated munged process tests encode/decode and is then stopped.
Only NEW packages from existing base/updates are permitted, never upgrades.
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time

VERSION = "2026-10-20.2"
PACKAGES = ("munge", "munge-libs", "slurm", "slurm-libs", "slurm-slurmctld", "slurm-slurmd")
SERVICES = ("munge", "slurmctld", "slurmd")
CONFIG_PATHS = ("/etc/slurm", "/etc/slurm.conf", "/etc/munge",
                "/etc/sysconfig/slurm", "/etc/sysconfig/slurmctld",
                "/etc/sysconfig/slurmd", "/etc/sysconfig/munge") + tuple(
                    "/etc/systemd/system/" + s + suffix
                    for s in SERVICES for suffix in (".service", ".service.d"))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def package_id(package):
    return (str(package.name), str(package.arch), str(package.epoch or 0),
            str(package.version), str(package.release))


def installed(rpm):
    ts = rpm.TransactionSet("/")
    return {(str(h["name"]), str(h["arch"]), str(h["epoch"] or 0),
             str(h["version"]), str(h["release"])) for h in ts.dbMatch()}


def run(argv, timeout=30, env=None):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           check=False, timeout=timeout,
                           env={**os.environ, "LC_ALL": "C", **(env or {})})
        return {"argv": argv, "rc": p.returncode, "stdout": p.stdout[:131072],
                "stderr": p.stderr[:32768],
                "truncated": len(p.stdout) > 131072 or len(p.stderr) > 32768}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "rc": None, "error": str(error)}


def command(name):
    path = shutil.which(name)
    require(path is not None, "Missing command: " + name)
    return path


class Report:
    def __init__(self, target):
        fd, filename = tempfile.mkstemp(prefix="slurm-install-" + target + "-",
                                        suffix=".json", dir=Path.cwd())
        self.path = Path(filename)
        self.file = os.fdopen(fd, "w+", encoding="utf-8")
        if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit() and \
                os.environ.get("SUDO_GID", "").isdigit():
            os.fchown(fd, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        self.data = {"script_version": VERSION, "hostname": socket.gethostname(),
                     "target_host": target, "requested_packages": PACKAGES,
                     "transaction_started": False, "checks": {},
                     "cluster_started": False, "runtime_isolation_verified": False,
                     "rollback": {"automatic": False,
                                  "scope": "package history + protected pre-install configuration backup; accounts/scriptlets require review"}}
        self.save("created")

    def save(self, state):
        self.data["state"] = state
        self.data["updated_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.file.seek(0)
        json.dump(self.data, self.file, ensure_ascii=False, indent=2)
        self.file.write("\n")
        self.file.truncate()
        self.file.flush()
        os.fsync(self.file.fileno())
        print("Status: {} | Report: {}".format(state, self.path), flush=True)


def check_host(target):
    local = socket.gethostname().lower().rstrip(".")
    require(target.lower().rstrip(".") in {local, local.split(".")[0]}, "Wrong target host")
    require(os.geteuid() == 0, "Run with sudo /usr/bin/python3")
    require(platform.machine() == "x86_64", "Only x86_64 is supported")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            words = shlex.split(value)
            release[key] = words[0] if words else ""
    require(release.get("ID") == "redos" and release.get("VERSION_ID") == "8.0.3",
            "This pilot requires RED OS 8.0.3")


def service_states():
    return {s: run(["systemctl", "show", s + ".service",
                    "--property=LoadState,ActiveState,SubState,UnitFileState"]) for s in SERVICES}


def is_active(probe):
    return bool(re.search(r"^ActiveState=(active|activating|reloading)$", probe.get("stdout", ""), re.M))


def backup_configuration(report):
    # Root-owned location: never put copies of an existing MUNGE key into the report.
    root = Path("/var/backups/slurm-pilot")
    require(not root.is_symlink(), "Backup root must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, "Backup root must be root-owned and not writable by others")
    directory = Path(tempfile.mkdtemp(prefix="package-probe-", dir=root))
    report.data["rollback"]["backup_directory"] = str(directory)
    manifest = []
    with tarfile.open(directory / "configuration.tar", "x", dereference=False) as archive:
        for name in CONFIG_PATHS:
            path = Path(name)
            exists = os.path.lexists(path)
            manifest.append({"path": name, "existed_before": exists})
            if exists:
                archive.add(path, arcname=name.lstrip("/"), recursive=True)
    (directory / "configuration.tar").chmod(0o600)
    (directory / "manifest.json").write_text(json.dumps({
        "paths": manifest, "packages_before": report.data["packages_before"],
        "services_before": report.data["services_before"],
        "note": "Review before restore. Do not blindly extract over later changes or delete system accounts."
    }, indent=2) + "\n")
    (directory / "manifest.json").chmod(0o600)
    report.save("configuration_backed_up")


def configure_dnf(base):
    c = base.conf
    c.read()
    require(c.installroot == "/", "Custom installroot is not supported")
    require(not (set(c.tsflags) - {"nodocs"}), "Unsupported RPM transaction flags")
    c.plugins = False
    c.gpgcheck = True
    c.localpkg_gpgcheck = True
    c.sslverify = True
    c.keepcache = True
    c.cacheonly = False
    base.read_all_repos()
    enabled = set()
    for repo in base.repos.values():
        if repo.id in {"base", "updates"} and repo.enabled:
            repo.gpgcheck = True
            repo.sslverify = True
            repo.skip_if_unavailable = False
            enabled.add(repo.id)
        else:
            repo.disable()
    require(enabled == {"base", "updates"}, "Existing signed base and updates repositories are required")
    base.fill_sack_from_repos_in_cache(load_system_repo=True)


def validate_transaction(transaction, before):
    packages = list(transaction.install_set)
    require(not list(transaction.remove_set), "Refusing removals, upgrades or replacements of installed RPMs")
    before_names = {p[0] for p in before}
    require(0 < len(packages) <= 100, "Unexpected transaction size")
    for p in packages:
        require(p.name not in before_names, "Refusing to modify installed package: " + p.name)
        require(p.repoid in {"base", "updates"} and p.arch in {"x86_64", "noarch"},
                "Unexpected package repository or architecture: " + p.name)
        require(not re.match(r"^(kernel|kmod|akmod|nvidia|cuda|systemd|dnf|rpm)(-|$)", p.name),
                "Package outside the pilot installation scope: " + p.name)
    selected = {p.name for p in packages}
    require(set(PACKAGES) <= selected, "Solver did not include all six requested components")
    versions = {(str(p.epoch or 0), p.version, p.release) for p in packages if p.name.startswith("slurm")}
    require(len(versions) == 1, "Slurm component versions differ")
    return packages


def install_components(base, rpm, report):
    before = installed(rpm)
    report.data["packages_before"] = sorted(before)
    present = {p[0] for p in before} & set(PACKAGES)
    if present == set(PACKAGES):
        report.save("components_already_installed")
        return
    require(not present, "Partial installation exists; collect --check-only report before changing it")
    backup_configuration(report)
    report.save("loading_cached_repository_metadata")
    configure_dnf(base)
    for name in PACKAGES:
        base.install(name + ".x86_64", strict=True)
    base.resolve(allow_erasing=False)
    packages = validate_transaction(base.transaction, before)
    expected = {package_id(p) for p in packages}
    report.data["resolved_packages"] = sorted(package_id(p) + (str(p.repoid),) for p in packages)
    report.save("downloading_os_rpms")
    base.download_packages(packages)
    report.save("checking_rpm_signatures")
    for p in packages:
        require(p.repo.gpgcheck, "RPM signature check must be enabled")
        status, message = base.package_signature_check(p)
        require(status == 0, "Signature rejected for {}: {}".format(p.name, message))
    require(installed(rpm) == before, "RPM database changed during preparation")
    validate_transaction(base.transaction, before)
    report.data["transaction_started"] = True
    report.save("installing_packages")
    tid = base.do_transaction()  # DNF performs RPM dependency check/test before apply.
    report.data["dnf_history_id"] = tid
    report.data["rollback"]["review_command"] = "dnf --assumeno history undo {}".format(tid) if tid else None
    after = installed(rpm)
    report.data["packages_after"] = sorted(after)
    report.data["added"] = sorted(after - before)
    report.data["removed"] = sorted(before - after)
    require(after == before | expected, "RPM post-check differs from the resolved install-only transaction")
    report.save("packages_installed")


def munge_probe():
    account = pwd.getpwnam("munge")
    require(account.pw_uid != 0, "MUNGE probe must run as the unprivileged munge account")
    with tempfile.TemporaryDirectory(prefix="slurm-munge-probe-", dir="/run") as temporary:
        directory = Path(temporary)
        os.chown(directory, account.pw_uid, account.pw_gid)
        key = directory / "key"
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
            stream.write(os.urandom(512))
        sock = str(directory / "munge.socket.2")
        argv = [command("munged"), "--foreground", "--socket", sock,
                "--key-file", str(key), "--pid-file", str(directory / "pid"),
                "--seed-file", str(directory / "seed"), "--log-file", str(directory / "log")]
        with tempfile.TemporaryFile() as log:
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                    user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                    cwd=temporary, start_new_session=True,
                                    env={**os.environ, "LC_ALL": "C"})
            result = {"isolated_temporary_socket": True, "persistent_key_changed": False}
            try:
                deadline = time.monotonic() + 8
                while proc.poll() is None and not Path(sock).exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                require(proc.poll() is None and Path(sock).exists(), "Temporary munged did not become ready")
                # Credentials are intentionally never included in the JSON.
                encoded = subprocess.run([command("munge"), "--socket", sock, "-n"],
                                         capture_output=True, timeout=10, check=False,
                                         env={**os.environ, "LC_ALL": "C"})
                result["encode_rc"] = encoded.returncode
                require(encoded.returncode == 0, "Temporary MUNGE encoding failed")
                decoded = subprocess.run([command("unmunge"), "--socket", sock],
                                         input=encoded.stdout, capture_output=True, timeout=10, check=False,
                                         env={**os.environ, "LC_ALL": "C"})
                result["decode_rc"] = decoded.returncode
                result["status_success"] = decoded.returncode == 0 and b"Success (0)" in decoded.stdout
            except Exception as error:
                result["error"] = "{}: {}".format(type(error).__name__, error)
            finally:
                result["daemon_returncode_before_cleanup"] = proc.poll()
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
            log.seek(0)
            result["daemon_stderr"] = log.read(32768).decode(errors="replace")
            daemon_log = directory / "log"
            if daemon_log.is_file():
                with daemon_log.open(errors="replace") as stream:
                    result["daemon_log"] = stream.read(32768)
            return result


def gres_probe(hardware, devices, cgroup_v2_parse=False):
    require(hardware.get("rc") == 0, "Need successful slurmd -C")
    fields = dict(re.findall(r"\b(CPUs|Boards|SocketsPerBoard|CoresPerSocket|ThreadsPerCore)=([0-9]+)\b",
                             hardware.get("stdout", "")))
    require("CPUs" in fields, "Could not parse detected Slurm CPU topology")
    with tempfile.TemporaryDirectory(prefix="slurm-gres-probe-", dir="/run") as temporary:
        directory = Path(temporary)
        node = socket.gethostname().split(".")[0]
        config = "\n".join([
            "ClusterName=component_probe", "SlurmctldHost=" + node + "(127.0.0.1)",
            "SlurmUser=root", "SlurmdUser=root", "AuthType=auth/munge",
            "StateSaveLocation=" + temporary, "SlurmdSpoolDir=" + temporary,
            "SlurmdPidFile=" + temporary + "/slurmd.pid", "SlurmdLogFile=" + temporary + "/slurmd.log",
            "SelectType=select/cons_tres", "SelectTypeParameters=CR_Core_Memory",
            "ProctrackType=proctrack/linuxproc", "TaskPlugin=task/none",
            "JobAcctGatherType=jobacct_gather/none", *(["GresTypes=gpu"] if devices else []),
            "NodeName=" + node + " NodeAddr=127.0.0.1 " +
            " ".join(k + "=" + v for k, v in fields.items()) + " RealMemory=1024" +
            (" Gres=gpu:" + str(len(devices)) if devices else ""),
            "PartitionName=probe Nodes=" + node + " Default=YES State=UP", ""])
        path = directory / "slurm.conf"
        path.write_text(config)
        (directory / "gres.conf").write_text(("AutoDetect=nvml\n" if devices else "") + "".join(
            "Name=gpu File=" + device + "\n" for device in devices))
        (directory / "cgroup.conf").write_text(
            ("CgroupPlugin=cgroup/v2\n" if cgroup_v2_parse else "") +
            "ConstrainCores=no\nConstrainRAMSpace=no\nConstrainDevices=no\n")
        result = run([command("slurmd"), "-G", "-N", node, "-f", str(path)], timeout=60,
                     env={"SLURM_CONF": str(path)})
        result["note"] = "GRES inspection only. RC 0 alone does not establish GPU count, NVML or job/device isolation; review output."
        result["nvidia_autodetect_requested"] = bool(devices)
        daemon_log = directory / "slurmd.log"
        if daemon_log.is_file():
            with daemon_log.open(errors="replace") as stream:
                result["slurmd_log"] = stream.read(32768)
        if cgroup_v2_parse:
            result["note"] = "Temporary CgroupPlugin=cgroup/v2 configuration parse through slurmd -G; no GPU autodetection, cgroup task/proctrack plugin or daemon is started. This does not verify runtime isolation."
        return result


def collect_checks(report):
    checks = report.data["checks"]
    probes = {
        "package_versions": ["rpm", "-q", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n", *PACKAGES],
        "package_integrity": ["rpm", "--verify", "--noscripts", *PACKAGES],
        "package_files": ["rpm", "-ql", *PACKAGES],
        "slurm_changelog": ["rpm", "-q", "--changelog", "slurm", "slurm-libs"],
        "slurmd_version": ["slurmd", "-V"], "slurmctld_version": ["slurmctld", "-V"],
        "slurm_hardware": ["slurmd", "-C"], "munge_version": ["munge", "--version"],
        "nvidia_inventory": ["nvidia-smi", "--query-gpu=index,name,uuid,driver_version,memory.total", "--format=csv,noheader"],
        "nvml_library": ["ldconfig", "-p"],
        "systemd_version": ["systemctl", "--version"],
        "unit_files": ["systemctl", "cat", "munge.service", "slurmctld.service", "slurmd.service"],
        "cgroup_mount": ["findmnt", "-n", "-o", "TARGET,FSTYPE,OPTIONS", "/sys/fs/cgroup"],
    }
    for name, argv in probes.items():
        report.save("checking_" + name)
        checks[name] = run(argv, timeout=60)
    checks["nvml_library"]["stdout"] = "\n".join(
        line for line in checks["nvml_library"].get("stdout", "").splitlines() if "libnvidia-ml" in line)
    devices = sorted(p for p in glob.glob("/dev/nvidia*")
                     if re.fullmatch(r"/dev/nvidia[0-9]+", p) and stat.S_ISCHR(os.stat(p).st_mode))
    report.data["nvidia_devices"] = devices
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    report.data["cgroup_v2_host"] = controllers.is_file()
    report.data["cgroup_controllers"] = controllers.read_text().split() if controllers.is_file() else []
    evidence = []
    files = checks["package_files"].get("stdout", "").splitlines()
    for name in sorted(set(files)):
        path = Path(name)
        if path.suffix == ".so" and any(word in path.name for word in ("cgroup", "nvml", "gres_gpu", "task_affinity")) and path.is_file():
            data = path.read_bytes()
            evidence.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                             "cgroup_v2_marker": b"cgroup/v2\x00" in data,
                             "dependencies": run(["ldd", name])})
    report.data["plugin_evidence"] = evidence
    report.data["cgroup_v2_plugin_marker_detected"] = any(p["cgroup_v2_marker"] for p in evidence)
    report.data["cgroup_v2_assessment"] = "evidence_only_runtime_not_verified"
    for name, probe in (("munge_local", munge_probe),
                        ("gres_nvml", lambda: gres_probe(checks["slurm_hardware"], devices)),
                        ("cpu_config_baseline", lambda: gres_probe(checks["slurm_hardware"], [])),
                        ("cgroup_v2_config_probe", lambda: gres_probe(checks["slurm_hardware"], [], cgroup_v2_parse=True))):
        report.save("checking_" + name)
        try:
            checks[name] = probe()
        except Exception as error:
            checks[name] = {"error": "{}: {}".format(type(error).__name__, error)}
    report.data["remaining_checks"] = ["Review cgroup v2 vendor backport/plugin evidence",
                                        "Configure and start the reviewed single-node cluster",
                                        "CPU/GPU jobs and actual cgroup memory/device isolation"]
    report.data["checks_requiring_review"] = [
        name for name, result in checks.items()
        if "error" in result or ("rc" in result and result["rc"] != 0)]
    if not checks.get("munge_local", {}).get("status_success"):
        report.data["checks_requiring_review"].append("munge_local_round_trip")
    if not checks["nvml_library"].get("stdout"):
        report.data["checks_requiring_review"].append("nvml_library_not_found")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--check-only", action="store_true")
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.target_host):
        parser.error("Invalid target hostname")
    report = Report(args.target_host)
    base = rpm = None
    status = 1
    finalize_error = False
    try:
        check_host(args.target_host)
        report.data["services_before"] = service_states()
        require(all(not is_active(s) for s in report.data["services_before"].values()),
                "Existing active Slurm/MUNGE service: stop and review before this isolated probe")
        if args.install:
            report.save("loading_system_dnf")
            import dnf
            import rpm as system_rpm
            rpm = system_rpm
            base = dnf.Base()
            install_components(base, rpm, report)
            base.close()
            base = None
        collect_checks(report)
        versions = report.data["checks"]["package_versions"]
        require(versions.get("rc") == 0, "One or more required packages are missing; review report")
        report.save("packages_present_checks_recorded")
        status = 0
    except (Exception, KeyboardInterrupt) as error:
        report.data["error"] = "{}: {}".format(type(error).__name__, error)
        report.save("failed_review_required" if report.data["transaction_started"] else "stopped_before_apply")
    finally:
        if rpm is not None:
            try:
                report.data["packages_after"] = sorted(installed(rpm))
            except Exception as error:
                report.data["rpm_post_read_error"] = str(error)
        if base is not None:
            try:
                base.close()
            except Exception as error:
                report.data["dnf_close_error"] = str(error)
                status = 1
                finalize_error = True
        if "services_before" in report.data:
            report.data["services_after"] = service_states()
            # Record RPM scriptlet effects; never start/enable or blindly stop a service.
            if any(is_active(s) for s in report.data["services_after"].values()):
                report.data["service_review_required"] = True
                status = 1
                finalize_error = True
        report.save("failed_review_required" if finalize_error else report.data["state"])
        report.file.close()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
