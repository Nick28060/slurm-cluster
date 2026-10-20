#!/usr/bin/env python3
"""Apply the reviewed RED OS curl transaction, using system DNF 4 Python bindings.

Manual use: sudo /usr/bin/python3 update_curl.py --apply --target-host HOST
No SSH, repository creation, key import, OS snapshot or automatic rollback.
The exact 20-package transaction is mandatory. Existing cached metadata is used;
RPM payloads may be downloaded with TLS, checksum and signature verification.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import shlex
import socket
import subprocess
import tempfile

VERSION = "2026-10-20.1"
CORE = {"curl", "libcurl", "libcurl-devel"}
# name, arch, epoch, version, release, repository (from the approved preview).
APPROVED = (
    ("curl", "x86_64", "0", "8.21.0", "1.red80", "updates"),
    ("libcurl", "x86_64", "0", "8.21.0", "1.red80", "updates"),
    ("libcurl-devel", "x86_64", "0", "8.21.0", "1.red80", "updates"),
    ("brotli-devel", "x86_64", "0", "1.2.0", "1.red80", "updates"),
    ("keyutils-libs-devel", "x86_64", "0", "1.6.3", "1.red80", "updates"),
    ("krb5-devel", "x86_64", "0", "1.21.3", "4.red80", "updates"),
    ("libcom_err-devel", "x86_64", "0", "1.46.3", "2.red80", "base"),
    ("libidn2-devel", "x86_64", "0", "2.3.2", "4.red80", "base"),
    ("libkadm5", "x86_64", "0", "1.21.3", "4.red80", "updates"),
    ("libnghttp2-devel", "x86_64", "0", "1.69.0", "1.red80", "updates"),
    ("libpsl-devel", "x86_64", "0", "0.21.1", "5.red80", "base"),
    ("libselinux-devel", "x86_64", "0", "3.5", "1.red80", "updates"),
    ("libsepol-devel", "x86_64", "0", "3.5", "1.red80", "updates"),
    ("libssh-devel", "x86_64", "0", "0.12.2", "1.red80", "updates"),
    ("libverto-devel", "x86_64", "0", "0.3.2", "3.red80", "base"),
    ("openssl-devel", "x86_64", "1", "3.5.5", "1.red80", "updates"),
    ("pcre2-devel", "x86_64", "0", "10.46", "1.red80", "updates"),
    ("pcre2-utf16", "x86_64", "0", "10.46", "1.red80", "updates"),
    ("pcre2-utf32", "x86_64", "0", "10.46", "1.red80", "updates"),
    ("publicsuffix-list", "noarch", "0", "20210518", "3.red80", "base"),
)
EXPECTED = {p[:5] for p in APPROVED}
NAMES = {p[0] for p in APPROVED}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def package_id(package):
    return (str(package.name), str(package.arch), str(package.epoch or 0),
            str(package.version), str(package.release))


def installed(rpm):
    # A fresh read-only RPM transaction avoids reusing a pre-update RPMDB view.
    ts = rpm.TransactionSet("/")
    return {(str(h["name"]), str(h["arch"]), str(h["epoch"] or 0),
             str(h["version"]), str(h["release"])) for h in ts.dbMatch()}


def nevra(identity):
    name, arch, epoch, version, release = identity
    return "{}-{}:{}-{}.{}".format(name, epoch, version, release, arch)


def validate_initial(before, rpm):
    relevant = {p for p in before if p[0] in NAMES}
    if relevant == EXPECTED:
        return False  # An already completed run never starts another transaction.
    old = {p for p in relevant if p[0] in CORE}
    require(len(old) == 3 and {p[0] for p in old} == CORE,
            "Expected exactly one installed x86_64 package for each curl component")
    require(relevant == old and all(p[1] == "x86_64" for p in old),
            "Package state changed: the 17 approved dependencies must be new")
    for previous in old:
        target = next(p for p in EXPECTED if p[0] == previous[0])
        require(rpm.labelCompare(previous[2:], target[2:]) < 0,
                "Refusing a reinstall or downgrade: " + previous[0])
    return True


def validate_transaction(transaction, before):
    incoming = list(transaction.install_set)
    outgoing = list(transaction.remove_set)
    actual = {package_id(p) + (str(p.repoid),) for p in incoming}
    old = {p for p in before if p[0] in CORE}
    require(len(incoming) == 20 and actual == set(APPROVED),
            "Resolved packages/versions/repositories differ from the approved 20 RPMs")
    require(len(outgoing) == 3 and {package_id(p) for p in outgoing} == old,
            "Refusing transaction: removal set differs from the 3 replaced curl RPMs")
    return incoming, old


class Report:
    """Keep a private checkpoint even if a native DNF library terminates Python."""

    def __init__(self, target):
        host = socket.gethostname()
        safe_host = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)
        fd, filename = tempfile.mkstemp(prefix="curl-update-" + safe_host + "-",
                                        suffix=".json", dir=Path.cwd())
        self.path = Path(filename)
        self.file = os.fdopen(fd, "w+", encoding="utf-8")
        if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit() and \
                os.environ.get("SUDO_GID", "").isdigit():
            os.fchown(fd, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        self.data = {"script_version": VERSION, "hostname": host, "target_host": target,
                     "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "approved_packages": APPROVED, "transaction_started": False,
                     "rollback": {"automatic": False, "old_rpm_availability": "not_verified",
                                  "os_snapshot": "waived_by_user"}}
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
    # The explicit target in the manual command must match the local host.
    local = socket.gethostname().lower().rstrip(".")
    requested = target.lower().rstrip(".")
    require(requested and (requested == local or requested == local.split(".")[0]),
            "Wrong host: --target-host must match the local hostname")
    require(os.geteuid() == 0, "Run with sudo /usr/bin/python3")
    require(platform.machine() == "x86_64", "Only x86_64 is approved")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            tokens = shlex.split(value)
            release[key] = tokens[0] if tokens else ""
    require(release.get("ID") == "redos" and release.get("VERSION_ID") == "8.0.3",
            "Only RED OS 8.0.3 is approved")


def execute(base, rpm, report):
    before = installed(rpm)
    report.data["packages_before"] = sorted(before)
    report.data["rollback"]["previous_curl_nevras"] = sorted(
        nevra(p) for p in before if p[0] in CORE)
    report.save("checking_initial_packages")
    if not validate_initial(before, rpm):
        report.save("already_installed")
        return

    conf = base.conf
    conf.read()
    require(conf.installroot == "/", "Custom installroot is not supported")
    require(not (set(conf.tsflags) - {"nodocs"}), "Unsupported RPM transaction flags")
    conf.plugins = False
    conf.gpgcheck = True
    conf.localpkg_gpgcheck = True
    conf.sslverify = True
    conf.keepcache = True
    conf.cacheonly = False  # Cached metadata, but allow verified RPM payload downloads.
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
    require(enabled == {"base", "updates"}, "Existing base and updates repos must be enabled")
    report.save("loading_cached_metadata")
    base.fill_sack_from_repos_in_cache(load_system_repo=True)
    for identity in APPROVED:
        if identity[0] in CORE:
            base.install(nevra(identity[:5]), reponame=identity[5], strict=True)
    base.resolve(allow_erasing=False)
    packages, old = validate_transaction(base.transaction, before)
    report.data["resolved_packages"] = sorted(
        package_id(p) + (str(p.repoid),) for p in packages)
    report.save("downloading_approved_rpms")
    base.download_packages(packages)
    report.save("checking_rpm_signatures")
    for package in packages:
        require(package.repo.gpgcheck, "RPM signature verification must be enabled")
        status, message = base.package_signature_check(package)
        require(status == 0, "RPM signature rejected for {}: {}".format(package.name, message))
    require(installed(rpm) == before, "Installed RPM state changed during preparation")
    # Recheck the SAME resolved object immediately before RPM check/test/apply.
    validate_transaction(base.transaction, before)
    report.data["transaction_started"] = True
    report.save("applying_transaction")
    history_id = base.do_transaction()
    report.data["dnf_history_id"] = history_id
    report.data["rollback"]["review_command"] = (
        "dnf --assumeno history undo {}".format(history_id) if history_id else None)
    after = installed(rpm)
    report.data["packages_after"] = sorted(after)
    report.data["added"] = sorted(after - before)
    report.data["removed"] = sorted(before - after)
    require(after == (before - old) | EXPECTED,
            "Post-check failed: installed RPM state differs from the approved result")
    report.save("checking_fresh_processes")
    report.data["checks"] = []
    for command in (["/usr/bin/curl", "--version"],
                    ["/usr/bin/dnf", "--cacheonly", "--noplugins", "--assumeno",
                     "--setopt=gpgcheck=True", "list", "--installed",
                     "curl.x86_64", "libcurl.x86_64", "libcurl-devel.x86_64"]):
        checked = subprocess.run(command, capture_output=True, text=True,
                                 errors="replace", timeout=90, check=False)
        report.data["checks"].append({"argv": command, "rc": checked.returncode,
                                     "stdout": checked.stdout[-20000:],
                                     "stderr": checked.stderr[-20000:]})
        require(checked.returncode == 0, "Post-update command failed: " + command[0])
    report.save("completed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--apply", action="store_true", help="apply the reviewed package update")
    parser.add_argument("--target-host", help="explicit expected local hostname")
    args = parser.parse_args(argv)
    if not args.apply or not args.target_host:
        parser.error("both --apply and --target-host are required; no packages were changed")
    report = Report(args.target_host)
    rpm = None
    base = None
    result = 1
    try:
        check_host(args.target_host)
        report.save("loading_system_dnf")
        import dnf
        import rpm as system_rpm
        rpm = system_rpm
        base = dnf.Base()
        execute(base, rpm, report)
        result = 0
    except (Exception, KeyboardInterrupt) as error:
        report.data["error"] = "{}: {}".format(type(error).__name__, error)
        if rpm is not None:
            try:
                report.data["packages_after"] = sorted(installed(rpm))
            except Exception as read_error:
                report.data["post_read_error"] = str(read_error)
        report.save("failed_review_required" if report.data["transaction_started"] else "stopped_before_apply")
    finally:
        if base is not None:
            try:
                base.close()
            except Exception as close_error:
                report.data["close_error"] = str(close_error)
                report.save("failed_review_required")
                result = 1
        report.file.close()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
