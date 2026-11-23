"""Rebind an atomic public-reference policy in one admitted test container.

Single-file Docker bind mounts retain the old inode after os.replace(). Only
this newly allocated fixture's exact native Issuance container may restart;
the product image, registered owners, database and other workloads stay intact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import time
from pathlib import Path

TARGET = "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json"
INSPECT = ("{{json .Config.Image}}\n{{json .Config.Labels}}\n{{json .Mounts}}\n"
           "{{json .Config.User}}\n{{.State.Running}}\n"
           "{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}")
DEADLINE = 0.0


class PolicyReloadError(ValueError):
    """A closed, credential-free failure label from this controller."""


def signal_group(group: int, signum: int) -> bool:
    try:
        os.killpg(group, signum)
    except ProcessLookupError:
        return False
    return True


def retire_group(process: subprocess.Popen[str]) -> None:
    for signum, seconds in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
        if not signal_group(process.pid, signum):
            process.wait(timeout=1)
            return
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            process.poll()
            if not signal_group(process.pid, 0):
                process.wait(timeout=1)
                return
            time.sleep(0.02)
    raise PolicyReloadError("owned policy CLI group did not retire")


def docker(*arguments: str, timeout: int = 20) -> str:
    remaining = min(timeout, DEADLINE - time.monotonic())
    if remaining <= 0:
        raise PolicyReloadError("owned policy overall deadline")
    process = subprocess.Popen(["docker", *arguments], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise PolicyReloadError("owned policy overall deadline") from None
    finally:
        # This group belongs only to this one CLI invocation, including an SSH
        # transport child. Never let a timed-out helper leave it behind.
        retire_group(process)
    if process.returncode:
        raise PolicyReloadError("owned policy Docker operation failed")
    return output.strip()


def refresh(owner_file: Path, policy_file: Path, digest: str) -> None:
    global DEADLINE
    # Caller permits100s. All CLI/readiness work shares80s, plus at most3s
    # termination/collection on the one failing CLI operation.
    DEADLINE = time.monotonic() + 80
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise PolicyReloadError("invalid policy digest")
    for path, private in ((owner_file, True), (policy_file, False)):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_size > 128 * 1024 or (private and info.st_mode & 0o077)):
            raise PolicyReloadError("unsafe owned policy input")
    owner = json.loads(owner_file.read_text(encoding="utf-8"))
    run_id = owner.get("run_id", "")
    if (owner.get("schema") != "elevenid.disposable-project-ownership/v1"
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", run_id)):
        raise PolicyReloadError("invalid policy project ownership")
    project = f"marty-conformance-{run_id}"
    if owner.get("projects") != [project, f"{project}-trust-registry"]:
        raise PolicyReloadError("policy project ownership mismatch")
    if json.loads(docker("info", "--format", "{{json .ID}}")) != owner.get("engine_id"):
        raise PolicyReloadError("policy Engine differs from admitted owner")
    image = owner["cleanup_environment"]["MARTY_SERVICES_IMAGE"]
    if not isinstance(image, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
        raise PolicyReloadError("policy image is not the admitted artifact")
    if hashlib.sha256(policy_file.read_bytes()).hexdigest() != digest:
        raise PolicyReloadError("policy changed before reload")
    containers = docker("ps", "-q", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}",
                        "--filter", "label=com.docker.compose.service=issuance-native").splitlines()
    if len(containers) != 1 or not re.fullmatch(r"[0-9a-f]{64}", containers[0]):
        raise PolicyReloadError("one owned native Issuance container is required")
    container = containers[0]

    def check() -> str:
        lines = docker("inspect", "--format", INSPECT, container).splitlines()
        if len(lines) != 6:
            raise PolicyReloadError("invalid owned container observation")
        actual_image, labels, mounts, user = (json.loads(line) for line in lines[:4])
        if (actual_image != image or labels.get("com.docker.compose.project") != project
                or labels.get("com.docker.compose.service") != "issuance-native"
                or user != "10001:10001" or lines[4] != "true"):
            raise PolicyReloadError("owned native container binding changed")
        selected = [mount for mount in mounts if mount.get("Destination") == TARGET]
        if (len(selected) != 1 or selected[0].get("RW") is not False
                or selected[0].get("Type") != "bind"
                or selected[0].get("Source") != str(policy_file.resolve())):
            raise PolicyReloadError("owned policy mount binding changed")
        return lines[5]

    check()
    # No other container/service ID or command is accepted from the caller.
    docker("restart", "--time", "10", container, timeout=45)
    deadline = time.monotonic() + 45
    while check() != "healthy":
        if time.monotonic() >= deadline:
            raise PolicyReloadError("owned native Issuance readiness deadline")
        time.sleep(0.25)
    observed = docker("exec", container, "sha256sum", TARGET).split()
    if (not observed or observed[0] != digest
            or hashlib.sha256(policy_file.read_bytes()).hexdigest() != digest):
        raise PolicyReloadError("atomic policy did not reach the owned container")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        refresh(args.owner, args.policy, args.sha256)
    except PolicyReloadError as error:
        print(f"Owned DIDComm policy reload failed: {error}")
        return 1
    except Exception:
        # Never copy Docker errors, environment or policy data into CI logs.
        print("Owned DIDComm policy reload failed")
        return 1
    print("Owned DIDComm policy rebind and readiness verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
