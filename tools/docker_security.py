#!/usr/bin/env python3
"""Docker security scanning module - Container image vulnerability detection via Trivy."""

import subprocess
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package, update_package_list
from utils.system import command_exists


TRIVY_KEYRING = Path("/usr/share/keyrings/trivy.gpg")
TRIVY_SOURCES = Path("/etc/apt/sources.list.d/trivy.list")


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command safely; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def _setup_trivy_repo() -> bool:
    """
    Add the Aqua Security apt repository for Trivy.
    Each step runs as a separate, non-shell subprocess — no sudo inside root.
    """
    log_info("Setting up Trivy apt repository...")

    try:
        # 1. Install prerequisites
        if not install_package("wget apt-transport-https gnupg"):
            log_warning("Failed to install Trivy repo prerequisites")
            return False

        # 2. Download and dearmor the GPG key
        key_url = "https://aquasecurity.github.io/trivy-repo/deb/public.key"
        wget_result = _run(
            ["wget", "-qO", "-", key_url],
            timeout=30,
        )
        if wget_result.returncode != 0:
            log_warning(f"Failed to download Trivy GPG key: {wget_result.stderr.strip()}")
            return False

        # 3. Write dearmored key to keyring
        TRIVY_KEYRING.parent.mkdir(parents=True, exist_ok=True)
        dearmor = subprocess.run(
            ["gpg", "--dearmor"],
            input=wget_result.stdout,
            capture_output=True,
            timeout=10,
        )
        if dearmor.returncode != 0:
            log_warning(f"gpg --dearmor failed: {dearmor.stderr.decode().strip()}")
            return False
        TRIVY_KEYRING.write_bytes(dearmor.stdout)
        TRIVY_KEYRING.chmod(0o644)

        # 4. Detect codename for the sources entry
        codename_result = _run(["lsb_release", "-sc"], timeout=5)
        codename = codename_result.stdout.strip() if codename_result.returncode == 0 else "noble"

        # 5. Write sources list
        TRIVY_SOURCES.write_text(
            f"deb [signed-by={TRIVY_KEYRING}] "
            f"https://aquasecurity.github.io/trivy-repo/deb {codename} main\n",
            encoding="utf-8",
        )
        TRIVY_SOURCES.chmod(0o644)

        log_success("Trivy apt repository added")
        return True

    except Exception as e:
        log_error(f"Failed to set up Trivy repository: {e}")
        return False


def install() -> bool:
    """
    Install Trivy for container image scanning.

    Tries apt first (in case Trivy is already in the distro repos),
    then falls back to adding the official Aqua Security repo.
    """
    if command_exists("trivy"):
        log_success("Trivy is already installed")
        return True

    log_info("Installing Trivy scanner...")

    # Fast path: already in apt cache (some distros include it)
    result = _run(["apt-get", "install", "-y", "trivy"], timeout=120)
    if result.returncode == 0:
        log_success("Trivy installed from system repos")
        return True

    # Slower path: add the official upstream repo
    log_info("Trivy not in system repos — adding Aqua Security repository...")
    if not _setup_trivy_repo():
        log_error("Could not add Trivy repository — please install manually")
        return False

    if not update_package_list():
        log_warning("apt-get update failed after adding Trivy repo")

    if not install_package("trivy"):
        log_error("Failed to install Trivy after adding repository")
        return False

    log_success("Trivy installed from Aqua Security repository")
    return True


def scan_image(image_name: str) -> str:
    """Scan a Docker image for vulnerabilities."""
    log_info(f"Scanning Docker image: {image_name}...")

    try:
        result = _run(
            ["trivy", "image", image_name],
            timeout=300,
        )
        if result.returncode == 0:
            return result.stdout
        error_msg = result.stderr.strip() or "unknown error"
        return f"Scan failed: {error_msg}"

    except subprocess.TimeoutExpired:
        return "Scan timed out (image may be large)"
    except Exception as e:
        return f"Scan error: {e}"


def scan_all_local_images() -> str:
    """Scan all locally cached Docker images."""
    if not command_exists("docker"):
        return "Docker is not installed — no images to scan"

    log_info("Scanning all local Docker images...")

    try:
        list_result = _run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            timeout=30,
        )
        if list_result.returncode != 0:
            return "Unable to list Docker images — is the Docker daemon running?"

        images = [img for img in list_result.stdout.splitlines() if img.strip()]
        if not images:
            return "No Docker images found"

        log_info(f"Found {len(images)} image(s), scanning...")
        results = []
        for image in images:
            log_info(f"  Scanning: {image}")
            result = _run(["trivy", "image", "-q", image], timeout=300)
            results.append(f"{image}: {'OK' if result.returncode == 0 else 'issues found'}")

        return "\n".join(results)

    except Exception as e:
        return f"Scan error: {e}"


def configure() -> bool:
    """No daemon configuration needed — Trivy is an on-demand scanner."""
    log_success("Trivy is ready for on-demand image scanning")
    log_info("Usage: trivy image <image:tag>")
    return True


def check() -> bool:
    """Check if Trivy is installed."""
    return command_exists("trivy")


def status() -> str:
    """Show Trivy version and Docker availability."""
    parts = []

    result = _run(["trivy", "version"], timeout=10)
    if result.returncode == 0:
        version_line = result.stdout.splitlines()[0]
        parts.append(f"Trivy: {version_line}")
    else:
        parts.append("Trivy: not installed")

    docker_ok = command_exists("docker")
    parts.append(f"Docker CLI: {'available' if docker_ok else 'not found'}")

    return "\n".join(parts)
