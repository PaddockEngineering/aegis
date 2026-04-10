#!/usr/bin/env python3
"""Docker security scanning module - Container image vulnerability detection."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error, log_warning
from utils.system import command_exists


def install():
    """Install Trivy for container image scanning."""
    log_info("Installing Trivy scanner...")

    try:
        # Check if already installed
        if command_exists("trivy"):
            log_success("Trivy is already installed")
            return True

        # Install Trivy from GitHub releases
        result = subprocess.run(
            ["apt-get", "install", "-y", "trivy"],
            capture_output=True,
            timeout=120
        )

        if result.returncode == 0:
            log_success("Trivy installed")
            return True
        else:
            # Fallback: install via curl from GitHub
            log_info("Installing Trivy from GitHub...")

            install_script = """
            sudo apt-get install -y wget apt-transport-https gnupg lsb-release
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update
            sudo apt-get install -y trivy
            """

            result = subprocess.run(
                ["bash", "-c", install_script],
                capture_output=True,
                timeout=180
            )

            if result.returncode != 0:
                log_warning("Trivy installation from GitHub failed, but package may still be available")
                return False

            log_success("Trivy installed from GitHub")
            return True

    except subprocess.TimeoutExpired:
        log_error("Trivy installation timed out")
        return False
    except Exception as e:
        log_error(f"Trivy installation failed: {e}")
        return False


def scan_image(image_name):
    """Scan a Docker image for vulnerabilities."""
    log_info(f"Scanning Docker image: {image_name}...")

    try:
        result = subprocess.run(
            ["trivy", "image", image_name],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            return result.stdout
        else:
            error_msg = result.stderr if result.stderr else "Unknown error"
            return f"Scan failed: {error_msg}"

    except subprocess.TimeoutExpired:
        return "Scan timed out (images may be large)"
    except Exception as e:
        return f"Scan error: {e}"


def scan_all_local_images():
    """Scan all locally cached Docker images."""
    log_info("Scanning all local Docker images...")

    try:
        # Get list of local images
        list_result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if list_result.returncode != 0:
            return "Unable to list Docker images (Docker daemon running?)"

        images = [img for img in list_result.stdout.split('\n') if img.strip()]

        if not images:
            return "No Docker images found"

        log_info(f"Found {len(images)} images, scanning...")

        # Scan each image
        results = []
        for image in images:
            log_info(f"  Scanning: {image}")

            result = subprocess.run(
                ["trivy", "image", "-q", image],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                results.append(f"{image}: OK")
            else:
                results.append(f"{image}: Issues found")

        return "\n".join(results)

    except Exception as e:
        return f"Scan error: {e}"


def check():
    """Check if Trivy is installed."""
    return command_exists("trivy")


def status():
    """Show Trivy status and database info."""
    try:
        result = subprocess.run(
            ["trivy", "version"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            return f"Trivy is installed ({version_line}). Scan images with: sudo aegis docker-scan <image:tag>"
        else:
            return "Trivy is installed but version check failed"

    except Exception as e:
        return f"Unable to check Trivy status: {e}"


def configure():
    """No configuration needed - Trivy is ready to use."""
    log_success("Trivy is ready for on-demand image scanning")
    return True
