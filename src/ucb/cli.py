#!/usr/bin/env python3

import argparse
import glob
import importlib.resources
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
from ucb import version


# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

AGENT_NAME = "agent-environment:1.1.0"
GHIDRA_NAME = "gaas:1.0.1"


def run_command(command, cwd=None):
    """Run a command and exit on failure."""
    logger.info("Running command: %s", " ".join(command))
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        logger.error("Command failed: %s", " ".join(command))
        sys.exit(result.returncode)


def get_env_variable(var_name):
    """Load environment variable and exit if not found."""
    load_dotenv()
    value = os.getenv(var_name)
    if value is None:
        # Explicitly allowing empty string in this check
        logger.error("%s not set in environment.", var_name)
        sys.exit(1)
    return value


def build_core_containers(container_dir, image_base, push=True):
    """Build the core agent and ghidra containers in parallel and push them."""

    container_specs = [
        (
            image_base + AGENT_NAME,
            os.path.join(container_dir, "agent", "Dockerfile"),
            os.path.join(container_dir, "agent"),
        ),
        (
            image_base + GHIDRA_NAME,
            os.path.join(container_dir, "gaas", "Dockerfile"),
            os.path.join(container_dir, "gaas"),
        ),
    ]

    processes = []
    for tag, dockerfile, context in container_specs:
        cmd = ["docker", "build", "-t", tag, "-f", dockerfile, context]
        logger.info("Building container with tag %s", tag)
        proc = subprocess.Popen(cmd)
        processes.append((proc, tag))

    for proc, tag in processes:
        proc.wait()
        if proc.returncode != 0:
            logger.error("Build failed for %s", tag)
            sys.exit(proc.returncode)

    if push:
        for tag in [AGENT_NAME, GHIDRA_NAME]:
            run_command(["docker", "push", image_base + tag])


def build_challenge_images(challenges_dir, multithread=True):
    """
    Find all docker compose temporary files (compose.y*ml.tmp) in the challenges
    directory and run their build (with --push) commands in parallel.
    """
    pattern = os.path.join(challenges_dir, "**", "compose.y*ml.tmp")
    compose_files = glob.glob(pattern, recursive=True)
    if not compose_files:
        logger.warning("No compose files found in %s", challenges_dir)
        return

    if multithread:
        num_parallel = os.cpu_count() or 1
    else:
        num_parallel = 1

    def build_compose(compose_file):
        logger.debug("Processing compose file: %s", compose_file)
        cmd = ["docker", "compose", "-f", compose_file, "build", "--push"]
        result = subprocess.run(cmd)
        if result.returncode != 0:
            logger.error("Build failed for %s", compose_file)
        return result.returncode

    with ThreadPoolExecutor(max_workers=num_parallel) as executor:
        futures = {executor.submit(build_compose, cf): cf for cf in compose_files}
        for future in as_completed(futures):
            cf = futures[future]
            try:
                ret = future.result()
                if ret != 0:
                    logger.error("Error building %s", cf)
            except Exception as exc:
                logger.exception("Exception building %s: %s", cf, exc)


def extract_images_from_compose(compose_file):
    """
    Run 'docker compose -f <compose_file> config' and extract image names.
    Returns a set of image names.
    """
    images = set()
    logger.debug("Processing compose config for %s", compose_file)
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "config"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error("Error processing %s: %s", compose_file, e)
        return images

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("image:"):
            parts = line.split()
            if len(parts) >= 2:
                images.add(parts[1])
    return images


def extract_unique_images(root_dir):
    """
    Recursively find all compose files and extract unique image names.
    """
    pattern = os.path.join(root_dir, "**", "compose.y*ml")
    compose_files = glob.glob(pattern, recursive=True)
    all_images = set()
    for comp_file in compose_files:
        all_images.update(extract_images_from_compose(comp_file))
    return all_images


def push_image(image, image_base):
    """Push a docker image if it contains image_base."""
    if image_base in image:
        logger.info("Pushing image: %s", image)
        result = subprocess.run(["docker", "push", image])
        if result.returncode != 0:
            logger.error("Failed to push image: %s", image)
        return result.returncode
    else:
        logger.info("Skipping image (does not match base): %s", image)
        return 0


def push_images(images, image_base):
    """Push images in parallel using push_image."""
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(push_image, img, image_base): img for img in images}
        for future in as_completed(futures):
            img = futures[future]
            try:
                ret = future.result()
                if ret != 0:
                    logger.error("Error pushing image: %s", img)
            except Exception as exc:
                logger.exception("Exception pushing image %s: %s", img, exc)


def modify_compose_files(pattern):
    """
    Modify files matching the given pattern by uncommenting build/context lines.
    Returns a list of temporary file paths created.
    """
    tmp_files = []
    for filepath in glob.glob(pattern, recursive=True):
        if filepath.endswith(".tmp"):
            continue
        logger.debug("Modifying file %s", filepath)
        with open(filepath, "r") as f:
            content = f.read()
        content_new = content.replace(" #context:", " context:").replace(
            " #build:", " build:"
        )
        tmp_file = filepath + ".tmp"
        with open(tmp_file, "w") as f:
            f.write(content_new)
        tmp_files.append(tmp_file)
    return tmp_files


def cleanup_temp_files(pattern):
    """Cleanup temporary files matching pattern."""
    for filepath in glob.glob(pattern, recursive=True):
        if os.path.exists(filepath):
            logger.debug("Cleaning up temporary file %s", filepath)
            os.remove(filepath)


def pull_image(image):
    """Pull a docker image and report its status."""
    logger.info("Pulling image: %s", image)
    result = subprocess.run(["docker", "pull", image])
    if result.returncode != 0:
        logger.error("Failed to pull image: %s", image)
    return result.returncode


def build(args):
    """
    Entrypoint for building (and optionally pushing) container images.
    """

    challenges_dir = os.path.abspath(args.challenges_dir)
    container_dir = os.path.join(os.path.dirname(challenges_dir), "containers")

    image_base = get_env_variable("UCB_CONTAINER_REGISTRY")
    logger.info("Processing core images with docker image base = %s", image_base)

    # Build core containers and push if requested.
    #build_core_containers(container_dir, image_base, args.push)

    # Modify compose files (create temporary files with .tmp suffix)
    compose_pattern = os.path.join(challenges_dir, "**", "compose.y*")
    modify_compose_files(compose_pattern)

    # Build challenge images using modified compose files (which have .tmp extension)
    build_challenge_images(challenges_dir, multithread=args.multithread)
    logger.info("All containers built.")

    if args.push:
        logger.info("Pushing containers to registry: %s", image_base)
        # Collect unique container images from docker compose config output
        images = extract_unique_images(challenges_dir)
        logger.debug("Collected container images to push:")
        for img in sorted(images):
            logger.debug(img)

        # Push images that include IMAGE_BASE
        push_images(images, image_base)
        logger.info("All containers pushed to %s", image_base)

    # Cleanup temporary files
    cleanup_temp_files(compose_pattern + ".tmp")


def pull(args):
    """
    Entrypoint for pulling images.
    """

    challenges_dir = os.path.abspath(args.challenges_dir)

    image_base = get_env_variable("UCB_CONTAINER_REGISTRY")
    logger.info("Processing core images with docker image base = %s", image_base)

    # Extract unique images from all compose files.
    logger.info("Extracting unique image names from all compose files...")
    unique_images = extract_unique_images(challenges_dir)
    unique_images.update([image_base + AGENT_NAME, image_base + GHIDRA_NAME])

    logger.info("Identified %d unique images to pull", len(unique_images))
    logger.debug("Unique images found:")
    for image in sorted(unique_images):
        logger.debug(image)

    # Pull images in parallel.
    if args.multithread:
        num_workers = os.cpu_count() or 1
    else:
        num_workers = 1
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(pull_image, img): img for img in unique_images}
        for future in as_completed(futures):
            img = futures[future]
            try:
                ret = future.result()
                if ret != 0:
                    logger.error("Error pulling image: %s", img)
            except Exception as exc:
                logger.exception("Exception while pulling %s: %s", img, exc)

    logger.info("All containers pulled.")


def start_gaas(args):
    cache = Path.home() / ".gaas"
    cache.mkdir(exist_ok=True)
    run_command(
        [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{args.port}:5000",
            "-it",
            "-d",
            "-v",
            f"{cache}:/app/cache",
            (get_env_variable("UCB_CONTAINER_REGISTRY") or "") + GHIDRA_NAME,
        ]
    )


def env_init(args):
    # Determine the destination path in the current working directory
    dest = os.path.join(os.getcwd(), ".env")

    if os.path.isfile(dest) and not args.force:
        logger.error("Refusing to clobber existing .env. Run with --force if necessary")
        sys.exit(1)

    # Get the path to the resource file 'env.example' from the 'ucb' package.
    # Adjust the package/resource arguments as needed.
    with importlib.resources.path("ucb", "env.example") as src:
        # Copy the file from the resource path to the destination
        shutil.copy(src, dest)
        logger.info(f"Created {dest}. Be sure to populate the variables in the file!")


def main():
    with importlib.resources.path("ucb", "challenges") as src:
        default_challenges_dir = src

    # Global parser
    parser = argparse.ArgumentParser(
        description=f"Manage container images: build/push, pull, or GAAS.\n\nUCB version {version}"
    )
    parser.add_argument(
        "--challenges-dir",
        default=default_challenges_dir,
        help=f"Path to the challenges directory containing compose files (default: {default_challenges_dir})",
    )

    # Create subparsers for each subcommand
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Subcommand to run"
    )

    # Build subcommand
    parser_build = subparsers.add_parser("build", help="Build images")
    parser_build.add_argument(
        "--push",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Push the images to the container registry after building (default: False)",
    )
    parser_build.add_argument(
        "--multithread",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Execute build (and push) in parallel (default: True)",
    )

    # Pull subcommand
    parser_pull = subparsers.add_parser("pull", help="Pull images from the registry")
    parser_pull.add_argument(
        "--multithread",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pull images in parallel (default: True)",
    )

    # GAAS subcommand
    parser_gaas = subparsers.add_parser("gaas", help="Start Ghidra-as-a-service (GAAS)")
    parser_gaas.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port number to use for GAAS (default: 5000)",
    )

    # env-init subcommand
    parser_gaas = subparsers.add_parser("env-init", help="Initialize a .env file")
    parser_gaas.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Clobber an existing .env file (default: False)",
    )

    args = parser.parse_args()

    # Dispatch to the appropriate function based on the subcommand
    if args.command == "build":
        build(args)
    elif args.command == "pull":
        pull(args)
    elif args.command == "gaas":
        start_gaas(args)
    elif args.command == "env-init":
        env_init(args)


if __name__ == "__main__":
    main()
