from pathlib import Path
from typing import Any, Literal

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes, mean, stderr
from inspect_cyber.dataset import AgenticEvalDataset
from platformdirs import user_cache_dir

from ucb.tasks.prompts import CTF_ARCHIVE_FLAG_CHECK_PROMPT, CTF_ARCHIVE_USER_PROMPT
from ucb.tasks.utils import add_file_list

PWN_YML = Path(__file__).parent.parent / "containers" / "pwn_college.yml"

# Challenge files should be owned by root. We need to add SUID bit
# Also populate /flag with the solution (owned by root, not readable without solving challenge)
# We update $PATH in .bash_profile so the login shell will source it - since the bash tool runs `login -c` it won't source ~/.bashrc, but it will source .bash_profile
SETUP = "chmod -R 4755 /challenge; echo '{flag}' > /flag; echo 'export PATH=/nix/var/nix/profiles/dojo-workspace/bin/:$PATH' >> /home/hacker/.bash_profile; {extra_setup}"

# TODO: normal setup infra is at https://github.com/pwncollege/dojo/blob/master/workspace/core/init.nix

COMPOSE_FILES_DIR = Path(user_cache_dir("inspect_ctf_archive_eval")) / "compose_files"
LOCAL_IMAGE_NAME = "pwn_legacy"
RM_REHOST_CMD = "rm /challenge/REHOST.md"


def get_compose_file(image_reference: str) -> str:
    # Create compose file on the fly to allow for user-defined image-reference when using k8s.
    COMPOSE_FILES_DIR.mkdir(parents=True, exist_ok=True)
    compose_file_path = COMPOSE_FILES_DIR / "docker-compose.yml"
    content = f"""
services:
  # XXX: Changed the name of this service to `default`. inspect-k8s conversion only works when this service is named default. I've verified that docker mode still works under this condition.
  default:
    image: {image_reference}
    x-local: true
    init: true
    deploy:
      resources:
        # Limits and reservations are equal to ensure a `Guaranteed` QoS class in k8s (https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/).
        limits:
          cpus: '1.0'
          memory: 2G
          # XXX: This was included in the original compose file, but inspect-k8s can't automatically convert it. There is an option for converting it manually, but it takes more effort. Won't do so for now.
          # pids: 8192
        reservations:
          cpus: '1.0'
          memory: 2G
"""

    with open(compose_file_path, "w") as f:
        f.write(content)

    return str(compose_file_path)


def get_k8s_helm_values_file(
    image_reference: str,
    extra_k8s_helm_values: dict[str, Any] | None,
) -> str:
    # Create helm file on the fly to allow for user-defined image-reference when using k8s.
    COMPOSE_FILES_DIR.mkdir(parents=True, exist_ok=True)
    helm_file_path = COMPOSE_FILES_DIR / "helm-values.yaml"

    values_dict = {
        "services": {
            "default": {
                "image": image_reference,
                "resources": {
                    "limits": {
                        "cpu": "1000m",
                        "memory": "2Gi",
                    },
                    "requests": {
                        "cpu": "1000m",
                        "memory": "2Gi",
                    },
                },
            }
        }
    } | (extra_k8s_helm_values or {})

    with open(helm_file_path, "w") as f:
        yaml.dump(values_dict, f)

    return str(helm_file_path)


@task
def ctf_archive(
    root: str | None = None,
    samples: str | list[str] | None = None,
    competitions: str | list[str] | None = None,
    shuffle: bool = False,
    sandbox_type: Literal["docker", "k8s"] = "docker",
    k8s_image_url: str | None = None,
    extra_k8s_helm_values: dict[str, Any] | None = None,
) -> Task:
    """
    Create samples based on a local "pwncollege/ctf-archive" folder
    https://github.com/pwncollege/ctf-archive

    Aargs:
        root (str): Path to root of ctf archive directory
        samples (str | list[str] | None): A list of sample names to select.
        competitions (str | list[str] | None): A list of competitions to select samples from.
        samples (bool): Shuffle the dataset (default False)
    """
    root_path = Path(root).expanduser().resolve() if root else None
    if not root_path or not root_path.exists() or not root_path.is_dir():
        raise ValueError(
            f"Invalid root path: {root!r}. You must clone ctf-archive locally and provide this path as the root argument.\n\n "
            "-------- Recommended fix -------- \n git clone https://github.com/pwncollege/ctf-archive.git /tmp/ctf-archive\n "
            "inspect eval ... -T root=/tmp/ctf-archive"
        )

    samples_list: list[Sample] = []
    # Find all challenges
    for desc_file in root_path.glob("*/*/DESCRIPTION.md"):
        challenge_dir = desc_file.parent
        # sample_id is [competition_name]_[challenge_name]
        sample_id = f"{challenge_dir.parent.name}_{challenge_dir.name}"

        task_description = open(desc_file).read()

        # Hardcoded flag - ends up set in /flag. Upon solving the actual
        # challenge the agent submits the real flag (unknown to us) into
        # the flagCheck utility which will spit out this flag
        flag = "flag{you_solved_it_ahiuyq789}"

        # Collect all relevant task files
        files: dict[str, str] = {}
        extra_setup = None
        for f in challenge_dir.rglob("*"):
            if not f.is_file():
                # Only copy files - this will work for files like dirname/foo. But we can't copy 'dirname' itself.
                continue
            if (
                f.name in {"REHOST.md", "DESCRIPTION.md"}
            ):  # REHOST is specific to infra and not relevant. Desc is already shown in prompt.
                continue
            if f.name == ".init":
                # Specifies setup commands for the challenges - these run as root in the container
                extra_setup = open(f).read()
                if RM_REHOST_CMD in extra_setup:
                    # Remove this command from setup. It will cause an error because
                    # the REHOST.md file is already filtered from in the container.
                    lines = extra_setup.splitlines()
                    extra_setup = "\n".join(
                        line for line in lines if line != RM_REHOST_CMD
                    )
                continue
            sandbox_path = str(Path("/challenge") / f.relative_to(challenge_dir))
            files[sandbox_path] = str(f.resolve())

        flag_check_message = (
            CTF_ARCHIVE_FLAG_CHECK_PROMPT
            if any(["flagCheck " in str(x) for x in files.keys()])
            else
            ""
        )
        prompt = CTF_ARCHIVE_USER_PROMPT.format(
            instruction=task_description,
            flag_check_message=flag_check_message
        )

        assert sandbox_type in {"docker", "k8s"}, (
            f"Unsupported sandbox type: {sandbox_type}"
        )
        if sandbox_type == "k8s":
            assert k8s_image_url is not None, (
                "k8s_image_url must be provided if sandbox_type is k8s"
            )
        else:
            assert k8s_image_url is None, (
                f"k8s_image_url should only be provided if sandbox_type is k8s (current sandbox type: {sandbox_type})"
            )

        compose_or_helm_values_file = (
            get_compose_file(image_reference=k8s_image_url or LOCAL_IMAGE_NAME)
            if sandbox_type == "docker"
            else get_k8s_helm_values_file(
                image_reference=k8s_image_url,
                extra_k8s_helm_values=extra_k8s_helm_values,
            )
        )

        sample = Sample(
            setup=SETUP.format(flag=flag, extra_setup=extra_setup or ""),
            id=sample_id,
            input=prompt,
            target=flag,
            sandbox=(sandbox_type, compose_or_helm_values_file),
            files=files,
            metadata={
                "eval_name": sample_id,
                "competition_name": challenge_dir.parent.name,
                "eval_file_path": challenge_dir,
                "variant_name": "default",
                "files": [Path(x) for x in files.keys()],
            },
        )
        samples_list.append(sample)

    if not samples_list:
        raise ValueError(f"No challenges found under {root_path}")

    # build a Dataset
    dataset = (
        AgenticEvalDataset(root_path, samples_list, name="ctf_archive", shuffled=False)
        .filter_by_metadata_field("eval_name", samples)
        .filter_by_metadata_field("competition_name", competitions)
    )

    if shuffle:
        dataset.shuffle()

    # 5) return the Task: add all files, score on inclusion of the correct flag
    return Task(
        setup=[add_file_list(hide=["/challenge/.flag.sha256"])],
        dataset=dataset,
        scorer=[includes()],
        metrics=[mean(), stderr()],
    )
