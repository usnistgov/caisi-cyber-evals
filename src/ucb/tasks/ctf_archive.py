from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.scorer import includes, mean, stderr
from inspect_ai.dataset import Sample
from inspect_cyber.dataset import AgenticEvalDataset
from ucb.tasks.utils import add_file_list
from ucb.tasks.prompts import CTF_ARCHIVE_USER_PROMPT, CTF_ARCHIVE_FLAG_CHECK_PROMPT

PWN_YML = Path(__file__).parent.parent / "containers" / "pwn_college.yml"

# Challenge files should be owned by root. We need to add SUID bit
# Also populate /flag with the solution (owned by root, not readable without solving challenge)
# We update $PATH in .bash_profile so the login shell will source it - since the bash tool runs `login -c` it won't source ~/.bashrc, but it will source .bash_profile
SETUP = "chmod -R 4755 /challenge; echo '{flag}' > /flag; echo 'export PATH=/nix/var/nix/profiles/dojo-workspace/bin/:$PATH' >> /home/hacker/.bash_profile; {extra_setup}"

# TODO: normal setup infra is at https://github.com/pwncollege/dojo/blob/master/workspace/core/init.nix


@task
def ctf_archive(
    root: str | None = None,
    samples: str | list[str] | None = None,
    competitions: str | list[str] | None = None,
    shuffle: bool = False,
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
                continue

            sandbox_path = str(Path("/challenge") / f.relative_to(challenge_dir))
            files[sandbox_path] = str(f.resolve())

        flag_check_message = (
            CTF_ARCHIVE_FLAG_CHECK_PROMPT
            if any(["flagCheck" in str(x) for x in files.keys()])
            else ""
        )
        prompt = CTF_ARCHIVE_USER_PROMPT.format(
            instruction=task_description, flag_check_message=flag_check_message
        )

        sample = Sample(
            setup=SETUP.format(flag=flag, extra_setup=extra_setup or ""),
            id=sample_id,
            input=prompt,
            target=flag,
            sandbox=("docker", str(PWN_YML)),
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
        setup=[add_file_list()],
        dataset=dataset,
        scorer=[includes()],
        metrics=[mean(), stderr()],
    )
