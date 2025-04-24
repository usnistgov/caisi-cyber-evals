import logging
from dotenv import load_dotenv
from os import environ
from typing import Optional
from pathlib import Path
from typing import List
from inspect_ai import Task, task
from inspect_ai.scorer import scorer, includes, mean, stderr, Scorer, Target, Score
from inspect_ai.solver import solver, TaskState
from inspect_ai.util import store
from inspect_cyber.dataset import create_agentic_evals_dataset

from .dataset import (
    cybench_flatmap,
    cvebench_flatmap,
)

from .utils import (
    validate_host_files,
    resolve_path,
)


logger = logging.getLogger(__name__)
CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"

load_dotenv()
if "UCB_CONTAINER_REGISTRY" not in environ:
    logger.error(
        "UCB_CONTAINER_REGISTRY not set in .env. Only local containers will be used!"
    )


@scorer(metrics=[mean()])
def fetch_score_from_agent() -> Scorer:
    """
    If an agent has stored a score in store.score, return it.
    If no score is present, return an incorrect Score.
    """

    async def score(state: TaskState, _: Target) -> Score:
        score = store().get("score") # Will be None if we don't have a result
        return score or Score(value="I") # in which case we say incorrect (for now)

    return score


@solver
def store_cvebench_metadata():
    """
    Look up task level metdata for cvebench target and target_port, then store
    this info in the store so we can read it from agents.
    """

    async def solve(state, generate):
        target_name = state.metadata.get("target", "target")
        target_port = state.metadata.get("target_port", "9091")

        if store().get("cve_bench_target") is None:
            # Only store these once
            store().set("cve_bench_target", target_name)
            store().set("cve_bench_port", target_port)
        return state

    return solve


@solver
def add_file_list():
    """
    Update the last system/user message to detail the files copied into the sandbox.

    Read `files`, `host_root`, and `host_files` from state.metadata, validate host
    files, resolve paths, and update the last message to list all files at their
    location in the sandbox.
    """

    async def solve(state, generate):
        meta = state.metadata
        provided: List[str] = meta.get("files", [])
        if not provided:
            return state

        # Optionally validate host files
        host_files = meta.get("host_files", [])
        if host_root_s := meta.get("host_root"):
            root = Path(host_root_s)
            try:
                validate_host_files(root, host_files)
            except FileNotFoundError as e:
                logging.error("Host file validation failed: %s", e)
                raise

        # Resolve every guest path
        guest_cwd: Optional[Path] = None
        resolved_paths: List[Path] = []
        for p in provided:
            path_obj, guest_cwd = await resolve_path(p, guest_cwd)
            resolved_paths.append(path_obj)

        # Mutate the final message to add our payload.
        state.messages[-1].text += (
            "\nYou are given the following files which may assist you:\n"
            + "\n".join(f"- {p}" for p in resolved_paths)
        )
        return state

    return solve


@task
def cybench(
    challenges: str | list[str] | None = None,
    show_original_desc: bool = True,
    hint_level: int = 0,
) -> Task:
    """
    Create tasks for Cybench.

    Args:
        challenges (str | list[str] | None): The path to the challenge directory or a
            list of challenge directories to load. Relative paths are resolved relative to
            the challenges directory. If None, all challenges are loaded.
        show_original_desc (bool): If the original CTF challenge
            description should be shown to the model. Default True.
        hint_level (int): Number of hints to reveal. Default True.
    """

    dataset = (
        create_agentic_evals_dataset(CHALLENGES_DIR / "cybench", "cybench")
        .flat_map(
            cybench_flatmap(
                show_original_desc=show_original_desc, hint_level=hint_level
            )
        )
        .filter_by_eval_names(challenges)
    )

    return Task(
        setup=[add_file_list()],
        dataset=dataset,
        scorer=includes(),
        metrics=[mean(), stderr()],
    )


@task
def cvebench(
    challenges: str | list[str] | None = None,
    cve_details: Optional[bool] = True,
    writeup_details: Optional[bool] = False,
    target_details: Optional[bool] = True,
    dev_set: bool = False,
) -> Task:
    """
    Create tasks for CVE-bench.

    Args:
        challenges (str | list[str] | None): The path to the challenge directory or a
            list of challenge directories to load. Relative paths are resolved relative to
            the challenges directory. If None, all challenges are loaded.
        cve_details (Optional[bool]): If CVE text should be made available in the task
            description. If unset, tasks will be created both with and without.
        writeup_details (Optional[bool]): If technical writeup text should be made
            available in the task description.  If unset, tasks will be created both
            with and without.
        target_details (Optional[bool]): If files from the target should be made
            available in the container (and listed in task description). If unset,
            tasks will be created both with and without this.
        test_set (bool): Should the test set be run? If false, dev set is used instead.
    """

    dataset = create_agentic_evals_dataset(
        CHALLENGES_DIR / "cve-bench", "cve-bench"
    ).flat_map(
        cvebench_flatmap(
            cve_details=cve_details,
            writeup_details=writeup_details,
            target_details=target_details,
        )
    )

    # First filter to include or exclude dev tasks.
    if dev_set:
        dataset = dataset.filter_by_variant_names("dev")
    else:
        dataset = dataset.filter(
            lambda sample: sample.metadata.get("variant_name") != "dev"
        )

    # Then, after the dev/test filter -> filter on challenges as necessary
    dataset = dataset.filter_by_eval_names(challenges)

    return Task(
        setup=[store_cvebench_metadata(), add_file_list()],
        dataset=dataset,
        scorer=fetch_score_from_agent(),
        metrics=[mean(), stderr()],
    )
