import logging
from dotenv import load_dotenv
from os import environ
from typing import Optional
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.scorer import scorer, includes, mean, stderr, Scorer, Target, Score
from inspect_ai.solver import solver, TaskState
from inspect_ai.util import store
from inspect_cyber.dataset import create_agentic_eval_dataset

from ucb.tasks.dataset import (
    cybench_flatmap,
    cvebench_flatmap,
)

from .utils import add_file_list

logger = logging.getLogger(__name__)
BENCHMARK_DIR = Path(__file__).parent.parent / "benchmarks"

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
        score = store().get("score")  # Will be None if we don't have a result
        return score or Score(value="I")  # in which case we say incorrect (for now)

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


@task
def cybench(
    samples: str | list[str] | None = None,
    show_original_desc: bool = True,
    hint_level: int = 0,
) -> Task:
    """
    Create tasks for Cybench.

    Args:
        samples (str | list[str] | None): A list of sample names to load. If None,
            all samples are loaded.
        show_original_desc (bool): If the original CTF challenge
            description should be shown to the model. Default True.
        hint_level (int): Number of hints to reveal. Default True.
    """

    dataset = (
        create_agentic_eval_dataset(BENCHMARK_DIR / "cybench", "cybench")
        .flat_map(
            cybench_flatmap(
                show_original_desc=show_original_desc, hint_level=hint_level
            )
        )
        .filter_by_metadata_field("eval_name", samples)
    )

    return Task(
        setup=[add_file_list()],
        dataset=dataset,
        scorer=includes(),
        metrics=[mean(), stderr()],
    )


@task
def cvebench(
    samples: str | list[str] | None = None,
    cve_details: Optional[bool] = True,
    writeup_details: Optional[bool] = False,
    target_details: Optional[bool] = True,
    dev_set: bool = False,
) -> Task:
    """
    Create tasks for CVE-bench.

    Args:
        samples (str | list[str] | None): A list of sample names to load. If None,
            all samples are loaded.
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

    dataset = create_agentic_eval_dataset(
        BENCHMARK_DIR / "cve-bench", "cve-bench"
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

    # Then, after the dev/test filter -> filter on sample as necessary
    dataset = dataset.filter_by_metadata_field("eval_name", samples)

    return Task(
        setup=[store_cvebench_metadata(), add_file_list()],
        dataset=dataset,
        scorer=fetch_score_from_agent(),
        metrics=[mean(), stderr()],
    )


@task
def _custom(
    root: str,
    samples: str | list[str] | None = None,
) -> Task:
    """
    Developer interface. Create samples directly from a directory. No
    fanout.

    Args:
        root (str): Path to directory from which samples.yaml files will be loaded.
        samples (str | list[str] | None): A list of sample names to load.
    """

    if not root:
        raise ValueError("Root dir must be set via -T root=...")

    dataset = create_agentic_eval_dataset(
        Path(root).absolute(), "custom"
    ).filter_by_metadata_field("eval_name", samples)

    return Task(
        setup=[add_file_list()],
        dataset=dataset,
        scorer=[includes()],  # Matching on includes won't stop the run!
        metrics=[mean(), stderr()],
    )
