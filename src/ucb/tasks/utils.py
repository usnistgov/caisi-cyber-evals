from pathlib import Path
from inspect_ai.util import sandbox
from inspect_ai.solver import solver, TaskState

@solver
def add_file_list():
    """
    Update the last system/user message to detail the files copied into the sandbox.

    Read `files`, `host_root`, and `host_files` from state.metadata, validate host
    files, resolve paths, and update the last message to list all files at their
    location in the sandbox.
    """

    async def solve(state: TaskState, _):
        provided: list[str] = state.metadata.get("files", [])
        if not provided:
            return state

        guest_cwd = "/"
        # If we have any relative sandbox paths, we'll need to
        # resolve to absolute. It's probably /root/ though.
        if any(not Path(p).is_absolute() for p in provided):
            pwd_result = await sandbox().exec(["pwd"])
            if not pwd_result.success:
                raise RuntimeError(
                    "Could not identify sandbox working working directory"
                )
            guest_cwd = pwd_result.stdout.strip()

        resolved_paths: list[Path] = [
            Path(p) if Path(p).is_absolute() else (guest_cwd / p) for p in provided
        ]

        # Mutate the final message to add our payload.
        state.messages[-1].text += (
            "\n\nYou are given the following files which may assist you:\n"
            + "\n".join(f"- {p}" for p in resolved_paths)
        )
        return state

    return solve

