from pathlib import Path
from typing import List, Optional
from inspect_ai.util import sandbox


async def get_guest_cwd() -> Path:
    """
    Ask the sandbox for its current working directory.
    """
    result = await sandbox().exec(["pwd"])
    if not result.success:
        raise RuntimeError(f"Failed to run pwd: {result}")
    return Path(result.stdout.strip())


def validate_host_files(root: Path, host_files: List[str]) -> None:
    """
    Verify that each of the given host_files (relative to `root`) actually exists.
    """
    for rel in host_files:
        full = root / rel
        if not full.exists():
            raise FileNotFoundError(f"Host file '{rel}' not found under '{root}'.")


async def resolve_path(guest_path: str, guest_cwd: Optional[Path]) -> Path:
    """
    Turn a guest_path (absolute or relative) into an absolute Path.
    Returns the new cwd if we had to fetch it.
    """
    if ":" in guest_path:
        raise NotImplementedError(f"Targets not supported: '{guest_path}'")

    # Already absolute?
    p = Path(guest_path)
    if p.is_absolute():
        return p, guest_cwd

    # Lazily fetch cwd
    if guest_cwd is None:
        guest_cwd = await get_guest_cwd()
    return guest_cwd / p, guest_cwd
