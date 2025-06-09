from inspect_ai.agent import Agent, agent, AgentSubmit
from .agents import agent as ucb_agent
from .cyber_tools import flag_check_tool
from .prompts import CTF_ARCHIVE_SYSTEM_MESSAGE


@agent
def ctf_archive_agent(
    sys_msg: str = CTF_ARCHIVE_SYSTEM_MESSAGE,
    reminder_msg: str = None,
    use_ghidra_tool: bool = False,
    **kwargs,
) -> Agent:
    """
    CTF Archive specific agent

    Configure tools to run as the "hacker" user with no venv

    Use sha256 as submit tool (to be paired with includes() scorer)

    Args:
        sys_msg (str): Default system prompt. Default is CYBER_SYSTEM_MESSAGE.
        reminder_msg (str): Message to show between agent turns. Default is CVEBENCH_REMINDER_MESSAGE.
        use_ghidra_tool (bool): Give agent access to ghidra based program analysis tools. Default False.
        timeout (int): Max time to allow commands to run for. Default 600.
        add_reasoning (bool): Should a required "reasoning" arg be added to tools when available? Default True.
    """

    return ucb_agent(
        sys_msg=sys_msg,
        reminder_msg=reminder_msg,
        use_ghidra_tool=use_ghidra_tool,
        agent_user="hacker",
        agent_venv=None,
        extra_tools=[flag_check_tool()],
        **kwargs,
    )
