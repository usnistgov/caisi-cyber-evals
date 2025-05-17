from shortuuid import uuid
from typing import Optional, List, Callable
from inspect_ai.agent import Agent, agent, react, AgentSubmit, AgentAttempts, AgentPrompt
from inspect_ai.tool import (
    bash_session,
    text_editor,
    think,
)

from .cyber_tools import (
    bash,
    python,
    cvebench_submit,
    give_up,
    list_functions,
    decompile,
    disassemble,
    get_callers,
    get_callees,
)

from .prompts import (
    CVEBENCH_INCORRECT_SUBMISSION,
    CYBENCH_SYSTEM_MESSAGE,
    CYBER_SYSTEM_MESSAGE,
    REASONING_INSTRUCTIONS,
    THINK_DESCRIPTION,
    INCORRECT_SUBMISSION,
)

from .utils import cvebench_grader, continue_method, _is_reasoning_model


def _make_tool_list(
    timeout=600,
    use_ghidra_tool=False,
    add_reasoning=True,
):
    """
    Helper to select and configure tools that will be made available to a model.
    """

    tools = [
        think(THINK_DESCRIPTION),  # No reasoning (intended)
        bash_session(timeout=timeout, wait_for_output=30),  # No reasoning arg (TODO)
        text_editor(timeout=60),  #  No reasoning arg (TODO)
        bash(max_timeout=timeout, add_reasoning=add_reasoning),
        python(max_timeout=timeout, add_reasoning=add_reasoning),
        give_up(
            3, add_reasoning=add_reasoning
        ),  # After 3 calls to this tool we will terminate
    ]

    if use_ghidra_tool:
        tools.extend(
            [
                decompile(timeout, add_reasoning=add_reasoning),
                disassemble(timeout, add_reasoning=add_reasoning),
                get_callers(timeout, add_reasoning=add_reasoning),
                get_callees(timeout, add_reasoning=add_reasoning),
                list_functions(timeout, add_reasoning=add_reasoning),
            ]
        )
    return tools


@agent
def cybench_agent(sys_msg: str = CYBENCH_SYSTEM_MESSAGE, **kwargs) -> Agent:
    """
    Cybench default solver.

    Uses the old Cybench-specific prompt for backwards compatability - but the
    generic agent prompt should also work well.
    """
    return agent(sys_msg=sys_msg, **kwargs)


@agent
def cvebench_agent(
    sys_msg: str = CYBER_SYSTEM_MESSAGE,
    reminder_msg: str = None,
    use_ghidra_tool: bool = False,
    **kwargs,
) -> Agent:
    """
    CVE-Bench specific agent.

    Args:
        sys_msg (str): Default system prompt. Default is CYBER_SYSTEM_MESSAGE.
        reminder_msg (str): Message to show between agent turns. Default is CVEBENCH_REMINDER_MESSAGE.
        use_ghidra_tool (bool): Give agent access to ghidra based program analysis tools. Default False.
    """

    return agent(
        sys_msg=sys_msg,
        reminder_msg=reminder_msg,
        use_ghidra_tool=use_ghidra_tool,
        submit=AgentSubmit(tool=cvebench_submit(), name="submit"),
        incorrect_msg=CVEBENCH_INCORRECT_SUBMISSION,
        early_stop_fns=[cvebench_grader],
        **kwargs,
    )


@agent
def agent(
    sys_msg: str = CYBER_SYSTEM_MESSAGE,
    reminder_msg: Optional[str] = None,
    use_ghidra_tool: bool = True,
    submit: AgentSubmit = AgentSubmit(),
    max_submit_tool_calls: int = 10,
    incorrect_msg: str = INCORRECT_SUBMISSION,
    timeout: int = 180,
    early_stop_fns: Optional[List[Callable]] = None,
    instance: str | None = uuid(),
) -> Agent:
    """
    Generic cyber agent.

    Args:
        sys_msg (str): Default system prompt. Default is CYBER_SYSTEM_MESSAGE defined inprompts.py.
        use_ghidra_tool (bool): Give agent access to ghidra based program analysis tools. Default False.
        submit (AgentSubmit): Submit tool to use, default is the standard submit tool.
        max_submit_tool_calls (int): Maximum number of allowed submissions with submit
            tool. Set to -1 for unlimited. Default 10.
        incorrect_msg (str): Message to show to agent after a failed submission.
        timeout (int): Default timeout for tool calls. Default 180.
        early_stop_fns (Optional[List[Callable]]): List of functions to be run between turns to check
            if termination condition has been met.
    """

    # TODO: dynamically detect reasoning models using inspect APIs
    reasoning_model = _is_reasoning_model()

    if not reasoning_model:
        sys_msg += "\n" + REASONING_INSTRUCTIONS

    tools = _make_tool_list(
        timeout=timeout,
        use_ghidra_tool=use_ghidra_tool,
        add_reasoning=True,  # XXX: Should we disable for reasoning models?
    )

    # We could configure this more to set an assistant message
    # to better handle multi-agent interactions? This is default when given str
    # prompt = AgentPrompt(sys_msg)

    # Normally warn about typos and retries. For cvebench talk about the grader
    if max_submit_tool_calls == -1:
        max_submit_tool_calls = 999  # "Unlimited"

    attempts = AgentAttempts(
        attempts=max_submit_tool_calls, incorrect_message=incorrect_msg
    )

    return react(
        name="ctf_agent",
        description="Expert at completing cybersecurity challenges.",
        prompt=AgentPrompt(
            instructions=sys_msg,
            assistant_prompt=""
        ),
        tools=tools,
        attempts=attempts,
        submit=submit,
        on_continue=continue_method(early_stop_fns, reminder_msg),
    )
