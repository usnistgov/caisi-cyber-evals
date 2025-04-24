# AISI Cyber Evaluations

This repository packages a few benchmarks and agents used by the [US AI Safety Institute](https://www.nist.gov/aisi)
for cyber capability evaluations of AI systems. It aims to provide a standard, user-friendly interface to running
agentic cyber benchmarks with the [Inspect evaluation framework](https://github.com/UKGovernmentBEIS/inspect_ai/).

The package currently includes 2 agents and 2 benchmarks.

## Integrated Benchmarks

### CVE-Bench
* Based on [CVE-Bench created by Yuxuan Zhu et al.](https://arxiv.org/pdf/2503.17332).
* AISI's modifications are largely around the Inspect integration and automated evaluation.
* This version of the benchmark has 7 tasks plus a dev tasks.
* The [upstream repository](https://github.com/uiuc-kang-lab/cve-bench) has 40 tasks.

### Cybench Benchmark
* This code is based off the public cybench fork maintained by the UK AI Safety Institute
[here](https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/cybench), originally
developed by Andy Zhang et al. [paper](https://arxiv.org/abs/2408.08926).
* AISI added original task descriptions, and updated system/task level prompts.
* AISI updated the benchmark to support running all samples within a single eval
(i.e., produce one .eval file instead of 40).

# Quickstart

1. Create a virtual environment in which to install ucb
Install uv per [its docs](https://docs.astral.sh/uv/getting-started/installation/), then
```bash
uv venv
source .venv/bin/activate
```

2. Install ucb:

```
uv sync
```

3. Configure variables for your run.

You should now create a `.env` file and add the relevant API keys to it.
It is highly recommend to use a container registry via `UCB_CONTAINER_REGISTRY` which can
point at a domain and a directory prefix, e.g., "gitlab.com/aisi/cyber/ucb/". This should
end with a trailing slash.

```bash
ucb init-env # Populate .env from a template
vim .env # Then fill it in manually
```

4. Build (or pull) containers

If you have previously pushed images to your container registry, you can skip building and simply
run `ucb pull` to download them.

Otherwise you'll need to build your images with `ucb build`. You can add a `--push` argument if you
want to push the images to a container registry, assuming you have set one up.

5. Launch Ghidra-as-a-Service (Gaas) container
```bash
ucb gaas
```

6. Confirm functionality by running a single task with a small budget:
```bash
inspect eval ucb/cybench --solver ucb/agent --model anthropic/claude-3-5-sonnet-20240620 --limit 1 --token-limit 2000
```

# Running evals

Ensure your GaaS server is running (e.g., with `docker ps`) if you haven't started it, launch it with `ucb gaas`.
GaaS will cache Ghidra projects and static analysis analysis results.
Once you've confirmed GaaS is running, you'll want to launch an eval with `inspect eval` or `inspect eval-set`
combined with the arguments described below.

## Benchmark and Agents

You should specify at least one benchmark to run, either `ucb/cybench` or `ucb/cvebench` as part of your inspect command.
Note you can put both in the command and the tasks from both benchmarks will be run, but this is currently incompatible
with the UCB solvers.

You should also specify a single agent with `--solver ucb/cybench_agent` or `--solver ucb/ctf_solver`. You MUST specify an
agent.

### General Inspect Arguments

* A model can be set with `--model=name`, for example `--model=openai/o3-mini-2025-01-31`. If using `eval-set`, multiple models
can be specified and should be separated by a comma, for example `--model=openai/o3-mini-2025-01-31,anthropic/claude-3-5-sonnet-20240620`
* The total number of tokens can be limited with `--token-limit X`.
* Reasoning effort can be set with `--reasoning-effort <low/medium/high>` for OpenAI reasoning models or `--reasoning-tokens X` for Anthropic reasoning models.
* Limit the amount of resources used on your system with `--max-samples`, `--max-tasks`, `--max-sandboxes`, and `--max-subprocesses`.
* A number of epochs can be set with `--epochs`, for example `--epochs 5`, default is 1.
* For other arguments refer to the [Inspect documentation](https://inspect.ai-safety-institute.org.uk/reference/inspect_ai.html#eval).


### Agent Configuration
You should specify an agent with `--solver <name>` where the name is either `ucb/ctf_agent` or `ucb/cvebench_agent`. The `cvebench_agent`
is simply a wrapper on the standard agent, paired with the task-specific graders for CVE bench tasks.

Agent behavior can be configured with the `-S` flag followed by a key-value pair with an equals sign, e.g., `-S key=value`.

* `sys_msg: str = CYBER_SYSTEM_MESSAGE`: System prompt. Customized by `cvebench_agent`.
* `use_ghidra_tool: bool = True`: if the Ghidra-based tools should be provided to the agent. Disabled by `cvebench_agent`.
* `max_submit_tool_calls: int = 10`: Maximum number of calls to submit tool. -1 for unlimited.
* `timeout int = 180`: Timeout for tool calls.

### Task-Level options
Task level options can also be configured with the `-T` flag.

Task options vary depending on the benchmark you select, but the `samples` option is valid for all benchmarks:

* `samples: Optional[List[str]]`: List of task names to include. Separate with commas (i.e., `-T samples=one,two`).
   You can select samples by name across benchmarks. If unset, all tasks will be selected from the specified benchmarks.

#### CVE-bench Task-Level Options:
These options will impact tasks from CVE-bench:

* `cve_details: bool = True`: Should the CVE text be made available.
* `target_details: bool = True`: Should the agent be given a copy of relevant files from the target.
* `writeup_details: bool = False`: Should the text of a technical writeup be made available.
* `dev_set: bool = False`: Should only development tasks be selected?


#### Cybench Task-level Options
These options will impact tasks from Cybench:

* `show_original_desc: bool = True`: Should the original CTF task description be shown to the model (in addition to the standard task description).

### Example Invocations:

```bash
inspect eval ucb/cvebench --model anthropic/claude-3-5-sonnet-20240620 --solver ucb/cvebench_agent --token-limit 100000
inspect eval ucb/cybench --model openai/o3-2025-04-16 -T samples=avatar,delulu --epochs 10 --solver ucb/ctf_agent --token-limit 150000
```

To run a large evaluation with high parallelism, we highly recommend using `inspect eval-set`, including the `--no-fail-on-error` flag, specifying
epochs, and setting `max-tasks` and `max-sandboxes` based on your system's resources. Note that `eval-set` needs a unique `log-dir` for each
evaluation you launch so it's typically important to set this as well instead of using the default `logs`. For example, an `eval-set`command
might look like:

```bash
inspect eval-set ucb/cvebench \
  --solver ucb/cvebench_agent \
  --model openai/o4-mini-2025-04-16 \
  --no-fail-on-error --epochs 4 \
	--max-tasks=20 --max-sandboxes=40 \
  --log-dir o4_mini_results \
  --token-limit 250000 \
  --working-limit 7200
```

Spurious failures (e.g., docker containers that failed to start) can then be addressed by rerunning the same command after it finishes -
`eval-set` will parse the existing logs and attempt to finish previously-failed tasks.

# Repository Structure
`src/ucb/containers/` contains generic containers used across tasks, for
example the container from which an agent will launch its attacks, and a
Ghidra-as-a-service (GaaS) container.

Benchmark information is stored in `src/ucb/benchmarks/` where each benchmark
has its files stored in a unique subfolder (e.g., `cybench`). Within each benchmark,
a subfolder exists for each unique task (e.g., CTF problem) and individual samples
are specified in `samples.yml`. Typically there is one sample per task, but multiple
samples can be defined in a given samples.yml file (e.g., changing a task description
or the files provided to a model). Within the task folder (e.g.,
`src/ucb/benchmarks/cybench/avatar`) there are two required files, in addition to
any challenge-specific files (e.g.  container files):

| File               | Description                                               |
|--------------------|-----------------------------------------------------------|
| `samples.yml`      | Details of the sample(s) (e.g. instructions and flag)     |
| `compose.yml`      | Docker Compose file which defines Docker infrastructure   |


The glue to parse samples is stored in `src/ucb/tasks/` which parses samples.yml files
and provides them to inspect.

Agents are implemented in `src/ucb/agents`.

## Adding new benchmarks and tasks
1. Create new directory within `src/ucb/samples/`
2. Add subfolders for each task, create required files, and task-specific containers
3. Update `src/ucb/inspect/task.py` to support generating tasks for your benchmark.


# Acknowledgements

This repository is largely a combination of existing open source projects with some new glue between them. The authors of the upstream projects
deserve significant credit for their effort!

## UK AI Security Institute
* Creators of [Inspect](https://github.com/UKGovernmentBEIS/inspect_ai/)
* Creators of [Inspect evals](https://github.com/UKGovernmentBEIS/inspect_evals/) which contains a Cybench fork we drew inspiration from.
* Creators of [Inspect cyber](https://github.com/UKGovernmentBEIS/inspect_cyber)

## Zhang et al.
Cybench authors. [Paper](https://arxiv.org/pdf/2408.08926). [Repo](https://github.com/andyzorigin/cybench).
Thanks to Andy K. Zhang, Neil Perry, Riya Dulepet, Joey Ji, Celeste Menders, Justin W. Lin, Eliot Jones, Gashon Hussein, Samantha Liu, Donovan Jasper, Pura Peetathawatchai, Ari Glenn, Vikram Sivashankar, Daniel Zamoshchin, Leo Glikbarg, Derek Askaryar, Mike Yang, Teddy Zhang, Rishi Alluri, Nathan Tran, Rinnara Sangpisit, Polycarpos Yiorkadjis, Kenny Osele, Gautham Raghupathi, Dan Boneh, Daniel E. Ho, Percy Liang

```
@misc{
  cybench
  title={Cybench: A framework for evaluating cybersecurity capabilities and risks of language models},
  author={Zhang, Andy K and Perry, Neil and Dulepet, Riya and Ji, Joey and Menders, Celeste and Lin, Justin W and Jones, Eliot and Hussein, Gashon and Liu, Samantha and Jasper, Donovan and others},
  year={2024},
  url={https://arxiv.org/abs/2408.08926}
}
```


## Zhu et al.
CVE-Bench authors. [Paper](https://arxiv.org/abs/2503.17332). [Repo](https://github.com/uiuc-kang-lab/cve-bench/blob/main/README.md).
Thanks to Yuxuan Zhu and Antony Kellermann and Dylan Bowman and Philip Li and Akul Gupta and Adarsh Danda and Richard Fang and Conner Jensen and Eric Ihli and Jason Benn and Jet Geronimo and Avi Dhir and Sudhit Rao and Kaicheng Yu and Twm Stone and Daniel Kang.

```
@misc{
    cvebench,
    title={CVE-Bench: A Benchmark for AI Agents’ Ability to Exploit Real-World Web Application Vulnerabilities},
    author={Yuxuan Zhu and Antony Kellermann and Dylan Bowman and Philip Li and Akul Gupta and Adarsh Danda and Richard Fang and Conner Jensen and Eric Ihli and Jason Benn and Jet Geronimo and Avi Dhir and Sudhit Rao and Kaicheng Yu and Twm Stone and Daniel Kang},
    year={2025},
    url={https://arxiv.org/abs/2503.17332}
}
```
