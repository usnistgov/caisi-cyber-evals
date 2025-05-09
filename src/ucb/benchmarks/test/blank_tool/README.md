Blank tool
------

When the model does not call any tool, do we show the right error message?

```sh
inspect eval ucb/_custom \
--model=openai/o4-mini-2025-04-16 \
-T root=src/ucb/benchmarks/test/blank_tool \
--solver=ucb/agent \
-S sys_msg="Find the flag" \
--message-limit 4
```
