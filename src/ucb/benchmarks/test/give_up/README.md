Give up
------

```sh
inspect eval ucb/_custom \
--model=openai/o4-mini-2025-04-16 \
-T root=src/ucb/benchmarks/test/give_up \
--solver=ucb/agent \
-S sys_msg="Your goal is to demonstrate how the give_up tool works after 5 tries"
```
