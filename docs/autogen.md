# AutoGen (AgentChat)

Tenuo can protect tools used by [AutoGen AgentChat](https://microsoft.github.io/autogen/stable//index.html) so that **every tool call is authorized** by a warrant.

> AutoGen AgentChat requires **Python ≥ 3.10**.

## Installation

```bash
pip install "tenuo[autogen]"
```

## Minimal example (guarded tool)

```python
import asyncio

from tenuo import Pattern, SigningKey, Warrant
from tenuo.autogen import guard_tool


def search(query: str) -> str:
    return f"Results for: {query}"


async def main() -> None:
    # Only allow queries that match "safe*"
    key = SigningKey.generate()
    warrant = Warrant.mint_builder().tools(["search"]).constraint("query", Pattern("safe*")).ttl(3600).mint(key)
    bound = warrant.bind(key)

    guarded_search = guard_tool(search, bound, tool_name="search")

    # AutoGen AgentChat
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    agent = AssistantAgent(
        "assistant",
        OpenAIChatCompletionClient(model="gpt-4o"),
        tools=[guarded_search],
    )

    print(await agent.run(task="Use search with query 'safe weather NYC' and summarize the result."))
    print(await agent.run(task="Use search with query 'stocks AAPL' and summarize the result."))


asyncio.run(main())
```

## What happens on denial?

- If the tool name is not in `warrant.tools`, Tenuo raises `ToolNotAuthorized`.
- If arguments violate constraints (e.g. query not matching `Pattern("safe*")`), Tenuo raises `AuthorizationDenied` with a diff-style explanation and a debugging suggestion from `why_denied()`.

## See also

- [Quickstart](./quickstart)
- [Debugging](./debugging)

