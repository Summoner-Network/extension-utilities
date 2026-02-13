# Visionary: a client flow visualizer

> [!CAUTION]
> **Development vs composed SDK import path**
>
> The repo `extension-utilities` hosting this extension contains a test script at `tests/test_visionary/agent.py` that imports **Visionary** as `tooling.visionary...`, along with a small `sys.path` insertion so it can run directly inside the extension-template layout.
>
> In a composed SDK, the same module is imported as `summoner.visionary...`, and no `sys.path` insertion is needed.

Visionary is a lightweight browser visualizer for **Summoner client flow graphs**. It is meant to make your client’s control structure visible while it runs by showing three things at the same time:

* The **static graph** extracted from `client.dna()`, meaning nodes and labeled arrows.
* The **active snapshot** you provide at runtime, meaning a set of tokens that should be highlighted.
* A **live activity terminal**, meaning your Python logger output streamed into the page.

The implementation is intentionally small. On the Python side, you use one wrapper, `ClientFlowVisualizer`. On the web side, there are two assets, `viz.css` and `viz.js`, served by a tiny local HTTP server started by the wrapper.

## Canonical example you can run anytime

The hosting repo (namely `extension-utilities`) for this module ships a minimal working agent that demonstrates the module end-to-end:

```bash
python tests/test_visionary/agent.py
```

That script:

* defines a small flow graph with nodes and labeled arrows
* starts **Visionary** and opens a browser tab
* pushes active tokens (nodes and label tokens) so you can see highlighting
* streams the client logger into the web activity terminal

It is the reference demo for this README.

If you want to drive it interactively, start the InputAgent in another terminal and send labels like `ab1`, JSON like `["bc1","bd2"]`, or run the canned test sequence `/test.visionary` (see the InputAgent section below).

### How Visionary works

Visionary renders a graph and highlights tokens. It does not infer anything on its own.

* The graph comes from your client’s DNA. If the DNA has no routes, there is nothing to draw.
* Highlighting is based on string identity. If the token `"A"` is in your active list, node `A` lights up. If the token `"ab1"` is in your active list, the label pill `ab1` lights up.
* Logs appear only if you attach a logger.

Everything else is the mechanics of getting the right graph into the browser and pushing the right tokens over time.

## Quick reference

In this section, you will see a minimal setup that uses `ClientFlowVisualizer` to start the web UI, load a graph from your client’s DNA, highlight active tokens, and stream logs. The table below describes the main methods you will use and what each one is for.

### Public entry point

This module exposes a single public entry point: `ClientFlowVisualizer`. The following table briefly describes the methods exposed by this class.

### `ClientFlowVisualizer` methods at a glance

| Method                                             | What it does                                                                             | Key detail                                                                |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `start(open_browser=True)`                         | Starts a local `ThreadingHTTPServer` on `127.0.0.1:<port>` and optionally opens the page | Idempotent: calling it again does nothing if it is already started        |
| `set_graph_from_dna(dna, parse_route=None)`        | Extracts nodes and edges from DNA and stores them for the UI                             | If you pass `parse_route`, arrows and label pills are rendered reliably   |
| `push_states(states)`                              | Replaces the current active token snapshot served at `/state`                            | Accepts a dict, list/tuple, or a single token, and stringifies everything |
| `push_log(line)`                                   | Appends one log line to the terminal buffer                                              | Strips ANSI color codes and uses a ring buffer capped at `max_logs`       |
| `push_logs(lines)`                                 | Convenience wrapper to push multiple lines                                               | Accepts a list/tuple or a single value                                    |
| `attach_logger(logger, level=..., formatter=None)` | Adds a logging handler that mirrors records into the web terminal                        | Reuses the first existing logger handler formatter when available         |

## Getting started

The simplest way to use **Visionary** is to structure your code in two phases:

* First, define routes on a `SummonerClient` so that `client.dna()` contains a graph to draw.
* Then, start the visualizer, load that DNA-derived graph, and push an initial active token snapshot.

If you do not define any routes, your DNA may be empty, and the canvas will be empty even if you push states.

### Overall structure

Start from this mental outline:

```python
# imports and development import path

# initialize Summoner agent

# initialize flow and arrow syntax

# define receive and send routes

# initialize visualizer

# start visualizer, load DNA graph, push initial active tokens

# run the client
```

Each block below corresponds to one of those lines.

### Imports and development import path

```python
import argparse, json
from typing import Any

from summoner.client import SummonerClient
from summoner.protocol import Node, Move, Stay, Test, Event

import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.visionary import ClientFlowVisualizer
```

What this block gives you:

* `SummonerClient` to define an agent and connect it to a server.
* `Node`, `Move`, `Stay`, `Test`, `Event` to write handlers that return events and to represent tokens.
* `ClientFlowVisualizer` to start the web UI and publish the graph, state, and logs.

The `sys.path` insertion is only there for the extension-template development layout (so `tooling.*` imports resolve). In a composed SDK, you normally import the visualizer from `summoner.visionary`, and you do not need this path manipulation.

### Initialize the Summoner agent

```python
AGENT_ID = "VisionaryTestAgent"
client = SummonerClient(name=AGENT_ID)
```

This creates the client object where you will register routes. The routes you register are what eventually appear in `client.dna()`.

If you have not registered any routes yet, `client.dna()` may represent an empty graph. That is the main reason an initial canvas can be empty.

### Initialize the flow and arrow syntax

```python
client_flow = client.flow().activate()
client_flow.add_arrow_style(stem="-", brackets=("[", "]"), separator=",", tip=">")
Trigger = client_flow.triggers()
```

This block does two things:

* It creates a flow object associated with the client and activates the flow route language.
* It declares the arrow syntax you will use in route strings like `A --[ ab1 ]--> B`.

You will use `Trigger` inside handlers to construct events such as `Test(Trigger.ok)` or `Move(Trigger.ok)`.

A key practical point: when you later load DNA into **Visionary**, you pass `parse_route=client_flow.parse_route`. That means **Visionary** uses the same route parsing logic as your flow, so the graph is reconstructed in a stable way from the declarative route strings you registered.

### Multiple arrow styles in code, one normalized style in the visual

Summoner flows can accept multiple arrow syntaxes at the same time by declaring several styles:

```python
client_flow.add_arrow_style(stem="-", brackets=("[", "]"), separator=",", tip=">")
client_flow.add_arrow_style(stem="~", brackets=("[", "]"), separator=",", tip=">")
```

This allows mixed handler strings such as:

```python
@client.receive(route="A ~~[ ab1 ]~~> B")
async def ab1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ab1") else Stay(Trigger.ok)
```

and:

```python
@client.receive(route="B --[ bc1 ]--> C")
async def bc1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "bc1") else Stay(Trigger.ok)
```

Visionary does not try to interpret arrow glyphs itself. It uses the Summoner route parser you pass in `parse_route=client_flow.parse_route`, so the graph is extracted canonically from DNA and rendered in a single consistent visual style.

### Define receive and send routes

This is the part that creates the graph. Each `@client.receive(route="...")` you define becomes part of the DNA. **Visionary** draws whatever the DNA describes.

Start with one node-only route. This is the smallest possible proof that your graph is not empty:

```python
@client.receive(route="A")
async def on_A(_: Any) -> Event:
    return Test(Trigger.ok)
```

Once you add that, node `A` exists in DNA and the browser can draw it.

Then you can add more nodes in the same style:

```python
@client.receive(route="B")
async def on_B(_: Any) -> Event:
    return Test(Trigger.ok)
```

After nodes are visible, add arrow routes to create transitions and label tokens. For example:

```python
@client.receive(route="A --[ ab1 ]--> B")
async def ab1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ab1") else Stay(Trigger.ok)
```

This introduces:

* an edge from `A` to `B`
* a label token `ab1` that **Visionary** renders as a pill

If you add another route with the same endpoints but a different label, you get multiple pills on that edge:

```python
@client.receive(route="A --[ ab2 ]--> B")
async def ab2(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ab2") else Stay(Trigger.ok)
```

At this stage, the canvas should show nodes and arrows even before you do anything with active states.

### Initialize the visualizer

```python
viz = ClientFlowVisualizer(title=f"{AGENT_ID} Graph", port=8710)
```

This only constructs the wrapper. It does not start the server yet.

### Start the visualizer, load the graph, push initial active tokens

```python
viz.attach_logger(client.logger)
viz.start(open_browser=True)
viz.set_graph_from_dna(json.loads(client.dna()), parse_route=client_flow.parse_route)
viz.push_states([Node("A")])
```

Each line has a distinct role:

* `attach_logger(...)` connects your client’s logger to the activity terminal at the bottom of the page.
* `start(...)` launches a local HTTP server and serves the UI.
* `set_graph_from_dna(...)` publishes the extracted graph to the browser. This is what determines whether the canvas has nodes and edges.
* `push_states(...)` publishes the current active token snapshot. This affects only highlighting.

The most important distinction is between the last two lines:

* `set_graph_from_dna(...)` determines what exists to be drawn.
* `push_states(...)` determines what is lit up.

If you push `Node("A")` but `A` does not exist in the loaded graph, nothing lights up. If you never registered routes, then `A` also does not exist in DNA, so the canvas can be empty and highlighting will do nothing.

### Run the client

```python
client.run(host="127.0.0.1", port=8888, config_path=args.config_path or "configs/client_config.json")
```

This connects to the server and begins normal operation. The visualization page will keep polling for state and logs while the client runs.

## Driving the visualization at runtime

Once the browser page can draw your graph, the runtime story becomes simple: you control what lights up, you control what appears in the activity terminal, and you decide how to translate distributed state into a snapshot that is meaningful to inspect.

> [!NOTE]
> **Best practice:** publish the **Visionary** snapshot from the state management handlers.
>
> In other words, call `viz.push_states(...)` inside `@client.upload_states()` and `@client.download_states()`, and treat those two functions as the canonical place where the UI state is updated.

This matters because these two handlers are where your agent state is synchronized (or updated) through the state resolution layer. If you publish the visualization snapshot anywhere else, it is easy for the UI to drift from the post-resolution reality. If you push in both handlers, the UI stays aligned with what you believe locally (upload) and what you receive after merging (download).

### Highlighting tokens with `push_states`

The only runtime protocol for highlighting is:

```python
viz.push_states(...tokens...)
```

Think of `push_states` as "publish the current highlight set." It replaces the previous snapshot with whatever you provide. On the frontend, the page polls `/state` repeatedly and highlights tokens by string identity.

Everything is reduced to a string using `str(x).strip()`. This is why both of the following are equivalent from the UI’s perspective:

* `Node("A")`
* `"A"`

`push_states` is flexible about input shape. You can pass a single token, a list/tuple, or a dict whose values are tokens or lists of tokens. All values are flattened into one list of token strings.

Examples:

```python
viz.push_states(["A", "ab1"])
viz.push_states({"nodes": ["A", "C"], "labels": ["bc1"]})
viz.push_states("A")
```

### Concrete example with `upload_states` and `download_states`

A practical way to make **Visionary** track distributed state is to keep two sets in your agent: one for object-node tokens and one for label tokens, and then connect them to the state management handlers. The upload handler is where you publish what you currently believe; the download handler is where you receive the merged candidate set and decide how to update your local view.

In the example agent, the local state is held in:

* `ACTIVE_NODES`: a set of node tokens such as `{"A","B","C","D"}`
* `ACTIVE_EDGES`: a set of label tokens such as `{"ab1","bd2"}`
* `OBJECTS`: the universe of valid node objects, used to partition received tokens into nodes vs labels

The upload handler does two jobs at once. It returns a list of node objects to Summoner’s state resolution layer, and it pushes both nodes and labels into **Visionary** so the UI reflects the full snapshot you care about.

```python
@client.upload_states()
async def upload_states(_: Any) -> list[Node]:
    nodes = [Node(x) for x in sorted(ACTIVE_NODES)]
    edges = [Node(x) for x in sorted(ACTIVE_EDGES)]
    viz.push_states(nodes + edges)
    return nodes
```

A small but important detail is that the return value and the visualization payload do not have to match. Here, only the node objects are returned to the resolution layer, while the visualizer receives a richer snapshot that includes label tokens as well.

On the download side, the handler receives a merged candidate set `possible_states`. The code treats it as a bag of tokens and partitions it. Tokens that belong to `OBJECTS` are interpreted as object nodes, and everything else is interpreted as a label token. This makes the logic explicit and prevents labels from being accidentally interpreted as nodes.

```python
@client.download_states()
async def download_states(possible_states: list[Node]) -> None:
    ps = set(possible_states or [])
    nodes = sorted([str(n) for n in ps if str(n) not in ACTIVE_NODES and n in OBJECTS])
    edges = sorted([str(n) for n in ps if str(n) not in ACTIVE_EDGES and n not in OBJECTS])

    if nodes:
        ACTIVE_NODES.clear()
        ACTIVE_NODES.update(nodes)
    else:
        nodes = [n for n in ps if str(n) in ACTIVE_NODES and n in OBJECTS]

    ACTIVE_EDGES.clear()
    ACTIVE_EDGES.update(edges)

    viz.push_states(edges + nodes)
```

The update policy here is intentionally deterministic:

* If the merged snapshot contains any node tokens that differ from your current active nodes, it replaces `ACTIVE_NODES` with those.
* Otherwise, it keeps the current active node(s) (the `else` branch reconstructs `nodes` for the final visualization push).
* It always replaces `ACTIVE_EDGES` with the label tokens received.

Finally, it calls `viz.push_states(edges + nodes)` so the browser always reflects the post-merge view, including both the node-level state and the label-level intent.

If you later want branching behavior, the place to change it is the node update policy. Instead of clearing and replacing `ACTIVE_NODES`, you can union, apply priorities, or preserve multiple nodes at once. The visualizer does not constrain that choice; it only reflects the tokens you decide to publish.

### Running the demo with the InputAgent

The hosting repo `extension-utilities` includes a concrete working setup under `tests/test_visionary/agent.py`. The easiest way to understand the runtime loop is to run the three-process demo:

```bash
# terminal 1
python server.py

# terminal 2
python tests/test_visionary/agent.py

# terminal 3
python agents/agent_InputAgent/agent.py
```

Then, in the InputAgent terminal prompt, you can send commands that exercise the **Visionary** test agent:

* Send a single label token as a string:

  ```text
  > ab1
  ```

* Send several label tokens at once by typing JSON (the InputAgent parses JSON before sending):

  ```text
  > ["bc1","bd2"]
  ```

* Run the canned deterministic sequence:

  ```text
  > /test.visionary
  ```

As you send these, the **Visionary** page will keep polling `/state` and will highlight whatever snapshot the test agent publishes from its `upload_states` and `download_states` decorators. If you kept `viz.attach_logger(client.logger)` enabled in the test agent, you will also see the agent logs mirrored into the web activity terminal.

## Web UI behavior

### Frontend interaction model

The UI is built for quick inspection while your agent runs.

#### Interactions

| Action             | Effect               | Notes                             |
| ------------------ | -------------------- | --------------------------------- |
| Mouse drag         | Pan the view         | Moves the whole canvas viewport   |
| Mouse wheel        | Zoom the global view | Scales the full scene             |
| Ctrl + mouse wheel | Zoom a single column | A column corresponds to one layer |
| Double click       | Reset view           | Returns to the default framing    |

#### Rendering and highlighting model

| Concept                           | What it means in the UI                                                 | Practical implication                                                     |
| --------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Layered layout                    | Tokens are arranged into layers and drawn as separate columns           | The graph is visually structured by depth rather than as one flat cluster |
| Nodes start at the base layer     | Node tokens appear in the lowest layer                                  | Nodes anchor the layout                                                   |
| Label tokens occupy higher layers | Edge-label tokens (pills) appear above nodes in higher layers           | Labels are separated from nodes to stay readable                          |
| One column per layer              | Each layer `k` is rendered in its own vertical column                   | You can zoom a layer independently with Ctrl + wheel                      |
| Collision avoidance for labels    | Label pills try not to overlap                                          | Dense label sets remain legible without manual layout                     |
| Active token rule                 | A token is active if its string appears in the active set from `/state` | Highlighting is purely membership-based, with no inference                |

Final constraint: highlighting requires exact string identity after token stringification and whitespace stripping.

## Troubleshooting

* **Why is the canvas empty?**
  The visualizer can only draw what exists in `client.dna()`. If you have not registered any `@client.receive(...)` handlers, `client.dna()` may represent an empty graph, so Visionary has nothing to render. Add a node-only route such as `route="A"` to confirm the pipeline end-to-end.

* **Why does the graph render but nothing lights up?**
  Highlighting is driven only by what you publish with `viz.push_states(...)`. Loading the graph does not imply any active state. Make sure you are calling `viz.push_states(...)` at runtime with tokens you expect to be active.

* **Why do label pills not light up?**
  A label lights up only if the exact label token string you push matches a label token present in the loaded DNA graph. Check that you are pushing the exact token (for example, `"ab1"`), after the same whitespace-stripping behavior, and that the label actually exists in the graph you loaded.

* **Why is the activity terminal empty?**
  The web terminal is opt-in. You must call `viz.attach_logger(client.logger)` before emitting log lines; otherwise, nothing will be forwarded into the visualizer buffer.

## Imports in development and in the composed SDK

The template uses `tooling.visionary` plus a `sys.path` insertion. That setup is typical in an extension-template development context.

In a composed SDK, users should import:

```python
from summoner.visionary import ClientFlowVisualizer
```

In that environment, no `sys.path` insertion is needed.
