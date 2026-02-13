import argparse, json
from typing import Any

from summoner.client import SummonerClient
from summoner.protocol import Node, Move, Stay, Test, Event

import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.visionary import ClientFlowVisualizer


AGENT_ID = "VisionaryTestAgent"
viz = ClientFlowVisualizer(title=f"{AGENT_ID} Graph", port=8710)

client = SummonerClient(name=AGENT_ID)

client_flow = client.flow().activate()
client_flow.add_arrow_style(stem="-", brackets=("[", "]"), separator=",", tip=">")
Trigger = client_flow.triggers()

OBJECTS = {Node("A"), Node("B"), Node("C"), Node("D")}

# Multi-state snapshot
ACTIVE_NODES = {"A"}   # {"A","C"} etc.
ACTIVE_EDGES = set()  # {"ab1","bd2"} etc. (label tokens)


def wants(msg: Any, label: str) -> bool:
    """
    Minimal command taxonomy:
      - {"content": "ab1"}          triggers that label only
      - {"content": ["bc1","bd2"]}  triggers multiple labels, enabling branching
    """
    payload = msg.get("content") if isinstance(msg, dict) else msg

    if isinstance(payload, str):
        return payload.strip() == label

    if isinstance(payload, list):
        return label in [str(x).strip() for x in payload]

    return False


@client.upload_states()
async def upload_states(_: Any) -> list[Node]:
    nodes = [Node(x) for x in sorted(ACTIVE_NODES)]
    edges = [Node(x) for x in sorted(ACTIVE_EDGES)]
    viz.push_states(nodes + edges)
    return nodes


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


# Optional object handlers (not necessary, but harmless in tutorials)
@client.receive(route="A")
async def on_A(msg: Any) -> Event: 
    client.logger.info(msg)
    return Test(Trigger.ok)

@client.receive(route="B")
async def on_B(msg: Any) -> Event: 
    client.logger.info(msg)
    return Test(Trigger.ok)

@client.receive(route="C")
async def on_C(msg: Any) -> Event: 
    client.logger.info(msg)
    return Test(Trigger.ok)

@client.receive(route="D")
async def on_D(msg: Any) -> Event: 
    client.logger.info(msg)
    return Test(Trigger.ok)


# A -> B (two labeled arrows)
@client.receive(route="A --[ ab1 ]--> B")
async def ab1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ab1") else Stay(Trigger.ok)

@client.receive(route="A --[ ab2 ]--> B")
async def ab2(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ab2") else Stay(Trigger.ok)


# B -> C (two labeled arrows)
@client.receive(route="B --[ bc1 ]--> C")
async def bc1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "bc1") else Stay(Trigger.ok)

@client.receive(route="B --[ bc2 ]--> C")
async def bc2(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "bc2") else Stay(Trigger.ok)


# B -> D (two labeled arrows)
@client.receive(route="B --[ bd1 ]--> D")
async def bd1(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "bd1") else Stay(Trigger.ok)

@client.receive(route="B --[ bd2 ]--> D")
async def bd2(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "bd2") else Stay(Trigger.ok)


# C -> A, D -> A
@client.receive(route="C --[ ca ]--> A")
async def ca(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "ca") else Stay(Trigger.ok)

@client.receive(route="D --[ da ]--> A")
async def da(msg: Any) -> Event:
    return Move(Trigger.ok) if wants(msg, "da") else Stay(Trigger.ok)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a Summoner client with a specified config.")
    parser.add_argument('--config', dest='config_path', required=False, help='The relative path to the config file (JSON) for the client (e.g., --config configs/client_config.json)')
    args = parser.parse_args()

    # Start visual window (browser) and build graph from dna
    viz.attach_logger(client.logger)
    viz.start(open_browser=True)
    viz.set_graph_from_dna(json.loads(client.dna()), parse_route=client_flow.parse_route)
    viz.push_states([Node("A")])

    client.run(host = "127.0.0.1", port = 8888, config_path=args.config_path or "configs/client_config.json")
