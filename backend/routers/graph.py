"""
routers/graph.py - GET /graph endpoint.

Returns current graph enrichment payload from P2.
Day 1: returns mock data. Day 3: wires to real graph-worker output.
"""

from fastapi import APIRouter
from backend.contracts import GraphEnrichment
from backend.mocks.mock_store import MOCK_GRAPH

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("", response_model=GraphEnrichment)
async def get_graph() -> GraphEnrichment:
    """
    Return the latest graph enrichment snapshot including propagation
    risk, attack paths, next-target predictions, and MITRE tags.
    """
    return MOCK_GRAPH
