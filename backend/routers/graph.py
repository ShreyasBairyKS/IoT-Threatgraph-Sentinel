"""
routers/graph.py - GET /graph endpoint.

Day 2+: serves from live GraphStore (populated via POST /ingest/graph).
Falls back to mock data when no P2 enrichment has arrived yet.
"""

from fastapi import APIRouter, HTTPException
from backend.contracts import GraphEnrichment
from backend.store import graph_store
from backend.mocks.mock_store import MOCK_GRAPH

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("", response_model=GraphEnrichment)
async def get_graph() -> GraphEnrichment:
    """
    Return the latest graph enrichment snapshot.
    Falls back to mock data when no P2 data has arrived yet.
    """
    live = await graph_store.get()
    return live if live else MOCK_GRAPH
