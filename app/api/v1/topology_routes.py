from fastapi import APIRouter, Query
from typing import Optional
from app.services.graph_service import GraphService

router = APIRouter()

# Reusable graph service (Neo4j)
graph_service = GraphService()


# =====================================================
# NETWORK TOPOLOGY GRAPH (DOMAIN BASED)
# =====================================================

@router.get("/topology")
def get_topology(domain: Optional[str] = Query(None)):

    """
    Fetch topology graph
    - If domain is provided → return only that domain graph
    - Else → return full graph (fallback)
    """

    try:

        # 🔥 IMPORTANT: pass domain to service
        data = graph_service.get_topology(domain=domain)

        if not data:
            return {
                "nodes": [],
                "edges": []
            }

        return {
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", [])
        }

    except Exception as e:

        return {
            "nodes": [],
            "edges": [],
            "error": str(e)
        }