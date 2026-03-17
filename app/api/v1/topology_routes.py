from fastapi import APIRouter
from app.services.graph_service import GraphService

router = APIRouter()


# =====================================================
# NETWORK TOPOLOGY GRAPH (NEO4J)
# =====================================================

@router.get("/topology")
def get_topology():

    graph = GraphService()

    try:
        data = graph.get_topology()

        # Ensure frontend always gets valid format
        if not data:
            return {
                "nodes": [],
                "links": []
            }

        return data

    except Exception as e:
        return {
            "nodes": [],
            "links": [],
            "error": str(e)
        }

    finally:
        graph.close()