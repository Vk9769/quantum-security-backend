# app/db/neo4j.py

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Neo4jConnection:

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")

        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, self.password)
        )

    def close(self):
        if self.driver is not None:
            self.driver.close()

    def execute_query(self, query, parameters=None):
        """
        Generic function to execute queries
        """
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]


# Initialize connection
neo4j_db = None


# --------------------------------------------------
# GRAPH OPERATIONS
# --------------------------------------------------

def create_node(node_type, value):
    """
    Create a topology node
    Example:
    node_type: Domain
    value: api.bank.in
    """

    query = """
    MERGE (n:AssetNode {type: $node_type, value: $value})
    RETURN n
    """

    return neo4j_db.execute_query(query, {
        "node_type": node_type,
        "value": value
    })


def create_relationship(source, target, relation):
    """
    Create graph relationship

    Example:
    bank.in -> api.bank.in
    relation = SUBDOMAIN
    """

    query = f"""
    MATCH (a {{value:$source}})
    MATCH (b {{value:$target}})
    MERGE (a)-[r:{relation}]->(b)
    RETURN a,r,b
    """

    return neo4j_db.execute_query(query, {
        "source": source,
        "target": target
    })


def get_asset_graph(asset):
    """
    Get asset dependency graph
    """

    query = """
    MATCH (a {value:$asset})-[r]->(b)
    RETURN a,r,b
    """

    return neo4j_db.execute_query(query, {"asset": asset})


def get_full_topology():
    """
    Return entire topology graph
    """

    query = """
    MATCH (a)-[r]->(b)
    RETURN a,r,b
    LIMIT 100
    """

    return neo4j_db.execute_query(query)