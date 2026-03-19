from app.db.neo4j import get_driver

driver = get_driver()

def get_topology():

    query = """
    MATCH (d:Domain)
    OPTIONAL MATCH (d)-[:OWNS]->(a:Asset)
    OPTIONAL MATCH (a)-[:HAS_PORT]->(p:Port)
    OPTIONAL MATCH (a)-[:HAS_TLS]->(t:TLS)
    OPTIONAL MATCH (a)-[:HAS_CERTIFICATE]->(c:Certificate)
    OPTIONAL MATCH (a)-[:HAS_CBOM]->(cb:CBOM)

    RETURN d,a,p,t,c,cb
    LIMIT 1000
    """

    with driver.session() as session:

        result = session.run(query)

        nodes = []
        edges = []

        for record in result:

            d = record["d"]
            a = record["a"]
            p = record["p"]
            t = record["t"]

            if d:
                nodes.append({
                    "id": d["name"],
                    "type": "domain"
                })

            if a:
                nodes.append({
                    "id": a["hostname"],
                    "type": "asset"
                })

                edges.append({
                    "from": d["name"],
                    "to": a["hostname"]
                })

            if p:
                nodes.append({
                    "id": f"{a['hostname']}:{p['port']}",
                    "type": "port"
                })

                edges.append({
                    "from": a["hostname"],
                    "to": f"{a['hostname']}:{p['port']}"
                })

        return {
            "nodes": nodes,
            "edges": edges
        }