from neo4j import GraphDatabase
import os

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "password"


class GraphService:

    def __init__(self):
        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )
        
    def close(self):
        self.driver.close()
        
    def execute(self, query, params=None):

        with self.driver.session() as session:
            session.run(query, params or {})

    def create_domain(self, domain):

        query = """
        MERGE (d:Domain {name:$domain})
        RETURN d
        """

        with self.driver.session() as session:
            session.run(query, domain=domain)

    def create_asset(self, domain, asset):

        query = """
        MERGE (d:Domain {name:$domain})
        MERGE (a:Asset {name:$asset})
        ON CREATE SET a.created_at = timestamp()
        MERGE (d)-[:OWNS]->(a)
        """

        with self.driver.session() as session:
            session.run(query, domain=domain, asset=asset)
            
    def add_port(self, asset, port):

        query = """
        MERGE (a:Asset {name:$asset})
        MERGE (p:Port {number:$port, asset:$asset})
        MERGE (a)-[:HAS_PORT]->(p)
        """

        with self.driver.session() as session:
            session.run(query, asset=asset, port=port)

    def add_vulnerability(self, asset, cve):

        query = """
        MERGE (a:Asset {name:$asset})
        MERGE (v:Vulnerability {cve:$cve})
        MERGE (a)-[:HAS_VULNERABILITY]->(v)
        """

        with self.driver.session() as session:
            session.run(query, asset=asset, cve=cve)
            
    def add_tls(self, asset, version, cipher):

        query = """
        MATCH (a:Asset {name:$asset})
        MERGE (t:TLS {asset:$asset})
        SET
            t.version = $version,
            t.cipher = $cipher
        MERGE (a)-[:HAS_TLS]->(t)
        """

        self.execute(query, {
            "asset": asset,
            "version": version,
            "cipher": cipher
        })
        
    def add_certificate(self, asset, issuer, subject, expiry, algo, key):

        query = """
        MATCH (a:Asset {name:$asset})

        MERGE (c:Certificate {
            issuer:$issuer,
            subject:$subject
        })

        SET
            c.expiry = $expiry,
            c.algorithm = $algo,
            c.key_size = $key

        MERGE (a)-[:HAS_CERTIFICATE]->(c)
        """

        self.execute(query, {
            "asset": asset,
            "issuer": issuer,
            "subject": subject,
            "expiry": expiry,
            "algo": algo,
            "key": key
        })
        
    def add_cbom(self, asset, algo, key, expiry):

        # Replace None values
        algo = algo or "unknown"
        key = key or 0
        expiry = expiry or "unknown"

        query = """
        MATCH (a:Asset {name:$asset})

        MERGE (cb:CBOM {
            algorithm:$algo,
            key_size:$key,
            expiry:$expiry
        })

        MERGE (a)-[:HAS_CBOM]->(cb)
        """

        self.execute(query, {
            "asset": asset,
            "algo": algo,
            "key": key,
            "expiry": expiry
        })
        
    def add_risk(self, asset, score, quantum_risk):

        query = """
        MATCH (a:Asset {name:$asset})

        MERGE (r:Risk {
            asset:$asset
        })

        SET
            r.score = $score,
            r.quantum_risk = $quantum_risk,
            r.updated_at = timestamp()

        MERGE (a)-[:HAS_RISK]->(r)
        """

        with self.driver.session() as session:
            session.run(
                query,
                asset=asset,
                score=score,
                quantum_risk=quantum_risk
            )
            
    def get_topology(self, domain=None):

        if domain:
            query = """
            MATCH (d:Domain {name:$domain})
            OPTIONAL MATCH (d)-[:OWNS]->(a:Asset)
            OPTIONAL MATCH (a)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (a)-[:HAS_TLS]->(t:TLS)
            OPTIONAL MATCH (a)-[:HAS_CERTIFICATE]->(c:Certificate)
            OPTIONAL MATCH (a)-[:HAS_CBOM]->(cb:CBOM)

            RETURN d,a,p,t,c,cb
            LIMIT 2000
            """
            params = {"domain": domain}
        else:
            query = """
            MATCH (d:Domain)
            OPTIONAL MATCH (d)-[:OWNS]->(a:Asset)
            OPTIONAL MATCH (a)-[:HAS_PORT]->(p:Port)
            OPTIONAL MATCH (a)-[:HAS_TLS]->(t:TLS)
            OPTIONAL MATCH (a)-[:HAS_CERTIFICATE]->(c:Certificate)
            OPTIONAL MATCH (a)-[:HAS_CBOM]->(cb:CBOM)

            RETURN d,a,p,t,c,cb
            LIMIT 2000
            """
            params = {}

        nodes = {}
        edges = set()

        with self.driver.session() as session:

            result = session.run(query, params)

            for record in result:

                d = record["d"]
                a = record["a"]
                p = record["p"]
                t = record["t"]
                c = record["c"]
                cb = record["cb"]

                # -------------------------
                # DOMAIN NODE
                # -------------------------

                if d:

                    domain_id = f"domain:{d['name']}"

                    nodes[domain_id] = {
                        "id": domain_id,
                        "label": d["name"],
                        "type": "domain"
                    }

                # -------------------------
                # ASSET / SUBDOMAIN
                # -------------------------

                if a:

                    asset_id = f"asset:{a['name']}"

                    nodes[asset_id] = {
                        "id": asset_id,
                        "label": a["name"],
                        "type": "subdomain"
                    }

                    if d:
                        edges.add((domain_id, asset_id))

                # -------------------------
                # PORT
                # -------------------------

                if p and a:

                    port_id = f"port:{p['number']}:{a['name']}"

                    nodes[port_id] = {
                        "id": port_id,
                        "label": str(p["number"]),
                        "type": "port"
                    }

                    edges.add((asset_id, port_id))

                # -------------------------
                # TLS
                # -------------------------

                if t and a:

                    tls_id = f"tls:{t.get('version','TLS')}:{a['name']}"

                    nodes[tls_id] = {
                        "id": tls_id,
                        "label": t.get("version", "TLS"),
                        "type": "tls"
                    }

                    edges.add((asset_id, tls_id))

                # -------------------------
                # CERTIFICATE
                # -------------------------

                if c and a:

                    cert_id = f"cert:{c.get('issuer','cert')}:{a['name']}"

                    nodes[cert_id] = {
                        "id": cert_id,
                        "label": c.get("issuer", "Certificate"),
                        "type": "cert"
                    }

                    edges.add((asset_id, cert_id))

                # -------------------------
                # CBOM
                # -------------------------

                if cb and a:

                    cbom_id = f"cbom:{cb.get('algorithm','cbom')}:{a['name']}"

                    nodes[cbom_id] = {
                        "id": cbom_id,
                        "label": cb.get("algorithm", "CBOM"),
                        "type": "cbom"
                    }

                    edges.add((asset_id, cbom_id))

        return {
            "nodes": list(nodes.values()),
            "edges": [{"from": f, "to": t} for f, t in edges]
        }