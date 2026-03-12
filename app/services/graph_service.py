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
        MERGE (t:TLS {version:$version, cipher:$cipher})
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
            subject:$subject,
            expiry:$expiry,
            algorithm:$algo,
            key_size:$key
        })
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