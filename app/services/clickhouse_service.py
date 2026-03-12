from app.db.clickhouse import client
from datetime import datetime


# -----------------------------------------
# Insert Port Scan Result
# -----------------------------------------

def insert_port_scan(asset_id, ip, port, protocol, state, service):

    query = """
    INSERT INTO port_scan_history
    (asset_id, ip_address, port, protocol, state, service, scan_time)
    VALUES
    """

    data = [[
        asset_id,
        ip,
        port,
        protocol,
        state,
        service,
        datetime.utcnow()
    ]]

    client.insert(query, data)


# -----------------------------------------
# Insert TLS Scan Result
# -----------------------------------------

def insert_tls_scan(asset_id, domain, tls, cipher, key_exchange):

    query = """
    INSERT INTO tls_scan_history
    (asset_id, domain, tls_version, cipher_suite, key_exchange, scan_time)
    VALUES
    """

    data = [[
        asset_id,
        domain,
        tls,
        cipher,
        key_exchange,
        datetime.utcnow()
    ]]

    client.insert(query, data)


# -----------------------------------------
# Insert CBOM Crypto Inventory
# -----------------------------------------

def insert_cbom(asset_id, domain, tls, cipher, key_exchange, key_size, algorithm, pqc_risk):

    query = """
    INSERT INTO cbom_crypto_inventory
    (asset_id, domain, tls_version, cipher_suite, key_exchange, key_size,
     certificate_algorithm, pqc_risk, recorded_at)
    VALUES
    """

    data = [[
        asset_id,
        domain,
        tls,
        cipher,
        key_exchange,
        key_size,
        algorithm,
        pqc_risk,
        datetime.utcnow()
    ]]

    client.insert(query, data)