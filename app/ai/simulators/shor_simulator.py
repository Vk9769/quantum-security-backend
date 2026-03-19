import math


def estimate_qubits(key_size):
    """
    Estimate logical & physical qubits required for Shor's algorithm.
    Based on current research approximations.
    """

    if not key_size:
        return None, None

    # Logical qubits approx: 2n + 3
    logical_qubits = 2 * key_size + 3

    # Physical qubits (error correction overhead ~1000x)
    physical_qubits = logical_qubits * 1000

    return logical_qubits, physical_qubits


def estimate_attack_time(key_size):
    """
    Estimate time to break RSA using quantum computer.
    These are approximate research-based estimations.
    """

    if not key_size:
        return "UNKNOWN"

    if key_size <= 1024:
        return "Minutes"

    elif key_size <= 2048:
        return "Hours"

    elif key_size <= 4096:
        return "Days"

    else:
        return "Years"


def calculate_quantum_risk(key_size):
    """
    Determine risk level based on key size.
    """

    if not key_size:
        return "UNKNOWN"

    if key_size <= 2048:
        return "CRITICAL"

    elif key_size <= 3072:
        return "HIGH"

    elif key_size <= 4096:
        return "MEDIUM"

    else:
        return "LOW"


def simulate_shor_attack(key_size):
    """
    Simulate Shor's algorithm attack on RSA/ECC keys.
    Returns a detailed attack feasibility report.
    """

    if not key_size:
        return {
            "attack": "Shor",
            "status": "FAILED",
            "reason": "Key size not provided",
            "risk": "UNKNOWN"
        }

    logical_qubits, physical_qubits = estimate_qubits(key_size)

    attack_time = estimate_attack_time(key_size)

    risk = calculate_quantum_risk(key_size)

    return {
        "attack": "Shor Algorithm",
        "target": f"RSA-{key_size}",
        "logical_qubits_required": logical_qubits,
        "physical_qubits_required": physical_qubits,
        "estimated_attack_time": attack_time,
        "quantum_feasibility": "POSSIBLE",
        "risk": risk
    }