import subprocess
import sys

workers = [
    "app.workers.scan_worker",
    "app.workers.subdomain_worker",
    "app.workers.port_scan_worker",
    "app.workers.tls_worker",
    "app.workers.certificate_worker",
    "app.workers.cbom_worker",
    "app.workers.risk_worker",
    "app.workers.alert_worker",
    "app.workers.orchestrator_worker"
]

processes = []

for worker in workers:
    print(f"Starting {worker}")

    p = subprocess.Popen(
        [sys.executable, "-m", worker],
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    processes.append(p)

print("\nAll workers started using:", sys.executable)

for p in processes:
    p.wait()