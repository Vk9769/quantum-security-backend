import os
import sys
import signal
import threading
import subprocess
from typing import Dict, Optional


class WorkerManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.processes: Dict[str, subprocess.Popen] = {}

        self.workers = [
            "app.workers.scan_worker",
            "app.workers.subdomain_worker",
            "app.workers.port_scan_worker",
            "app.workers.tls_worker",
            "app.workers.certificate_worker",
            "app.workers.cbom_worker",
            "app.workers.risk_worker",
            "app.workers.alert_worker",
            "app.workers.orchestrator_worker",
        ]

    def _is_running(self, process: Optional[subprocess.Popen]) -> bool:
        return process is not None and process.poll() is None

    def ensure_workers_running(self):
        with self.lock:
            for worker in self.workers:
                process = self.processes.get(worker)

                if self._is_running(process):
                    continue

                print(f"[WorkerManager] Starting {worker}")

                creationflags = 0
                preexec_fn = None

                if os.name == "nt":
                    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
                else:
                    preexec_fn = os.setsid

                new_process = subprocess.Popen(
                    [sys.executable, "-m", worker],
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    creationflags=creationflags,
                    preexec_fn=preexec_fn
                )

                self.processes[worker] = new_process

    def stop_all_workers(self):
        with self.lock:
            for worker, process in self.processes.items():
                if not self._is_running(process):
                    continue

                print(f"[WorkerManager] Stopping {worker}")

                try:
                    if os.name == "nt":
                        process.terminate()
                    else:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except Exception as e:
                    print(f"[WorkerManager] Error stopping {worker}: {e}")
                    try:
                        process.kill()
                    except Exception:
                        pass

            self.processes.clear()

    def get_worker_status(self):
        with self.lock:
            result = {}
            for worker in self.workers:
                process = self.processes.get(worker)
                result[worker] = "running" if self._is_running(process) else "stopped"
            return result


worker_manager = WorkerManager()