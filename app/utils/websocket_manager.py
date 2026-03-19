from fastapi import WebSocket
from typing import List


class ConnectionManager:

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

        # ✅ DEBUG
        print(f"✅ WS CONNECTED | Total Clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

        # ✅ DEBUG
        print(f"❌ WS DISCONNECTED | Total Clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):

        if not self.active_connections:
            # ✅ DEBUG (IMPORTANT)
            print("⚠️ No active WebSocket clients")
            return

        dead_connections = []

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # mark dead connection
                dead_connections.append(connection)

        # ✅ CLEAN DEAD CONNECTIONS
        for conn in dead_connections:
            self.disconnect(conn)


manager = ConnectionManager()