import logging
import asyncio
from app.utils.websocket_manager import manager

# ✅ GLOBAL LOOP STORAGE
MAIN_LOOP = None

def set_main_loop(loop):
    global MAIN_LOOP
    MAIN_LOOP = loop
    
def get_main_loop():
    return MAIN_LOOP


# class WebSocketLogHandler(logging.Handler):
#     """
#     Thread-safe WebSocket logger (WORKS with Kafka + workers)
#     """
#
#     def emit(self, record):
#         try:
#             log_entry = self.format(record)
#
#             if (
#                 "uvicorn.access" in log_entry
#                 or "uvicorn.error" in log_entry
#                 or "GET /" in log_entry
#                 or "POST /" in log_entry
#                 or "WebSocket" in log_entry
#                 or "connection open" in log_entry
#                 or "127.0.0.1" in log_entry
#             ):
#                 return
#
#             if MAIN_LOOP and MAIN_LOOP.is_running():
#                 MAIN_LOOP.call_soon_threadsafe(
#                     asyncio.create_task,
#                     manager.broadcast({
#                         "type": "log",
#                         "message": log_entry
#                     })
#                 )
#
#         except Exception as e:
#             print("LOG STREAM ERROR:", e)


def setup_logger():

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    

    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s - %(message)s"
    )

# handler = WebSocketLogHandler()
# handler.setFormatter(formatter)
#
# if not any(isinstance(h, WebSocketLogHandler) for h in root_logger.handlers):
#     root_logger.addHandler(handler)

    # ❌ disable noisy logs
    logging.getLogger("uvicorn").disabled = True
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("uvicorn.error").disabled = True

    logging.getLogger("kafka").setLevel(logging.WARNING)