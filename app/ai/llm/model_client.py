import requests
import json

from app.ai.intent_detector import detect_scan_intent
from app.ai.actions.scan_action import execute_scan

# =========================================================
# GPU AI SERVER
# =========================================================

AI_SERVER_URL = "https://ceiling-morgan-bay-hostel.trycloudflare.com"

# =========================================================
# GENERATE AI RESPONSE
# =========================================================

async def generate_ai_response(message: str):

    try:
        
        # =========================================================
        # LOCAL SCAN ACTION DETECTION
        # =========================================================

        intent = detect_scan_intent(message)

        if intent:

            print("\n======================================")
            print("SCAN INTENT DETECTED")
            print("TARGET:", intent["domain"])
            print("======================================\n")

            return await execute_scan(intent["domain"])

        print("\n======================================")
        print("SENDING REQUEST TO GPU SERVER")
        print("MESSAGE:", message)
        print("======================================")

        # =================================================
        # SEND REQUEST
        # =================================================

        response = requests.post(
            f"{AI_SERVER_URL}/chat",
            json={
                "message": message
            },
            timeout=300
        )

        # =================================================
        # DEBUG RESPONSE
        # =================================================

        print("\n======================================")
        print("GPU SERVER STATUS:", response.status_code)
        print("GPU SERVER RAW RESPONSE:")
        print(response.text)
        print("======================================\n")

        # =================================================
        # CHECK EMPTY RESPONSE
        # =================================================

        if not response.text.strip():

            return "GPU SERVER RETURNED EMPTY RESPONSE"

        # =================================================
        # CONVERT TO JSON
        # =================================================

        try:

            data = response.json()

        except json.JSONDecodeError:

            return f"INVALID JSON RESPONSE FROM GPU SERVER: {response.text}"

        # =================================================
        # SUCCESS RESPONSE
        # =================================================

        if data.get("success"):

            return data.get("response")

        # =================================================
        # ERROR RESPONSE
        # =================================================

        return data.get(
            "error",
            "UNKNOWN GPU SERVER ERROR"
        )

    except requests.exceptions.Timeout:

        return "GPU SERVER TIMEOUT"

    except requests.exceptions.ConnectionError:

        return "CANNOT CONNECT TO GPU SERVER"

    except Exception as e:

        print("\n======================================")
        print("MODEL CLIENT ERROR")
        print(str(e))
        print("======================================\n")

        return f"AI SERVER ERROR: {str(e)}"