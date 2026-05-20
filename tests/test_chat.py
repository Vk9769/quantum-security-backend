import requests

url = "http://localhost:8000/api/v1/ai/chat"

while True:

    message = input("\nYou: ")

    if message.lower() == "exit":
        break

    response = requests.post(
        url,
        json={
            "message": message
        }
    )

    data = response.json()

    print("\nAI:", data["response"])