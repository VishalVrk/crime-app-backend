import requests
import json

def test_single_analysis():
    url = "http://localhost:8000/api/analyze-text"
    
    # Test case 1: Normal text
    payload1 = {
        "text": "This is a normal business email about scheduling a meeting.",
        "metadata": {"source": "email", "user_id": "123"}
    }
    
    # Test case 2: Suspicious text
    payload2 = {
        "text": "Need to transfer $50,000 to offshore account immediately. Delete all records after.",
        "metadata": {"source": "email", "user_id": "456"}
    }
    
    # Send requests
    print("\nTesting normal text:")
    response1 = requests.post(url, json=payload1)
    print_response(response1)
    
    print("\nTesting suspicious text:")
    response2 = requests.post(url, json=payload2)
    print_response(response2)

def test_batch_analysis():
    url = "http://localhost:8000/api/analyze-batch"
    
    # Batch of texts
    payload = [
        {
            "text": "Regular meeting at 2 PM to discuss project timeline.",
            "metadata": {"source": "chat"}
        },
        {
            "text": "Need to hide these transactions and delete the evidence quickly.",
            "metadata": {"source": "email"}
        }
    ]
    
    print("\nTesting batch analysis:")
    response = requests.post(url, json=payload)
    print_response(response)

def print_response(response):
    if response.status_code == 200:
        print("Status: Success")
        print("Response:")
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    print("Testing Forensic Analysis API")
    test_single_analysis()
    test_batch_analysis()
    print("\nTesting completed.")