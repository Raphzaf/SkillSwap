import requests

BASE = "http://localhost:8001/api"
HEAD = {"X-Device-Id": "dev-main-001"}

def p(label, resp):
    print("==>", label, resp.status_code)
    try:
        print(resp.json())
    except Exception:
        print(resp.text)

# Ping
r = requests.get(f"{BASE}/")
p("root", r)

# Get me (should auto-create)
r = requests.get(f"{BASE}/me", headers=HEAD)
p("get_me", r)

# Update me
r = requests.put(f"{BASE}/me", json={"name": "Tester", "age": 33, "bio": "From dev_test_phase1"}, headers=HEAD)
p("update_me", r)

# Update settings
r = requests.put(f"{BASE}/me/settings", json={"distanceKm": 25, "visible": False}, headers=HEAD)
p("update_settings", r)

print("DONE")