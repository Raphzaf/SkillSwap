import requests, time

BASE = "http://localhost:8001/api"
HEAD = {"X-Device-Id": "dev-user-A"}
HEAD_B = {"X-Device-Id": "dev-user-B"}

def p(label, r):
    print("==>", label, r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

# Ensure two users exist
requests.get(f"{BASE}/me", headers=HEAD)
requests.put(f"{BASE}/me", headers=HEAD, json={"name": "Alice", "age": 27})
requests.get(f"{BASE}/me", headers=HEAD_B)
requests.put(f"{BASE}/me", headers=HEAD_B, json={"name": "Bob", "age": 29})

# Get decks
r = requests.get(f"{BASE}/deck?limit=5", headers=HEAD)
p("deck_A", r)

# Simulate mutual like: A likes B's user id from deck if present; else skip
profiles = r.json().get("profiles", [])
if profiles:
    target_id = profiles[0]["id"]
    r1 = requests.post(f"{BASE}/swipe", headers=HEAD, json={"targetUserId": target_id, "action": "like"})
    p("A_like", r1)
    r2 = requests.post(f"{BASE}/swipe", headers=HEAD_B, json={"targetUserId": r.json()["profiles"][0]["id"], "action": "like"})
    p("B_like", r2)

    # List matches for A
    rm = requests.get(f"{BASE}/matches", headers=HEAD)
    p("matches_A", rm)
    data = rm.json()
    if data.get("matches"):
        mid = data["matches"][0]["id"]
        # Send a message A -> B
        ms = requests.post(f"{BASE}/matches/{mid}/messages", headers=HEAD, json={"text": "Hello from A"})
        p("A_msg", ms)
        # List messages
        lm = requests.get(f"{BASE}/matches/{mid}/messages", headers=HEAD)
        p("messages", lm)

print("DONE")