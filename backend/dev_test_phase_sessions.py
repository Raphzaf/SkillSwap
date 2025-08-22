import requests, datetime, time

BASE = "http://localhost:8001/api"
HEAD = {"Authorization": ""}

# For dev, you can set AUTH_LITE_DEBUG=true and use X-Device-Id
HEAD_LITE = {"X-Device-Id": "dev-user-SCHED-1"}
HEAD_LITE_B = {"X-Device-Id": "dev-user-SCHED-2"}

# Create two users via /me
print("create A")
requests.get(f"{BASE}/me", headers=HEAD_LITE)
requests.put(f"{BASE}/me", headers=HEAD_LITE, json={"name":"Alice","age":26})
print("create B")
requests.get(f"{BASE}/me", headers=HEAD_LITE_B)
requests.put(f"{BASE}/me", headers=HEAD_LITE_B, json={"name":"Bob","age":29})

# Create match by mutual likes
print("like")
ua = requests.get(f"{BASE}/me", headers=HEAD_LITE).json()["user"]["id"]
ub = requests.get(f"{BASE}/me", headers=HEAD_LITE_B).json()["user"]["id"]
requests.post(f"{BASE}/swipe", headers=HEAD_LITE, json={"targetUserId": ub, "action":"like"})
requests.post(f"{BASE}/swipe", headers=HEAD_LITE_B, json={"targetUserId": ua, "action":"like"})

# Fetch matches for A and find match id
rm = requests.get(f"{BASE}/matches", headers=HEAD_LITE).json()
mid = rm["matches"][0]["id"] if rm["matches"] else None
print("match id:", mid)

# Create session proposed by A
start = (datetime.datetime.utcnow() + datetime.timedelta(minutes=1)).replace(microsecond=0)
resp = requests.post(f"{BASE}/sessions", headers=HEAD_LITE, json={
  "matchId": mid,
  "startAt": start.isoformat()+"Z",
  "durationMin": 60,
  "locationType":"online",
  "locationValue":"https://meet.example.com/abc"
})
print("create session:", resp.status_code, resp.json())
sid = resp.json()["session"]["id"]

# Accept by B
resp = requests.patch(f"{BASE}/sessions/{sid}", headers=HEAD_LITE_B, json={"status":"confirmed"})
print("confirm:", resp.status_code, resp.json())

# ICS download (should work only when confirmed)
resp = requests.get(f"{BASE}/sessions/{sid}/ics", headers=HEAD_LITE_B)
print("ics:", resp.status_code)

# Fast-forward to allow rating (simulate by setting endAt in past if needed in DB)
print("DONE")