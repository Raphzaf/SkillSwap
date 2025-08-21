# SkillSwap Backend Contracts v1 (for future integration)

Base URL and Routing
- Frontend must call `${process.env.REACT_APP_BACKEND_URL}/api/...` (do not hardcode URLs/ports).
- All backend routes are under the /api prefix to satisfy ingress rules.

Auth & Identity (MVP options)
1) Anonymous device identity (recommended for first pass)
   - Client generates and stores a deviceId in localStorage (uuid v4).
   - Send with every request as X-Device-Id header. Backend creates a user if none exists.
2) Magic email code (optional follow-up)
   - POST /api/auth/magic/start { email } -> { requestId }
   - POST /api/auth/magic/verify { requestId, code } -> { token, user }
   - Thereafter, Authorization: Bearer <token>. (We can keep deviceId as a fallback.)

Data Models (MongoDB)
- User
  { _id, email?, deviceId?, name, age, bio, photos: [string], skillsTeach: [string], skillsLearn: [string], createdAt, updatedAt }
- Settings
  { _id, userId (ref User), location?: string, distanceKm: number, ageRange: [number, number], visible: boolean, notifications: boolean, updatedAt }
- Swipe
  { _id, userId, targetUserId, action: 'like'|'pass'|'superlike', ts }
- Match
  { _id, users: [userIdA, userIdB], createdAt, lastMessageAt }
  - Unique index on { users: 1 } with sorted pair to avoid duplicates.
- Message
  { _id, matchId, fromUserId, text?: string, imageUrl?: string, clientSessionId?: string, ts }
  - Index on { matchId: 1, ts: -1 }

API Contracts
- Health
  GET /api/ -> 200 { message: "Hello World" }

- Me / Profile
  GET /api/me
    headers: X-Device-Id
    200 { user: User, settings: Settings }
  PUT /api/me
    body: { name?, age?, bio?, photos?, skillsTeach?, skillsLearn? }
    200 { user }
  PUT /api/me/settings
    body: { location?, distanceKm?, ageRange?, visible?, notifications? }
    200 { settings }

- Discovery
  GET /api/deck?cursor=<opaque>&limit=20
    headers: X-Device-Id
    200 { profiles: Array<UserPublic>, nextCursor?: string }
    where UserPublic = { id, name, age, distanceKm, bio, photos: [string], skillsToTeach: [string], skillsToLearn: [string] }
  POST /api/swipe
    headers: X-Device-Id
    body: { targetUserId: string, action: 'like'|'pass'|'superlike' }
    200 { status: 'ok', matched: boolean, matchId?: string }

- Matches & Chats
  GET /api/matches
    headers: X-Device-Id
    200 { matches: Array<{ id, user: UserPublic, lastMessage?: { text?: string, imageUrl?: string, ts: number } }> }
  GET /api/matches/:id/messages?cursor=&limit=30
    200 { messages: Array<Message>, nextCursor?: string }
  POST /api/matches/:id/messages
    body: { text?: string, imageBase64?: string, clientSessionId?: string }
    201 { message: Message }
    Notes: For MVP we may store base64 directly or convert to data URL; later we will switch to object storage (e.g., S3) and return imageUrl.

Errors (uniform)
- 4xx/5xx payload: { error: { code: string, message: string, details?: any } }
- Common codes: invalid_input, unauthorized, not_found, rate_limited, server_error

Which data is mocked today (src/mock.js)
- profiles: array of 8 sample profiles with photos, bios, skills
- seededConversations: 2 conversations with messages
- defaultUser: starter profile for the signed-in user

Frontend integration plan (mapping → endpoints)
- Swipe.jsx
  - Replace nextProfile/randomMatch with GET /api/deck and POST /api/swipe
  - When POST /api/swipe returns { matched: true, matchId }, open the match modal
- Account.jsx
  - Onboarding/ProfileEditor: read via GET /api/me, update via PUT /api/me
  - Photo selection stays client-side; later we can support uploads
  - Settings: PUT /api/me/settings
- Chats (in App.js)
  - Threads list from GET /api/matches
  - Active conversation messages from GET /api/matches/:id/messages
  - Sending via POST /api/matches/:id/messages; include a clientSessionId to dedupe

Incremental rollout
1) Implement Me (GET/PUT) + Settings (PUT) – unblock profile
2) Implement Discovery: /deck + /swipe with match creation
3) Implement Matches + Messages (GET/POST)
4) Optional magic email auth endpoints

Indexes & performance
- Users: index on deviceId, email
- Settings: index on userId
- Swipes: compound index (userId, targetUserId)
- Matches: unique index on sorted pair and index lastMessageAt for listing
- Messages: index on (matchId, ts)

Security & CORS
- Keep current permissive CORS for MVP; tighten later
- Validate X-Device-Id; basic input validation with Pydantic

Testing approach (before frontend wiring)
- Implement FastAPI routes with Motor ODM calls
- Write minimal pytest API tests for Me, Deck, Swipe match flow, Messages create+list
- Use supervisor logs to debug; do not change .env URLs; keep /api prefix

Integration checklist
- Never hardcode URLs; always derive `${process.env.REACT_APP_BACKEND_URL}/api`
- Ensure all new backend routes mount under the existing FastAPI app with prefix "/api"
- After backend is ready, replace mock imports with a small data layer (api.ts) and update components via small edits (str_replace where safe)

Notes
- Current frontend remains fully functional with mocks; backend wiring will progressively replace mock.js usage.
