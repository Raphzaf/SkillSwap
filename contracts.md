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

# SkillSwap Backend API v2 - New Features Documentation

## Credits/Points System

### User Model Updates
- `creditBalance`: number (default: 100) - Current credit balance
- `creditEarned`: number (default: 0) - Total credits earned
- `creditSpent`: number (default: 0) - Total credits spent

### Session Model Updates
- `creditValue`: number - Credits required for session
- `teacherId`: string - User teaching (receiving credits)
- `learnerId`: string - User learning (spending credits)
- `creditsProcessed`: boolean - Whether credits have been transferred

### Credit Transaction Model
```
{
  _id: string,
  userId: string,
  fromUserId: string?,
  toUserId: string?,
  amount: number,
  sessionId: string?,
  type: "session_payment" | "bonus" | "refund" | "admin_adjustment",
  reason: string,
  balanceAfter: number,
  createdAt: datetime
}
```

### Credits API Endpoints

GET /api/credits/balance
- Headers: X-Device-Id or Authorization: Bearer <token>
- Response: { creditBalance: number, creditEarned: number, creditSpent: number }

GET /api/credits/history?cursor=<datetime>&limit=30
- Headers: X-Device-Id or Authorization: Bearer <token>
- Response: { transactions: Array<Transaction>, nextCursor?: string }

## Reputation & Rating System

### Rating Model Updates
- `teachingQuality`: number (1-5)
- `communication`: number (1-5)
- `punctuality`: number (1-5)
- `overallExperience`: number (1-5)
- `skillRated`: string - Which skill was taught
- `reviewText`: string (max 500 chars) - Written review

### User Stats & Badges

GET /api/users/:userId/ratings?cursor=<datetime>&limit=20
- Response: { ratings: Array<Rating>, nextCursor?: string }
- Rating includes: stars, comment, teachingQuality, communication, punctuality, overallExperience, skillRated, reviewText, raterName, createdAt

GET /api/users/:userId/stats
- Response: {
    userId: string,
    averageRating: number,
    totalRatings: number,
    totalSessionsCompleted: number,
    totalAsTeacher: number,
    totalAsLearner: number,
    skillRatings: { [skill: string]: number },
    badges: string[] // ["verified", "top_teacher", "rising_star", "reliable"]
  }

### Badge Types
- `verified`: Email confirmed
- `top_teacher`: 4.8+ rating, 10+ sessions
- `rising_star`: 5 stars on first 3 sessions
- `reliable`: 100% attendance rate

## Enhanced Matching Algorithm

GET /api/candidates?cursor=0&limit=10&minRating=4.0&hasCredits=true
- Query params:
  - cursor: number (pagination)
  - limit: number (1-50)
  - minRating: float (0.0-5.0, optional)
  - hasCredits: boolean (filter users with >=30 credits, optional)
- Response: {
    candidates: Array<{
      id, name, age, bio, skillsTeach, skillsLearn, photos,
      avgRating, ratingsCount, creditBalance, distanceKm,
      matchScore: number (0-100),
      matchReasons: string[],
      isMutualMatch: boolean
    }>,
    nextCursor: number
  }

### Match Scoring Algorithm (0-100 points)
- Skill complementarity: 40 points (perfect match if both can teach each other)
- Rating compatibility: 20 points (similar rating levels)
- Credit balance: 20 points (has credits for sessions)
- Profile completeness: 10 points (bio, photos)
- Activity level: 10 points (ratings count)

## Skills Catalog & Discovery

GET /api/skills/catalog
- Response: {
    topSkills: Array<{ name: string, count: number }>,
    categories: {
      tech: Array<{ name: string, count: number }>,
      design: Array<{ name: string, count: number }>,
      business: Array<{ name: string, count: number }>,
      languages: Array<{ name: string, count: number }>,
      creative: Array<{ name: string, count: number }>,
      wellness: Array<{ name: string, count: number }>,
      other: Array<{ name: string, count: number }>
    },
    totalSkills: number
  }

GET /api/skills/search?q=<query>
- Query params: q (min 2 chars)
- Response: { query: string, skills: string[], userCount: number }

GET /api/skills/:skillName/teachers?limit=20
- Response: {
    skill: string,
    teachers: Array<{
      id, name, age, bio, photos, avgRating, ratingsCount,
      sessionsCount, locationCity, skillsTeach
    }>,
    count: number
  }

## Security & Privacy

### Privacy Settings (added to Settings model)
- `profileVisibility`: "public" | "matches_only" | "hidden"
- `messagePrivacy`: "everyone" | "matches_only"
- `showOnlineStatus`: boolean

### Report Model
```
{
  _id: string,
  reporterId: string,
  reportedUserId: string,
  reason: "spam" | "harassment" | "inappropriate_content" | "fake_profile" | "other",
  description: string (max 500 chars),
  status: "pending" | "reviewed" | "resolved",
  createdAt: datetime
}
```

### Block Model
```
{
  _id: string,
  blockerId: string,
  blockedId: string,
  createdAt: datetime
}
```

### Security API Endpoints

POST /api/users/:userId/report
- Body: { reportedUserId: string, reason: string, description?: string }
- Rate limit: 10 per 5 minutes
- Response: { success: boolean, message: string }

POST /api/users/:userId/block
- Response: { success: boolean, message: string }

DELETE /api/users/:userId/block
- Response: { success: boolean, message: string }

GET /api/me/blocks
- Response: {
    blockedUsers: Array<{
      id, name, photo, blockedAt
    }>,
    count: number
  }

## Bonus Credits System

### Automatic Credit Bonuses
1. Profile Completion: +20 credits
   - Triggered when: name, age, bio, >=1 skillsTeach, >=1 skillsLearn, >=1 photo
2. First Session: +10 credits (per user, both teacher and learner)
   - Triggered after: First session is rated
3. High Rating: +5 credits
   - Triggered when: Receiving a 5-star rating

## Data Flow: Session Credits

1. Session created → Check learner has enough credits (>=creditValue)
2. Both users complete session → Both rate the session
3. After both ratings → Credits transfer:
   - Learner: creditBalance -= creditValue, creditSpent += creditValue
   - Teacher: creditBalance += creditValue, creditEarned += creditValue
4. Transaction records created for both users
5. Check for bonuses (first session, high rating)
