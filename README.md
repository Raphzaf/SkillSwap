# SkillSwap 🎓🤝

SkillSwap is a collaborative skills exchange platform where users can teach what they know and learn what they want, all without money. The platform uses a **credit-based economy** to balance exchanges and ensure fair value.

## 🌟 Core Value Proposition

- **Democratize learning** and mutual aid
- **Learn without money** - value knowledge as currency
- **Collaborative economy** + continuous learning + human networking
- **Alternative to expensive training** programs

## ✨ Key Features

### 🪙 Credit Economy System
- Every user starts with 100 credits
- Earn credits by teaching others
- Spend credits to learn new skills
- Automatic bonuses for:
  - Profile completion (+20 credits)
  - First session (+10 credits)
  - High ratings (5 stars = +5 credits)

### 🎯 Intelligent Matching
- **Smart match scoring** (0-100 points) based on:
  - Skill complementarity (I teach what you want, you teach what I want)
  - Rating compatibility
  - Credit balance
  - Profile completeness
  - Activity level
- **Match explanations** - understand why you're compatible
- **Mutual match detection** - prioritize perfect matches

### ⭐ Reputation & Trust
- Detailed ratings (teaching quality, communication, punctuality)
- Skill-specific ratings
- Achievement badges:
  - **Verified** - Email confirmed
  - **Top Teacher** - 4.8+ rating, 10+ sessions
  - **Rising Star** - 5 stars on first 3 sessions
  - **Reliable** - 100% attendance
- Public user stats and reviews

### 🔍 Skills Discovery
- Searchable skills catalog
- Organized by categories (Tech, Design, Business, Languages, Creative, Wellness)
- Find teachers by skill
- Popular skills trending

### 🔒 Security & Privacy
- Report system (spam, harassment, inappropriate content)
- Block/unblock users
- Privacy settings (profile visibility, message privacy)
- Blocked users filtered from all interactions
- Input validation and security hardening

### 💬 Communication
- Match-based messaging
- Session scheduling with calendar export (.ics)
- Session proposals with credit negotiation

## 🛠️ Technologies

### Backend (Python/FastAPI)
- **FastAPI** - Modern, fast web framework
- **MongoDB** (Motor) - NoSQL database with geospatial support
- **JWT Authentication** - Secure token-based auth
- **Rate Limiting** - Prevent abuse
- **Input Validation** - Pydantic models
- **Security** - Regex escaping, CORS, CSP headers

### Frontend (React)
- **React** - Component-based UI
- **shadcn/ui** - Modern, accessible UI components
- **Tailwind CSS** - Utility-first styling
- **Axios** - HTTP client with interceptors
- **Dark Mode** - System preference support

### Infrastructure
- **MongoDB** - Document database with indexes
- **Environment Variables** - Secure configuration
- **CORS** - Strict origin validation in production

## 📋 Setup Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+
- MongoDB 5.0+

### Backend Setup

1. **Navigate to backend directory:**
```bash
cd backend
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Create `.env` file:**
```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=skillswap
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRES_DAYS=7
REFRESH_EXPIRES_DAYS=30
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
ENV=dev
AUTH_LITE_DEBUG=true
SENDGRID_API_KEY=your-sendgrid-key-optional
FROM_EMAIL=noreply@skillswap.com
```

4. **Run the server:**
```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

### Frontend Setup

1. **Navigate to frontend directory:**
```bash
cd frontend
```

2. **Install dependencies:**
```bash
npm install
```

3. **Create `.env` file:**
```env
REACT_APP_BACKEND_URL=http://localhost:8001
```

4. **Run the development server:**
```bash
npm start
```

The app will be available at `http://localhost:3000`

## 📚 API Documentation

See [contracts.md](./contracts.md) for complete API documentation including:
- Authentication endpoints
- User profile management
- Credits system
- Matching algorithm
- Skills catalog
- Security features
- Data models

## 🗄️ Database Models

### User
```javascript
{
  _id: string,
  email: string,
  name: string,
  age: number,
  bio: string,
  skillsTeach: string[],
  skillsLearn: string[],
  photos: string[],
  creditBalance: number,
  creditEarned: number,
  creditSpent: number,
  avgRating: number,
  ratingsCount: number,
  badges: string[]
}
```

### Session
```javascript
{
  _id: string,
  matchId: string,
  participants: string[],
  teacherId: string,
  learnerId: string,
  creditValue: number,
  startAt: datetime,
  endAt: datetime,
  locationType: "online" | "in_person",
  status: "proposed" | "confirmed" | "cancelled"
}
```

### CreditTransaction
```javascript
{
  _id: string,
  userId: string,
  fromUserId: string,
  toUserId: string,
  amount: number,
  type: "session_payment" | "bonus" | "refund",
  reason: string,
  balanceAfter: number,
  createdAt: datetime
}
```

## 🔐 Security Features

- **Rate Limiting** - Prevents API abuse
- **JWT Authentication** - Secure token-based auth
- **Input Validation** - Pydantic models validate all inputs
- **Regex Escaping** - Prevents regex injection attacks
- **CORS Protection** - Strict origin validation in production
- **Security Headers** - CSP, X-Frame-Options, HSTS
- **Content Moderation** - Banned word filtering
- **User Blocking** - Complete isolation from blocked users
- **Report System** - Track and handle abuse reports

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 🚀 Deployment

### Production Checklist

1. **Environment Variables:**
   - Set `ENV=prod`
   - Set `AUTH_LITE_DEBUG=false`
   - Configure strong `JWT_SECRET`
   - Set production `CORS_ORIGINS`
   - Configure `SENDGRID_API_KEY` for emails

2. **Database:**
   - Use MongoDB Atlas or managed MongoDB
   - Enable authentication
   - Create indexes (automatically created on startup)
   - Configure backups

3. **Backend:**
   - Deploy to Render, Railway, or similar
   - Set environment variables
   - Configure health checks
   - Enable HTTPS

4. **Frontend:**
   - Build: `npm run build`
   - Deploy to Vercel, Netlify, or similar
   - Set `REACT_APP_BACKEND_URL` to production API URL
   - Configure CDN for static assets

## 📊 Project Statistics

- **Backend:** ~2000 lines of Python
- **Frontend:** ~1500 lines of React/JavaScript
- **API Endpoints:** 30+
- **Data Models:** 8
- **Database Indexes:** 10+
- **Features:** Credit economy, intelligent matching, reputation system, skills discovery, security

## 🎯 Future Enhancements

### High Priority
- Session attendance tracking
- Notification system (email/push)
- Skills marketplace UI
- Report/Block UI
- Privacy settings UI
- Mobile app (React Native)

### Medium Priority
- Onboarding wizard
- Profile completeness indicator
- PWA features (offline support, install prompt)
- Video call integration
- Calendar integration

### Low Priority
- Analytics dashboard
- Admin panel
- Advanced search filters
- Gamification features
- Social sharing

## 👩‍💻 Author

Developed by **Raphael Zafran** as part of a Fullstack Developer training program.

## 📄 License

See LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- shadcn/ui for beautiful, accessible UI components
- MongoDB for flexible document storage
- The open-source community
