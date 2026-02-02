# SkillSwap Deployment Guide

## Architecture Overview

```
Frontend (React) → Netlify
Backend (FastAPI) → Render
Database → MongoDB Atlas
```

## Prerequisites

1. **MongoDB Atlas Account**
   - Create a cluster at https://www.mongodb.com/cloud/atlas
   - Create a database user
   - Whitelist IP addresses (use `0.0.0.0/0` for development)
   - Get connection string

2. **Render Account**
   - Sign up at https://render.com

3. **Netlify Account**
   - Sign up at https://netlify.com

## Backend Deployment (Render)

### Step 1: Create Web Service

1. Go to Render dashboard
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name:** `skillswap-backend` (or any name)
   - **Language:** Docker
   - **Branch:** `main`
   - **Region:** Choose closest to your users
   - **Root Directory:** `backend`
   - **Dockerfile Path:** `backend/Dockerfile`

### Step 2: Set Environment Variables

Add these in Render dashboard (Environment tab):

```
MONGO_URL=mongodb+srv://user:password@cluster.mongodb.net/
DB_NAME=skillswap
JWT_SECRET=generate-a-random-32-char-string
JWT_EXPIRES_DAYS=7
REFRESH_EXPIRES_DAYS=30
AUTH_LITE_DEBUG=false
IS_PROD=true
FRONTEND_ORIGIN=https://your-app.netlify.app
PORT=8001
```

**Generate JWT Secret:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Step 3: Deploy

1. Click "Create Web Service"
2. Wait for build to complete (~3-5 minutes)
3. Note your backend URL (e.g., `https://skillswap-backend.onrender.com`)
4. Test: `curl https://your-backend-url.onrender.com/api/`
   - Should return: `{"ok": true, ...}`

### Step 4: Configure MongoDB Access

1. Go to MongoDB Atlas → Network Access
2. Add IP address: `0.0.0.0/0` (allows all IPs)
   - Or add Render's specific IPs if available
3. Go to Database Access → Add user with read/write permissions

## Frontend Deployment (Netlify)

### Step 1: Update netlify.toml

Before deploying, update `netlify.toml` in your repository:

```toml
[context.production.environment]
  REACT_APP_BACKEND_URL = "https://your-actual-backend-url.onrender.com"
```

Replace with your actual Render backend URL from previous step.

### Step 2: Deploy to Netlify

#### Option A: Netlify UI
1. Go to Netlify dashboard
2. Click "Add new site" → "Import an existing project"
3. Connect GitHub repository
4. Configure:
   - **Base directory:** `frontend`
   - **Build command:** `npm run build`
   - **Publish directory:** `frontend/build`
5. Add environment variable:
   - `REACT_APP_BACKEND_URL` = `https://your-backend-url.onrender.com`
6. Click "Deploy site"

#### Option B: Netlify CLI
```bash
cd frontend
npm install -g netlify-cli
netlify login
netlify init
netlify deploy --prod
```

### Step 3: Custom Domain (Optional)

1. Go to Netlify → Site settings → Domain management
2. Add custom domain
3. Update DNS records as instructed

## Post-Deployment Verification

### Backend Health Check
```bash
curl https://your-backend.onrender.com/api/
# Should return: {"ok": true, "ts": "...", "mode": "jwt"}
```

### Frontend Health Check
1. Visit your Netlify URL
2. Open browser console (F12)
3. Check for API connection errors
4. Try the Swipe page - should load candidates

### Test Complete Flow
1. Create an account (auto device-id)
2. Complete profile (Account page)
3. Browse candidates (Swipe page)
4. Send a message (Chats page)
5. Check MongoDB - verify data is saved

## Troubleshooting

### Backend Issues

**Error: "ImportError: cannot import name '_QUERY_OPTIONS'"**
- Solution: Dependencies are outdated, update `requirements.txt`

**Error: "MONGO_URL not found"**
- Solution: Add environment variables in Render dashboard

**Error: "Connection refused"**
- Solution: Check MongoDB Atlas network access whitelist

### Frontend Issues

**Error: "REACT_APP_BACKEND_URL is undefined"**
- Solution: Add environment variable in Netlify

**Error: "CORS policy blocked"**
- Solution: Update `FRONTEND_ORIGIN` in backend environment variables

**Error: "Failed to fetch candidates"**
- Solution: Check backend is running and accessible

## Monitoring & Logs

### Render Logs
- Go to Render dashboard → Your service → Logs
- Real-time logs show all API requests and errors

### Netlify Logs
- Go to Netlify dashboard → Your site → Deploys → Deploy log
- Shows build logs and deployment status

### MongoDB Logs
- Go to MongoDB Atlas → Clusters → Monitoring
- Shows database operations and performance

## Scaling Considerations

### Free Tier Limitations
- **Render Free:** Spins down after 15 min inactivity (cold start ~30s)
- **Netlify Free:** 100GB bandwidth/month, 300 build minutes
- **MongoDB Atlas Free:** 512MB storage

### Upgrade Recommendations
- **When you reach 100+ users:** Upgrade Render to paid ($7/month)
- **When you reach 1000+ users:** Consider dedicated MongoDB cluster
- **For production:** Use custom domain + SSL (free with Netlify/Render)

## CI/CD Setup (Optional)

Both Render and Netlify support auto-deploy on push to main branch.

**To enable:**
1. Render: Already enabled by default
2. Netlify: Already enabled by default

**To disable:**
1. Render: Settings → Auto-Deploy → Disable
2. Netlify: Site settings → Build & deploy → Stop builds

## Security Checklist

- [ ] JWT_SECRET is random and secure (32+ characters)
- [ ] AUTH_LITE_DEBUG=false in production
- [ ] MongoDB user has minimal required permissions
- [ ] CORS configured with specific frontend origin (not *)
- [ ] Environment variables never committed to Git
- [ ] SSL/HTTPS enabled (automatic with Render/Netlify)

## Support

For issues:
1. Check Render logs for backend errors
2. Check Netlify deploy logs for frontend errors
3. Check MongoDB Atlas logs for database issues
4. Review `contracts.md` for API documentation
