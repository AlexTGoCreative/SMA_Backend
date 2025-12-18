# Backend Deployment Guide

## Option 1: Deploy to Render.com (Recommended)

### Step 1: Setup MongoDB Atlas (Free)
1. Go to https://www.mongodb.com/cloud/atlas/register
2. Create a free account
3. Create a new cluster (M0 Free tier)
4. Click "Connect" → "Connect your application"
5. Copy the connection string (looks like: `mongodb+srv://username:password@cluster.mongodb.net/expoapp`)

### Step 2: Deploy to Render
1. Go to https://render.com and sign up
2. Click "New +" → "Web Service"
3. Connect your GitHub account (or use "Public Git repository")
4. If using GitHub:
   - Push your backend folder to a GitHub repo
   - Select the repository
5. Configure:
   - **Name**: expo-auth-backend
   - **Root Directory**: backend (if your backend is in a subfolder)
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Plan**: Free

### Step 3: Add Environment Variables
In Render dashboard, go to "Environment" and add:
- `MONGODB_URI`: Your MongoDB Atlas connection string
- `JWT_SECRET`: A random secret key (generate one at https://randomkeygen.com/)
- `NODE_ENV`: production

### Step 4: Deploy
- Click "Create Web Service"
- Wait for deployment (takes 2-3 minutes)
- Copy your service URL (e.g., `https://expo-auth-backend.onrender.com`)

### Step 5: Update Frontend
In your `utils/api.js`, change:
```javascript
const API_URL = 'https://your-service-name.onrender.com/api';
```

---

## Option 2: Deploy to Railway.app

### Step 1: Setup MongoDB Atlas (same as above)

### Step 2: Deploy to Railway
1. Go to https://railway.app and sign up
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Railway will auto-detect Node.js

### Step 3: Add Environment Variables
- `MONGODB_URI`: Your MongoDB Atlas connection string
- `JWT_SECRET`: A random secret key
- `PORT`: 3000

### Step 4: Deploy
- Railway will automatically deploy
- Copy your service URL

---

## Option 3: Deploy to Fly.io

### Step 1: Install Fly CLI
```bash
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"
```

### Step 2: Login and Deploy
```bash
cd backend
fly auth login
fly launch
```

Follow the prompts and add environment variables when asked.

---

## Testing Your Deployed Backend

Once deployed, test your backend:
```bash
curl https://your-backend-url.com/
```

You should see: `{"message":"Server is running!"}`

---

## Important Notes

⚠️ **Free Tier Limitations:**
- Render: Service sleeps after 15 minutes of inactivity (first request takes ~30 seconds to wake up)
- Railway: $5 credit per month
- Fly.io: Limited to 3 apps on free tier

💡 **Tip:** For production apps, consider upgrading to a paid plan for better performance.

