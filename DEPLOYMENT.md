# Learnsphere Deployment Guide

This guide details how to deploy Learnsphere to production.

Learnsphere is designed as a unified full-stack Node.js / Express application that serves both the frontend web client (`index.html`, `courses.html`, `pmp-details.html`, `admin.html`) and the REST API backend (`/api/*`), connecting to MongoDB Atlas and Cloudflare R2.

---

## 1. Quick Deployment Platforms

### Option A: Render (Recommended - 1-Click / Blueprint)

1. Push your code to GitHub.
2. Sign in to [Render](https://render.com).
3. Click **New +** → **Blueprint**.
4. Connect your `learnsphere` repository.
5. Render will automatically detect `render.yaml` and configure the web service.
6. Provide the required environment variables in the Render dashboard:
   - `MONGO_URI`
   - `JWT_SECRET` (at least 32 characters, or let Render auto-generate)
   - `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`
   - `EMAIL_USER`, `EMAIL_PASS`, `RECEIVER_EMAIL`
7. Click **Apply**. Render will build and deploy the web service with automatic SSL.

---

### Option B: Railway

1. Sign in to [Railway](https://railway.app).
2. Click **New Project** → **Deploy from GitHub repo**.
3. Select `learnsphere`.
4. Go to **Variables** and add:
   ```env
   NODE_ENV=production
   PORT=5000
   MONGO_URI=mongodb+srv://...
   JWT_SECRET=your-random-secret-at-least-32-chars
   R2_ACCOUNT_ID=...
   R2_ACCESS_KEY_ID=...
   R2_SECRET_ACCESS_KEY=...
   R2_BUCKET_NAME=learnsphere-pmp
   EMAIL_USER=...
   EMAIL_PASS=...
   RECEIVER_EMAIL=...
   TRUST_PROXY=1
   ```
5. Railway will detect `Procfile` / `package.json` and deploy.
6. In **Settings** → **Networking**, click **Generate Domain**.

---

### Option C: Docker / VPS (DigitalOcean, AWS, Linode, Hetzner)

A production-ready `Dockerfile` and `.dockerignore` are included.

1. **Build the container image:**
   ```bash
   docker build -t learnsphere:latest .
   ```

2. **Run container with environment variables:**
   ```bash
   docker run -d \
     --name learnsphere \
     --restart unless-stopped \
     -p 5000:5000 \
     --env-file .env \
     learnsphere:latest
   ```

3. **Check container status and health:**
   ```bash
   docker ps
   curl http://localhost:5000/health
   ```

---

## 2. Environment Variables Checklist

| Variable | Required | Description | Example |
| :--- | :---: | :--- | :--- |
| `NODE_ENV` | Yes | Node environment | `production` |
| `PORT` | Yes | Server listen port | `5000` |
| `MONGO_URI` | Yes | MongoDB Atlas connection string | `mongodb+srv://user:pass@cluster.mongodb.net/learnsphere` |
| `JWT_SECRET` | Yes | Secret for signing tokens (min 32 chars) | `vX9...random-secret-key...92A` |
| `ALLOWED_ORIGINS` | Optional | Additional allowed CORS origins | `https://thelearnsphere.in,https://www.thelearnsphere.in` |
| `R2_ACCOUNT_ID` | Optional* | Cloudflare account ID | `804f2a91cdd7d479a04969c96de17e14` |
| `R2_ACCESS_KEY_ID` | Optional* | Cloudflare R2 API token key | `...` |
| `R2_SECRET_ACCESS_KEY` | Optional* | Cloudflare R2 API secret | `...` |
| `R2_BUCKET_NAME` | Optional* | Cloudflare R2 bucket name | `learnsphere-pmp` |
| `EMAIL_USER` | Optional | Gmail or SMTP sending address | `notifications@thelearnsphere.in` (or Gmail address) |
| `EMAIL_PASS` | Optional | Google Workspace / Gmail App Password | `abcd efgh ijkl mnop` |
| `RECEIVER_EMAIL` | Optional | Admin notification destination | `admin@thelearnsphere.in` |
| `ENABLE_ADMIN_SETUP` | Setup only | Enable `/api/setup-admin` endpoint | Set `true` once, then `false` |
| `ADMIN_SETUP_SECRET` | Setup only | Passphrase for admin setup endpoint | `your-secret-setup-phrase` |
| `TRUST_PROXY` | Recommended | Enable if behind reverse proxy/Cloudflare | `1` |

*\* Cloudflare R2 is required for PMP video lectures and PDF streaming. The server will safely start and serve the website without it, logging a clear warning.*

---

## 3. Initial Admin Account Setup

Once your app is live at `https://thelearnsphere.in`:

1. In your cloud dashboard environment settings, temporarily set:
   ```env
   ENABLE_ADMIN_SETUP=true
   ADMIN_SETUP_SECRET=my-temporary-secret-12345
   ```
2. Send a `POST` request to `/api/setup-admin`:
   ```bash
   curl -X POST https://thelearnsphere.in/api/setup-admin \
     -H "Content-Type: application/json" \
     -d '{
       "setupSecret": "my-temporary-secret-12345",
       "identifier": "admin@thelearnsphere.in",
       "password": "StrongAdminPassword123!"
     }'
   ```
3. Set `ENABLE_ADMIN_SETUP=false` immediately afterwards in your environment variables to lock the endpoint.
4. Log into the admin dashboard at `https://thelearnsphere.in/admin`.

---

## 4. Health Checks & Verification

- **Liveness probe:** `GET https://thelearnsphere.in/health` or `GET https://thelearnsphere.in/api/healthz` (Returns `200 OK` `{"status":"ok"}`)
- **Readiness / Diagnostic probe:** `GET https://thelearnsphere.in/api/health` (Returns detailed DB and storage connection status)
- **Frontend Pages:**
  - `GET https://thelearnsphere.in/` (Home)
  - `GET https://thelearnsphere.in/courses` (Course Catalog)
  - `GET https://thelearnsphere.in/pmp-details` (PMP Course Details)
  - `GET https://thelearnsphere.in/admin` (Admin Panel)

---

## 5. Custom Domain DNS Configuration (`thelearnsphere.in`)

To connect your purchased domain `thelearnsphere.in` (e.g. from GoDaddy, Namecheap, Cloudflare, or Hostinger):

### Step 1: Add Custom Domain in your Cloud Provider

- **Render:**
  1. Open your `learnsphere` Web Service on Render.
  2. Go to **Settings** → **Custom Domains**.
  3. Click **Add Custom Domain** and enter:
     - `thelearnsphere.in`
     - `www.thelearnsphere.in`
  4. Render will provide the exact DNS records (CNAME or ANAME/ALIAS) to point to.

- **Railway:**
  1. Open your project → **Service Settings** → **Networking**.
  2. Click **Custom Domain** and enter `thelearnsphere.in` and `www.thelearnsphere.in`.

### Step 2: Configure DNS Records at your Domain Registrar

Log into your DNS management portal (Cloudflare, GoDaddy, Namecheap, etc.) and add the following records:

| Type | Name / Host | Target / Value | TTL | Note |
| :--- | :--- | :--- | :--- | :--- |
| **CNAME** or **ALIAS/ANAME** | `@` (root) | Provided by Render/Railway (e.g. `learnsphere.onrender.com`) | Auto / 300 | Points `thelearnsphere.in` |
| **CNAME** | `www` | Provided by Render/Railway (e.g. `learnsphere.onrender.com`) | Auto / 300 | Points `www.thelearnsphere.in` |

*Note: If your DNS provider does not support CNAME flattening on root `@`, use an `A` record pointing to the static IP address provided by your host (Render provides A records for root domains).*

### Step 3: SSL / HTTPS Verification
- Both Render and Railway automatically provision a free Let's Encrypt SSL certificate once DNS propagates (usually takes 5 to 30 minutes).
- Your site will then be securely accessible at `https://thelearnsphere.in`.

