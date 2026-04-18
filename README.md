# Alarmist 🔔 — Production Deployment Guide
**wake up. get stuff done.**

Full-stack Flask app — SMS OTP login, user profiles, to-do tracker,
alarm clock with mini-games. Production-ready for Render.com.

---

## Project structure
```
alarmist/
├── app.py              ← Flask app (hardened for production)
├── gunicorn.conf.py    ← Production WSGI server config
├── render.yaml         ← Render.com blueprint (one-click deploy)
├── requirements.txt    ← Python dependencies
├── .env.example        ← Environment variables template
├── .gitignore
└── templates/
    └── index.html      ← Full frontend SPA
```

---

## Local development

```bash
cd alarmist
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env           # then edit .env
python app.py
```
Open http://localhost:5000

Generate a SECRET_KEY:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Deploy to Render.com

### 1. Push to GitHub
```bash
git init && git add . && git commit -m "Initial commit"
git remote add origin https://github.com/YOUR/alarmist.git
git push -u origin main
```

### 2. Connect on Render
- Go to https://render.com → New → Blueprint
- Connect your GitHub repo
- Render reads render.yaml and auto-creates the web service + PostgreSQL

### 3. Set Twilio env vars
In Render dashboard → your service → Environment:

| Key | Value |
|-----|-------|
| TWILIO_ACCOUNT_SID | From https://console.twilio.com |
| TWILIO_AUTH_TOKEN | From https://console.twilio.com |
| TWILIO_PHONE_NUMBER | Your Twilio number e.g. +15551234567 |

SECRET_KEY and DATABASE_URL are set automatically by the blueprint.

### 4. Deploy
Click Manual Deploy → Deploy latest commit.
Your app is live at https://alarmist.onrender.com

---

## Security hardening applied

| What | How |
|------|-----|
| HTTPS forced | Flask-Talisman + HSTS header |
| Secure cookies | SESSION_COOKIE_SECURE=True in prod |
| Security headers | CSP, X-Frame-Options, XSS protection |
| OTP hashed | SHA-256 — plain codes never stored in DB |
| Input validation | All API fields validated and sanitized |
| Rate limiting | 5 OTP/min, 10 verify/min, 500 req/day |
| SQL injection | SQLAlchemy ORM parameterized queries |
| Debug off | Auto-disabled when RENDER=true |
| DB pooling | pool_pre_ping + pool_recycle for stability |
| Error messages | Generic only — no stack traces exposed |

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/send-otp | No | Send OTP to phone |
| POST | /api/auth/verify-otp | No | Verify OTP, start session |
| POST | /api/auth/logout | No | Clear session |
| GET | /api/auth/me | Yes | Current user profile |
| DELETE | /api/auth/delete-account | Yes | Delete account + data |
| PUT | /api/profile | Yes | Update profile/settings |
| GET/POST | /api/todos | Yes | List / create todos |
| PUT/DELETE | /api/todos/:id | Yes | Update / delete todo |
| GET/POST | /api/alarms | Yes | List / create alarms |
| PUT/DELETE | /api/alarms/:id | Yes | Update / delete alarm |
| GET | /api/stats | Yes | Task + alarm statistics |
| GET | /health | No | Health check for Render |

---

## Demo Mode
Leave Twilio vars blank to run in Demo Mode:
- OTP printed to console (view via render logs)
- OTP shown on login screen (remove before going public)

## Upgrading free tier
Free tier sleeps after 15 min inactivity. Upgrade to Starter ($7/mo)
for always-on hosting. Free PostgreSQL expires after 90 days.
