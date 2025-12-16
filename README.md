# 🔒 Semgrep → Linear Integration

Automatically create Linear tickets from Semgrep Pro security findings. This containerized application receives webhooks from Semgrep and creates well-formatted issues in your Linear workspace.

## ✨ Features

- 🎯 **Automatic ticket creation** from Semgrep findings
- 🧙 **Setup Wizard** - beautiful GUI that guides you through configuration
- 🚇 **Auto-tunnel for local dev** - built-in ngrok integration for local testing
- 🔐 **Webhook signature verification** for security
- 📊 **Severity-based prioritization** (Critical/High → Urgent, Medium → High, etc.)
- 🔄 **Duplicate detection** prevents creating multiple tickets for the same finding
- 🌐 **Status dashboard** for monitoring

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/jpsemgrep/semgrep-linear-integration.git
cd semgrep-linear-integration
```

### 2. Start the Application

```bash
docker-compose up -d
```

### 3. Open the Setup Wizard

Go to **http://localhost:8080/setup** in your browser.

The wizard will guide you through:

| Step | What You'll Do |
|------|----------------|
| 1️⃣ | **Set up ngrok tunnel** - Get a public URL for local testing |
| 2️⃣ | **Enter Linear API key** - Validates and fetches your teams |
| 3️⃣ | **Select your team** - Choose where issues will be created |
| 4️⃣ | **Select a project** (optional) - Assign issues to a specific project |
| 5️⃣ | **Configure security** - Set webhook secret |
| 6️⃣ | **Done!** - Copy your webhook URL for Semgrep |

### 4. Configure Semgrep Webhook

1. Go to **Semgrep AppSec Platform** → **Settings** → **Integrations**
2. Click **Add** → Select **Webhook**
3. Paste the webhook URL from the setup wizard (e.g., `https://xxxx.ngrok-free.app/webhook`)
4. Set the Signature Secret (shown in wizard)
5. Click **Subscribe**

### 5. Enable Notifications

1. Go to **Rules** → **Policies** → **Rule Modes**
2. Enable **Webhook notifications** for desired rule modes (Block, Comment, Monitor)

---

## 📋 How Tickets Are Created

Once configured, Linear tickets are created automatically when Semgrep finds security issues:

### Trigger Methods

| Method | How It Works |
|--------|--------------|
| **CI/CD Scan** | Push code → Semgrep scans → Findings create tickets |
| **Manual CLI** | Run `semgrep ci` → Findings create tickets |
| **Dashboard Scan** | Click "Scan Now" in Semgrep → Findings create tickets |

### Example: Test the Integration

1. Create a file with a vulnerability:

```python
# test_vuln.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection!
    return conn.execute(query).fetchone()
```

2. Commit and push to a monitored repository
3. Check Linear for your new ticket! 🎉

### Ticket Format

| Field | Example |
|-------|---------|
| **Title** | `[Semgrep] HIGH: sql-injection in my-repo` |
| **Priority** | Urgent (Critical/High), High (Medium), Medium (Low) |
| **Description** | Finding details, code snippet, file location, remediation steps |

---

## 🖥️ Local Development

The setup wizard automatically handles ngrok tunnel creation:

1. **Get a free ngrok token** at https://dashboard.ngrok.com/get-started/your-authtoken
2. **Open the setup wizard** at http://localhost:8080/setup
3. **Paste your token** in Step 1
4. **Your public URL appears** instantly - use it in Semgrep!

---

## 🌐 Production Deployment

For production, deploy to a cloud service with HTTPS:

### Railway (Recommended)
```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

### Render
1. Connect your GitHub repo at [render.com](https://render.com)
2. Select **Docker** environment
3. Add environment variables

### Fly.io
```bash
curl -L https://fly.io/install.sh | sh
fly auth login
fly launch
fly deploy
```

### Google Cloud Run
```bash
gcloud builds submit --tag gcr.io/PROJECT_ID/semgrep-linear
gcloud run deploy semgrep-linear \
  --image gcr.io/PROJECT_ID/semgrep-linear \
  --platform managed \
  --allow-unauthenticated
```

---

## 📋 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LINEAR_API_KEY` | ✅ | Your Linear personal API key |
| `LINEAR_TEAM_ID` | ✅ | Team ID where issues are created |
| `LINEAR_PROJECT_ID` | ❌ | Optional project to assign issues |
| `LINEAR_DEFAULT_PRIORITY` | ❌ | Default priority 1-4 (default: 2) |
| `SEMGREP_WEBHOOK_SECRET` | ❌ | Secret for webhook verification |
| `LOCAL_DEV` | ❌ | Set to `true` to enable auto-tunnel |
| `NGROK_AUTHTOKEN` | ❌ | ngrok auth token for local tunneling |
| `PORT` | ❌ | Server port (default: 8080) |
| `DEBUG` | ❌ | Enable debug logging (default: false) |

---

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status dashboard |
| `/setup` | GET | Setup wizard |
| `/health` | GET | Health check |
| `/webhook` | POST | Semgrep webhook receiver |
| `/api/teams` | GET | List Linear teams |
| `/api/projects/<team_id>` | GET | List projects for a team |
| `/api/tunnel/status` | GET | Check tunnel status |
| `/api/tunnel/configure` | POST | Configure ngrok and start tunnel |

---

## 🔒 Security

- **Webhook Verification:** Set `SEMGREP_WEBHOOK_SECRET` to verify incoming requests
- **API Key Security:** Use environment variables; never commit `.env` files
- **HTTPS Required:** Always use HTTPS in production
- **Non-root Container:** Runs as unprivileged user

---

## 🐛 Troubleshooting

### Tickets not being created
1. Check logs: `docker-compose logs -f`
2. Verify webhook is enabled in Semgrep for your rule modes
3. Ensure findings are new (duplicates are skipped)

### "Invalid webhook URL" in Semgrep
- You need a **public URL**, not localhost
- Use the ngrok URL from the setup wizard
- Example: `https://abc123.ngrok-free.app/webhook`

### Tunnel not starting
1. Check your ngrok token is valid
2. Ensure you're using a free or paid ngrok account
3. Check logs for errors: `docker-compose logs -f`

---

## 📄 License

MIT License - feel free to use and modify!

---

Made with ❤️ for security teams
