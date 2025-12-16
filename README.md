# 🔒 Semgrep → Linear Integration

Automatically create Linear tickets from Semgrep Pro security findings. This containerized application receives webhooks from Semgrep and creates well-formatted issues in your Linear workspace.

## ✨ Features

- 🎯 **Automatic ticket creation** from Semgrep findings
- 🧙 **Setup Wizard** - beautiful GUI for easy configuration
- 🚇 **Auto-tunnel for local dev** - ngrok integration for local testing
- 🔐 **Webhook signature verification** for security
- 📊 **Severity-based prioritization** (Critical/High → Urgent, Medium → High, etc.)
- 🔄 **Duplicate detection** prevents creating multiple tickets for the same finding
- 🌐 **Status dashboard** for monitoring

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/johnpeterappsectesting/semgrep-linear-integration.git
cd semgrep-linear-integration
```

### 2. Start the Application

**For Local Development/Testing:**
```bash
# Set your ngrok auth token (get free token at https://dashboard.ngrok.com)
export NGROK_AUTHTOKEN=your_ngrok_token_here
export LOCAL_DEV=true

# Start with Docker Compose
docker-compose up -d
```

**For Production:**
```bash
docker-compose up -d
```

### 3. Run the Setup Wizard

Open your browser and go to:
```
http://localhost:8080/setup
```

The setup wizard will guide you through:
1. **Enter your Linear API key** - validates and fetches your teams
2. **Select your team** - choose where issues will be created
3. **Select a project** (optional) - assign issues to a specific project
4. **Configure security** - set webhook secret and debug options

### 4. Configure Semgrep Webhook

After completing the wizard:
1. Go to **Semgrep AppSec Platform** → **Settings** → **Integrations**
2. Click **Add** → Select **Webhook**
3. Enter your webhook URL (shown in the dashboard - use the ngrok URL for local testing)
4. Set the Signature Secret (shown in wizard)
5. Click **Subscribe**

### 5. Enable Notifications for Rule Modes

1. Go to **Rules** → **Policies** → **Rule Modes**
2. Click on a rule mode (e.g., "Block", "Comment", "Monitor")
3. Enable **Webhook notifications** for that mode
4. Repeat for each rule mode you want to trigger Linear tickets

---

## 📋 How to Create Linear Tickets via Semgrep

Once the integration is configured, Linear tickets are created automatically when Semgrep finds security issues. Here's how it works:

### Method 1: CI/CD Scan (Automatic)

When Semgrep runs in your CI/CD pipeline and finds issues:

1. **Push code to your repository** that Semgrep is monitoring
2. **Semgrep automatically scans** the code during CI/CD
3. **If findings match your policy**, Semgrep sends a webhook
4. **This integration receives the webhook** and creates a Linear ticket

```yaml
# Example: GitHub Actions with Semgrep
name: Semgrep
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: semgrep/semgrep-action@v1
        with:
          publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
```

### Method 2: Manual Scan via CLI

Trigger a scan manually and findings will create tickets:

```bash
# Login to Semgrep
semgrep login

# Run a scan that reports to Semgrep Cloud
semgrep ci
```

### Method 3: Semgrep Cloud Dashboard

1. Go to **Semgrep AppSec Platform** → **Projects**
2. Select a project and click **Scan Now**
3. Any findings that match your webhook-enabled policies will create tickets

### What Triggers a Ticket?

Tickets are created when:
- ✅ A **new finding** is detected (not already seen)
- ✅ The finding's **rule mode** has webhook notifications enabled
- ✅ The finding **severity** matches your configured policies

Tickets are **NOT** created when:
- ❌ The same finding already exists (duplicate detection)
- ❌ The rule mode doesn't have webhooks enabled
- ❌ The finding was marked as ignored/false positive in Semgrep

### Example: Testing the Integration

1. **Create a test file** with a known vulnerability:

```python
# test_vuln.py - SQL Injection example
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    # Vulnerable to SQL injection!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()
```

2. **Commit and push** to a monitored repository
3. **Watch the scan** in Semgrep Dashboard
4. **Check Linear** for the new ticket!

### Ticket Format

Created tickets include:
- **Title:** `[Semgrep] SEVERITY: Rule Name in repo-name`
- **Priority:** Based on severity (Critical/High → Urgent, Medium → High, Low → Medium)
- **Description:**
  - Finding ID and rule information
  - File location with line numbers
  - Code snippet showing the issue
  - Link to view in repository
  - Remediation guidance

---

## 🖥️ Local Development with Auto-Tunnel

For local testing, the app can automatically create an ngrok tunnel:

### Setup

1. **Get a free ngrok token** at https://dashboard.ngrok.com/get-started/your-authtoken

2. **Configure environment variables:**
```bash
export NGROK_AUTHTOKEN=your_token_here
export LOCAL_DEV=true
```

3. **Start the application:**
```bash
docker-compose up -d
```

4. **Check the dashboard** at http://localhost:8080 - your public ngrok URL will be displayed!

The tunnel URL (e.g., `https://abc123.ngrok-free.app/webhook`) can be used directly in Semgrep's webhook configuration.

---

## 🌐 Production Hosting Options

For production, deploy to a cloud service with HTTPS:

### Railway (Recommended - Free Tier)
```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

### Render (Free Tier)
1. Connect your GitHub repo at [render.com](https://render.com)
2. Select **Docker** environment
3. Add environment variables

### Fly.io (Free Tier)
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

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status dashboard |
| `/setup` | GET | Setup wizard |
| `/health` | GET | Health check (for load balancers) |
| `/webhook` | POST | Semgrep webhook receiver |
| `/api/teams` | GET | List available Linear teams |
| `/api/projects/<team_id>` | GET | List projects for a team |
| `/api/tunnel/status` | GET | Check tunnel status |
| `/api/tunnel/start` | POST | Manually start tunnel |

## 🔒 Security Considerations

1. **Webhook Verification:** Always set `SEMGREP_WEBHOOK_SECRET` in production
2. **API Key Security:** Use environment variables or secrets management
3. **HTTPS Required:** Deploy behind HTTPS for production
4. **Non-root Container:** The container runs as a non-root user

## 🐛 Troubleshooting

### Tickets not being created

1. **Check the logs:** `docker-compose logs -f`
2. **Verify webhook is enabled** in Semgrep for your rule modes
3. **Check LINEAR_TEAM_ID** is correct (visible in dashboard)
4. **Ensure findings are new** (duplicates are skipped)

### Webhook URL invalid error

- For local testing, ensure `LOCAL_DEV=true` and `NGROK_AUTHTOKEN` are set
- The ngrok tunnel URL will be shown in the dashboard
- Use the full URL: `https://xxxx.ngrok-free.app/webhook`

### Signature verification failed

1. Ensure `SEMGREP_WEBHOOK_SECRET` matches Semgrep's configured secret
2. Check for trailing whitespace in the secret

### Connection issues

1. Check your server is accessible from the internet
2. Verify firewall rules allow port 8080
3. For local dev, ensure ngrok tunnel is running

## 📄 License

MIT License - feel free to use and modify!

---

Made with ❤️ for security teams
