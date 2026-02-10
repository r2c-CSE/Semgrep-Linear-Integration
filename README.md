# 🔒 Semgrep → Linear Integration

Automatically create Linear tickets from Semgrep Pro security findings. This containerized application receives webhooks from Semgrep and creates well-formatted issues in your Linear workspace.

**Note**: This is an unofficial tool, provided as-is. If you have improvements to share, feel free to collaborate!

## ✨ Features

- 🎯 **Automatic ticket creation** from Semgrep findings
- 🧙 **Setup Wizard** - beautiful GUI that guides you through configuration
- 🚇 **Auto-tunnel for local dev** - built-in ngrok integration for local testing
- 🔐 **Webhook signature verification** for security
- 📊 **Severity-based prioritization** (Critical/High → Urgent, Medium → High, etc.)
- 🔄 **Duplicate detection** prevents creating multiple tickets for the same finding
- 🌐 **Status dashboard** with real-time activity log
- 🏭 **Production ready** - authentication, rate limiting, metrics, structured logging

---

## 🚀 Quick Start (Development)

### 1. Clone the Repository

```bash
git clone https://github.com/r2c-cse/semgrep-linear-integration.git
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
3. Paste the webhook URL from the setup wizard
4. Click **Subscribe**

---

## 🏭 Production Deployment

For production use, use the production-ready configuration:

### Option 1: Using docker-compose.prod.yml

```bash
# Create your production .env file
cat > .env << 'EOF'
# Required
LINEAR_API_KEY=lin_api_your_key_here
LINEAR_TEAM_ID=your_team_id
SEMGREP_WEBHOOK_SECRET=your_webhook_secret

# Authentication (choose at least one)
DASHBOARD_API_KEY=slw_your_generated_api_key
# Or use basic auth:
# DASHBOARD_USERNAME=admin
# DASHBOARD_PASSWORD=secure_password_here
EOF

# Start in production mode
docker-compose -f docker-compose.prod.yml up -d
```

### Option 2: Kubernetes/Helm

```yaml
# Example Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: semgrep-linear
spec:
  replicas: 2
  selector:
    matchLabels:
      app: semgrep-linear
  template:
    spec:
      containers:
      - name: semgrep-linear
        image: your-registry/semgrep-linear:latest
        ports:
        - containerPort: 8080
        env:
        - name: PRODUCTION
          value: "true"
        - name: LINEAR_API_KEY
          valueFrom:
            secretKeyRef:
              name: semgrep-linear-secrets
              key: linear-api-key
        # ... other env vars from secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
```

### Option 3: Cloud Platforms

#### AWS ECS / Fargate
```bash
# Build and push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_URL
docker build -t semgrep-linear .
docker tag semgrep-linear:latest $ECR_URL/semgrep-linear:latest
docker push $ECR_URL/semgrep-linear:latest

# Deploy via ECS Task Definition with environment variables
```

#### Google Cloud Run
```bash
gcloud builds submit --tag gcr.io/$PROJECT_ID/semgrep-linear
gcloud run deploy semgrep-linear \
  --image gcr.io/$PROJECT_ID/semgrep-linear \
  --set-env-vars "PRODUCTION=true,LINEAR_API_KEY=$LINEAR_API_KEY,..."
```

#### Azure Container Apps
```bash
az containerapp create \
  --name semgrep-linear \
  --resource-group mygroup \
  --image your-registry/semgrep-linear:latest \
  --env-vars "PRODUCTION=true" "LINEAR_API_KEY=secretref:linear-key"
```

---

## 🔐 Production Security Checklist

| Requirement | Description | How to Configure |
|-------------|-------------|------------------|
| ✅ **HTTPS** | Always use TLS in production | Use a reverse proxy (nginx, traefik) or cloud load balancer |
| ✅ **Webhook Secret** | Verify requests are from Semgrep | Set `SEMGREP_WEBHOOK_SECRET` |
| ✅ **Dashboard Auth** | Protect the UI from unauthorized access | Set `DASHBOARD_API_KEY` or `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` |
| ✅ **Rate Limiting** | Prevent abuse | Enabled by default (60 req/min) |
| ✅ **Non-root** | Container runs as unprivileged user | Built into Dockerfile |
| ✅ **Health Checks** | Monitor application health | Use `/health` and `/ready` endpoints |

---

## 📋 Environment Variables

### Required (Production)

| Variable | Description |
|----------|-------------|
| `LINEAR_API_KEY` | Your Linear personal API key (starts with `lin_api_`) |
| `LINEAR_TEAM_ID` | Team ID where issues are created |
| `SEMGREP_WEBHOOK_SECRET` | Secret for verifying webhook signatures |

### Authentication (Required in Production)

| Variable | Description |
|----------|-------------|
| `DASHBOARD_API_KEY` | API key for dashboard access (recommended) |
| `DASHBOARD_USERNAME` | Basic auth username (alternative) |
| `DASHBOARD_PASSWORD` | Basic auth password (alternative) |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LINEAR_PROJECT_ID` | - | Project to assign issues to |
| `LINEAR_DEFAULT_PRIORITY` | `2` | Default priority (1=Urgent to 4=Low) |
| `PRODUCTION` | `false` | Enable production mode |
| `PORT` | `8080` | Server port |
| `DEBUG` | `false` | Enable debug logging |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR |
| `LOG_FORMAT` | `text` | `json` for production, `text` for dev |
| `LOG_FILE` | - | Path to log file (also logs to stdout) |
| `ACTIVITY_LOG_FILE` | - | Path to persist activity history |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | `60` | Max webhook requests per minute per IP |
| `RATE_LIMIT_BURST` | `10` | Burst allowance |

### Linear API Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `LINEAR_API_TIMEOUT` | `30` | Request timeout in seconds |
| `LINEAR_API_RETRIES` | `3` | Retry attempts on failure |
| `LINEAR_API_RETRY_DELAY` | `1.0` | Delay between retries |

### Local Development Only

| Variable | Description |
|----------|-------------|
| `LOCAL_DEV` | Set to `true` to enable ngrok tunnel |
| `NGROK_AUTHTOKEN` | Your ngrok auth token |

---

## 🔧 API Endpoints

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | Semgrep webhook receiver |
| `/ping` | GET | Simple connectivity test |
| `/health` | GET | Health check (for load balancers) |
| `/ready` | GET | Readiness probe (fully configured) |
| `/metrics` | GET | Prometheus-compatible metrics |

### Protected Endpoints (require auth in production)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status dashboard |
| `/dashboard` | GET | Dashboard (always accessible) |
| `/setup` | GET | Setup wizard |
| `/api/activity` | GET | Activity log |
| `/api/teams` | GET | List Linear teams |
| `/api/projects/<team_id>` | GET | List projects |

### Accessing Protected Endpoints

**With API Key:**
```bash
curl -H "X-API-Key: your_api_key" http://localhost:8080/dashboard
```

**With Basic Auth:**
```bash
curl -u username:password http://localhost:8080/dashboard
```

**In Browser:**
- Add `?api_key=your_key` to URL, OR
- Browser will prompt for username/password

---

## 📊 Monitoring

### Prometheus Metrics

The `/metrics` endpoint exposes:

```
semgrep_linear_activities_total 42
semgrep_linear_issues_created_total 15
semgrep_linear_issues_skipped_total 5
semgrep_linear_webhooks_received_total 20
semgrep_linear_errors_total 2
semgrep_linear_up 1
```

### Health Checks

| Endpoint | Use Case |
|----------|----------|
| `/health` | Kubernetes liveness probe |
| `/ready` | Kubernetes readiness probe |
| `/ping` | Simple uptime check |

### Structured Logging (Production)

With `LOG_FORMAT=json`:
```json
{"timestamp": "2024-01-15T10:30:00", "level": "INFO", "logger": "app.main", "message": "Webhook received from 10.0.0.1"}
```

---

## 🐛 Troubleshooting

### Tickets not being created
1. Check logs: `docker-compose logs -f`
2. Verify webhook is enabled in Semgrep
3. Check the activity log in the dashboard
4. Ensure findings are new (duplicates are skipped)

### "Invalid signature" errors
- Ensure `SEMGREP_WEBHOOK_SECRET` matches Semgrep's configuration
- Or leave it empty to disable signature verification (not recommended)

### Rate limit errors
- Increase `RATE_LIMIT_PER_MINUTE` if legitimate traffic is high
- Check for duplicate webhook deliveries from Semgrep

### Linear API errors
- Verify your API key is valid
- Check if the team/project IDs are correct
- The app will retry failed requests automatically

---

## 📄 License

MIT License - feel free to use and modify!

---

Made with ❤️ for security teams
