"""
Semgrep → Linear Integration - Main Application
Production-ready webhook handler for creating Linear issues from Semgrep findings.
"""
import os
import sys
import json
import logging
import hmac
import hashlib
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, render_template, redirect, g, make_response
from .config import config
from .linear_client import LinearClient
from .webhook_handler import WebhookHandler
from . import tunnel
from . import activity
from .middleware import init_rate_limiter, rate_limit, require_auth, validate_webhook_payload


# ============================================
# Logging Configuration
# ============================================

def setup_logging():
    """Configure logging based on environment."""
    log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    
    # JSON formatter for production
    if config.LOG_FORMAT == "json":
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    "timestamp": self.formatTime(record),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                }
                if record.exc_info:
                    log_data["exception"] = self.formatException(record.exc_info)
                return json.dumps(log_data)
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if configured)
    if config.LOG_FILE:
        file_handler = RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return logging.getLogger(__name__)


logger = setup_logging()


# ============================================
# Application Initialization
# ============================================

app = Flask(__name__)

# Configure app
app.config["MAX_CONTENT_LENGTH"] = config.WEBHOOK_MAX_PAYLOAD_SIZE_KB * 1024

# Initialize rate limiter
init_rate_limiter(config.RATE_LIMIT_PER_MINUTE, config.RATE_LIMIT_BURST)

# Configure activity log persistence
activity.configure(
    log_file=config.ACTIVITY_LOG_FILE,
    max_size_mb=config.ACTIVITY_LOG_MAX_SIZE_MB
)

# Initialize clients (will be None if not configured)
linear_client = LinearClient(
    config.LINEAR_API_KEY,
    timeout=config.LINEAR_API_TIMEOUT,
    max_retries=config.LINEAR_API_RETRIES,
    retry_delay=config.LINEAR_API_RETRY_DELAY
) if config.LINEAR_API_KEY else None

webhook_handler = WebhookHandler(linear_client) if linear_client else None

# Validate production configuration
if config.PRODUCTION:
    production_errors = config.validate_production()
    if production_errors:
        logger.error("Production configuration errors:")
        for error in production_errors:
            logger.error(f"  - {error}")
        if not config.DEBUG:
            logger.warning("Starting anyway, but some features may not work correctly")

# Start ngrok tunnel if in local dev mode (not in production)
if not config.PRODUCTION and tunnel.is_local_development():
    public_url = tunnel.start_tunnel(config.PORT)
    if public_url:
        logger.info(f"✅ Local development mode - tunnel active")
        activity.log_activity("startup", f"Server started with ngrok tunnel", {"public_url": public_url}, "success")
    else:
        logger.warning("⚠️  Local dev mode enabled but tunnel failed to start. Set NGROK_AUTHTOKEN.")
        activity.log_activity("startup", "Server started (tunnel not active)", {}, "warning")
else:
    mode = "production" if config.PRODUCTION else "standard"
    activity.log_activity("startup", f"Server started ({mode} mode)", {"production": config.PRODUCTION}, "info")


# ============================================
# Helper Functions
# ============================================

def is_configured():
    """Check if the integration is configured."""
    return bool(config.LINEAR_API_KEY and config.LINEAR_TEAM_ID)


def reinitialize_clients():
    """Reinitialize clients after configuration changes."""
    global linear_client, webhook_handler
    config.reload()
    logger.info(f"Config reloaded: LINEAR_API_KEY={'set' if config.LINEAR_API_KEY else 'empty'}, LINEAR_TEAM_ID={config.LINEAR_TEAM_ID}")
    linear_client = LinearClient(
        config.LINEAR_API_KEY,
        timeout=config.LINEAR_API_TIMEOUT,
        max_retries=config.LINEAR_API_RETRIES,
        retry_delay=config.LINEAR_API_RETRY_DELAY
    ) if config.LINEAR_API_KEY else None
    webhook_handler = WebhookHandler(linear_client) if linear_client else None


def render_dashboard():
    """Render the main dashboard page."""
    config.reload()
    reinitialize_clients()
    
    validation_errors = config.validate()
    linear_connected = False
    teams = []
    
    if linear_client and not validation_errors:
        try:
            linear_connected = linear_client.test_connection()
            if linear_connected:
                teams = linear_client.get_teams()
        except Exception as e:
            logger.error(f"Error testing Linear connection: {e}")
    
    webhook_url = tunnel.get_webhook_url(request.host)
    
    return render_template(
        "status.html",
        config=config,
        validation_errors=validation_errors,
        linear_connected=linear_connected,
        teams=teams,
        webhook_configured=bool(config.SEMGREP_WEBHOOK_SECRET),
        webhook_url=webhook_url,
        tunnel_active=tunnel.get_public_url() is not None,
        public_url=tunnel.get_public_url(),
        production_mode=config.PRODUCTION,
        auth_enabled=config.is_dashboard_auth_enabled()
    )


# ============================================
# Dashboard Routes (with optional auth)
# ============================================

@app.route("/", methods=["GET"])
@require_auth(config)
def index():
    """Root route - redirect to setup only on first visit when not configured."""
    skip_setup = request.cookies.get('setup_visited') or request.args.get('dashboard')
    
    if not is_configured() and not skip_setup:
        return redirect("/setup")
    
    return render_dashboard()


@app.route("/dashboard", methods=["GET"])
@require_auth(config)
def dashboard():
    """Dashboard page - always accessible, shows status regardless of configuration."""
    return render_dashboard()


@app.route("/setup", methods=["GET"])
def setup():
    """Setup wizard page (no auth required to enable initial setup)."""
    response = make_response(render_template("setup.html"))
    response.set_cookie('setup_visited', 'true', max_age=30*24*60*60, httponly=True, samesite='Lax')
    return response


# ============================================
# Health & Monitoring Endpoints
# ============================================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for container orchestration."""
    errors = config.validate()
    
    # Don't expose detailed errors in production unless authenticated
    if errors and config.PRODUCTION and not request.args.get('detailed'):
        return jsonify({"status": "unhealthy"}), 503
    
    if errors:
        return jsonify({
            "status": "unhealthy",
            "errors": errors
        }), 503
    
    linear_ok = False
    try:
        if linear_client:
            linear_ok = linear_client.test_connection()
    except Exception:
        pass
    
    return jsonify({
        "status": "healthy",
        "linear_connected": linear_ok,
        "tunnel_active": tunnel.get_public_url() is not None,
        "production": config.PRODUCTION
    })


@app.route("/ready", methods=["GET"])
def ready():
    """Readiness probe - returns 200 only if fully configured and connected."""
    if not is_configured():
        return jsonify({"ready": False, "reason": "not_configured"}), 503
    
    try:
        if linear_client and not linear_client.test_connection():
            return jsonify({"ready": False, "reason": "linear_disconnected"}), 503
    except Exception:
        return jsonify({"ready": False, "reason": "linear_error"}), 503
    
    return jsonify({"ready": True})


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus-compatible metrics endpoint."""
    metrics_data = activity.get_metrics()
    
    # Format as Prometheus text format
    output = []
    for key, value in metrics_data.items():
        output.append(f"# TYPE {key} counter")
        output.append(f"{key} {value}")
    
    # Add uptime metric
    output.append("# TYPE semgrep_linear_up gauge")
    output.append("semgrep_linear_up 1")
    
    response = make_response("\n".join(output))
    response.headers["Content-Type"] = "text/plain; version=0.0.4"
    return response


@app.route("/ping", methods=["GET", "POST", "OPTIONS"])
def ping():
    """Simple ping endpoint - always returns 200."""
    return jsonify({"status": "ok", "message": "pong"}), 200


# ============================================
# Webhook Endpoint (rate limited)
# ============================================
@app.route("/webhook", methods=["GET", "POST", "OPTIONS"])
@rate_limit
@validate_webhook_payload(config.WEBHOOK_MAX_PAYLOAD_SIZE_KB)
def webhook():
    """Main webhook endpoint for Semgrep events."""
    global linear_client, webhook_handler

    # Handle preflight OPTIONS request (CORS)
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        # IMPORTANT: must match the actual header the client sends
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Semgrep-Signature-256"
        return response, 200

    # Handle GET request (connectivity test)
    if request.method == "GET":
        logger.info("Webhook GET request received (connectivity test)")
        return jsonify({
            "status": "ok",
            "message": "Semgrep-Linear webhook endpoint is active",
            "method": "GET",
            "info": "Send POST requests with Semgrep findings to create Linear issues"
        }), 200

    # POST request - process webhook
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    logger.info(f"Webhook POST received from {client_ip}")
    activity.log_activity("webhook_received", f"Webhook from {client_ip}", {"method": "POST"}, "info")

    # Reload config and reinitialize if needed
    config.reload()
    if config.LINEAR_API_KEY and not webhook_handler:
        linear_client = LinearClient(
            config.LINEAR_API_KEY,
            timeout=config.LINEAR_API_TIMEOUT,
            max_retries=config.LINEAR_API_RETRIES,
            retry_delay=config.LINEAR_API_RETRY_DELAY
        )
        webhook_handler = WebhookHandler(linear_client)

    if not webhook_handler:
        logger.warning("Webhook received but Linear not configured")
        return jsonify({"error": "Integration not configured"}), 503

    # ============================================================
    # Parse JSON payload first (needed for signature verification)
    # ============================================================
    raw_body: bytes = request.get_data(cache=True, as_text=False)
    
    if not raw_body:
        return jsonify({"error": "Empty payload"}), 400

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        logger.warning(f"Invalid JSON: {e} raw_preview={raw_body[:200]!r}")
        activity.log_activity("webhook_error", "Invalid JSON payload", {}, "error")
        return jsonify({"error": "Invalid JSON"}), 400

    # ============================================================
    # Signature verification (per Semgrep docs)
    # Semgrep computes signature on compact JSON: json.dumps(payload, separators=(',', ':'))
    # ============================================================
    provided_sig = request.headers.get("X-Semgrep-Signature-256", "") or ""
    secret_str = (getattr(config, "SEMGREP_WEBHOOK_SECRET", "") or "").strip()

    if secret_str:
        # Re-serialize payload as compact JSON (no spaces) per Semgrep's method
        payload_str = json.dumps(payload, separators=(',', ':'))
        
        computed_sig = hmac.new(
            secret_str.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Handle both formats: raw hex or "sha256=<hex>" prefix
        if provided_sig.startswith("sha256="):
            provided_sig = provided_sig[len("sha256="):]
        provided_sig = provided_sig.strip().lower()
        computed_sig = computed_sig.lower()

        logger.info(f"sig_debug provided={provided_sig}")
        logger.info(f"sig_debug computed={computed_sig}")

        if not hmac.compare_digest(provided_sig, computed_sig):
            logger.warning("Invalid webhook signature")
            activity.log_activity("signature_invalid", "Invalid webhook signature", {}, "error")
            return jsonify({"error": "Invalid signature"}), 401
        
        logger.info("Webhook signature verified successfully")
    else:
        logger.info("Signature verification skipped: SEMGREP_WEBHOOK_SECRET not configured")

    try:
        results = []
        logger.debug(f"Webhook payload type: {type(payload).__name__}")

        # Handle array of findings
        if isinstance(payload, list):
            logger.info(f"Processing {len(payload)} items from array")
            for item in payload:
                if isinstance(item, dict):
                    if "semgrep_finding" in item:
                        result = webhook_handler.process_finding(item["semgrep_finding"])
                    elif "text" in item or "username" in item:
                        continue  # Skip Slack notifications
                    else:
                        result = webhook_handler.process_finding(item)
                    results.append(result)
            return jsonify({"status": "success", "processed": len(results), "results": results}), 200

        # Handle dict payload
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid payload type"}), 400

        event_type = payload.get("type", "unknown")

        if event_type == "semgrep_finding" or "semgrep_finding" in payload:
            finding = payload.get("semgrep_finding", payload.get("finding", payload))
            results.append(webhook_handler.process_finding(finding))

        elif event_type == "semgrep_scan" or "semgrep_scan" in payload:
            scan = payload.get("semgrep_scan", payload.get("scan", payload))
            results.append(webhook_handler.process_scan(scan))
            for finding in payload.get("findings", []):
                results.append(webhook_handler.process_finding(finding))

        elif "findings" in payload:
            for finding in payload.get("findings", []):
                results.append(webhook_handler.process_finding(finding))

        elif "data" in payload and isinstance(payload.get("data"), dict):
            data = payload["data"]
            for finding in data.get("findings", [data]):
                results.append(webhook_handler.process_finding(finding))

        elif any(k in payload for k in ["rule", "severity", "check_id", "path"]):
            results.append(webhook_handler.process_finding(payload))

        else:
            logger.warning(f"Unknown payload type: {event_type}, keys: {list(payload.keys())}")
            return jsonify({"warning": f"Unknown event type: {event_type}"}), 200

        return jsonify({"status": "success", "processed": len(results), "results": results}), 200

    except Exception as e:
        logger.exception(f"Webhook error: {e}")
        activity.log_activity("webhook_error", str(e)[:200], {}, "error")
        return jsonify({"error": str(e)}), 500


# ============================================
# API Endpoints
# ============================================

@app.route("/api/activity", methods=["GET"])
def get_activity():
    """Get recent activity log."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify({
        "activities": activity.get_activities(limit),
        "stats": activity.get_stats()
    })


@app.route("/api/activities", methods=["GET"])
def get_activities_alias():
    """Alias for /api/activity."""
    return get_activity()


@app.route("/test-webhook", methods=["GET", "POST"])
@require_auth(config)
def test_webhook():
    """Test endpoint to verify the integration works."""
    config.reload()
    
    if not config.LINEAR_API_KEY or not config.LINEAR_TEAM_ID:
        return jsonify({
            "status": "error",
            "message": "Integration not configured",
            "configured": False
        }), 400
    
    try:
        test_client = LinearClient(config.LINEAR_API_KEY)
        connected = test_client.test_connection()
        teams = test_client.get_teams() if connected else []
        
        return jsonify({
            "status": "success",
            "message": "Integration is working!",
            "configured": True,
            "linear_connected": connected,
            "team_count": len(teams),
            "webhook_url": tunnel.get_webhook_url(request.host)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Linear connection failed: {e}",
            "configured": True,
            "linear_connected": False
        }), 500


@app.route("/api/teams", methods=["GET"])
@require_auth(config)
def get_teams():
    """Get available Linear teams."""
    if not linear_client:
        return jsonify({"error": "Linear not configured"}), 503
    try:
        return jsonify({"teams": linear_client.get_teams()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/projects/<team_id>", methods=["GET"])
@require_auth(config)
def get_projects(team_id: str):
    """Get projects for a team."""
    if not linear_client:
        return jsonify({"error": "Linear not configured"}), 503
    try:
        return jsonify({"projects": linear_client.get_projects(team_id)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================
# Setup Wizard API
# ============================================

@app.route("/api/setup/validate-key", methods=["POST"])
def validate_api_key():
    """Validate a Linear API key."""
    try:
        data = request.get_json()
        api_key = data.get("api_key", "").strip()
        
        if not api_key or not api_key.startswith("lin_api_"):
            return jsonify({"valid": False, "error": "Invalid API key format"})
        
        test_client = LinearClient(api_key)
        teams = test_client.get_teams()
        return jsonify({"valid": True, "teams": teams})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/api/setup/projects", methods=["POST"])
def get_team_projects():
    """Get projects for a team using provided API key."""
    try:
        data = request.get_json()
        api_key = data.get("api_key", "").strip()
        team_id = data.get("team_id", "").strip()
        
        if not api_key or not team_id:
            return jsonify({"projects": [], "error": "Missing parameters"})
        
        test_client = LinearClient(api_key)
        return jsonify({"projects": test_client.get_projects(team_id)})
    except Exception as e:
        return jsonify({"projects": [], "error": str(e)})


@app.route("/api/setup/save", methods=["POST"])
def save_configuration():
    """Save configuration to .env file."""
    try:
        data = request.get_json()
        
        api_key = data.get("api_key", "").strip()
        team_id = data.get("team_id", "").strip()
        project_id = data.get("project_id", "").strip()
        webhook_secret = data.get("webhook_secret", "").strip()
        debug = data.get("debug", False)
        
        if not api_key or not team_id:
            return jsonify({"success": False, "error": "Missing required fields"})
        
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        
        # Preserve existing values
        ngrok_token = os.getenv("NGROK_AUTHTOKEN", "")
        local_dev = os.getenv("LOCAL_DEV", "false")
        production = os.getenv("PRODUCTION", "false")
        dashboard_key = os.getenv("DASHBOARD_API_KEY", "")
        
        env_content = f"""# Semgrep → Linear Integration Configuration
# Generated by Setup Wizard

# Linear API Configuration
LINEAR_API_KEY={api_key}
LINEAR_TEAM_ID={team_id}
LINEAR_PROJECT_ID={project_id}
LINEAR_DEFAULT_PRIORITY=2

# Semgrep Webhook Configuration
SEMGREP_WEBHOOK_SECRET={webhook_secret}

# Application Settings
PORT=8080
DEBUG={'true' if debug else 'false'}
PRODUCTION={production}

# Dashboard Authentication (optional)
DASHBOARD_API_KEY={dashboard_key}

# Logging
LOG_LEVEL={'DEBUG' if debug else 'INFO'}
LOG_FORMAT=text

# Local Development
LOCAL_DEV={local_dev}
NGROK_AUTHTOKEN={ngrok_token}
"""
        
        with open(env_path, "w") as f:
            f.write(env_content)
        
        # Update environment
        os.environ["LINEAR_API_KEY"] = api_key
        os.environ["LINEAR_TEAM_ID"] = team_id
        os.environ["LINEAR_PROJECT_ID"] = project_id
        os.environ["SEMGREP_WEBHOOK_SECRET"] = webhook_secret
        os.environ["DEBUG"] = "true" if debug else "false"
        
        reinitialize_clients()
        
        return jsonify({
            "success": True,
            "webhook_url": tunnel.get_webhook_url(request.host)
        })
    except Exception as e:
        logger.exception(f"Failed to save configuration: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/tunnel/status", methods=["GET"])
def tunnel_status():
    """Get tunnel status."""
    public_url = tunnel.get_public_url()
    return jsonify({
        "active": public_url is not None,
        "public_url": public_url,
        "webhook_url": f"{public_url}/webhook" if public_url else None,
        "local_dev": tunnel.is_local_development(),
        "ngrok_configured": bool(tunnel.get_ngrok_auth_token())
    })


@app.route("/api/tunnel/configure", methods=["POST"])
def configure_tunnel():
    """Configure ngrok and start tunnel."""
    try:
        data = request.get_json()
        ngrok_token = data.get("ngrok_token", "").strip()
        
        if not ngrok_token:
            return jsonify({"success": False, "error": "ngrok token required"})
        
        os.environ["NGROK_AUTHTOKEN"] = ngrok_token
        os.environ["LOCAL_DEV"] = "true"
        
        public_url = tunnel.start_tunnel(config.PORT)
        
        if public_url:
            # Persist to .env
            env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    content = f.read()
                
                lines = content.split("\n")
                new_lines = []
                found_ngrok = found_local = False
                
                for line in lines:
                    if line.startswith("NGROK_AUTHTOKEN="):
                        new_lines.append(f"NGROK_AUTHTOKEN={ngrok_token}")
                        found_ngrok = True
                    elif line.startswith("LOCAL_DEV="):
                        new_lines.append("LOCAL_DEV=true")
                        found_local = True
                    else:
                        new_lines.append(line)
                
                if not found_ngrok:
                    new_lines.append(f"NGROK_AUTHTOKEN={ngrok_token}")
                if not found_local:
                    new_lines.append("LOCAL_DEV=true")
                
                with open(env_path, "w") as f:
                    f.write("\n".join(new_lines))
            
            return jsonify({
                "success": True,
                "public_url": public_url,
                "webhook_url": f"{public_url}/webhook"
            })
        
        return jsonify({"success": False, "error": "Failed to start tunnel"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/tunnel/start", methods=["POST"])
def start_tunnel_endpoint():
    """Start ngrok tunnel."""
    if not tunnel.get_ngrok_auth_token():
        return jsonify({"success": False, "error": "NGROK_AUTHTOKEN not configured"}), 400
    
    public_url = tunnel.start_tunnel(config.PORT)
    if public_url:
        return jsonify({
            "success": True,
            "public_url": public_url,
            "webhook_url": f"{public_url}/webhook"
        })
    return jsonify({"success": False, "error": "Failed to start tunnel"}), 500


# ============================================
# Application Factory
# ============================================

def create_app():
    """Application factory for WSGI servers."""
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=config.DEBUG)
