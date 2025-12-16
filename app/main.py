import os
import logging
from flask import Flask, request, jsonify, render_template, redirect
from .config import config
from .linear_client import LinearClient
from .webhook_handler import WebhookHandler
from . import tunnel

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize clients (will be None if not configured)
linear_client = LinearClient(config.LINEAR_API_KEY) if config.LINEAR_API_KEY else None
webhook_handler = WebhookHandler(linear_client) if linear_client else None

# Start ngrok tunnel if in local dev mode
if tunnel.is_local_development():
    public_url = tunnel.start_tunnel(config.PORT)
    if public_url:
        logger.info(f"✅ Local development mode - tunnel active")
    else:
        logger.warning("⚠️  Local dev mode enabled but tunnel failed to start. Set NGROK_AUTHTOKEN.")


def is_configured():
    """Check if the integration is configured."""
    return bool(config.LINEAR_API_KEY and config.LINEAR_TEAM_ID)


def reinitialize_clients():
    """Reinitialize clients after configuration changes."""
    global linear_client, webhook_handler
    # Reload config from environment (uses singleton)
    config.reload()
    logger.info(f"Config reloaded: LINEAR_API_KEY={'set' if config.LINEAR_API_KEY else 'empty'}, LINEAR_TEAM_ID={config.LINEAR_TEAM_ID}")
    linear_client = LinearClient(config.LINEAR_API_KEY) if config.LINEAR_API_KEY else None
    webhook_handler = WebhookHandler(linear_client) if linear_client else None


@app.route("/", methods=["GET"])
def index():
    """Status page or redirect to setup wizard."""
    if not is_configured():
        return redirect("/setup")
    
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
    
    # Get webhook URL (uses tunnel if available)
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
        public_url=tunnel.get_public_url()
    )


@app.route("/setup", methods=["GET"])
def setup():
    """Setup wizard page."""
    return render_template("setup.html")


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    errors = config.validate()
    if errors:
        return jsonify({
            "status": "unhealthy",
            "errors": errors
        }), 503
    
    return jsonify({
        "status": "healthy",
        "linear_connected": linear_client.test_connection() if linear_client else False,
        "tunnel_active": tunnel.get_public_url() is not None
    })


@app.route("/webhook", methods=["POST"])
def webhook():
    """Main webhook endpoint for Semgrep events."""
    if not webhook_handler:
        return jsonify({"error": "Integration not configured"}), 503
    
    # Verify signature
    signature = request.headers.get("X-Semgrep-Signature-256", "")
    if not webhook_handler.verify_signature(request.data, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401
    
    try:
        payload = request.get_json()
        
        if not payload:
            return jsonify({"error": "Empty payload"}), 400
        
        results = []
        
        # Log the full payload structure for debugging
        logger.info(f"Received webhook payload type: {type(payload).__name__}")
        logger.info(f"Webhook payload keys: {payload.keys() if isinstance(payload, dict) else 'N/A (list)'}")
        logger.debug(f"Full webhook payload: {payload}")
        
        # Handle array of findings (Semgrep sends findings as a list)
        if isinstance(payload, list):
            logger.info(f"Processing {len(payload)} findings from array payload")
            for item in payload:
                # Semgrep wraps each finding in a 'semgrep_finding' key
                if isinstance(item, dict) and 'semgrep_finding' in item:
                    finding = item['semgrep_finding']
                    result = webhook_handler.process_finding(finding)
                    results.append(result)
                elif isinstance(item, dict) and ('text' in item or 'username' in item):
                    # Skip Slack-format notifications
                    logger.info("Skipping Slack-format notification in array")
                    continue
                else:
                    result = webhook_handler.process_finding(item)
                    results.append(result)
            return jsonify({
                "status": "success",
                "processed": len(results),
                "results": results
            })
        
        event_type = payload.get("type", "unknown")
        
        if event_type == "semgrep_finding":
            # Single finding event
            result = webhook_handler.process_finding(payload.get("finding", payload))
            results.append(result)
            
        elif event_type == "semgrep_scan":
            # Scan completion event
            result = webhook_handler.process_scan(payload.get("scan", payload))
            results.append(result)
            
            # Process any findings included in the scan
            findings = payload.get("findings", [])
            for finding in findings:
                result = webhook_handler.process_finding(finding)
                results.append(result)
        
        elif "findings" in payload:
            # Handle payload with 'findings' array (common Semgrep format)
            findings = payload.get("findings", [])
            logger.info(f"Processing {len(findings)} findings from 'findings' array")
            for finding in findings:
                result = webhook_handler.process_finding(finding)
                results.append(result)
        
        elif "data" in payload and isinstance(payload.get("data"), dict):
            # Handle nested data structure
            data = payload.get("data", {})
            if "findings" in data:
                findings = data.get("findings", [])
                logger.info(f"Processing {len(findings)} findings from nested data.findings")
                for finding in findings:
                    result = webhook_handler.process_finding(finding)
                    results.append(result)
            else:
                # Try to process data as a single finding
                result = webhook_handler.process_finding(data)
                results.append(result)
        
        elif "semgrep_scan" in payload:
            # Handle semgrep_scan event (scan metadata, no findings to process)
            scan_data = payload.get("semgrep_scan", {})
            logger.info(f"Received scan event: {scan_data.get('hashed_id', 'unknown')}")
            return jsonify({
                "status": "success",
                "message": "Scan event received",
                "scan_id": scan_data.get("hashed_id")
            })
        
        elif "semgrep_finding" in payload:
            # Single finding wrapped in semgrep_finding
            finding = payload.get("semgrep_finding", {})
            result = webhook_handler.process_finding(finding)
            results.append(result)
        
        else:
            # Try to process as a finding directly
            if "rule" in payload or "severity" in payload or "check_id" in payload or "path" in payload:
                result = webhook_handler.process_finding(payload)
                results.append(result)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                logger.warning(f"Payload keys: {list(payload.keys())}")
                return jsonify({"warning": f"Unknown event type: {event_type}", "keys": list(payload.keys())}), 200
        
        return jsonify({
            "status": "success",
            "processed": len(results),
            "results": results
        })
        
    except Exception as e:
        logger.exception(f"Error processing webhook: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================
# Setup Wizard API Endpoints
# ============================================

@app.route("/api/setup/validate-key", methods=["POST"])
def validate_api_key():
    """Validate a Linear API key and return available teams."""
    try:
        data = request.get_json()
        api_key = data.get("api_key", "").strip()
        
        if not api_key:
            return jsonify({"valid": False, "error": "API key is required"})
        
        if not api_key.startswith("lin_api_"):
            return jsonify({"valid": False, "error": "Invalid API key format"})
        
        # Test the API key
        test_client = LinearClient(api_key)
        teams = test_client.get_teams()
        
        return jsonify({
            "valid": True,
            "teams": teams
        })
        
    except Exception as e:
        logger.error(f"API key validation failed: {e}")
        return jsonify({"valid": False, "error": "Invalid API key or connection error"})


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
        projects = test_client.get_projects(team_id)
        
        return jsonify({"projects": projects})
        
    except Exception as e:
        logger.error(f"Failed to fetch projects: {e}")
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
        
        # Determine the .env file path
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        
        # Preserve existing NGROK_AUTHTOKEN and LOCAL_DEV if set
        ngrok_token = os.getenv("NGROK_AUTHTOKEN", "")
        local_dev = os.getenv("LOCAL_DEV", "")
        
        # Build the .env content
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

# Local Development (set to 'true' to auto-start ngrok tunnel)
LOCAL_DEV={local_dev}
NGROK_AUTHTOKEN={ngrok_token}
"""
        
        # Write the .env file
        with open(env_path, "w") as f:
            f.write(env_content)
        
        logger.info(f"Configuration saved to {env_path}")
        
        # Update environment variables for current process
        os.environ["LINEAR_API_KEY"] = api_key
        os.environ["LINEAR_TEAM_ID"] = team_id
        os.environ["LINEAR_PROJECT_ID"] = project_id
        os.environ["SEMGREP_WEBHOOK_SECRET"] = webhook_secret
        os.environ["DEBUG"] = "true" if debug else "false"
        
        # Reinitialize clients with new config
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
    """Get tunnel status and public URL."""
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
    """Configure ngrok token and start tunnel."""
    try:
        data = request.get_json()
        ngrok_token = data.get("ngrok_token", "").strip()
        
        if not ngrok_token:
            return jsonify({"success": False, "error": "ngrok token is required"})
        
        # Set the token in environment
        os.environ["NGROK_AUTHTOKEN"] = ngrok_token
        os.environ["LOCAL_DEV"] = "true"
        
        # Try to start the tunnel
        public_url = tunnel.start_tunnel(config.PORT)
        
        if public_url:
            # Save token to .env file for persistence
            env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
            try:
                # Read existing .env content
                existing_content = ""
                if os.path.exists(env_path):
                    with open(env_path, "r") as f:
                        existing_content = f.read()
                
                # Update or add NGROK_AUTHTOKEN and LOCAL_DEV
                lines = existing_content.split("\n")
                new_lines = []
                found_ngrok = False
                found_local = False
                
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
                    
            except Exception as e:
                logger.warning(f"Could not save ngrok token to .env: {e}")
            
            return jsonify({
                "success": True,
                "public_url": public_url,
                "webhook_url": f"{public_url}/webhook"
            })
        else:
            return jsonify({
                "success": False, 
                "error": "Failed to start tunnel. Check your ngrok token."
            })
            
    except Exception as e:
        logger.exception(f"Failed to configure tunnel: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/tunnel/start", methods=["POST"])
def start_tunnel_endpoint():
    """Manually start the ngrok tunnel."""
    if not tunnel.get_ngrok_auth_token():
        return jsonify({
            "success": False, 
            "error": "NGROK_AUTHTOKEN not configured. Get a free token at https://dashboard.ngrok.com"
        }), 400
    
    public_url = tunnel.start_tunnel(config.PORT)
    if public_url:
        return jsonify({
            "success": True,
            "public_url": public_url,
            "webhook_url": f"{public_url}/webhook"
        })
    else:
        return jsonify({"success": False, "error": "Failed to start tunnel"}), 500


# ============================================
# Existing API Endpoints
# ============================================

@app.route("/api/teams", methods=["GET"])
def get_teams():
    """Get available Linear teams for configuration."""
    if not linear_client:
        return jsonify({"error": "Linear not configured"}), 503
    
    try:
        teams = linear_client.get_teams()
        return jsonify({"teams": teams})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/projects/<team_id>", methods=["GET"])
def get_projects(team_id: str):
    """Get projects for a specific team."""
    if not linear_client:
        return jsonify({"error": "Linear not configured"}), 503
    
    try:
        projects = linear_client.get_projects(team_id)
        return jsonify({"projects": projects})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def create_app():
    """Application factory."""
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=config.DEBUG)
