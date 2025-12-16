import hmac
import hashlib
import logging
from typing import Optional
from .config import config
from .linear_client import LinearClient

logger = logging.getLogger(__name__)


class WebhookHandler:
    """Handles incoming Semgrep webhooks and creates Linear issues."""
    
    def __init__(self, linear_client: LinearClient):
        self.linear_client = linear_client
    
    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify the Semgrep webhook signature."""
        if not config.SEMGREP_WEBHOOK_SECRET:
            logger.warning("No webhook secret configured - skipping signature verification")
            return True
        
        if not signature:
            logger.error("No signature provided in request")
            return False
        
        expected_signature = hmac.new(
            config.SEMGREP_WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # Signature format: sha256=<hash>
        provided_hash = signature.replace("sha256=", "")
        
        return hmac.compare_digest(expected_signature, provided_hash)
    
    def process_finding(self, finding: dict) -> Optional[dict]:
        """Process a Semgrep finding and create a Linear issue."""
        try:
            logger.info(f"Processing finding with keys: {list(finding.keys())}")
            
            # Extract finding details - handle multiple possible formats
            # Format 1: Standard format with nested rule object
            # Format 2: Flat format with check_id, path, etc.
            
            finding_id = (
                finding.get("id") or 
                finding.get("finding_id") or 
                finding.get("check_id") or 
                "unknown"
            )
            
            # Rule info - try nested first, then flat
            rule_obj = finding.get("rule", {})
            if isinstance(rule_obj, dict):
                rule_id = rule_obj.get("id", finding.get("check_id", "unknown-rule"))
                rule_name = rule_obj.get("name", rule_id)
                message = rule_obj.get("message", finding.get("extra", {}).get("message", "No description available"))
            else:
                rule_id = finding.get("check_id", str(rule_obj) if rule_obj else "unknown-rule")
                rule_name = rule_id
                message = finding.get("extra", {}).get("message", "No description available")
            
            # Severity - check multiple possible locations
            severity = (
                finding.get("severity") or
                finding.get("extra", {}).get("severity") or
                finding.get("metadata", {}).get("severity") or
                "medium"
            ).lower()
            
            # Location info - handle both nested and flat formats
            location = finding.get("location", {})
            if location:
                file_path = location.get("file_path", location.get("path", "unknown"))
                start_line = location.get("start_line", location.get("start", {}).get("line", 0))
                end_line = location.get("end_line", location.get("end", {}).get("line", start_line))
            else:
                # Flat format
                file_path = finding.get("path", "unknown")
                start_line = finding.get("start", {}).get("line", finding.get("line", 0))
                end_line = finding.get("end", {}).get("line", start_line)
            
            # Repository info - try multiple locations
            repo = finding.get("repository", finding.get("repo", {}))
            if isinstance(repo, dict):
                repo_name = repo.get("name", repo.get("repo_name", "unknown-repo"))
                repo_url = repo.get("url", repo.get("repo_url", ""))
            else:
                repo_name = str(repo) if repo else "unknown-repo"
                repo_url = ""
            
            logger.info(f"Extracted finding: id={finding_id}, rule={rule_id}, severity={severity}, file={file_path}")
            
            # Check for existing issue
            existing = self.linear_client.find_existing_issue(
                config.LINEAR_TEAM_ID,
                finding_id
            )
            
            if existing:
                logger.info(f"Issue already exists for finding {finding_id}: {existing['identifier']}")
                return {"status": "exists", "issue": existing}
            
            # Build issue title and description
            title = f"[Semgrep] {severity.upper()}: {rule_name} in {repo_name}"
            
            description = self._build_description(
                finding_id=finding_id,
                rule_id=rule_id,
                severity=severity,
                message=message,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                repo_name=repo_name,
                repo_url=repo_url,
                finding=finding
            )
            
            # Map severity to priority
            priority = config.SEVERITY_PRIORITY_MAP.get(severity, config.LINEAR_DEFAULT_PRIORITY)
            
            # Create the issue
            result = self.linear_client.create_issue(
                team_id=config.LINEAR_TEAM_ID,
                title=title[:200],  # Linear title limit
                description=description,
                priority=priority,
                project_id=config.LINEAR_PROJECT_ID if config.LINEAR_PROJECT_ID else None,
            )
            
            if result.get("success"):
                issue = result.get("issue", {})
                logger.info(f"Created Linear issue {issue.get('identifier')} for finding {finding_id}")
                return {"status": "created", "issue": issue}
            else:
                logger.error(f"Failed to create issue for finding {finding_id}")
                return {"status": "error", "message": "Failed to create issue"}
                
        except Exception as e:
            logger.exception(f"Error processing finding: {e}")
            return {"status": "error", "message": str(e)}
    
    def _build_description(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        message: str,
        file_path: str,
        start_line: int,
        end_line: int,
        repo_name: str,
        repo_url: str,
        finding: dict
    ) -> str:
        """Build a formatted issue description."""
        
        # Get code snippet if available - check multiple possible locations
        code_snippet = (
            finding.get("syntactic_context", "") or
            finding.get("extra", {}).get("lines", "") or
            finding.get("extra", {}).get("code", "") or
            finding.get("match", "") or
            ""
        )
        
        # Build link to code if URL available
        code_link = ""
        if repo_url and file_path:
            code_link = f"{repo_url}/blob/main/{file_path}#L{start_line}-L{end_line}"
        
        description = f"""## Semgrep Security Finding

**Finding ID:** `{finding_id}`
**Rule:** `{rule_id}`
**Severity:** {severity.upper()}
**Repository:** {repo_name}

---

### Description
{message}

---

### Location
- **File:** `{file_path}`
- **Lines:** {start_line} - {end_line}
"""

        if code_link:
            description += f"- **Link:** [View in repository]({code_link})\n"

        if code_snippet:
            description += f"""
---

### Code Snippet
```
{code_snippet}
```
"""

        description += f"""
---

### Remediation
Please review this finding and take appropriate action:
1. If this is a true positive, fix the vulnerability
2. If this is a false positive, mark it as ignored in Semgrep with a comment

---
*This issue was automatically created by the Semgrep-Linear Integration*
"""
        return description

    def process_scan(self, scan_data: dict) -> dict:
        """Process a scan completion event."""
        scan_id = scan_data.get("id", "unknown")
        status = scan_data.get("status", "unknown")
        findings_count = scan_data.get("findings_count", 0)
        
        logger.info(f"Scan {scan_id} completed with status {status}, {findings_count} findings")
        
        return {
            "status": "processed",
            "scan_id": scan_id,
            "scan_status": status,
            "findings_count": findings_count
        }

