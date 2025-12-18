import time
import requests
import logging
from typing import Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class LinearClient:
    """Client for interacting with Linear's GraphQL API with retry logic."""
    
    API_URL = "https://api.linear.app/graphql"
    
    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json",
        }
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
    
    def _execute_query(self, query: str, variables: dict = None) -> dict:
        """Execute a GraphQL query against Linear's API with retry logic."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.post(
                    self.API_URL,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout
                )
                
                # Handle rate limiting explicitly
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", self.retry_delay * (attempt + 1)))
                    logger.warning(f"Linear API rate limited, retrying after {retry_after}s")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                result = response.json()
                
                # Check for GraphQL errors
                if "errors" in result:
                    logger.error(f"Linear GraphQL error: {result['errors']}")
                
                return result
                
            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(f"Linear API timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                    
            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(f"Linear API error (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
        
        # All retries exhausted
        logger.error(f"Linear API request failed after {self.max_retries} attempts")
        raise last_error or Exception("Linear API request failed")
    
    def get_teams(self) -> list:
        """Fetch all teams for configuration assistance."""
        query = """
        query {
            teams {
                nodes {
                    id
                    name
                    key
                }
            }
        }
        """
        result = self._execute_query(query)
        return result.get("data", {}).get("teams", {}).get("nodes", [])
    
    def get_projects(self, team_id: str) -> list:
        """Fetch projects for a team."""
        query = """
        query($teamId: String!) {
            team(id: $teamId) {
                projects {
                    nodes {
                        id
                        name
                    }
                }
            }
        }
        """
        result = self._execute_query(query, {"teamId": team_id})
        team_data = result.get("data", {}).get("team")
        if not team_data:
            return []
        return team_data.get("projects", {}).get("nodes", [])
    
    def get_labels(self, team_id: str) -> list:
        """Fetch labels for a team."""
        query = """
        query($teamId: String!) {
            team(id: $teamId) {
                labels {
                    nodes {
                        id
                        name
                    }
                }
            }
        }
        """
        result = self._execute_query(query, {"teamId": team_id})
        team_data = result.get("data", {}).get("team")
        if not team_data:
            return []
        return team_data.get("labels", {}).get("nodes", [])
    
    def create_issue(
        self,
        team_id: str,
        title: str,
        description: str,
        priority: int = 2,
        project_id: Optional[str] = None,
        label_ids: Optional[list] = None,
    ) -> dict:
        """Create a new issue in Linear."""
        mutation = """
        mutation IssueCreate($input: IssueCreateInput!) {
            issueCreate(input: $input) {
                success
                issue {
                    id
                    identifier
                    title
                    url
                }
            }
        }
        """
        
        input_data = {
            "teamId": team_id,
            "title": title,
            "description": description,
            "priority": priority,
        }
        
        if project_id:
            input_data["projectId"] = project_id
        
        if label_ids:
            input_data["labelIds"] = label_ids
        
        result = self._execute_query(mutation, {"input": input_data})
        
        if "errors" in result:
            logger.error(f"Linear API error: {result['errors']}")
            raise Exception(f"Failed to create issue: {result['errors']}")
        
        return result.get("data", {}).get("issueCreate", {})
    
    def find_existing_issue(self, team_id: str, finding_id: str) -> Optional[dict]:
        """Check if an issue already exists for this finding."""
        query = """
        query($filter: IssueFilter) {
            issues(filter: $filter) {
                nodes {
                    id
                    identifier
                    title
                    url
                }
            }
        }
        """
        
        try:
            # Search for issues containing the finding ID in description
            result = self._execute_query(query, {
                "filter": {
                    "team": {"id": {"eq": team_id}},
                    "description": {"contains": finding_id}
                }
            })
            
            if not result:
                return None
            
            data = result.get("data")
            if not data:
                logger.warning(f"No data in Linear response: {result}")
                return None
            
            issues = data.get("issues")
            if not issues:
                return None
            
            nodes = issues.get("nodes", [])
            return nodes[0] if nodes else None
        except Exception as e:
            logger.error(f"Error searching for existing issue: {e}")
            return None
    
    def test_connection(self) -> bool:
        """Test the API connection."""
        try:
            self.get_teams()
            return True
        except Exception as e:
            logger.error(f"Linear connection test failed: {e}")
            return False
