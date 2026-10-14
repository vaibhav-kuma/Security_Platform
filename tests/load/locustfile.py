"""
Load testing script for the Security Assessment Platform.

This Locust script simulates realistic user behavior and load patterns
to identify bottlenecks and verify scaling behavior.

Run with:
    locust -f tests/load/locustfile.py --host=http://localhost:8000

Or for headless load test:
    locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 50 -r 5 -t 300s
"""

import random
import uuid
from typing import Any

from locust import HttpUser, between, task, tag


class SASPUser(HttpUser):
    """Simulates a user interacting with the SASP platform."""
    
    wait_time = between(1, 5)  # Wait 1-5 seconds between tasks
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.project_id = None
        self.access_token = None
        self.headers = {"Content-Type": "application/json"}
    
    def on_start(self):
        """Called when a user starts - authenticate and create a project."""
        self.authenticate()
        self.create_project()
    
    def authenticate(self):
        """Authenticate and get access token."""
        # Use test credentials
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpass123"},
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 200:
            data = response.json()
            self.access_token = data.get("access_token")
            self.headers["Authorization"] = f"Bearer {self.access_token}"
        else:
            # Try to register first
            self.register()
            self.authenticate()
    
    def register(self):
        """Register a test user."""
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": "testpass123",
                "full_name": "Test User",
            },
            headers={"Content-Type": "application/json"},
        )
        return response.status_code in (200, 201)
    
    def create_project(self):
        """Create a test project."""
        response = self.client.post(
            "/api/v1/projects",
            json={
                "name": f"Load Test Project {uuid.uuid4().hex[:8]}",
                "description": "Project created by load test",
            },
            headers=self.headers,
        )
        if response.status_code in (200, 201):
            self.project_id = response.json().get("id")
    
    @tag("read")
    @task(10)
    def list_projects(self):
        """List projects - frequent read operation."""
        self.client.get("/api/v1/projects", headers=self.headers)
    
    @tag("read")
    @task(5)
    def get_project(self):
        """Get project details."""
        if self.project_id:
            self.client.get(f"/api/v1/projects/{self.project_id}", headers=self.headers)
    
    @tag("write")
    @task(3)
    def create_scope(self):
        """Create a scope for the project."""
        if not self.project_id:
            return
        
        response = self.client.post(
            f"/api/v1/projects/{self.project_id}/scopes",
            json={
                "name": f"Scope {uuid.uuid4().hex[:8]}",
                "description": "Load test scope",
            },
            headers=self.headers,
        )
        if response.status_code in (200, 201):
            scope_id = response.json().get("id")
            self.add_scope_rules(scope_id)
    
    def add_scope_rules(self, scope_id: str):
        """Add scope rules."""
        rules = [
            {"effect": "allow", "target_type": "domain", "pattern": "example.com"},
            {"effect": "allow", "target_type": "subdomain", "pattern": "*.example.com"},
            {"effect": "deny", "target_type": "domain", "pattern": "internal.example.com"},
        ]
        for rule in rules:
            self.client.post(
                f"/api/v1/projects/{self.project_id}/scopes/{scope_id}/rules",
                json=rule,
                headers=self.headers,
            )
    
    @tag("write")
    @task(3)
    def create_target(self):
        """Create a target for scanning."""
        if not self.project_id:
            return
        
        response = self.client.post(
            f"/api/v1/projects/{self.project_id}/targets",
            json={
                "name": f"target-{uuid.uuid4().hex[:8]}.example.com",
                "target_type": "domain",
                "description": "Load test target",
            },
            headers=self.headers,
        )
        if response.status_code in (200, 201):
            target_id = response.json().get("id")
            self.evaluate_target(target_id)
    
    @tag("read")
    @task(5)
    def evaluate_target(self, target_id: str | None = None):
        """Evaluate target scope status."""
        if not self.project_id:
            return
        
        # Get targets
        response = self.client.get(
            f"/api/v1/projects/{self.project_id}/targets",
            headers=self.headers,
        )
        if response.status_code == 200:
            targets = response.json().get("items", [])
            if targets:
                target = random.choice(targets)
                self.client.post(
                    f"/api/v1/projects/{self.project_id}/targets/{target['id']}/evaluate",
                    headers=self.headers,
                )
    
    @tag("scan")
    @task(2)
    def start_scan(self):
        """Start a scan - heavier operation."""
        if not self.project_id:
            return
        
        # Get targets first
        response = self.client.get(
            f"/api/v1/projects/{self.project_id}/targets",
            headers=self.headers,
        )
        if response.status_code != 200:
            return
        
        targets = response.json().get("items", [])
        if not targets:
            return
        
        target = random.choice(targets)
        
        response = self.client.post(
            f"/api/v1/projects/{self.project_id}/scans",
            json={
                "name": f"Load Test Scan {uuid.uuid4().hex[:8]}",
                "scan_type": "recon",
                "target_id": target["id"],
                "configuration": {},
            },
            headers=self.headers,
        )
        if response.status_code in (200, 201):
            scan_id = response.json().get("id")
            self.monitor_scan(scan_id)
    
    def monitor_scan(self, scan_id: str):
        """Monitor scan progress."""
        for _ in range(10):  # Check up to 10 times
            response = self.client.get(
                f"/api/v1/projects/{self.project_id}/scans/{scan_id}",
                headers=self.headers,
            )
            if response.status_code == 200:
                status = response.json().get("status")
                if status in ("completed", "failed", "cancelled"):
                    break
            self.wait_time = between(2, 5)
    
    @tag("read")
    @task(5)
    def list_findings(self):
        """List findings."""
        if not self.project_id:
            return
        self.client.get(
            f"/api/v1/projects/{self.project_id}/findings",
            headers=self.headers,
        )
    
    @tag("read")
    @task(3)
    def list_observations(self):
        """List observations."""
        if not self.project_id:
            return
        self.client.get(
            f"/api/v1/projects/{self.project_id}/observations",
            headers=self.headers,
        )
    
    @tag("read")
    @task(2)
    def get_review_queue(self):
        """Get manual review queue."""
        if not self.project_id:
            return
        self.client.get(
            f"/api/v1/projects/{self.project_id}/review",
            headers=self.headers,
        )
    
    @tag("admin")
    @task(1)
    def health_check(self):
        """Health check endpoint."""
        self.client.get("/health", headers=self.headers)
    
    @tag("admin")
    @task(1)
    def metrics_endpoint(self):
        """Prometheus metrics endpoint."""
        self.client.get("/api/metrics", headers=self.headers)


class SASPAdminUser(SASPUser):
    """Simulates an admin user with additional operations."""
    
    wait_time = between(2, 10)
    
    @tag("admin")
    @task(2)
    def list_all_users(self):
        """Admin: list all users."""
        self.client.get("/api/v1/admin/users", headers=self.headers)
    
    @tag("admin")
    @task(1)
    def get_system_stats(self):
        """Admin: get system statistics."""
        self.client.get("/api/v1/admin/stats", headers=self.headers)
    
    @tag("admin")
    @task(1)
    def worker_stats(self):
        """Admin: get worker statistics."""
        self.client.get("/api/v1/admin/workers", headers=self.headers)


class SAPSScanHeavyUser(SASPUser):
    """Simulates a user who primarily runs scans."""
    
    wait_time = between(5, 15)
    
    @tag("scan")
    @task(10)
    def start_scan(self):
        """Start scans more frequently."""
        super().start_scan()
    
    @tag("scan")
    @task(5)
    def start_priority_scan(self):
        """Start priority scan."""
        if not self.project_id:
            return
        
        response = self.client.get(
            f"/api/v1/projects/{self.project_id}/targets",
            headers=self.headers,
        )
        if response.status_code != 200:
            return
        
        targets = response.json().get("items", [])
        if not targets:
            return
        
        target = random.choice(targets)
        
        self.client.post(
            f"/api/v1/projects/{self.project_id}/scans",
            json={
                "name": f"Priority Scan {uuid.uuid4().hex[:8]}",
                "scan_type": "recon",
                "target_id": target["id"],
                "configuration": {"priority": True},
            },
            headers=self.headers,
        )


class SAPSReadOnlyUser(SASPUser):
    """Simulates a read-only user (viewer role)."""
    
    wait_time = between(1, 3)
    
    @tag("read")
    @task(20)
    def list_projects(self):
        super().list_projects()
    
    @tag("read")
    @task(10)
    def get_project(self):
        super().get_project()
    
    @tag("read")
    @task(10)
    def list_findings(self):
        super().list_findings()
    
    @tag("read")
    @task(5)
    def list_observations(self):
        super().list_observations()
    
    @tag("read")
    @task(5)
    def get_review_queue(self):
        super().get_review_queue()
    
    # No write operations for read-only user


# Custom load shapes for different test scenarios
class StepLoadShape:
    """Step load shape: gradually increase users."""
    
    def __init__(self):
        self.step_duration = 60  # seconds per step
        self.step_users = 10     # users per step
        self.max_users = 100
    
    def tick(self):
        run_time = self.get_run_time()
        current_step = int(run_time / self.step_duration)
        target_users = min(current_step * self.step_users, self.max_users)
        return (target_users, self.step_users)


class SpikeLoadShape:
    """Spike load shape: sudden traffic spike."""
    
    def __init__(self):
        self.spike_start = 60    # start spike at 60s
        self.spike_duration = 30 # spike lasts 30s
        self.normal_users = 10
        self.spike_users = 100
    
    def tick(self):
        run_time = self.get_run_time()
        if self.spike_start <= run_time <= self.spike_start + self.spike_duration:
            return (self.spike_users, self.spike_users)
        return (self.normal_users, self.normal_users)


class SoakLoadShape:
    """Soak load shape: sustained load for extended period."""
    
    def __init__(self):
        self.ramp_up = 300       # 5 minutes ramp up
        self.sustain = 1800      # 30 minutes sustained
        self.max_users = 50
    
    def tick(self):
        run_time = self.get_run_time()
        if run_time < self.ramp_up:
            # Ramp up
            target = int((run_time / self.ramp_up) * self.max_users)
            return (target, max(1, target // 10))
        elif run_time < self.ramp_up + self.sustain:
            # Sustained
            return (self.max_users, self.max_users)
        else:
            # Test done
            return None