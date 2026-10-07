"""WebSocket manager for real-time scan events."""

import json
from uuid import UUID

from fastapi import Depends, Query, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from sqlalchemy.orm import Session

from app.auth.token import validate_access_token
from app.db.session import get_db


class ConnectionManager:
    """Manages WebSocket connections for real-time scan events."""

    def __init__(self):
        # scan_id -> set of WebSocket connections
        self.active_connections: dict[str, set[WebSocket]] = {}
        # WebSocket -> scan_id mapping for cleanup
        self.connection_scan_map: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, scan_id: str) -> None:
        """Accept a new WebSocket connection for a scan."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)
        self.connection_scan_map[websocket] = scan_id

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        scan_id = self.connection_scan_map.pop(websocket, None)
        if scan_id and scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_event(self, scan_id: str, event: dict) -> None:
        """Send an event to all connections watching a scan."""
        if scan_id not in self.active_connections:
            return

        message = json.dumps(event)
        dead_connections = set()

        for connection in self.active_connections[scan_id]:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(message)
                else:
                    dead_connections.add(connection)
            except Exception:
                dead_connections.add(connection)

        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

    async def broadcast(self, event: dict) -> None:
        """Broadcast an event to all connected clients."""
        message = json.dumps(event)
        for scan_id, connections in self.active_connections.items():
            dead_connections = set()
            for connection in connections:
                try:
                    if connection.client_state == WebSocketState.CONNECTED:
                        await connection.send_text(message)
                    else:
                        dead_connections.add(connection)
                except Exception:
                    dead_connections.add(connection)

            for conn in dead_connections:
                self.disconnect(conn)


# Global connection manager instance
manager = ConnectionManager()


async def get_websocket_user(
    websocket: WebSocket,
    token: str = Query(None),
    db: Session = Depends(get_db),
):
    """Extract and validate user from WebSocket token query parameter."""
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
        return None

    try:
        payload = validate_access_token(token)
        # Get user from database
        from app.models.identity import User
        from app.repositories.base import SoftDeleteRepository
        repo = SoftDeleteRepository(db, User)
        user = repo.get(UUID(payload.sub))
        if user is None or user.is_deleted or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid user")
            return None
        return user
    except ValueError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
        return None


async def scan_websocket_endpoint(
    websocket: WebSocket,
    scan_id: str,
    user = Depends(get_websocket_user),
) -> None:
    """WebSocket endpoint for real-time scan events with authentication."""
    if user is None:
        # Connection already closed by get_websocket_user
        return

    # Verify user has access to this scan
    db = next(get_db())
    try:
        from app.models.scans import Scan
        scan = db.get(Scan, UUID(scan_id))
        if not scan:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Scan not found")
            return

        # Check if user is member of the project
        from app.auth.dependencies import require_project_member
        try:
            require_project_member(user, str(scan.project_id), db)
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Not authorized for this scan")
            return
    finally:
        db.close()

    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive - wait for client messages (ping/pong)
            data = await websocket.receive_text()
            # Echo back for ping/pong
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


async def emit_scan_event(scan_id: str, event_type: str, level: str, message: str, payload: dict) -> None:
    """Emit a scan event to WebSocket clients."""
    event = {
        "type": "scan_event",
        "scan_id": scan_id,
        "event_type": event_type,
        "level": level,
        "message": message,
        "payload": payload,
    }
    await manager.send_event(scan_id, event)


# Event type constants for frontend
SCAN_EVENT_TYPES = {
    "scan.started": "Scan started",
    "scan.progress": "Scan progress update",
    "scan.completed": "Scan completed successfully",
    "scan.failed": "Scan failed",
    "scan.cancelled": "Scan cancelled",
    "scan.paused": "Scan paused",
    "scan.resumed": "Scan resumed",
    "asset.discovered": "Asset discovered",
    "endpoint.discovered": "Endpoint discovered",
    "observation.created": "Observation created",
    "finding.created": "Finding created",
}
