"""
WebSocket manager for real-time event broadcasting and trace streaming.
"""
import json
import asyncio
from typing import Dict, List, Set
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime


class ConnectionManager:
    """Manages WebSocket connections for broadcasting events."""
    
    def __init__(self):
        # Store active connections for general event stream
        self.active_connections: List[WebSocket] = []
        # Store connections for trace streams (keyed by incident_id)
        self.trace_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket):
        """Accept and store a new general WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        # Remove from trace connections as well
        for incident_id, connections in self.trace_connections.items():
            if websocket in connections:
                connections.remove(websocket)
    
    async def connect_to_trace(self, websocket: WebSocket, incident_id: str):
        """Connect a WebSocket to a specific incident's trace stream."""
        await websocket.accept()
        if incident_id not in self.trace_connections:
            self.trace_connections[incident_id] = []
        self.trace_connections[incident_id].append(websocket)
    
    def disconnect_from_trace(self, websocket: WebSocket, incident_id: str):
        """Disconnect a WebSocket from a specific incident's trace stream."""
        if incident_id in self.trace_connections:
            if websocket in self.trace_connections[incident_id]:
                self.trace_connections[incident_id].remove(websocket)
            # Clean up empty lists
            if not self.trace_connections[incident_id]:
                del self.trace_connections[incident_id]
    
    async def broadcast_event(self, event_data: dict):
        """Broadcast an event to all connected general WebSocket clients."""
        if not self.active_connections:
            return
        
        message = json.dumps({
            "type": "event",
            "data": event_data,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        
        # Send to all connected clients
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                # Mark for removal if send fails
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def broadcast_trace(self, incident_id: str, trace_data: dict):
        """Broadcast trace data to all clients subscribed to a specific incident."""
        if incident_id not in self.trace_connections or not self.trace_connections[incident_id]:
            return
        
        message = json.dumps({
            "type": "trace",
            "incident_id": incident_id,
            "data": trace_data,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        
        # Send to all connected clients for this incident
        disconnected = []
        for connection in self.trace_connections[incident_id]:
            try:
                await connection.send_text(message)
            except Exception:
                # Mark for removal if send fails
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect_from_trace(connection, incident_id)


# Global connection manager instance
manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket):
    """General WebSocket endpoint for live event streaming."""
    await manager.connect(websocket)
    try:
        while True:
                # Keep connection alive and handle any incoming messages
                # We primarily use this for server-to-client broadcasting
                data = await websocket.receive_text()
                # Echo back or handle client messages if needed
                await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def trace_websocket_endpoint(websocket: WebSocket, incident_id: str):
    """WebSocket endpoint for streaming trace data for a specific incident."""
    await manager.connect_to_trace(websocket, incident_id)
    try:
        while True:
                # Keep connection alive
                data = await websocket.receive_text()
                # Echo back or handle client messages if needed
                await websocket.send_text(f"Trace echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect_from_trace(websocket, incident_id)
