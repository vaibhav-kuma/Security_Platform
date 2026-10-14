// WebSocket hook for real-time scan events

import { useEffect, useRef, useState, useCallback } from "react";
import { ScanProgress } from "@/lib/api/types";

interface ScanEvent {
  type: "scan_event";
  scan_id: string;
  event_type: string;
  level: string;
  message: string;
  payload: Record<string, unknown>;
}

interface UseScanWebSocketOptions {
  scanId: string;
  onEvent?: (event: ScanEvent) => void;
  onProgress?: (progress: ScanProgress) => void;
  onError?: (error: Event) => void;
  onClose?: () => void;
}

export function useScanWebSocket({
  scanId,
  onEvent,
  onProgress,
  onError,
  onClose,
}: UseScanWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/scans/${scanId}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log(`WebSocket connected for scan ${scanId}`);
        setIsConnected(true);
        reconnectAttempts.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Handle scan events
          if (data.type === "scan_event" && onEvent) {
            onEvent(data as ScanEvent);
          }

          // Handle progress updates
          if (data.event_type === "scan.progress" && onProgress) {
            const progress: ScanProgress = {
              scan_id: data.scan_id,
              status: data.payload.status as string || "running",
              progress: data.payload.progress as number || 0,
              total_jobs: data.payload.total_jobs as number || 0,
              completed_jobs: data.payload.completed_jobs as number || 0,
              failed_jobs: data.payload.failed_jobs as number || 0,
              running_jobs: data.payload.running_jobs as number || 0,
              queued_jobs: data.payload.queued_jobs as number || 0,
              started_at: data.payload.started_at as string || null,
              finished_at: data.payload.finished_at as string || null,
            };
            onProgress(progress);
          }

          // Handle pong responses
          if (data.type === "pong") {
            // Connection is alive
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };

      ws.onclose = () => {
        console.log(`WebSocket disconnected for scan ${scanId}`);
        setIsConnected(false);

        // Attempt reconnection
        if (reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
          reconnectTimeoutRef.current = setTimeout(connect, delay);
        } else {
          console.log("Max reconnection attempts reached");
        }

        if (onClose) onClose();
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        if (onError) onError(error);
      };

      // Send periodic ping to keep connection alive
      const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "ping" }));
        } else {
          clearInterval(pingInterval);
        }
      }, 30000);

      ws.onclose = () => {
        clearInterval(pingInterval);
      };
    } catch (err) {
      console.error("Failed to create WebSocket:", err);
    }
  }, [scanId, onEvent, onProgress, onError, onClose]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  const sendMessage = useCallback((message: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  return {
    isConnected,
    sendMessage,
    reconnect: connect,
  };
}