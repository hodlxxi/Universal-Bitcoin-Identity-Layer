"""
Admin Blueprint - Health Checks, Metrics, and Operational Endpoints

Provides monitoring and operational endpoints for infrastructure health.
"""

import logging
import time
from typing import Dict, Any

from flask import Blueprint, Response, current_app, jsonify
from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

from app.utils import get_rpc_connection

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__)

# Prometheus metrics
registry = CollectorRegistry()
request_counter = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=registry
)
active_connections = Gauge(
    "active_connections",
    "Number of active connections",
    registry=registry
)


@admin_bp.route("/health")
def health():
    """
    Comprehensive health check endpoint.

    Returns:
        JSON health status with service information
    """
    try:
        health_status: Dict[str, Any] = {
            "status": "healthy",
            "timestamp": time.time(),
            "service": "Universal Bitcoin Identity Layer",
            "version": "2.0.0",
            "components": {}
        }

        # Check Bitcoin RPC connectivity
        try:
            rpc = get_rpc_connection()
            blockchain_info = rpc.getblockchaininfo()
            health_status["components"]["bitcoin_rpc"] = {
                "status": "connected",
                "chain": blockchain_info.get("chain"),
                "blocks": blockchain_info.get("blocks"),
                "headers": blockchain_info.get("headers"),
                "verification_progress": blockchain_info.get("verificationprogress")
            }
        except Exception as e:
            logger.warning(f"Bitcoin RPC health check failed: {e}")
            health_status["components"]["bitcoin_rpc"] = {
                "status": "error",
                "error": str(e)
            }
            health_status["status"] = "degraded"

        # Check database connectivity
        try:
            from app.database import get_db
            db = get_db()
            db.execute("SELECT 1")
            health_status["components"]["database"] = {"status": "connected"}
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
            health_status["components"]["database"] = {
                "status": "error",
                "error": str(e)
            }
            health_status["status"] = "degraded"

        # Check Redis connectivity (optional)
        try:
            from app.database import get_redis
            redis = get_redis()
            if redis:
                redis.ping()
                health_status["components"]["redis"] = {"status": "connected"}
        except Exception as e:
            logger.info(f"Redis not available: {e}")
            health_status["components"]["redis"] = {"status": "optional_unavailable"}

        return jsonify(health_status), 200 if health_status["status"] == "healthy" else 503

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": time.time()
        }), 500


@admin_bp.route("/health/live")
def liveness():
    """
    Kubernetes liveness probe - checks if app is running.

    Returns:
        200 if process is alive
    """
    return jsonify({"status": "alive"}), 200


@admin_bp.route("/health/ready")
def readiness():
    """
    Kubernetes readiness probe - checks if app is ready to serve traffic.

    Returns:
        200 if ready, 503 if not ready
    """
    try:
        # Check critical dependencies
        from app.database import get_db
        db = get_db()
        db.execute("SELECT 1")
        return jsonify({"status": "ready"}), 200
    except Exception as e:
        logger.warning(f"Readiness check failed: {e}")
        return jsonify({"status": "not_ready", "error": str(e)}), 503


@admin_bp.route("/metrics")
def metrics_json():
    """
    JSON metrics endpoint for monitoring.

    Returns:
        JSON metrics data
    """
    try:
        metrics_data = {
            "timestamp": time.time(),
            "application": {
                "name": "Universal Bitcoin Identity Layer",
                "version": "2.0.0",
                "uptime": time.process_time()
            }
        }

        # Add Bitcoin RPC metrics if available
        try:
            rpc = get_rpc_connection()
            blockchain_info = rpc.getblockchaininfo()
            mempool_info = rpc.getmempoolinfo()

            metrics_data["bitcoin"] = {
                "chain": blockchain_info.get("chain"),
                "blocks": blockchain_info.get("blocks"),
                "headers": blockchain_info.get("headers"),
                "difficulty": blockchain_info.get("difficulty"),
                "mempool_size": mempool_info.get("size"),
                "mempool_bytes": mempool_info.get("bytes")
            }
        except Exception as e:
            logger.warning(f"Bitcoin metrics unavailable: {e}")

        return jsonify(metrics_data), 200

    except Exception as e:
        logger.error(f"Metrics endpoint failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/metrics/prometheus")
def metrics_prometheus():
    """
    Prometheus metrics endpoint.

    Returns:
        Prometheus text format metrics
    """
    try:
        # Update active connections gauge
        # This would be updated by middleware in production
        active_connections.set(0)

        # Generate Prometheus format
        metrics = generate_latest(registry)
        return Response(metrics, mimetype="text/plain; version=0.0.4")

    except Exception as e:
        logger.error(f"Prometheus metrics failed: {e}", exc_info=True)
        return Response(f"# Error: {e}\n", mimetype="text/plain"), 500


@admin_bp.route("/turn_credentials")
def turn_credentials():
    """
    TURN server credentials for WebRTC.

    Returns:
        JSON with TURN server configuration
    """
    import os
    import hashlib
    import hmac
    import base64
    from time import time

    try:
        turn_host = os.getenv("TURN_HOST", "turn.example.com")
        turn_port = int(os.getenv("TURN_PORT", "3478"))
        turn_secret = os.getenv("TURN_SECRET", "")

        if not turn_secret:
            return jsonify({"error": "TURN server not configured"}), 503

        # Generate time-limited credentials
        username = str(int(time() + 86400))  # Valid for 24 hours
        password = base64.b64encode(
            hmac.new(
                turn_secret.encode(),
                username.encode(),
                hashlib.sha1
            ).digest()
        ).decode()

        return jsonify({
            "urls": [
                f"turn:{turn_host}:{turn_port}?transport=udp",
                f"turn:{turn_host}:{turn_port}?transport=tcp",
            ],
            "username": username,
            "credential": password
        }), 200

    except Exception as e:
        logger.error(f"TURN credentials failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
