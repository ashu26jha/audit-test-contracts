# pylint: disable=invalid-name
import os

# Server socket
bind = "0.0.0.0:8000"

# Worker processes
worker_class = "uvicorn.workers.UvicornWorker"
workers = 1  # Changed from 2 to 1 for single worker
threads = 1
worker_connections = 1000

# Timeout
timeout = 300
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")

# Process naming
proc_name = "audit-agent-backend"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL
keyfile = None
certfile = None
