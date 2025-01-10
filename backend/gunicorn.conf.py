import multiprocessing
import os
from pathlib import Path


def get_python_files(directory):
    files = []
    base_path = Path("backend")
    search_path = base_path / directory
    if search_path.exists():
        for file in search_path.rglob("*.py"):
            files.append(str(file))
    return files


# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count()  # Will use 4 in your case
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 1800  # 30 minutes for long-running scans
keepalive = 2

# Process naming
proc_name = "audit-agent"

# SSL
keyfile = os.getenv("SSL_KEYFILE", None)
certfile = os.getenv("SSL_CERTFILE", None)

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Development settings
reload = os.getenv("ENVIRONMENT", "development") == "development"
reload_extra_files = get_python_files("api") + get_python_files("core") + get_python_files("config")

# Process Management
graceful_timeout = 120
max_requests = 1000
max_requests_jitter = 50

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
