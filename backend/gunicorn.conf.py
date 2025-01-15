import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 1024

# Worker processes
worker_class = "uvicorn.workers.UvicornWorker"
workers = 2  # Fixed at 2 workers
threads = 1  # Single thread per worker
worker_connections = 50
timeout = 300
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
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process Management
graceful_timeout = 120
max_requests = 250
max_requests_jitter = 50
worker_tmp_dir = "/dev/shm"

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
