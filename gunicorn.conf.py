# gunicorn.conf.py — Production server config for Render.com
import os

# Workers: 2 × CPU cores + 1 is the recommended formula
workers     = int(os.environ.get("WEB_CONCURRENCY", 3))
worker_class = "sync"
threads     = 2
timeout     = 120
keepalive   = 5

# Bind to the PORT Render provides
bind        = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Logging
accesslog   = "-"   # stdout
errorlog    = "-"   # stderr
loglevel    = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# Security
limit_request_line    = 4094
limit_request_fields  = 100
limit_request_field_size = 8190

# Graceful shutdown
graceful_timeout = 30
