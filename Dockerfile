# psychosecurity.io on a server of its own: the static site and the api/
# functions, served by gunicorn through server/app.py. Vercel ignores this
# file (.vercelignore); deploys there are unchanged.
#
#   docker build -t psychosecurity .
#   docker run --rm -p 127.0.0.1:8000:8000 --env-file /etc/psychosecurity/app.env psychosecurity
#
# The family's Flask kit (JoelMHarvey/projects, infra/apps/_flask) builds
# the same thing from apps.tsv with WSGI server.app:app and health path
# /api/health/live; this file is for running it without the kit. Same base
# image, gunicorn and settings as the kit.
FROM python:3.12.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt gunicorn==26.2.0

COPY . /app

ENV HEALTH_PATH=/api/health/live
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000'+os.environ['HEALTH_PATH'], timeout=5).status == 200 else 1)"
# --timeout 300 is above the 180 s vercel.json gives api/visibility.py.
# Only Caddy and the host's loopback reach this port, so X-Forwarded-Proto
# from anywhere is Caddy's.
CMD ["gunicorn", "server.app:app", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", \
     "--no-control-socket", "--timeout", "300", "--graceful-timeout", "30", "--forwarded-allow-ips", "*", \
     "--access-logfile", "-", "--error-logfile", "-"]
