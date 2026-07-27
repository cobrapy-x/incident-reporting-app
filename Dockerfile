# Small, free-to-host image for the encrypted Incident Reporting backend.
# Only the SERVER runs here (server.py + e2e helpers). The phone app runs on
# phones, not in this container.
FROM python:3.12-slim

WORKDIR /app

COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt

COPY server.py e2e.py ./

# SQLite database lives here; mount a volume so it survives restarts.
ENV DB_PATH=/data/incident.db
VOLUME /data

EXPOSE 8000
# Shell form so $PORT (set by hosts like Render) expands; defaults to 8000 locally.
CMD uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}
