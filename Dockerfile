# AndroShield — single image serving API + dashboard.
# Static analysis only; the container never executes uploaded APKs.
FROM python:3.12-slim

WORKDIR /app

# Install deps first for layer caching (all deps ship manylinux wheels — no compiler needed).
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY frontend ./frontend

WORKDIR /app/backend
ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
