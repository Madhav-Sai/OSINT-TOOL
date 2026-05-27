FastAPI backend scaffold for OSINT-TOOL

Run locally:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Run from project root to avoid import conflicts:
#   uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
# Or set PYTHONPATH to project root and run from backend/:
#   PYTHONPATH=".." uvicorn app:app --reload --host 0.0.0.0 --port 8000
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Available endpoints:
- `GET /health` — health check
- `POST /api/hash` — JSON body `{ "algorithm": "sha256", "value": "text" }`
- `POST /api/reputation` — placeholder for reputation queries

This is a scaffold. Replace placeholder endpoints with wrappers around existing `modules/*` functions as needed.
