Migration scaffold (hybrid)

What I added:
- `backend/` — FastAPI scaffold exposing simple API endpoints (`/health`, `/api/hash`, `/api/reputation`)
- `frontend/` — Next.js + Tailwind scaffold (TypeScript) with a small hash demo page
- `docker-compose.yml` — dev composition to run both services

Quick start (local, project root):

```bash
# Backend only
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Start the backend from the project root to ensure imports resolve correctly:
#   uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000

# Frontend only
cd frontend
npm install
npm run dev

# Or with docker-compose (requires Docker)
docker-compose up --build
```

Next recommended steps:
- Wrap existing `modules/*` logic into FastAPI routes (one endpoint per module).
- Add authentication and API key management for external services.
- Add caching (Redis) and background workers for long-running tasks.
- Incrementally replace Streamlit UI with Next.js pages; keep Python for heavy processing.

If you want, I can now:
- Implement one or two FastAPI endpoints that call into your existing `modules/*` functions.
- Scaffold CI (GitHub Actions) and a Dockerfile for each service.
- Add a prettier/Mantine-based UI instead of raw Tailwind.

Node wrapper (npm start)
---------------------------------
I added a Node.js wrapper backend that allows starting the backend with `npm start`. It proxies light endpoints (hashing) directly in Node and calls a small Python worker for heavy metadata extraction.

To run the Node backend:

```bash
cd backend_node
npm install
npm start
```

The Node server listens on port 8000 by default and exposes the same endpoints (`/health`, `/api/hash`, `/api/hash_file`, `/api/metadata`). For metadata extraction it calls `backend/python_worker.py` which uses existing Python `modules/` code.

Developer convenience
---------------------
You can use the provided `Makefile` for common tasks from the project root:

```bash
make backend-venv    # create python venv
make backend-reqs    # install python requirements into backend venv
make node-backend    # start the Node wrapper (npm start)
make frontend        # start the frontend
```

Which next step should I take? (I can implement module wrappers now.)
