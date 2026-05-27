.PHONY: help backend backend-venv backend-reqs node-backend frontend

help:
	@echo "Makefile for OSINT-TOOL"
	@echo "Commands:"
	@echo "  make backend-venv   - create + activate Python venv (recommended manual step)"
	@echo "  make backend-reqs   - install backend Python requirements"
	@echo "  make node-backend   - start Node wrapper backend (npm start)"
	@echo "  make frontend        - start Next.js frontend (npm run dev)"

backend-venv:
	python -m venv backend/.venv
	@echo "run: source backend/.venv/bin/activate"

backend-reqs:
	python -m venv backend/.venv || true
	@echo "activating venv and installing requirements"
	. backend/.venv/bin/activate && pip install -r backend/requirements.txt

node-backend:
	cd backend_node && npm install && npm start

frontend:
	cd frontend && npm install && npm run dev
