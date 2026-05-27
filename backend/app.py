from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import hashlib
from typing import Optional, List, Dict
import asyncio
from modules import hash_tool, metadata_inspector

app = FastAPI(title="OSINT-TOOL API", version="0.2")


class HashRequest(BaseModel):
    algorithm: str = "sha256"
    value: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/hash")
async def compute_hash(req: HashRequest):
    algo = req.algorithm.lower()
    if algo not in hashlib.algorithms_guaranteed:
        raise HTTPException(status_code=400, detail={"error": "unsupported algorithm", "supported": sorted(list(hashlib.algorithms_guaranteed))})
    h = hashlib.new(algo)
    h.update(req.value.encode("utf-8"))
    return {"algorithm": algo, "hash": h.hexdigest()}


@app.post("/api/hash_file")
async def compute_hash_file(algorithm: str = Form("sha256"), file: UploadFile = File(...)):
    data = await file.read()
    algo = algorithm.lower()
    if algo not in hashlib.algorithms_guaranteed:
        raise HTTPException(status_code=400, detail={"error": "unsupported algorithm", "supported": sorted(list(hashlib.algorithms_guaranteed))})
    result = hash_tool.compute_hash(data, algo)
    if result is None:
        raise HTTPException(status_code=500, detail="failed to compute hash")
    return {"algorithm": algo, "filename": file.filename, "hash": result}


@app.post("/api/metadata")
async def metadata_inspect(file: UploadFile = File(...), job_id: Optional[str] = Form(None)):
    """Inspect uploaded file and optionally broadcast progress to WebSocket subscribers for `job_id`."""
    data = await file.read()
    fname = (file.filename or "").lower()

    async def send_progress(msg: str):
        if not job_id:
            return
        await broadcast_progress(job_id, msg)

    try:
        await send_progress('started')
        if fname.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp")):
            await send_progress('extracting_image')
            meta = metadata_inspector.extract_image_metadata(data, fname)
            file_type = "image"
        elif fname.endswith(".pdf"):
            await send_progress('extracting_pdf')
            meta = metadata_inspector.extract_pdf_metadata(data)
            file_type = "pdf"
        elif fname.endswith((".docx", ".doc")):
            await send_progress('extracting_docx')
            meta = metadata_inspector.extract_docx_metadata(data)
            file_type = "docx"
        elif fname.endswith((".mp3", ".mp4", ".wav", ".flac", ".ogg", ".m4a", ".mov", ".avi", ".mkv")):
            await send_progress('extracting_audio')
            meta = metadata_inspector.extract_audio_video_metadata(data, fname)
            file_type = "audio_video"
        else:
            raise HTTPException(status_code=400, detail="unsupported file type")
        await send_progress('done')
    except Exception as e:
        await send_progress(f'error:{str(e)}')
        raise HTTPException(status_code=500, detail=str(e))

    return {"file": file.filename, "type": file_type, "metadata": meta}


# --- WebSocket progress broadcaster (in-memory, demo use only) ---
JOB_SUBSCRIBERS: Dict[str, List[WebSocket]] = {}
JOB_LOCK = asyncio.Lock()

async def broadcast_progress(job_id: str, message: str):
    async with JOB_LOCK:
        subs = JOB_SUBSCRIBERS.get(job_id, [])[:]
    for ws in subs:
        try:
            await ws.send_text(message)
        except Exception:
            # ignore; removal happens on disconnect
            pass


@app.websocket('/ws/metadata/{job_id}')
async def ws_metadata(websocket: WebSocket, job_id: str):
    await websocket.accept()
    async with JOB_LOCK:
        JOB_SUBSCRIBERS.setdefault(job_id, []).append(websocket)
    try:
        while True:
            # keep connection alive; we don't expect messages from client
            await websocket.receive_text()
    except WebSocketDisconnect:
        async with JOB_LOCK:
            lst = JOB_SUBSCRIBERS.get(job_id, [])
            if websocket in lst:
                lst.remove(websocket)


@app.post("/api/reputation")
async def reputation(payload: dict):
    # Placeholder endpoint — wire real module calls here.
    return {"status": "accepted", "payload": payload}
