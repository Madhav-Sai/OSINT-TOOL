#!/usr/bin/env python3
import sys
import json
from pathlib import Path
import time
import sys
from pathlib import Path

# Ensure top-level project path is on sys.path so `modules` can be imported
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# Worker can run different modes:
# metadata <file_path> <orig_name>
# subdomains <domain>
# reputation <domain_or_ip>

def emit_progress(msg: str):
    # progress marker lines start with PROGRESS: so the caller can parse them
    print(f"PROGRESS:{msg}", flush=True)


def run_metadata(file_path: str, orig_name: str):
    p = Path(file_path)
    if not p.exists():
        return {"error": "file not found"}
    data = p.read_bytes()
    name = orig_name.lower()
    try:
        from modules import metadata_inspector
    except Exception as e:
        return {"error": f"import modules failed: {e}"}

    try:
        emit_progress('started')
        time.sleep(0.1)
        if name.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp")):
            emit_progress('extracting_image')
            meta = metadata_inspector.extract_image_metadata(data, name)
            file_type = "image"
        elif name.endswith(".pdf"):
            emit_progress('extracting_pdf')
            meta = metadata_inspector.extract_pdf_metadata(data)
            file_type = "pdf"
        elif name.endswith((".docx", ".doc")):
            emit_progress('extracting_docx')
            meta = metadata_inspector.extract_docx_metadata(data)
            file_type = "docx"
        elif name.endswith((".mp3", ".mp4", ".wav", ".flac", ".ogg", ".m4a", ".mov", ".avi", ".mkv")):
            emit_progress('extracting_audio')
            meta = metadata_inspector.extract_audio_video_metadata(data, name)
            file_type = "audio_video"
        else:
            return {"error": "unsupported file type"}
        emit_progress('done')
        return {"file": orig_name, "type": file_type, "metadata": meta}
    except Exception as e:
        return {"error": str(e)}


def run_subdomains(domain: str):
    try:
        from modules import subdomains
    except Exception as e:
        return {"error": f"import modules failed: {e}"}
    emit_progress('started')
    try:
        subs = subdomains.fetch_subdomains(domain)
        emit_progress('done')
        return {"domain": domain, "subdomains": subs}
    except Exception as e:
        return {"error": str(e)}


def run_reputation(target: str):
    try:
        from modules import reputation
    except Exception as e:
        return {"error": f"import modules failed: {e}"}
    emit_progress('started')
    try:
        # choose domain vs ip heuristically
        if any(c.isalpha() for c in target):
            vt = reputation.fetch_vt_domain(target)
            emit_progress('done')
            return {"domain": target, "virustotal": vt}
        else:
            vt = reputation.fetch_vt_ip(target)
            sh = reputation.fetch_shodan_ip(target)
            ab = reputation.fetch_abuseipdb(target)
            emit_progress('done')
            return {"ip": target, "virustotal": vt, "shodan": sh, "abuseipdb": ab}
    except Exception as e:
        return {"error": str(e)}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: python_worker.py <mode> [args...]"}))
        sys.exit(2)
    mode = sys.argv[1]
    try:
        if mode == 'metadata':
            if len(sys.argv) < 4:
                print(json.dumps({"error": "usage: python_worker.py metadata <file_path> <orig_name>"}))
                sys.exit(2)
            res = run_metadata(sys.argv[2], sys.argv[3])
        elif mode == 'subdomains':
            if len(sys.argv) < 3:
                print(json.dumps({"error": "usage: python_worker.py subdomains <domain>"}))
                sys.exit(2)
            res = run_subdomains(sys.argv[2])
        elif mode == 'reputation':
            if len(sys.argv) < 3:
                print(json.dumps({"error": "usage: python_worker.py reputation <domain_or_ip>"}))
                sys.exit(2)
            res = run_reputation(sys.argv[2])
        else:
            res = {"error": f"unknown mode: {mode}"}
    except Exception as e:
        res = {"error": str(e)}

    # if res is a dict, print as JSON; progress markers may have already been emitted
    print(json.dumps(res), flush=True)
    # exit code 0 if no error
    sys.exit(0 if not (isinstance(res, dict) and res.get('error')) else 1)
