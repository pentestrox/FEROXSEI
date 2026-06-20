#!/usr/bin/env python3
"""
FEROXSEI Leaks Server - standalone credential search microservice.

Runs independently on its own port (default 5002).
FEROXSEI main app calls it via X-Leaks-Key header.

Search sources (merged automatically):
  1. Local files  - grep -F subprocess, multi-GB safe, 20 s budget
  2. DeHashed API - https://api.dehashed.com/search (Basic Auth, optional)

Config file: leaks_server/config.json  (auto-generated on first run)
"""

import json, os, subprocess, uuid, time, resource
import urllib.request as _ureq
import urllib.error   as _uerr
from functools import wraps
from flask import Flask, request, jsonify

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DEFAULT_CFG = {
    "api_key":          uuid.uuid4().hex,
    "port":             5002,
    "host":             "0.0.0.0",
    "dirs":             [],
    "dehashed_api_key": "",
    "dehashed_enabled": False
}

MEM_LIMIT_GB  = 8
SEARCH_BUDGET = 20.0

# ── memory cap ────────────────────────────────────────────────────────────────

def _apply_mem_limit(gb):
    try:
        limit = gb * 1024 ** 3
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        return True
    except Exception:
        return False

# ── config helpers ────────────────────────────────────────────────────────────

def _load():
    if not os.path.exists(CONFIG_FILE):
        _save(DEFAULT_CFG)
    with open(CONFIG_FILE, encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CFG.items():
        cfg.setdefault(k, v)
    return cfg

def _save(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__)

def _require_key(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        cfg = _load()
        k   = request.headers.get("X-Leaks-Key", "")
        if not k or k != cfg.get("api_key", ""):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return _wrap

# ── health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    cfg = _load()
    return jsonify({
        "ok":               True,
        "service":          "feroxsei-leaks-server",
        "dirs":             len(cfg.get("dirs", [])),
        "dehashed_enabled": bool(cfg.get("dehashed_enabled") and
                                 cfg.get("dehashed_api_key"))
    })

# ── DeHashed API v2 ───────────────────────────────────────────────────────────

DEHASHED_URL = "https://api.dehashed.com/v2/search"

def _dehashed_call(api_key, query, size=100, page=1, wildcard=False, regex=False, de_dupe=True):
    """
    Call DeHashed API v2.
    Auth: DeHashed-Api-Key header.
    POST JSON body; all credential fields in response are lists.
    Returns parsed JSON dict or raises.
    """
    body = json.dumps({
        "query":    query,
        "page":     page,
        "size":     size,
        "wildcard": wildcard,
        "regex":    regex,
        "de_dupe":  de_dupe,
    }).encode()
    req = _ureq.Request(DEHASHED_URL, data=body, method="POST")
    req.add_header("Content-Type",    "application/json")
    req.add_header("DeHashed-Api-Key", api_key)
    with _ureq.urlopen(req, timeout=20) as r:
        return json.loads(r.read())

def _first(val):
    """Return first element if val is a list, else val itself, or ''."""
    if isinstance(val, list):
        return val[0] if val else ""
    return val or ""

def _dehashed_entry_to_line(entry):
    """
    Format a DeHashed v2 entry as a human-readable credential line.
    All fields (email, password, username, …) are lists in v2.
    """
    email    = _first(entry.get("email"))
    username = _first(entry.get("username"))
    password = _first(entry.get("password"))
    hashed   = _first(entry.get("hashed_password"))

    primary = email or username or ""
    pw      = password or hashed or ""
    line    = f"{primary}:{pw}" if primary and pw else (primary or pw or "(no credential)")

    extras = []
    for fld in ("name", "phone", "ip_address", "address", "company"):
        v = _first(entry.get(fld))
        if v:
            extras.append(f"{fld}={v}")

    db  = entry.get("database_name") or "DeHashed"
    tag = f"[{db} | {', '.join(extras)}]" if extras else f"[{db}]"
    return f"{line}  {tag}"

def _dehashed_search(cfg, query, limit):
    """
    Search DeHashed and return (results_list, balance_remaining, error_str).
    """
    api_key = cfg.get("dehashed_api_key", "").strip()
    if not api_key:
        return [], None, "DeHashed API key not configured"

    size = min(limit, 10000)
    try:
        data    = _dehashed_call(api_key, query, size=size)
        entries = data.get("entries") or []
        balance = data.get("balance")
        results = [_dehashed_entry_to_line(e) for e in entries if e]
        return results, balance, None
    except _uerr.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")[:200]
        except Exception:
            pass
        return [], None, f"HTTP {e.code}: {body}"
    except Exception as ex:
        return [], None, str(ex)

# ── /api/dehashed endpoints ───────────────────────────────────────────────────

@app.route("/api/dehashed/config", methods=["GET"])
@_require_key
def dehashed_get_config():
    cfg = _load()
    return jsonify({
        "ok":               True,
        "dehashed_enabled": bool(cfg.get("dehashed_enabled")),
        "has_key":          bool(cfg.get("dehashed_api_key")),
    })

@app.route("/api/dehashed/config", methods=["POST"])
@_require_key
def dehashed_set_config():
    data = request.get_json(force=True) or {}
    cfg  = _load()
    if "api_key" in data:
        cfg["dehashed_api_key"] = data["api_key"].strip()
    if "enabled" in data:
        cfg["dehashed_enabled"] = bool(data["enabled"])
    _save(cfg)
    return jsonify({"ok": True})

@app.route("/api/dehashed/test", methods=["POST"])
@_require_key
def dehashed_test():
    """Test DeHashed credentials with a minimal 1-result query."""
    cfg     = _load()
    data    = request.get_json(force=True) or {}
    api_key = data.get("api_key", cfg.get("dehashed_api_key", "")).strip()
    if not api_key:
        return jsonify({"ok": False, "error": "API key required"}), 400
    try:
        resp = _dehashed_call(api_key, "test@example.com", size=1)
        return jsonify({
            "ok":      True,
            "balance": resp.get("balance"),
            "total":   resp.get("total", 0),
            "message": "Connected successfully",
        })
    except _uerr.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")[:300]
        except Exception:
            pass
        return jsonify({"ok": False, "error": f"HTTP {e.code}: {body}"}), 400
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 400

@app.route("/api/dehashed/balance", methods=["GET"])
@_require_key
def dehashed_balance():
    cfg     = _load()
    api_key = cfg.get("dehashed_api_key", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "API key not configured"}), 400
    try:
        resp = _dehashed_call(api_key, "test@example.com", size=1)
        return jsonify({"ok": True, "balance": resp.get("balance")})
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 400

# ── local file search ─────────────────────────────────────────────────────────

def _is_searchable(fname):
    _, ext = os.path.splitext(fname)
    return ext == "" or ext.lower() == ".txt"

def _shard_key(name, first_char):
    return (0 if name.lower().startswith(first_char) else 1, name.lower())

def _grep_file(fpath, q, remaining, time_left):
    try:
        proc = subprocess.run(
            ["grep", "-F", "-i", "-m", str(remaining), q, fpath],
            capture_output=True, text=True,
            timeout=min(time_left, 12.0),
            errors="replace"
        )
        return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception:
        return []

def _search_dir(directory, q, limit, deadline):
    results = []
    capped  = False
    if not os.path.isdir(directory):
        return results, capped
    first_char = q[0] if q else ""
    for root, dirs, files in os.walk(directory):
        dirs.sort(key=lambda d: _shard_key(d, first_char))
        for fname in sorted(files, key=lambda f: _shard_key(f, first_char)):
            if not _is_searchable(fname):
                continue
            now = time.monotonic()
            if now >= deadline:
                capped = True
                break
            remaining = limit - len(results)
            fpath     = os.path.join(root, fname)
            hits      = _grep_file(fpath, q, remaining, deadline - now)
            results.extend(hits)
            if len(results) >= limit:
                capped = True
                break
        if capped or time.monotonic() >= deadline:
            capped = True
            break
    return results, capped

# ── unified search ────────────────────────────────────────────────────────────

@app.route("/api/search", methods=["POST"])
@_require_key
def api_search():
    data  = request.get_json(force=True) or {}
    q     = (data.get("q", "") or "").strip()
    limit = min(int(data.get("limit", 500)), 1000)

    if not q or len(q) < 3:
        return jsonify({"ok": False, "error": "Query too short (min 3 chars)"}), 400

    cfg      = _load()
    results  = []
    capped   = False
    sources  = {}
    deadline = time.monotonic() + SEARCH_BUDGET

    # ── 1. Local file search ─────────────────────────────────────────────────
    local_results = []
    for d in cfg.get("dirs", []):
        r, c = _search_dir(d, q, limit - len(local_results), deadline)
        local_results.extend(r)
        if c or len(local_results) >= limit or time.monotonic() >= deadline:
            capped = True
            break
    sources["local"] = len(local_results)
    results.extend(local_results)

    # ── 2. DeHashed API search ───────────────────────────────────────────────
    dh_balance = None
    dh_error   = None
    if cfg.get("dehashed_enabled") and cfg.get("dehashed_api_key"):
        dh_limit   = max(1, limit - len(results))
        dh_results, dh_balance, dh_error = _dehashed_search(cfg, q, dh_limit)
        if dh_results:
            results.extend(dh_results)
            sources["dehashed"] = len(dh_results)
            if len(results) >= limit:
                capped = True

    return jsonify({
        "ok":      True,
        "query":   q,
        "count":   len(results),
        "results": results,
        "capped":  capped,
        "sources": sources,
        "dehashed_balance": dh_balance,
        "dehashed_error":   dh_error
    })

# ── directory management ──────────────────────────────────────────────────────

def _wc_lines(fpath):
    try:
        out = subprocess.check_output(
            ["wc", "-l", fpath], stderr=subprocess.DEVNULL, timeout=30
        ).decode().strip().split()[0]
        return int(out)
    except Exception:
        return 0

def _dir_stats(d):
    if not os.path.isdir(d):
        return {"exists": False, "files": 0, "records": 0}
    files   = 0
    records = 0
    for root, _dirs, fnames in os.walk(d):
        for fn in fnames:
            if not _is_searchable(fn):
                continue
            files   += 1
            records += _wc_lines(os.path.join(root, fn))
    return {"exists": True, "files": files, "records": records}

@app.route("/api/dirs", methods=["GET"])
@_require_key
def list_dirs():
    cfg  = _load()
    rows = []
    for d in cfg.get("dirs", []):
        st = _dir_stats(d)
        rows.append({"path": d, "exists": st["exists"],
                     "files": st["files"], "records": st["records"]})
    return jsonify({"ok": True, "dirs": rows})

@app.route("/api/dirs", methods=["POST"])
@_require_key
def add_dir():
    data = request.get_json(force=True) or {}
    path = (data.get("path", "") or "").strip()
    if not path:
        return jsonify({"ok": False, "error": "path required"}), 400
    if not os.path.isdir(path):
        return jsonify({"ok": False, "error": "Directory does not exist on leaks server"}), 400
    cfg = _load()
    if path not in cfg.get("dirs", []):
        cfg.setdefault("dirs", []).append(path)
        _save(cfg)
    return jsonify({"ok": True})

@app.route("/api/dirs", methods=["DELETE"])
@_require_key
def remove_dir():
    data = request.get_json(force=True) or {}
    path = (data.get("path", "") or "").strip()
    cfg  = _load()
    cfg["dirs"] = [d for d in cfg.get("dirs", []) if d != path]
    _save(cfg)
    return jsonify({"ok": True})

# ── key rotation ──────────────────────────────────────────────────────────────

@app.route("/api/rotate-key", methods=["POST"])
@_require_key
def rotate_key():
    cfg     = _load()
    new_key = uuid.uuid4().hex
    cfg["api_key"] = new_key
    _save(cfg)
    return jsonify({"ok": True, "api_key": new_key})

# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cfg  = _load()
    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 5002)
    key  = cfg.get("api_key", "")
    dh_on = bool(cfg.get("dehashed_enabled") and cfg.get("dehashed_api_key"))

    mem_ok = _apply_mem_limit(MEM_LIMIT_GB)

    import socket as _sock
    try:
        _display_ip = _sock.gethostbyname(_sock.gethostname())
    except Exception:
        _display_ip = host if host != "0.0.0.0" else "<this-server-ip>"

    print(f"\n{'='*60}")
    print(f"  FEROXSEI Leaks Server")
    print(f"  Listening  : {host}:{port}")
    print(f"  Public URL : http://{_display_ip}:{port}")
    print(f"  API Key    : {key}")
    print(f"  Local dirs : {len(cfg.get('dirs', []))}")
    print(f"  DeHashed   : {'ENABLED (API v2)' if dh_on else 'disabled (configure in Settings → Leaks)'}")
    print(f"  Memory cap : {MEM_LIMIT_GB} GB {'(active)' if mem_ok else '(unavailable)'}")
    print(f"  Search     : grep -F + DeHashed API  |  budget: {SEARCH_BUDGET}s")
    print(f"{'='*60}")
    print(f"\n  In FEROXSEI → Settings → Leaks → Remote Leaks Server:")
    print(f"    URL : http://{_display_ip}:{port}")
    print(f"    Key : {key}\n")

    app.run(host=host, port=port, debug=False, threaded=True)
