from fastapi import FastAPI, Request, UploadFile, File, Form, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import io
import hashlib
import json
import os
import requests
from urllib.parse import quote
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

import jwt 

# PDF / ReportLab
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm, inch
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# QR
import qrcode


# ---------------- ENV / CONFIG ----------------
NODE_GATEWAY_URL = os.getenv("NODE_GATEWAY_URL", "http://localhost:3000")

JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_change_this")

DEBUG_AUTH = (os.getenv("DEBUG_AUTH", "0").strip() == "1")


# ---------------- APP ----------------
app = FastAPI(title="Document Verifier (FastAPI)")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ---------------- AUTH HELPERS ----------------
def _read_token_from_request(request: Request) -> str | None:
    # 1) Authorization: Bearer <token>
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    # 2) Cookie: auth_token=<token>
    token = request.cookies.get("auth_token")
    if token:
        return token.strip()

    return None


def read_jwt_from_cookie(request: Request):
    """
    Verifies JWT stored in cookie.
    Token is issued by Node (/auth/login).
    """
    token = request.cookies.get("auth_token")
    if DEBUG_AUTH:
        print("COOKIE TOKEN:", token)
        print("JWT_SECRET:", JWT_SECRET)

    if not token:
        return None

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if DEBUG_AUTH:
            print("DECODE OK:", decoded)
        return decoded
    except Exception as e:
        if DEBUG_AUTH:
            print("DECODE ERROR:", e)
        return None


def get_current_claims_or_none(request: Request) -> dict | None:
    """
    Prefer cookie claims (browser flow). If later you add API calls with Bearer header,
    you can decode that too, but right now UI uses cookie.
    """
    return read_jwt_from_cookie(request)


def get_current_user_id(request: Request) -> str | None:
    claims = get_current_claims_or_none(request)
    sub = (claims or {}).get("sub")
    if isinstance(sub, str) and sub.strip():
        return sub.strip()
    return None


def is_admin(request: Request) -> bool:
    claims = get_current_claims_or_none(request) or {}
    return str(claims.get("role") or "").lower() == "admin"


def require_login_or_redirect(request: Request, next_path: str):
    if read_jwt_from_cookie(request):
        return
    return RedirectResponse(url=f"/login?next={quote(next_path)}", status_code=303)


def require_admin_or_redirect(request: Request, next_path: str):
    redir = require_login_or_redirect(request, next_path)
    if redir:
        return redir

    if not is_admin(request):
        return RedirectResponse(url="/", status_code=303)
    return None


def safe_next(n: str | None) -> str:
    n = (n or "/").strip()
    if not n.startswith("/"):
        return "/"
    if n.startswith("/login") or n.startswith("/auth"):
        return "/"
    return n


# ---------------- BASIC HELPERS ----------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt_dt(iso: str) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def _node_headers_from_request(request: Request) -> dict:
    """
    Node API is fully protected; we forward JWT in Authorization header.
    """
    token = _read_token_from_request(request)
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def node_get(request: Request, path: str, timeout: int = 30):
    headers = _node_headers_from_request(request)
    return requests.get(f"{NODE_GATEWAY_URL}{path}", headers=headers, timeout=timeout)


def node_post(request: Request, path: str, payload: dict, timeout: int = 30):
    headers = _node_headers_from_request(request)
    return requests.post(f"{NODE_GATEWAY_URL}{path}", json=payload, headers=headers, timeout=timeout)


def safe_json(r: requests.Response):
    try:
        return r.json()
    except Exception:
        return {"error": "Non-JSON response from node", "raw": r.text, "status_code": r.status_code}


def node_says_exists_by_hash(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("exists") is True:
        return True
    doc = payload.get("doc")
    if isinstance(doc, dict) and doc:
        return True
    if payload.get("documentId") or payload.get("contentHash") or payload.get("txId"):
        return True
    return False


def fmt_iso_human(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso


def wrap_hex(s: str, every: int = 40) -> str:
    if not s:
        return "—"
    s = str(s).strip()
    return "<br/>".join(s[i:i+every] for i in range(0, len(s), every))


# ---------------- AUTH ROUTES ----------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    nxt = safe_next(next)

    claims = read_jwt_from_cookie(request)
    if claims:
        return RedirectResponse(url=nxt, status_code=302)

    return templates.TemplateResponse("login.html", {
        "request": request,
        "next": nxt,
    })


@app.post("/auth/login")
async def auth_login(
    request: Request,
    userId: str = Form(...),
    password: str = Form(...),
    next: str = Form("/")
):
    """
    Login is handled by Node:
      FastAPI form -> Node /auth/login (JSON) -> JWT token -> set cookie -> redirect
    """
    nxt = safe_next(next)

    try:
        r = requests.post(
            f"{NODE_GATEWAY_URL}/auth/login",
            json={"userId": userId, "password": password},
            timeout=20
        )
    except Exception as e:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "next": nxt,
            "error": f"Nem érhető el a Node auth szolgáltatás. ({e})"
        }, status_code=502)

    if r.status_code >= 400:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "next": nxt,
            "error": "Hibás felhasználónév vagy jelszó (vagy nincs Fabrices identity ennél a usernél)."
        }, status_code=401)

    data = safe_json(r)
    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "next": nxt,
            "error": "Sikertelen bejelentkezés (hiányzó token)."
        }, status_code=401)

    resp = RedirectResponse(url=nxt, status_code=302)

    resp.set_cookie(
        key="auth_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  
        path="/"
    )
    return resp


@app.post("/auth/logout")
async def auth_logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("auth_token", path="/")
    return resp


# ---------------- PAGES ----------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    redir = require_login_or_redirect(request, "/")
    if redir:
        return redir

    claims = read_jwt_from_cookie(request)
    user = claims.get("sub") if claims else ""
    role = claims.get("role") if claims else ""

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "role": role,
            "is_admin": str(role or "").lower() == "admin",
        }
    )


@app.get("/health")
def health():
    return {"ok": True, "node": NODE_GATEWAY_URL}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    redir = require_login_or_redirect(request, "/dashboard")
    if redir:
        return redir

    claims = read_jwt_from_cookie(request) or {}
    role = claims.get("role") or ""

    try:
        r = node_get(request, "/documents/ids", timeout=30)
        ok = r.status_code < 400
        data = r.json() if ok else {"items": [], "error": r.text, "status_code": r.status_code}

        items = []
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            items = data["items"]

        enriched = []
        total_versions = 0
        revoked_count = 0
        latest_created_at_iso = None

        for it in items:
            doc_id = (it or {}).get("documentId")
            first_seen = (it or {}).get("firstSeenAt")

            latest_doc = None
            versions = []

            if doc_id:
                rv = node_get(request, f"/documents/versioned/{doc_id}", timeout=30)
                if rv.status_code < 400:
                    dv = rv.json()
                    if isinstance(dv, dict) and isinstance(dv.get("versions"), list):
                        versions = dv["versions"]

                total_versions += len(versions)

                for v in versions:
                    if isinstance(v, dict) and str(v.get("status", "")).upper() == "REVOKED":
                        revoked_count += 1

                if versions:
                    try:
                        versions_sorted = sorted(versions, key=lambda x: int(x.get("version", 0)))
                        latest_doc = versions_sorted[-1]
                    except Exception:
                        latest_doc = versions[-1]

                if latest_doc and isinstance(latest_doc, dict):
                    ca = latest_doc.get("createdAt")
                    if ca:
                        if (latest_created_at_iso is None) or (str(ca) > str(latest_created_at_iso)):
                            latest_created_at_iso = ca

            enriched.append({
                "documentId": doc_id,
                "firstSeenAt": first_seen,
                "latest": latest_doc,
                "versionsCount": len(versions),
            })

        latest_created_at_fmt = ""
        if latest_created_at_iso:
            try:
                dt = datetime.fromisoformat(str(latest_created_at_iso).replace("Z", "+00:00")).astimezone()
                latest_created_at_fmt = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                latest_created_at_fmt = str(latest_created_at_iso)

        stats = {
            "totalDocumentIds": len(items),
            "totalVersions": total_versions,
            "revokedCount": revoked_count,
            "latestCreatedAt": latest_created_at_fmt or "—",
        }

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "ok": ok,
            "items": enriched,
            "stats": stats,
            "error": data.get("error") if isinstance(data, dict) else None,
            "role": role,
            "is_admin": str(role or "").lower() == "admin",
        })

    except Exception as e:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "ok": False,
            "items": [],
            "stats": {
                "totalDocumentIds": 0,
                "totalVersions": 0,
                "revokedCount": 0,
                "latestCreatedAt": "—",
            },
            "error": str(e),
            "role": role,
            "is_admin": str(role or "").lower() == "admin",
        })


# --------- ADMIN PAGES ---------
@app.get("/api/admin/network")
async def api_admin_network(request: Request):
    claims = read_jwt_from_cookie(request)
    if not claims or str(claims.get("role", "")).lower() != "admin":
        return JSONResponse(status_code=403, content={"error": "Admin required"})

    checked_at = datetime.now(timezone.utc).isoformat()

    node_ok = False
    node = {}
    try:
        r = node_get(request, "/health", timeout=10)
        node_ok = r.status_code < 400
        d = safe_json(r)
        node = {
            "ok": node_ok,
            "status_code": r.status_code,
            "build": d.get("build") if isinstance(d, dict) else None,
            "channel": d.get("channelName") if isinstance(d, dict) else None,
            "chaincode": d.get("chaincodeName") if isinstance(d, dict) else None,
            "mspId": d.get("mspId") if isinstance(d, dict) else None,
            "peer": d.get("peerName") if isinstance(d, dict) else None,
            "raw": d,
        }
    except Exception as e:
        node = {"ok": False, "error": str(e)}

    ledger_ok = False
    ledger = {}
    try:
        r = node_get(request, "/documents/ids", timeout=15)
        d = safe_json(r)
        if r.status_code < 400 and isinstance(d, dict) and isinstance(d.get("items"), list):
            items = d["items"]
            total_document_ids = len(items)
            total_versions = 0
            revoked_count = 0
            archived_count = 0
            registered_count = 0
            latest_created_at = None

            for it in items:
                doc_id = (it or {}).get("documentId")
                if not doc_id:
                    continue

                rv = node_get(request, f"/documents/versioned/{doc_id}", timeout=20)
                if rv.status_code >= 400:
                    continue

                dv = safe_json(rv)
                versions = dv.get("versions", []) if isinstance(dv, dict) else []
                total_versions += len(versions)

                for v in versions:
                    if not isinstance(v, dict):
                        continue

                    st = str(v.get("status", "")).upper()
                    if st == "REVOKED":
                        revoked_count += 1
                    elif st == "ARCHIVED":
                        archived_count += 1
                    elif st == "REGISTERED":
                        registered_count += 1

                    ca = v.get("createdAt")
                    if ca and (latest_created_at is None or str(ca) > str(latest_created_at)):
                        latest_created_at = ca

            ledger_ok = True
            ledger = {
                "ok": True,
                "totalDocumentIds": total_document_ids,
                "totalVersions": total_versions,
                "revokedCount": revoked_count,
                "archivedCount": archived_count,
                "registeredCount": registered_count,
                "latestCreatedAt": fmt_dt(str(latest_created_at)) if latest_created_at else "—",
            }
        else:
            ledger = {"ok": False, "status_code": r.status_code, "raw": d}
    except Exception as e:
        ledger = {"ok": False, "error": str(e)}

    fabric_ok = False
    fabric = {}
    try:
        r = node_get(request, "/admin/status", timeout=15)
        d = safe_json(r)

        if r.status_code < 400 and isinstance(d, dict):
            fabric_ok = bool(d.get("ok"))
            fabric = {
                "ok": fabric_ok,
                "caStatus": d.get("caStatus", "unknown"),
                "peerStatus": d.get("peerStatus", "unknown"),
                "authStatus": d.get("authStatus", "unknown"),
                "details": d.get("details", {}),
            }
        else:
            fabric = {
                "ok": False,
                "caStatus": "unknown",
                "peerStatus": "unknown",
                "authStatus": "unknown",
                "raw": d,
            }
    except Exception as e:
        fabric = {
            "ok": False,
            "caStatus": "unknown",
            "peerStatus": "unknown",
            "authStatus": "unknown",
            "error": str(e),
        }

    return {
        "checkedAt": checked_at,
        "node": node,
        "fabric": fabric,
        "ledger": ledger,
    }

@app.get("/admin/network", response_class=HTMLResponse)
async def admin_network(request: Request):
    redir = require_admin_or_redirect(request, "/admin/network")
    if redir:
        return redir

    health_r = None
    ids_r = None
    health_data = None
    ids_data = None

    try:
        health_r = node_get(request, "/health", timeout=10)
        health_data = safe_json(health_r)
    except Exception as e:
        health_data = {"error": str(e)}

    try:
        ids_r = node_get(request, "/documents/ids", timeout=15)
        ids_data = safe_json(ids_r)
    except Exception as e:
        ids_data = {"error": str(e)}

    return templates.TemplateResponse("admin_network.html", {
        "request": request,
        "node_gateway_url": NODE_GATEWAY_URL,
        "health_status": getattr(health_r, "status_code", None),
        "health_data": health_data,
        "ids_status": getattr(ids_r, "status_code", None),
        "ids_data": ids_data,
        "is_admin": True,
    })


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        return redir

    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "is_admin": True,
    })


@app.post("/admin/users", response_class=HTMLResponse)
async def admin_users_create(
    request: Request,
    userId: str = Form(...),
    password: str = Form(...),
):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        return redir

    payload = {"userId": userId, "password": password, "role": "user"}
    try:
        r = node_post(request, "/admin/users", payload, timeout=30)
        data = safe_json(r)
        ok = r.status_code < 400
    except Exception as e:
        ok = False
        data = {"error": str(e)}

    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "is_admin": True,
        "create_ok": ok,
        "create_result": data,
        "create_status": getattr(r, "status_code", None) if "r" in locals() else None,
    })


@app.get("/api/admin/users")
async def api_admin_users_get(request: Request):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        raise HTTPException(status_code=401, detail="Admin login required")

    try:
        r = node_get(request, "/admin/users", timeout=20)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/admin/users")
async def api_admin_users_post(request: Request, payload: dict = Body(...)):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        raise HTTPException(status_code=401, detail="Admin login required")

    user_id = str(payload.get("userId") or "").strip()
    password = str(payload.get("password") or "")
    role = str(payload.get("role") or "user").lower()
    if role not in ("admin", "user"):
        role = "user"

    if not user_id or not password:
        raise HTTPException(status_code=400, detail="userId and password required")

    out = {"userId": user_id, "password": password, "role": role}

    try:
        r = node_post(request, "/admin/users", out, timeout=30)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/admin/users/{user_id}/disable")
async def api_admin_user_disable(request: Request, user_id: str):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        raise HTTPException(status_code=401, detail="Admin login required")

    uid = str(user_id or "").strip()
    if not uid:
        raise HTTPException(status_code=400, detail="userId required")

    try:
        r = node_post(request, f"/admin/users/{uid}/disable", {}, timeout=20)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/admin/users/{user_id}/enable")
async def api_admin_user_enable(request: Request, user_id: str):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        raise HTTPException(status_code=401, detail="Admin login required")

    uid = str(user_id or "").strip()
    if not uid:
        raise HTTPException(status_code=400, detail="userId required")

    try:
        r = node_post(request, f"/admin/users/{uid}/enable", {}, timeout=20)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/admin/users/{user_id}/reset-password")
async def api_admin_user_reset_password(request: Request, user_id: str, payload: dict = Body(...)):
    redir = require_admin_or_redirect(request, "/admin/users")
    if redir:
        raise HTTPException(status_code=401, detail="Admin login required")

    uid = str(user_id or "").strip()
    password = str(payload.get("password") or "")

    if not uid or not password:
        raise HTTPException(status_code=400, detail="userId and password required")

    try:
        r = node_post(
            request,
            f"/admin/users/{uid}/reset-password",
            {"password": password},
            timeout=30
        )
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/export/audit.csv")
async def export_audit_csv(request: Request):
    redir = require_login_or_redirect(request, "/dashboard")
    if redir:
        return redir

    try:
        r = node_get(request, "/documents/ids", timeout=30)
        if r.status_code >= 400:
            raise HTTPException(status_code=500, detail=f"Node /documents/ids error: {r.text}")

        data = r.json()
        items = data.get("items", []) if isinstance(data, dict) else []

        header = [
            "documentId",
            "version",
            "contentHash",
            "previousHash",
            "owner",
            "status",
            "createdAt",
            "createdByMSP",
            "txId",
        ]

        import csv

        def iter_csv_excel():
            yield "\ufeff"
            buf = io.StringIO()
            w = csv.writer(buf, delimiter=';')

            w.writerow(header)
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

            for it in items:
                doc_id = (it or {}).get("documentId")
                if not doc_id:
                    continue

                rv = node_get(request, f"/documents/versioned/{doc_id}", timeout=30)
                if rv.status_code >= 400:
                    continue

                dv = rv.json()
                versions = dv.get("versions", []) if isinstance(dv, dict) else []
                for v in versions:
                    if not isinstance(v, dict):
                        continue
                    w.writerow([
                        v.get("documentId", doc_id),
                        v.get("version", ""),
                        v.get("contentHash", ""),
                        v.get("previousHash", ""),
                        v.get("owner", ""),
                        v.get("status", ""),
                        v.get("createdAt", ""),
                        v.get("createdByMSP", ""),
                        v.get("txId", ""),
                    ])
                    yield buf.getvalue()
                    buf.seek(0); buf.truncate(0)

        return StreamingResponse(
            iter_csv_excel(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="audit.csv"'}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/timeline/{document_id}", response_class=HTMLResponse)
async def timeline(request: Request, document_id: str):
    redir = require_login_or_redirect(request, f"/timeline/{document_id}")
    if redir:
        return redir

    try:
        r = node_get(request, f"/documents/versioned/{document_id}", timeout=30)
        ok = r.status_code < 400
        data = safe_json(r) if ok else {"error": r.text, "status_code": r.status_code}

        versions = []
        if isinstance(data, dict) and isinstance(data.get("versions"), list):
            versions = data["versions"]

        for v in versions:
            if isinstance(v, dict) and "createdAt" in v:
                v["_createdAtFmt"] = fmt_dt(v.get("createdAt"))

        return templates.TemplateResponse("timeline.html", {
            "request": request,
            "ok": ok,
            "document_id": document_id,
            "versions": versions,
            "error": data.get("error") if isinstance(data, dict) else None
        })
    except Exception as e:
        return templates.TemplateResponse("timeline.html", {
            "request": request,
            "ok": False,
            "document_id": document_id,
            "versions": [],
            "error": str(e)
        })


@app.get("/api/latest/{document_id}")
async def api_latest(request: Request, document_id: str):
    try:
        r = node_get(request, f"/documents/latest/{document_id}", timeout=30)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/verify/{doc_hash}")
async def api_verify_hash(request: Request, doc_hash: str):
    try:
        r = node_get(request, f"/documents/by-hash/{doc_hash}", timeout=30)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/verify", response_class=HTMLResponse)
async def verify_by_hash(request: Request, doc_hash: str = Form(...)):
    redir = require_login_or_redirect(request, "/")
    if redir:
        return redir

    try:
        r = node_get(request, f"/documents/by-hash/{doc_hash}", timeout=30)
        ok = r.status_code < 400
        data = safe_json(r) if ok else {"error": r.text, "status_code": r.status_code}

        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Hash ellenőrzés",
            "action": "verify-hash",
            "ok": ok,
            "hash": doc_hash,
            "result": data
        })
    except Exception as e:
        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Hash ellenőrzés",
            "action": "verify-hash",
            "ok": False,
            "hash": doc_hash,
            "result": {"error": str(e)}
        })


@app.post("/verify-file", response_class=HTMLResponse)
async def verify_file(request: Request, file: UploadFile = File(...)):
    redir = require_login_or_redirect(request, "/")
    if redir:
        return redir

    try:
        content = await file.read()
        content_hash = sha256_bytes(content)

        r = node_get(request, f"/documents/by-hash/{content_hash}", timeout=30)
        ok = r.status_code < 400
        data = safe_json(r) if ok else {"error": r.text, "status_code": r.status_code}

        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Fájl ellenőrzés",
            "action": "verify-file",
            "ok": ok,
            "hash": content_hash,
            "result": data
        })
    except Exception as e:
        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Fájl ellenőrzés",
            "action": "verify-file",
            "ok": False,
            "hash": "",
            "result": {"error": str(e)}
        })


@app.post("/upload-versioned/prepare", response_class=HTMLResponse)
async def upload_versioned_prepare(
    request: Request,
    file: UploadFile = File(...),
    documentId: str = Form(...),
    owner: str = Form(...), 
):
    redir = require_login_or_redirect(request, "/")
    if redir:
        return redir

    owner_from_jwt = get_current_user_id(request)
    if not owner_from_jwt:
        return RedirectResponse(url="/login?next=/", status_code=303)

    try:
        content = await file.read()
        content_hash = sha256_bytes(content)

        metadata = {
            "filename": file.filename,
            "type": file.content_type,
            "size": len(content),
        }

        r_by_hash = node_get(request, f"/documents/by-hash/{content_hash}", timeout=30)
        data_by_hash = safe_json(r_by_hash)

        if r_by_hash.status_code < 400 and node_says_exists_by_hash(data_by_hash):
            return templates.TemplateResponse("result.html", {
                "request": request,
                "title": "Verzió mentése",
                "action": "upload-versioned",
                "ok": True,
                "hash": content_hash,
                "result": {
                    "alreadyRegistered": True,
                    "message": "Ez a tartalom (hash) már létezik a blokkláncon. Ugyanaz a hash csak egyszer kerülhet fel.",
                    **data_by_hash
                }
            })

        r_latest = node_get(request, f"/documents/latest/{documentId}", timeout=30)
        latest_data = safe_json(r_latest)

        doc_exists = False
        latest_doc = None
        next_version = 1

        if isinstance(latest_data, dict) and latest_data.get("exists") is True and isinstance(latest_data.get("doc"), dict):
            doc_exists = True
            latest_doc = latest_data["doc"]
            try:
                next_version = int(latest_doc.get("version", 0)) + 1
            except Exception:
                next_version = 1

        return templates.TemplateResponse("confirm_upload.html", {
            "request": request,
            "documentId": documentId,
            "owner": owner_from_jwt, 
            "contentHash": content_hash,
            "metadata_json": json.dumps(metadata, ensure_ascii=False),
            "docExists": doc_exists,
            "latestDoc": latest_doc,
            "nextVersion": next_version,
        })

    except Exception as e:
        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Verzió mentése",
            "action": "upload-versioned",
            "ok": False,
            "hash": "",
            "result": {"error": str(e)}
        })


@app.post("/upload-versioned/confirm", response_class=HTMLResponse)
async def upload_versioned_confirm(
    request: Request,
    documentId: str = Form(...),
    owner: str = Form(...),  
    contentHash: str = Form(...),
    nextVersion: int = Form(...),
    metadata_json: str = Form(...),
):
    redir = require_login_or_redirect(request, "/")
    if redir:
        return redir

    owner_from_jwt = get_current_user_id(request)
    if not owner_from_jwt:
        return RedirectResponse(url="/login?next=/", status_code=303)

    try:
        try:
            metadata = json.loads(metadata_json)
        except Exception:
            metadata = {}

        payload = {
            "documentId": documentId,
            "version": int(nextVersion),
            "contentHash": contentHash,
            "owner": owner_from_jwt,  
            "metadata": metadata,
        }

        r = node_post(request, "/documents/versioned", payload, timeout=30)

        if r.status_code == 409:
            return templates.TemplateResponse("result.html", {
                "request": request,
                "title": "Verzió mentése",
                "action": "upload-versioned",
                "ok": True,
                "hash": contentHash,
                "result": safe_json(r)
            })

        ok = r.status_code < 400
        data = safe_json(r) if ok else {"error": r.text, "status_code": r.status_code}

        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Verzió mentése",
            "action": "upload-versioned",
            "ok": ok,
            "hash": contentHash,
            "result": data
        })

    except Exception as e:
        return templates.TemplateResponse("result.html", {
            "request": request,
            "title": "Verzió mentése",
            "action": "upload-versioned",
            "ok": False,
            "hash": contentHash,
            "result": {"error": str(e)}
        })


@app.post("/api/status")
async def api_status(request: Request, payload: dict = Body(...)):
    if not read_jwt_from_cookie(request):
        return JSONResponse(status_code=401, content={"error": "Not logged in"})
    if not is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})

    try:
        r = node_post(request, "/documents/status", payload, timeout=30)
        return JSONResponse(status_code=r.status_code, content=safe_json(r))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/certificate/pdf/{content_hash}")
async def certificate_pdf(request: Request, content_hash: str):
    redir = require_login_or_redirect(request, f"/certificate/pdf/{content_hash}")
    if redir:
        return redir

    r = node_get(request, f"/documents/by-hash/{content_hash}", timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=404, detail="Hash nem található")

    data = safe_json(r)
    if not isinstance(data, dict) or data.get("exists") is not True or not isinstance(data.get("doc"), dict):
        raise HTTPException(status_code=404, detail="Hash nem található")

    d = data["doc"]

    qr_payload = content_hash

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(qr_payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)

    pdf_buf = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buf,
        pagesize=A4,
        leftMargin=18*mm,
        rightMargin=18*mm,
        topMargin=16*mm,
        bottomMargin=16*mm,
        title="Digitális dokumentum-tanúsítvány"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "subtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10.5,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=14,
    )

    label_style = ParagraphStyle(
        "label",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#222222"),
    )

    value_style = ParagraphStyle(
        "value",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
        wordWrap="CJK",
        textColor=colors.HexColor("#111111"),
    )

    story = []
    story.append(Paragraph("Digitális dokumentum-tanúsítvány", title_style))
    story.append(Paragraph("Hyperledger Fabric alapú hitelesítési kivonat", subtitle_style))
    story.append(Spacer(1, 6*mm))

    created_at_human = fmt_iso_human(d.get("createdAt"))

    rows = [
        [Paragraph("Hash", label_style), Paragraph(wrap_hex(content_hash, 44), value_style)],
        [Paragraph("Document ID", label_style), Paragraph(str(d.get("documentId", "—")), styles["Normal"])],
        [Paragraph("Version", label_style), Paragraph(str(d.get("version", "—")), styles["Normal"])],
        [Paragraph("Status", label_style), Paragraph(str(d.get("status", "—")), styles["Normal"])],
        [Paragraph("Created At", label_style), Paragraph(created_at_human, styles["Normal"])],
        [Paragraph("TxID", label_style), Paragraph(wrap_hex(d.get("txId", "—"), 44), value_style)],
        [Paragraph("Created By MSP", label_style), Paragraph(str(d.get("createdByMSP", "—")), styles["Normal"])],
    ]

    table = Table(
        rows,
        colWidths=[38*mm, 140*mm],
        hAlign="LEFT"
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.white),
        ("BOX", (0,0), (-1,-1), 0.8, colors.HexColor("#D0D7DE")),
        ("INNERGRID", (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#F8FAFC")),
    ]))

    story.append(table)
    story.append(Spacer(1, 10*mm))

    story.append(Paragraph("QR kód (hash tartalommal)", styles["Heading4"]))
    story.append(Spacer(1, 3*mm))

    qr_platypus = Image(qr_buf, width=45*mm, height=45*mm)
    story.append(qr_platypus)

    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(
        "A QR kód kizárólag a dokumentum SHA-256 hash-ét tartalmazza.",
        ParagraphStyle("note", parent=styles["Normal"], fontSize=9.5, textColor=colors.HexColor("#555555"))
    ))

    doc.build(story)

    pdf_bytes = pdf_buf.getvalue()
    headers = {
        "Content-Disposition": f'attachment; filename="certificate_{content_hash[:10]}.pdf"'
    }
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)