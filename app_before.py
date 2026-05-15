import os
import json
import logging
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv
import boto3
import mysql.connector
from flask import (
    Flask, Response, abort, flash, g,
    redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from security.rbac import admin_required, can_download_file

# ── 경로 설정 ──────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
LOG_DIR      = BASE_DIR / "logs"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── 환경 변수 로드 ─────────────────────────────────────────────────────────
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

DB_TYPE       = os.getenv("DB_TYPE", "sqlite").lower()
DB_HOST       = os.getenv("DB_HOST", "localhost")
DB_PORT       = os.getenv("DB_PORT", "3306")
DB_USER       = os.getenv("DB_USER", "admin")
DB_PASSWORD   = os.getenv("DB_PASSWORD", "")
DB_NAME       = os.getenv("DB_NAME", "cloudsec_db")
DB_PATH       = Path(os.getenv("DB_PATH", str(INSTANCE_DIR / "metadata.db")))

BUCKET_NAME   = os.getenv("S3_BUCKET_NAME", "cloudsec-corp-storage-0501")
REGION        = os.getenv("AWS_DEFAULT_REGION", "ap-northeast-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

DEFAULT_USERNAME = os.getenv("APP_DEFAULT_USERNAME", "admin")
DEFAULT_PASSWORD = os.getenv("APP_DEFAULT_PASSWORD", "ChangeMe123!")
AUDIT_LOG_PATH   = LOG_DIR / "security_audit.log"

# ── Flask 앱 설정 ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

# ── 로거 설정 ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
app_logger = logging.getLogger(__name__)

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(audit_handler)

# class CloudWatchHandler(logging.Handler):
#     def __init__(self):
#         super().__init__()
#         import boto3, threading
#         self.client = boto3.client("logs", region_name="ap-northeast-2")
#         self.log_group = "/cloudsec/audit"
#         self.stream_name = "ec2-app"
#         self._lock = threading.Lock()
#     def emit(self, record):
#         import threading, time
#         def send():
#             try:
#                 self.client.put_log_events(
#                     logGroupName=self.log_group,
#                     logStreamName=self.stream_name,
#                     logEvents=[{"timestamp": int(time.time()*1000), "message": self.format(record)}]
#                 )
#             except Exception:
#                 pass
#         threading.Thread(target=send, daemon=True).start()
# 
# cw_handler = CloudWatchHandler()
# cw_handler.setFormatter(logging.Formatter("%(message)s"))
# audit_logger.addHandler(cw_handler)

app_logger.info(f"Flask 앱 시작 | DB={DB_TYPE} | Bucket={BUCKET_NAME} | Region={REGION}")


# ── CORS 헤더 ──────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")

@app.after_request
def after_request(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS or not ALLOWED_ORIGINS[0]:
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# ── DB 연결 ────────────────────────────────────────────────────────────────
class DBConnectionWrapper:
    def __init__(self, conn, db_type=None):
        self.conn    = conn
        self.db_type = db_type or DB_TYPE

    def execute(self, query, params=None):
        if params is None:
            params = ()
        if self.db_type == "mysql":
            query = query.replace("?", "%s")
        cursor = self.conn.cursor(dictionary=True) if self.db_type == "mysql" else self.conn.cursor()
        cursor.execute(query, params) if params else cursor.execute(query)
        return cursor

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_s3_client():
    kwargs = {"region_name": REGION}
    if AWS_ACCESS_KEY and AWS_SECRET_KEY:
        kwargs.update(aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    return boto3.client("s3", **kwargs)


def get_db():
    if "db" not in g:
        if DB_TYPE == "mysql":
            conn = mysql.connector.connect(
                host=DB_HOST, port=int(DB_PORT), user=DB_USER,
                password=DB_PASSWORD, database=DB_NAME,
                auth_plugin="mysql_native_password",
            )
            g.db = DBConnectionWrapper(conn, db_type="mysql")
        else:
            import sqlite3
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            g.db = DBConnectionWrapper(conn, db_type="sqlite")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db:
        db.close()


# ── DB 초기화 ──────────────────────────────────────────────────────────────
def init_db():
    if DB_TYPE == "mysql":
        conn = mysql.connector.connect(
            host=DB_HOST, port=int(DB_PORT), user=DB_USER,
            password=DB_PASSWORD, database=DB_NAME,
        )
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTO_INCREMENT,
                username      VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role          VARCHAR(50)  NOT NULL DEFAULT 'user',
                level         INTEGER      NOT NULL DEFAULT 1
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id            INTEGER PRIMARY KEY AUTO_INCREMENT,
                owner_id      INTEGER      NOT NULL,
                uploaded_by   INTEGER      NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                s3_key        VARCHAR(255) UNIQUE NOT NULL,
                size_bytes    BIGINT       NOT NULL,
                uploaded_at   VARCHAR(50)  NOT NULL,
                target_levels VARCHAR(255) NOT NULL DEFAULT '1'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id        INTEGER PRIMARY KEY AUTO_INCREMENT,
                timestamp VARCHAR(50)  NOT NULL,
                event     VARCHAR(255) NOT NULL,
                username  VARCHAR(255),
                details   TEXT
            )
        """)
        for uname in (DEFAULT_USERNAME, "admin"):
            cursor.execute("SELECT id FROM users WHERE username = %s", (uname,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, level) VALUES (%s, %s, %s, %s)",
                    (uname, generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
                )
        conn.commit()
        conn.close()
    else:
        import sqlite3
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                level INTEGER NOT NULL DEFAULT 1
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                uploaded_by INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                s3_key TEXT UNIQUE NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                target_levels TEXT NOT NULL DEFAULT '1'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                username TEXT,
                details TEXT
            )
        """)
        for uname in (DEFAULT_USERNAME, "admin"):
            if not cursor.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone():
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, level) VALUES (?, ?, ?, ?)",
                    (uname, generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
                )
        conn.commit()
        conn.close()


# ── 감사 로그 ──────────────────────────────────────────────────────────────
def log_audit(audit_log: dict, level: str = "info"):
    msg = json.dumps(audit_log, ensure_ascii=False)
    getattr(audit_logger, level if level in ("critical", "warning", "error") else "info")(msg)
    try:
        db      = get_db()
        details = {k: v for k, v in audit_log.items() if k not in ("timestamp", "event", "actor")}
        db.execute(
            "INSERT INTO audit_logs (timestamp, event, username, details) VALUES (?, ?, ?, ?)",
            (audit_log.get("timestamp"), audit_log.get("event"),
             audit_log.get("username") or audit_log.get("actor"), json.dumps(details, ensure_ascii=False)),
        )
        db.commit()
    except Exception as e:
        app_logger.error(f"감사 로그 DB 저장 실패: {e}")


# ── 인증 데코레이터 ────────────────────────────────────────────────────────
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # [VULN] 세션 하이재킹 탐지 미적용 (Before 시나리오)
        return view_func(*args, **kwargs)
    return wrapped

# admin_required는 security/rbac.py 에서 import


# ── 라우트 ─────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    db        = get_db()
    all_files = db.execute("""
        SELECT f.id, f.owner_id, f.original_name, f.size_bytes,
               f.uploaded_at, f.target_levels, u.username AS uploaded_by_username
        FROM files f
        LEFT JOIN users u ON f.uploaded_by = u.id
        ORDER BY f.uploaded_at DESC
    """).fetchall()

    user_level     = session.get("level", 1)
    user_id        = session.get("user_id")
    filtered_files = []
    for file in all_files:
        if file["owner_id"] == user_id or session.get("role") == "admin":
            filtered_files.append(file)
        else:
            target_levels = [int(l.strip()) for l in file["target_levels"].split(",")]
            if user_level in target_levels:
                filtered_files.append(file)

    return render_template("index.html", files=filtered_files, username=session["username"])


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        target_id = request.form.get("user_id", type=int)
        new_level = request.form.get("new_level", type=int)

        if target_id is None or new_level not in (1, 2, 3):
            flash("유효한 레벨을 선택해주세요.", "danger")
            return redirect(url_for("admin_users"))

        user_row = db.execute("SELECT id, username FROM users WHERE id = ?", (target_id,)).fetchone()
        if not user_row:
            flash("사용자를 찾을 수 없습니다.", "danger")
            return redirect(url_for("admin_users"))

        db.execute("UPDATE users SET level = ? WHERE id = ?", (new_level, target_id))
        db.commit()
        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event":     "ADMIN_ACTION: USER_LEVEL_CHANGED",
            "username":  session.get("username"),
            "target_user_id":  target_id,
            "target_username": user_row["username"],
            "new_level": new_level,
        })
        flash(f"{user_row['username']}님의 레벨이 {new_level}로 변경되었습니다.", "success")
        return redirect(url_for("admin_users"))

    users = db.execute("SELECT id, username, level, is_locked FROM users ORDER BY id ASC").fetchall()
    users_by_level = {lvl: [u for u in users if u["level"] == lvl] for lvl in (1, 2, 3)}
    return render_template("admin_users.html", users_by_level=users_by_level)
   
@app.route("/admin/unlock", methods=["POST"])
@login_required
@admin_required
def admin_unlock():
    target_id = request.form.get("user_id", type=int)
    db = get_db()
    user_row = db.execute("SELECT username FROM users WHERE id = ?", (target_id,)).fetchone()
    if not user_row:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for("admin_users"))
    db.execute("UPDATE users SET is_locked = 0 WHERE id = ?", (target_id,))
    db.commit()
    flash(f"{user_row['username']}님의 계정이 잠금 해제되었습니다.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    logs = []
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    total = 0
    try:
        db = get_db()
        result = db.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()
        total = result["cnt"] if result else 0
        rows = db.execute(
            "SELECT timestamp, event, username, details FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
        for row in rows:
            entry = {"timestamp": row["timestamp"], "event": row["event"], "username": row["username"]}
            try:
                entry.update(json.loads(row["details"] or "{}"))
            except Exception:
                pass
            logs.append(entry)
    except Exception as e:
        app_logger.error(f"감사 로그 DB 조회 실패: {e}")
        try:
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                for line in reversed(f.readlines()[-100:]):
                    try:
                        logs.append(json.loads(line.strip()))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    total_pages = (total + per_page - 1) // per_page
    return render_template("admin_logs.html", logs=logs, page=page, total_pages=total_pages, total=total)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        flash("업로드할 파일을 선택해주세요.", "warning")
        return redirect(url_for("index"))

    filename        = uploaded_file.filename
    safe_name       = secure_filename(filename) or "uploaded_file"
    timestamp       = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    s3_key          = f"{session['user_id']}/{timestamp}_{safe_name}"

    uploaded_file.stream.seek(0, 2)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    try:
        get_s3_client().upload_fileobj(uploaded_file.stream, BUCKET_NAME, s3_key)
    except Exception as e:
        err = str(e)
        app_logger.error(f"S3 업로드 실패: {err}")
        if "NoCredentialsError" in type(e).__name__:
            flash("AWS 자격증명이 설정되지 않았습니다.", "danger")
        elif "403" in err or "Forbidden" in err:
            flash("S3 버킷 접근 권한이 없습니다.", "danger")
        elif "NoSuchBucket" in err:
            flash(f"S3 버킷 '{BUCKET_NAME}'이(가) 존재하지 않습니다.", "danger")
        else:
            flash(f"S3 업로드 오류: {err}", "danger")
        return redirect(url_for("index"))

    user_level      = session.get("level", 1)
    selected_levels = [lvl for lvl in range(1, 4) if request.form.get(f"level_{lvl}") == "on"]

    if not selected_levels:
        flash("접근 허용 레벨을 최소 하나 이상 선택해주세요.", "danger")
        return redirect(url_for("index"))

    if any(lvl > user_level for lvl in selected_levels):
        log_audit({
            "timestamp":        datetime.utcnow().isoformat(timespec="seconds"),
            "event":            "UNLAWFUL_LEVEL_ASSIGNMENT",
            "username":         session.get("username"),
            "user_level":       user_level,
            "requested_levels": ",".join(str(l) for l in selected_levels),
            "file_name":        filename,
            "ip":               request.remote_addr,
        }, level="critical")
        flash("자신의 권한보다 높은 레벨을 선택할 수 없습니다.", "danger")
        return redirect(url_for("index"))

    target_levels = ",".join(str(l) for l in selected_levels)
    uploaded_at   = datetime.utcnow().isoformat(timespec="seconds")
    db = get_db()
    db.execute(
        "INSERT INTO files (owner_id, uploaded_by, original_name, s3_key, size_bytes, uploaded_at, target_levels) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session["user_id"], session["user_id"], filename, s3_key, file_size, uploaded_at, target_levels),
    )
    log_audit({
        "timestamp":    datetime.utcnow().isoformat(timespec="seconds"),
        "event":        "FILE_UPLOAD",
        "actor":        session.get("username"),
        "target":       filename,
        "target_levels": target_levels,
        "size_bytes":   file_size,
        "status":       "SUCCESS",
    })
    db.commit()
    flash("파일이 업로드되었습니다.", "success")
    return redirect(url_for("index"))


@app.route("/download")
@login_required
def download():
    file_id = request.args.get("id", type=int)
    if not file_id:
        flash("잘못된 요청입니다.", "danger")
        return redirect(url_for("index"))

    db       = get_db()
    file_row = db.execute(
        "SELECT f.id, f.original_name, f.s3_key, f.target_levels, f.owner_id, u.username AS owner_username FROM files f LEFT JOIN users u ON f.owner_id = u.id WHERE f.id = ?",
        (file_id,),
    ).fetchone()

    if not file_row:
        flash("잘못된 요청입니다.", "danger")
        return redirect(url_for("index"))

    # [VULN] 접근 제어 미적용 - IDOR 시나리오 (Before)
    has_access = True

    if not has_access:
        log_audit({
            "timestamp":     datetime.utcnow().isoformat(timespec="seconds"),
            "event":         "SECURITY: GRANULAR_ACL_REJECTION",
            "username":      session.get("username"),
            "user_level":    session.get("level", 1),
            "allowed_levels": file_row["target_levels"],
            "file_id":       file_row["id"],
            "ip":            request.remote_addr,
        }, level="warning")
        abort(403)

    try:
        s3_obj = get_s3_client().get_object(Bucket=BUCKET_NAME, Key=file_row["s3_key"])
    except Exception:
        flash("파일 다운로드 중 오류가 발생했습니다.", "danger")
        return redirect(url_for("index"))

    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event":     "FILE_DOWNLOADED",
        "username":  session.get("username"),
        "file_name": file_row["original_name"],
        "file_id":   file_row["id"],
        "owner":     file_row["owner_username"],
        "ip":        request.remote_addr,
    })

    filename_header = quote(file_row["original_name"])
    return Response(
        s3_obj["Body"].read(),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_header}"},
    )


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    file_id = request.form.get("id", type=int)
    if not file_id:
        flash("잘못된 요청입니다.", "danger")
        return redirect(url_for("index"))

    db       = get_db()
    file_row = db.execute(
        "SELECT f.id, f.s3_key, f.original_name, f.owner_id, u.username AS owner_username "
        "FROM files f LEFT JOIN users u ON f.owner_id = u.id WHERE f.id = ?",
        (file_id,),
    ).fetchone()

    if not file_row:
        flash("파일을 찾을 수 없습니다.", "danger")
        return redirect(url_for("index"))

    if file_row["owner_id"] != session["user_id"] and session.get("role") != "admin":
        flash("삭제 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    try:
        get_s3_client().delete_object(Bucket=BUCKET_NAME, Key=file_row["s3_key"])
    except Exception:
        flash("S3 삭제 중 오류가 발생했습니다.", "danger")
        return redirect(url_for("index"))

    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event":     "FILE_DELETED",
        "username":  session.get("username"),
        "file_name": file_row["s3_key"],
        "file_id":   file_row["id"],
        "owner_id":  file_row["owner_id"],
        "owner":     file_row["owner_username"],
        "ip":        request.remote_addr,
    })
    db.execute("DELETE FROM files WHERE id = ?", (file_row["id"],))
    db.commit()
    flash("파일이 삭제되었습니다.", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db       = get_db()
        user     = db.execute(
            "SELECT id, username, password_hash, role, level, is_locked FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        
#         if user and user["is_locked"]:
#             flash("계정이 잠겼습니다. 관리자에게 문의하세요.", "danger")
#             return render_template("login.html")

        if not user or not check_password_hash(user["password_hash"], password):
            log_audit({
                "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                "event":     "LOGIN_FAILED",
                "username":  username,
                "ip":        request.remote_addr,
            }, level="warning")
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
#             fail_count = db.execute(
#                 "SELECT COUNT(*) as cnt FROM audit_logs WHERE username = ? AND event = 'LOGIN_FAILED' AND timestamp >= NOW() - INTERVAL 1 MINUTE",
#                 (username,)
#             ).fetchone()["cnt"]
#             if fail_count >= 10:
#                 db.execute("UPDATE users SET is_locked = 1 WHERE username = ?", (username,))
#                 db.commit()
            return render_template("login.html")
        session.clear()
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        session["role"]     = user["role"]
        session["level"]    = user["level"]
        session["login_ip"] = request.remote_addr

        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event":     "LOGIN_SUCCESS",
            "username":  user["username"],
            "ip":        request.remote_addr,
        })
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        password         = request.form.get("password", "").strip()
        password_confirm = request.form.get("password_confirm", "").strip()

        if not username or not password:
            flash("아이디와 비밀번호를 입력해주세요.", "danger")
            return render_template("signup.html")
        if len(username) < 3:
            flash("아이디는 최소 3글자 이상이어야 합니다.", "danger")
            return render_template("signup.html")
        if len(password) < 6:
            flash("비밀번호는 최소 6글자 이상이어야 합니다.", "danger")
            return render_template("signup.html")
        if password != password_confirm:
            flash("비밀번호가 일치하지 않습니다.", "danger")
            return render_template("signup.html")

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("이미 존재하는 아이디입니다.", "danger")
            return render_template("signup.html")

        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), "user"),
            )
            db.commit()
            log_audit({
                "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                "event":     "NEW_USER_REGISTERED",
                "username":  username,
                "ip":        request.remote_addr,
            })
            flash("회원가입이 완료되었습니다. 로그인해주세요.", "success")
            return redirect(url_for("login"))
        except Exception:
            flash("회원가입 중 오류가 발생했습니다.", "danger")
            return render_template("signup.html")

    return render_template("signup.html")


@app.route("/logout")
def logout():
    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event":     "LOGOUT",
        "username":  session.get("username"),
        "ip":        request.remote_addr,
    })
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
