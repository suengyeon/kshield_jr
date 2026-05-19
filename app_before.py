import os
import sqlite3
import json
import logging
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv
import boto3
import mysql.connector
from mysql.connector.cursor_cext import CMySQLCursorDict
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# .env 파일 로드 (명시적 경로 지정)
BASE_DIR = Path(__file__).resolve().parent
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

if not env_path.exists():
    logging.warning(f"⚠️ .env 파일을 찾을 수 없습니다: {env_path}")
else:
    logging.info(f"✓ .env 파일 로드됨: {env_path}")

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "cloudsec_app")
DB_PATH = Path(os.getenv("DB_PATH", str(INSTANCE_DIR / "metadata.db")))

BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "cloudsec-corp-storage-0501")
REGION = os.getenv("AWS_DEFAULT_REGION", "ap-northeast-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

DEFAULT_USERNAME = os.getenv("APP_DEFAULT_USERNAME", "admin")
DEFAULT_PASSWORD = os.getenv("APP_DEFAULT_PASSWORD", "ChangeMe123!")

AUDIT_LOG_PATH = LOG_DIR / "security_audit.log"

ENV_DEBUG = {
    "DB_TYPE": DB_TYPE,
    "DB_HOST": DB_HOST,
    "DB_PORT": DB_PORT,
    "DB_NAME": DB_NAME,
    "DB_PATH": str(DB_PATH),
    "S3_BUCKET_NAME": BUCKET_NAME,
    "AWS_REGION": REGION,
    "AWS_CREDENTIALS_LOADED": bool(AWS_ACCESS_KEY and AWS_SECRET_KEY),
    "FLASK_SECRET_KEY_SET": bool(os.getenv("FLASK_SECRET_KEY")),
}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# 보안 감사 로그 설정
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(audit_handler)

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')
app_logger = logging.getLogger(__name__)

app_logger.info("=" * 70)
app_logger.info("🚀 Flask 앱 시작 - 환경 변수 진단")
app_logger.info("=" * 70)
app_logger.info(f"📁 현재 디렉토리: {Path.cwd()}")
app_logger.info(f"📁 .env 파일 경로: {env_path}")
app_logger.info(f"✓ .env 파일 존재: {env_path.exists()}")

if env_path.exists():
    with open(env_path, 'r') as f:
        env_lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
    app_logger.info(f"✓ .env 파일 라인 수: {len(env_lines)}")
    app_logger.info("\n📋 환경 변수 로드 상태:")
    app_logger.info(f"  FLASK_SECRET_KEY: {'✓ 설정됨' if os.getenv('FLASK_SECRET_KEY') else '✗ 미설정'}")
    app_logger.info(f"  AWS_DEFAULT_REGION: {REGION}")
    app_logger.info(f"  S3_BUCKET_NAME: {BUCKET_NAME}")
    app_logger.info(f"  AWS_ACCESS_KEY_ID: {'✓ 로드됨' if AWS_ACCESS_KEY else '✗ 미설정'}")
    app_logger.info(f"  AWS_SECRET_ACCESS_KEY: {'✓ 로드됨' if AWS_SECRET_KEY else '✗ 미설정'}")
    app_logger.info(f"  APP_DEFAULT_USERNAME: {DEFAULT_USERNAME}")

if AWS_ACCESS_KEY and AWS_SECRET_KEY:
    app_logger.info("\n✅ AWS 자격증명 로드 완료! S3 업로드 가능합니다.")
else:
    app_logger.warning("\n⚠️ AWS 자격증명이 미설정되었습니다!")
    app_logger.warning("  → .env 파일의 AWS_ACCESS_KEY_ID와 AWS_SECRET_ACCESS_KEY를 확인하세요")
    app_logger.warning("  → 또는 ~/.aws/credentials 파일을 확인하세요")

app_logger.info("=" * 70)


class DBConnectionWrapper:
    def __init__(self, conn, cursor_factory=None, db_type=None):
        self.conn = conn
        self.cursor_factory = cursor_factory
        self.db_type = db_type or DB_TYPE

    def execute(self, query, params=None):
        if params is None:
            params = ()

        if self.db_type == "mysql" and "?" in query:
            query = query.replace("?", "%s")

        if self.cursor_factory:
            try:
                cursor = self.conn.cursor(cursor_factory=self.cursor_factory)
            except TypeError:
                cursor = self.conn.cursor(cursor_class=self.cursor_factory)
        else:
            cursor = self.conn.cursor()

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        return cursor

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_s3_client():
    if AWS_ACCESS_KEY and AWS_SECRET_KEY:
        return boto3.client(
            "s3",
            region_name=REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )
    return boto3.client("s3", region_name=REGION)


def connect_sqlite():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return DBConnectionWrapper(conn, db_type="sqlite")


def connect_mysql():
    conn = mysql.connector.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        auth_plugin='mysql_native_password'
    )
    return DBConnectionWrapper(conn, cursor_factory=CMySQLCursorDict, db_type="mysql")


def get_db():
    if "db" not in g:
        if DB_TYPE == "sqlite":
            g.db = connect_sqlite()
        elif DB_TYPE == "mysql":
            g.db = connect_mysql()
        else:
            raise ValueError(f"지원하지 않는 DB_TYPE입니다: {DB_TYPE}")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if DB_TYPE == "sqlite":
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
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
                target_levels TEXT NOT NULL DEFAULT '1',
                FOREIGN KEY(owner_id) REFERENCES users(id),
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            )
        """)

        columns = {row[1] for row in cursor.execute("PRAGMA table_info(files)").fetchall()}
        if "uploaded_by" not in columns:
            cursor.execute("ALTER TABLE files ADD COLUMN uploaded_by INTEGER")
            cursor.execute("UPDATE files SET uploaded_by = owner_id WHERE uploaded_by IS NULL")
        if "required_level" not in columns:
            cursor.execute("ALTER TABLE files ADD COLUMN required_level INTEGER NOT NULL DEFAULT 1")
        if "min_level" in columns:
            cursor.execute("UPDATE files SET required_level = min_level")
        if "allow_lower" in columns:
            all_files = cursor.execute("SELECT id, required_level, allow_lower FROM files").fetchall()
            for file_row in all_files:
                required_level = file_row[1]
                allow_lower = file_row[2]
                if allow_lower:
                    target_levels = ",".join(str(l) for l in range(1, required_level + 1))
                else:
                    target_levels = str(required_level)
                cursor.execute("UPDATE files SET target_levels = ? WHERE id = ?", (target_levels, file_row[0]))
            cursor.execute("ALTER TABLE files DROP COLUMN allow_lower")
        if "target_levels" not in columns:
            cursor.execute("ALTER TABLE files ADD COLUMN target_levels TEXT NOT NULL DEFAULT '1'")
        if "required_level" in columns and "target_levels" in columns:
            cursor.execute("UPDATE files SET target_levels = CAST(required_level AS TEXT) WHERE target_levels IS NULL")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                username TEXT,
                details TEXT
            )
        """)

        user_columns = {row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "level" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN level INTEGER NOT NULL DEFAULT 1")

        default_user = cursor.execute(
            "SELECT id FROM users WHERE username = ?", (DEFAULT_USERNAME,)
        ).fetchone()
        if not default_user:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, level) VALUES (?, ?, ?, ?)",
                (DEFAULT_USERNAME, generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
            )

        admin_user = cursor.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin_user:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, level) VALUES (?, ?, ?, ?)",
                ("admin", generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
            )

        db.commit()
        db.close()

    else:
        db = None
        if DB_TYPE == "mysql":
            db = mysql.connector.connect(
                host=DB_HOST,
                port=int(DB_PORT),
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
            )
        if db is None:
            raise ValueError(f"지원하지 않는 DB_TYPE입니다: {DB_TYPE}")

        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                level INTEGER NOT NULL DEFAULT 1
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                owner_id INTEGER NOT NULL,
                uploaded_by INTEGER NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                s3_key VARCHAR(255) UNIQUE NOT NULL,
                size_bytes BIGINT NOT NULL,
                uploaded_at VARCHAR(255) NOT NULL,
                target_levels VARCHAR(255) NOT NULL DEFAULT '1'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                timestamp VARCHAR(50) NOT NULL,
                event VARCHAR(255) NOT NULL,
                username VARCHAR(255),
                details TEXT
            )
        """)

        cursor.execute("SELECT id FROM users WHERE username = %s", (DEFAULT_USERNAME,))
        default_user = cursor.fetchone()
        if not default_user:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, level) VALUES (%s, %s, %s, %s)",
                (DEFAULT_USERNAME, generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
            )

        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        if not admin_user:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, level) VALUES (%s, %s, %s, %s)",
                ("admin", generate_password_hash(DEFAULT_PASSWORD), "admin", 3),
            )

        db.commit()
        db.close()


def log_audit(audit_log: dict, level: str = "info"):
    msg = json.dumps(audit_log, ensure_ascii=False)

    if level == "critical":
        audit_logger.critical(msg)
    elif level == "warning":
        audit_logger.warning(msg)
    else:
        audit_logger.info(msg)

    try:
        db = get_db()

        details = {
            k: v
            for k, v in audit_log.items()
            if k not in ("timestamp", "event", "actor")
        }

        if DB_TYPE == "sqlite":
            db.execute(
                "INSERT INTO audit_logs (timestamp, event, username, details) VALUES (?, ?, ?, ?)",
                (
                    audit_log.get("timestamp"),
                    audit_log.get("event"),
                    audit_log.get("actor"),
                    json.dumps(details, ensure_ascii=False),
                ),
            )
        else:
            db.execute(
                "INSERT INTO audit_logs (timestamp, event, username, details) VALUES (%s, %s, %s, %s)",
                (
                    audit_log.get("timestamp"),
                    audit_log.get("event"),
                    audit_log.get("actor"),
                    json.dumps(details, ensure_ascii=False),
                ),
            )

        db.commit()

    except Exception as e:
        app_logger.error(f"감사 로그 DB 저장 실패: {e}")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get("level") != 3:
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/")
@login_required
def index():
    db = get_db()
    all_files = db.execute("""
        SELECT f.id,
               f.owner_id,
               f.original_name,
               f.size_bytes,
               f.uploaded_at,
               f.target_levels,
               u.username AS uploaded_by_username
        FROM files f
        LEFT JOIN users u ON f.uploaded_by = u.id
        ORDER BY f.uploaded_at DESC
    """).fetchall()

    user_level = session.get("level", 1)
    user_id = session.get("user_id")
    filtered_files = []

    for file in all_files:
        has_access = False
        if file["owner_id"] == user_id:
            has_access = True
        elif session.get("role") == "admin":
            has_access = True
        else:
            target_levels = [int(l.strip()) for l in file["target_levels"].split(",")]
            if user_level in target_levels:
                has_access = True
        if has_access:
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

        if target_id is None or new_level is None or new_level not in (1, 2, 3):
            flash("유효한 레벨을 선택해주세요.", "danger")
            return redirect(url_for("admin_users"))

        user_row = db.execute(
            "SELECT id, username, level FROM users WHERE id = ?", (target_id,)
        ).fetchone()

        if not user_row:
            flash("사용자를 찾을 수 없습니다.", "danger")
            return redirect(url_for("admin_users"))

        db.execute("UPDATE users SET level = ? WHERE id = ?", (new_level, target_id))
        db.commit()

        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event": "ADMIN_ACTION: USER_LEVEL_CHANGED",
            "username": session.get("username"),
            "target_user_id": target_id,
            "target_username": user_row["username"],
            "new_level": new_level,
        })

        flash(f"{user_row['username']}님의 레벨이 {new_level}로 변경되었습니다.", "success")
        return redirect(url_for("admin_users"))

    users = db.execute("SELECT id, username, level FROM users ORDER BY id ASC").fetchall()
    users_by_level = {}
    for level in [1, 2, 3]:
        users_by_level[level] = [user for user in users if user["level"] == level]

    return render_template("admin_users.html", users_by_level=users_by_level)


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    logs = []
    try:
        db = get_db()
        rows = db.execute(
            "SELECT timestamp, event, username, details FROM audit_logs ORDER BY id DESC LIMIT 100"
        ).fetchall()

        for row in rows:
            entry = {"timestamp": row["timestamp"], "event": row["event"], "username": row["username"]}
            try:
                details = json.loads(row["details"] or "{}")
                entry.update(details)
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
                        continue
        except FileNotFoundError:
            pass

    return render_template("admin_logs.html", logs=logs)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        flash("업로드할 파일을 선택해주세요.", "warning")
        return redirect(url_for("index"))

    filename = uploaded_file.filename
    if not filename.strip():
        flash("유효하지 않은 파일명입니다.", "danger")
        return redirect(url_for("index"))

    safe_name_for_key = secure_filename(filename) or "uploaded_file"
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    s3_key = f"{session['user_id']}/{timestamp}_{safe_name_for_key}"

    uploaded_file.stream.seek(0, 2)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    try:
        s3 = get_s3_client()
        s3.upload_fileobj(uploaded_file.stream, BUCKET_NAME, s3_key)
    except Exception as e:
        error_msg = str(e)
        app_logger.error(f"S3 업로드 실패 - {error_msg}")
        if "NoCredentialsError" in str(type(e).__name__):
            flash("AWS 자격증명이 설정되지 않았습니다. .env 파일의 AWS_ACCESS_KEY_ID와 AWS_SECRET_ACCESS_KEY를 확인하세요.", "danger")
        elif "403" in error_msg or "Forbidden" in error_msg:
            flash("S3 버킷에 대한 접근 권한이 없습니다. IAM 정책을 확인하세요.", "danger")
        elif "NoSuchBucket" in error_msg:
            flash(f"S3 버킷 '{BUCKET_NAME}'이(가) 존재하지 않습니다.", "danger")
        else:
            flash(f"S3 업로드 중 오류가 발생했습니다: {error_msg}", "danger")
        return redirect(url_for("index"))

    user_level = session.get("level", 1)
    selected_levels = []
    for level in range(1, 4):
        if request.form.get(f"level_{level}") == "on":
            selected_levels.append(level)

    if not selected_levels:
        flash("접근 허용 레벨을 최소 하나 이상 선택해주세요.", "danger")
        return redirect(url_for("index"))

    if any(level > user_level for level in selected_levels):
        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event": "UNLAWFUL_LEVEL_ASSIGNMENT",
            "username": session.get("username"),
            "user_level": user_level,
            "requested_levels": ",".join(str(l) for l in selected_levels),
            "file_name": filename,
            "ip": request.remote_addr,
        }, level="critical")
        flash("자신의 권한보다 높은 레벨을 선택할 수 없습니다.", "danger")
        return redirect(url_for("index"))

    target_levels = ",".join(str(l) for l in selected_levels)
    uploaded_at = datetime.utcnow().isoformat(timespec="seconds")

    db = get_db()
    db.execute(
        """
        INSERT INTO files (owner_id, uploaded_by, original_name, s3_key, size_bytes, uploaded_at, target_levels)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session["user_id"], session["user_id"], filename, s3_key, file_size, uploaded_at, target_levels),
    )

    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event": "FILE_UPLOAD",
        "actor": session.get("username"),
        "owner": session.get("username"),
        "target": filename,
        "target_levels": target_levels,
        "size_bytes": file_size,
        "status": "SUCCESS"
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

    db = get_db()
    file_row = db.execute(
        """
        SELECT id, original_name, s3_key, target_levels, owner_id
        FROM files
        WHERE id = ?
        """,
        (file_id,),
    ).fetchone()

    if not file_row:
        flash("잘못된 요청입니다.", "danger")
        return redirect(url_for("index"))

    user_level = session.get("level", 1)
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"

    has_access = True  # 취약: 소유자 검증 없음

    if not has_access:
        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event": "SECURITY: GRANULAR_ACL_REJECTION",
            "username": session.get("username"),
            "user_level": user_level,
            "allowed_levels": file_row["target_levels"],
            "file_id": file_row["id"],
            "ip": request.remote_addr,
        }, level="warning")
        abort(403)

    try:
        s3_obj = get_s3_client().get_object(Bucket=BUCKET_NAME, Key=file_row["s3_key"])
    except Exception:
        flash("파일 다운로드 중 오류가 발생했습니다.", "danger")
        return redirect(url_for("index"))

    # ✅ 수정: IP 포함 (Lambda IDOR 탐지용)
    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event": "FILE_DOWNLOADED",
        "username": session.get("username"),
        "file_name": file_row["original_name"],
        "file_id": file_row["id"],
        "ip": request.remote_addr,
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

    db = get_db()
    file_row = db.execute(
        """
        SELECT f.id,
               f.s3_key,
               f.original_name,
               f.owner_id,
               u.username AS owner_username
        FROM files f
        LEFT JOIN users u ON f.owner_id = u.id
        WHERE f.id = ?
        """,
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
        "event": "FILE_DELETED",
        "username": session.get("username"),
        "file_name": file_row["s3_key"],
        "file_id": file_row["id"],
        "owner_id": file_row["owner_id"],
        "owner": file_row["owner_username"],
        "ip": request.remote_addr,
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

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, role, level FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            # ✅ 추가: 로그인 실패 로그 (Lambda Brute-force 탐지용)
            log_audit({
                "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                "event": "LOGIN_FAILED",
                "username": username,
                "ip": request.remote_addr,
            }, level="warning")
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["level"] = user["level"]
        session["login_ip"] = request.remote_addr  # ✅ 추가: IP 저장 (세션 하이재킹 탐지용)

        # ✅ 추가: 로그인 성공 로그
        log_audit({
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "event": "LOGIN_SUCCESS",
            "username": user["username"],
            "ip": request.remote_addr,
        })

        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
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
        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing_user:
            flash("이미 존재하는 아이디입니다.", "danger")
            return render_template("signup.html")

        try:
            password_hash = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, "user"),
            )
            db.commit()

            log_audit({
                "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                "event": "NEW_USER_REGISTERED",
                "username": username,
                "ip": request.remote_addr,
            })

            flash("회원가입이 완료되었습니다. 로그인해주세요.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            flash("회원가입 중 오류가 발생했습니다.", "danger")
            return render_template("signup.html")

    return render_template("signup.html")


@app.route("/logout")
def logout():
    log_audit({
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "event": "LOGOUT",
        "username": session.get("username"),
        "ip": request.remote_addr,
    })
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
