import os
import json
import logging
import ipaddress
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv
import boto3
import requests
import mysql.connector
from flask import (
    Flask, Response, abort, flash, g,
    redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import geoip2.database

BASE_DIR     = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
LOG_DIR      = BASE_DIR / "logs"
DATA_DIR     = BASE_DIR / "data"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
load_dotenv(dotenv_path=BASE_DIR / ".env")

DB_HOST       = os.getenv("DB_HOST", "localhost")
DB_PORT       = os.getenv("DB_PORT", "3306")
DB_USER       = os.getenv("DB_USER", "admin")
DB_PASSWORD   = os.getenv("DB_PASSWORD", "")
DB_NAME       = os.getenv("DB_NAME", "cloudsec_db")
BUCKET_NAME   = os.getenv("S3_BUCKET_NAME")
REGION        = os.getenv("AWS_DEFAULT_REGION", "ap-northeast-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
SLACK_WEBHOOK  = os.getenv("SLACK_WEBHOOK_URL", "")
AUDIT_LOG_PATH = LOG_DIR / "security_audit.log"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("audit")
audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(audit_handler)


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[-1].strip()
    return request.remote_addr


SNS_TOPIC_MAP = {
    "BRUTE_FORCE_DETECTED":    os.getenv("SNS_BRUTE_FORCE", ""),
    "IDOR_DETECTED":           os.getenv("SNS_IDOR", ""),
    "SESSION_HIJACK_DETECTED": os.getenv("SNS_SESSION_HIJACK", ""),
    "ABNORMAL_LOCATION_LOGIN": os.getenv("SNS_ABNORMAL_LOCATION", ""),
    "ADMIN_LOGIN_DETECTED":    os.getenv("SNS_SECURITY_OPERATOR", ""),
    "CREDENTIAL_STUFFING_DETECTED": os.getenv("SNS_BRUTE_FORCE", ""),
}

def publish_alert(event_type, username, ip, extra=None):
    topic_arn = SNS_TOPIC_MAP.get(event_type, "")
    if not topic_arn:
        print(f"[SNS] {event_type} 토픽 미설정 — 스킵", flush=True)
        return
    try:
        message = {
            "event":    event_type,
            "username": username,
            "ip":       ip,
            "time":     datetime.utcnow().isoformat(),
        }
        if extra:
            message.update(extra)
        sns = boto3.client("sns", region_name=REGION)
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message, ensure_ascii=False),
            Subject=f"[CloudSec] {event_type}",
        )
        print(f"[SNS] publish 완료: {event_type} / {username} / {ip}", flush=True)
    except Exception as e:
        print(f"[SNS] publish 오류: {e}", flush=True)


class DBConnectionWrapper:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, query, params=None):
        if params is None: params = ()
        cursor = self.conn.cursor(dictionary=True)
        cursor.execute(query.replace("?", "%s"), params)
        return cursor

    def commit(self): self.conn.commit()
    def close(self): self.conn.close()


def get_db():
    if "db" not in g:
        conn = mysql.connector.connect(
            host=DB_HOST, port=int(DB_PORT), user=DB_USER,
            password=DB_PASSWORD, database=DB_NAME,
            auth_plugin="mysql_native_password"
        )
        g.db = DBConnectionWrapper(conn)
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db: db.close()


def get_s3_client():
    kwargs = {"region_name": REGION}
    if AWS_ACCESS_KEY and AWS_SECRET_KEY:
        kwargs.update(aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    return boto3.client("s3", **kwargs)


def send_slack_alert(message):
    try:
        response = requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5)
        print(f"[Slack] status={response.status_code} response={response.text}", flush=True)
    except Exception as e:
        print(f"[Slack] 전송 오류: {e}", flush=True)


def log_audit(audit_log: dict, level: str = "info"):
    msg = json.dumps(audit_log, ensure_ascii=False)
    audit_logger.info(msg)
    try:
        db = get_db()
        details = {k: v for k, v in audit_log.items() if k not in ("timestamp", "event", "actor", "username")}
        db.execute(
            "INSERT INTO audit_logs (timestamp, event, username, details) VALUES (?, ?, ?, ?)",
            (audit_log.get("timestamp"), audit_log.get("event"),
             audit_log.get("username") or audit_log.get("actor"),
             json.dumps(details, ensure_ascii=False))
        )
        db.commit()
    except:
        pass


def cleanup_expired_lockouts(db):
    db.execute("DELETE FROM login_lockout WHERE unlock_at IS NOT NULL AND unlock_at < NOW()")
    db.commit()


def check_geoip_block(ip, username):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
        mmdb = str(DATA_DIR / "GeoLite2-Country.mmdb")
        if not os.path.exists(mmdb):
            return False
        reader = geoip2.database.Reader(mmdb)
        try:
            country_code = reader.country(ip).country.iso_code
        finally:
            reader.close()
        if country_code and country_code != 'KR':
            return country_code
    except Exception as e:
        print(f"[GeoIP] 검사 오류 (IP={ip}): {e}", flush=True)
    return False


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        current_ip = get_client_ip()
        if session.get("login_ip") and session.get("login_ip") != current_ip:
            log_audit({
                "timestamp":   datetime.utcnow().isoformat(),
                "event":       "SESSION_HIJACK_DETECTED",
                "username":    session["username"],
                "original_ip": session.get("login_ip"),
                "current_ip":  current_ip,
            }, "critical")
            publish_alert(
                "SESSION_HIJACK_DETECTED",
                username=session["username"],
                ip=current_ip,
                extra={"original_ip": session.get("login_ip")}
            )
            session.clear()
            flash("보안 위협으로 로그아웃되었습니다.", "danger")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin": abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@login_required
def index():
    db = get_db()
    all_files = db.execute(
        "SELECT f.*, u.username AS uploaded_by_username FROM files f "
        "LEFT JOIN users u ON f.uploaded_by = u.id ORDER BY f.uploaded_at DESC"
    ).fetchall()
    user_level, user_id, is_admin = session.get("level", 1), session.get("user_id"), session.get("role") == "admin"
    filtered = []
    for f in all_files:
        if f["owner_id"] == user_id or is_admin:
            filtered.append(f)
        else:
            try:
                allowed = [int(l.strip()) for l in str(f["target_levels"]).split(",") if l.strip()]
                if user_level in allowed: filtered.append(f)
            except:
                pass
    return render_template("index.html", files=filtered, username=session["username"])


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('filter', 'ALL')
    per_page = 50
    offset = (page - 1) * per_page
    filter_map = {
        'FILE_DOWNLOADED': 'FILE_DOWNLOADED',
        'FILE_UPLOAD': 'FILE_UPLOAD',
        'DELETED': 'DELETED',
        'SECURITY': 'SECURITY',
        'ADMIN': 'ADMIN',
        'LOGIN': 'LOGIN',
        'SESSION_HIJACK': 'SESSION_HIJACK'
    }
    db = get_db()
    filters = [f.strip() for f in filter_type.split(',') if f.strip()]
    if 'ALL' in filters or not filters:
        res = db.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()
        total = res["cnt"] if res else 0
        rows = db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
    else:
        keywords = [filter_map[f] for f in filters if f in filter_map]
        if not keywords:
            return render_template("admin_logs.html", logs=[], page=1, total_pages=0, total=0, filter_type=filter_type)
        cond = " OR ".join(["event LIKE ?" for _ in keywords])
        params = [f"%{k}%" for k in keywords]
        res = db.execute(f"SELECT COUNT(*) as cnt FROM audit_logs WHERE {cond}", tuple(params)).fetchone()
        total = res["cnt"] if res else 0
        rows = db.execute(
            f"SELECT * FROM audit_logs WHERE {cond} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params + [per_page, offset])
        ).fetchall()
    logs = []
    for r in rows:
        d = {"timestamp": r["timestamp"], "event": r["event"], "username": r["username"]}
        try: d.update(json.loads(r["details"] or "{}"))
        except: pass
        logs.append(d)
    return render_template(
        "admin_logs.html",
        logs=logs, page=page,
        total_pages=(total + per_page - 1) // per_page,
        total=total, filter_type=filter_type
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("파일 선택 필요", "warning")
        return redirect(url_for("index"))
    filename = secure_filename(file.filename)
    s3_key = f"{session['user_id']}/{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
    try:
        get_s3_client().upload_fileobj(file, BUCKET_NAME, s3_key)
        db = get_db()
        levels = ",".join([str(i) for i in range(1, 4) if request.form.get(f"level_{i}") == "on"])
        db.execute(
            "INSERT INTO files (owner_id, uploaded_by, original_name, s3_key, size_bytes, uploaded_at, target_levels) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session["user_id"], session["user_id"], filename, s3_key, 0, datetime.utcnow().isoformat(), levels)
        )
        db.commit()
        log_audit({"timestamp": datetime.utcnow().isoformat(), "event": "FILE_UPLOAD",
                   "actor": session["username"], "target": filename})
        flash("업로드 성공", "success")
    except Exception as e:
        flash(f"오류: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/download")
@login_required
def download():
    fid = request.args.get("id", type=int)
    db = get_db()
    cleanup_expired_lockouts(db)
    f = db.execute(
        "SELECT f.*, u.username as owner_username FROM files f "
        "JOIN users u ON f.owner_id = u.id WHERE f.id = ?",
        (fid,)
    ).fetchone()
    if not f: abort(404)

    user_id    = session.get("user_id")
    user_level = session.get("level", 1)
    is_admin   = session.get("role") == "admin"
    username   = session.get("username")
    ip         = get_client_ip()

    lock = db.execute(
        "SELECT unlock_at FROM login_lockout WHERE target_id = ? AND attack_type = 'IDOR' AND unlock_at > NOW()",
        (username,)
    ).fetchone()
    if lock:
        flash("비인가 접근 반복으로 30분 잠금 상태입니다.", "danger")
        session.clear()
        return redirect(url_for("login"))

    allowed = [int(l.strip()) for l in str(f["target_levels"]).split(",") if l.strip()]
    if not (is_admin or f["owner_id"] == user_id or user_level in allowed):
        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "event":     "SECURITY: GRANULAR_ACL_REJECTION",
            "username":  username,
            "file_id":   fid,
            "ip":        ip,
        }, "warning")
        publish_alert("IDOR_DETECTED", username=username, ip=ip, extra={"file_id": fid})
        lock_row = db.execute(
            "SELECT fail_count FROM login_lockout WHERE target_id = ? AND attack_type = 'IDOR'",
            (username,)
        ).fetchone()
        if lock_row:
            new_count = lock_row['fail_count'] + 1
            if new_count >= 5:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ?, unlock_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) "
                    "WHERE target_id = ? AND attack_type = 'IDOR'",
                    (new_count, username)
                )
                db.commit()
                session.clear()
                flash("비인가 접근 반복으로 30분 잠금되었습니다.", "danger")
                return redirect(url_for("login"))
            else:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ? WHERE target_id = ? AND attack_type = 'IDOR'",
                    (new_count, username)
                )
        else:
            db.execute(
                "INSERT INTO login_lockout (target_id, attack_type, fail_count) VALUES (?, 'IDOR', 1)",
                (username,)
            )
        db.commit()
        abort(403)

    try:
        obj = get_s3_client().get_object(Bucket=BUCKET_NAME, Key=f["s3_key"])
        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "event":     "FILE_DOWNLOADED",
            "username":  username,
            "file_name": f["original_name"],
        })
        return Response(
            obj["Body"].read(),
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(f['original_name'])}"}
        )
    except:
        flash("다운로드 오류", "danger")
        return redirect(url_for("index"))


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    fid = request.form.get("id", type=int)
    if not fid:
        flash("파일 ID가 필요합니다.", "warning")
        return redirect(url_for("index"))
    db = get_db()
    f = db.execute("SELECT * FROM files WHERE id = ?", (fid,)).fetchone()
    if not f: abort(404)
    user_id  = session.get("user_id")
    is_admin = session.get("role") == "admin"
    if not (is_admin or f["owner_id"] == user_id):
        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "event":     "SECURITY: UNAUTHORIZED_DELETE_ATTEMPT",
            "username":  session["username"],
            "file_id":   fid,
        }, "warning")
        abort(403)
    try:
        get_s3_client().delete_object(Bucket=BUCKET_NAME, Key=f["s3_key"])
        db.execute("DELETE FROM files WHERE id = ?", (fid,))
        db.commit()
        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "event":     "FILE_DELETED",
            "actor":     session["username"],
            "target":    f["original_name"],
            "file_id":   fid,
        })
        flash("삭제 완료", "success")
    except Exception as e:
        flash(f"삭제 오류: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    import random
    captcha_question = session.get("captcha_question")

    if request.method == "POST":
        u  = request.form.get("username", "").strip()
        p  = request.form.get("password")
        ip = get_client_ip()
        db = get_db()
        cleanup_expired_lockouts(db)

        blocked_country = check_geoip_block(ip, u)
        if blocked_country:
            log_audit({
                "timestamp": datetime.utcnow().isoformat(),
                "event":     "ABNORMAL_LOCATION_LOGIN",
                "username":  u,
                "ip":        ip,
                "country":   blocked_country,
            }, "warning")
            publish_alert("ABNORMAL_LOCATION_LOGIN", username=u, ip=ip, extra={"country": blocked_country})
            flash(f"해외 접속이 차단되었습니다 ({blocked_country})", "danger")
            return render_template("login.html")


        lock = db.execute(
            "SELECT unlock_at FROM login_lockout WHERE target_id = ? AND unlock_at > NOW()", (u,)
        ).fetchone()
        if lock:
            flash("계정 잠금 상태 (30분)", "danger")
            return render_template("login.html", captcha=captcha_question)

        if session.get("captcha_required"):
            user_answer = request.form.get("captcha_answer", "").strip()
            if not user_answer or user_answer != str(session.get("captcha_answer")):
                flash("CAPTCHA 답이 틀렸습니다. 다시 시도하세요.", "warning")
                return render_template("login.html", captcha=captcha_question)

        user = db.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        if user and check_password_hash(user["password_hash"], p):
            if user["is_locked"]:
                flash("영구 잠금 계정", "danger")
                return render_template("login.html")
            db.execute("DELETE FROM login_lockout WHERE target_id = ?", (u,))
            db.commit()
            session.clear()
            session.update({
                "user_id":  user["id"],
                "username": user["username"],
                "role":     user["role"],
                "level":    user["level"],
                "login_ip": ip,
            })
            return redirect(url_for("index"))

        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "event":     "LOGIN_FAILED",
            "username":  u,
            "ip":        ip,
        }, "warning")

        lock_row = db.execute(
            "SELECT fail_count FROM login_lockout WHERE target_id = ? AND attack_type = 'BRUTE_FORCE'", (u,)
        ).fetchone()
        if lock_row:
            new_count = lock_row['fail_count'] + 1
            if new_count >= 10:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ?, unlock_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) "
                    "WHERE target_id = ? AND attack_type = 'BRUTE_FORCE'",
                    (new_count, u)
                )
                db.commit()
                publish_alert("BRUTE_FORCE_DETECTED", username=u, ip=ip, extra={"fail_count": new_count})
                flash("로그인 10회 실패로 30분 잠금되었습니다.", "danger")
                return render_template("login.html")
            else:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ? WHERE target_id = ? AND attack_type = 'BRUTE_FORCE'",
                    (new_count, u)
                )
        else:
            new_count = 1
            db.execute(
                "INSERT INTO login_lockout (target_id, attack_type, fail_count) VALUES (?, 'BRUTE_FORCE', 1)", (u,)
            )

        ip_row = db.execute(
            "SELECT fail_count FROM login_lockout WHERE target_id = ? AND attack_type = 'IP_BRUTE_FORCE'", (ip,)
        ).fetchone()
        if ip_row:
            ip_count = ip_row['fail_count'] + 1
            if ip_count >= 50:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ?, unlock_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) "
                    "WHERE target_id = ? AND attack_type = 'IP_BRUTE_FORCE'",
                    (ip_count, ip)
                )
                db.commit()
                log_audit({
                    "timestamp":  datetime.utcnow().isoformat(),
                    "event":      "CREDENTIAL_STUFFING_DETECTED",
                    "username":   u,
                    "ip":         ip,
                    "fail_count": ip_count,
                publish_alert("CREDENTIAL_STUFFING_DETECTED", username=u, ip=ip, extra={"ip_fail_count": ip_count})
                }, "warning")
            else:
                db.execute(
                    "UPDATE login_lockout SET fail_count = ? WHERE target_id = ? AND attack_type = 'IP_BRUTE_FORCE'",
                    (ip_count, ip)
                )
        else:
            db.execute(
                "INSERT INTO login_lockout (target_id, attack_type, fail_count) VALUES (?, 'IP_BRUTE_FORCE', 1)", (ip,)
            )

        db.commit()

        if lock_row and new_count >= 5:
            a, b = random.randint(1, 9), random.randint(1, 9)
            session["captcha_required"] = True
            session["captcha_question"] = f"{a} + {b} = ?"
            session["captcha_answer"]   = a + b
            captcha_question = session["captcha_question"]
            flash(f"로그인 실패 {new_count}회. 아래 CAPTCHA를 완료해주세요.", "warning")
        else:
            flash("로그인 실패", "danger")

    return render_template("login.html", captcha=captcha_question)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ?", (u,)).fetchone():
            flash("중복 아이디", "danger")
            return render_template("signup.html")
        db.execute(
            "INSERT INTO users (username, password_hash, role, level) VALUES (?, ?, 'user', 1)",
            (u, generate_password_hash(p))
        )
        db.commit()
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        user_id   = request.form.get("user_id", type=int)
        new_level = request.form.get("new_level", type=int)
        if user_id and new_level in [1, 2, 3]:
            user = db.execute("SELECT username, level FROM users WHERE id = ?", (user_id,)).fetchone()
            if user:
                db.execute("UPDATE users SET level = ? WHERE id = ?", (new_level, user_id))
                db.commit()
                log_audit({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event":     "ADMIN: USER_LEVEL_CHANGED",
                    "admin":     session["username"],
                    "target":    user["username"],
                    "old_level": user["level"],
                    "new_level": new_level,
                })
                flash(f"{user['username']} 레벨이 {new_level}로 변경되었습니다.", "success")
        return redirect(url_for("admin_users"))
    users = db.execute("SELECT id, username, level, is_locked FROM users").fetchall()
    by_lvl = {i: [u for u in users if u["level"] == i] for i in range(1, 4)}
    return render_template("admin_users.html", users_by_level=by_lvl)


@app.route("/admin/unlock", methods=["POST"])
@login_required
@admin_required
def admin_unlock():
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("사용자 ID가 필요합니다.", "warning")
        return redirect(url_for("admin_users"))
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for("admin_users"))
    username = user["username"]
    db.execute("DELETE FROM login_lockout WHERE target_id = ?", (username,))
    db.execute("UPDATE users SET is_locked = 0 WHERE id = ?", (user_id,))
    db.commit()
    log_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "event":     "ADMIN: ACCOUNT_UNLOCKED",
        "admin":     session["username"],
        "target":    username,
    })
    flash(f"{username} 계정 잠금 해제 완료", "success")
    return redirect(url_for("admin_users"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
