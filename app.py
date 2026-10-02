"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复、迁移与独立保管域保护。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_VERIFY_VALID_DAYS = 30
# 旧数据升级时，没有保管域信息的副本统一归入历史占位域。
LEGACY_DOMAIN = "__legacy__"
COPY_STATES = ("healthy", "corrupt", "unconfirmed")
PROTECTION_STATES = ("protected", "unprotected", "unknown")


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock:
            legacy = self._detect_legacy_schema()
            with self.connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users(
                        id TEXT PRIMARY KEY, name TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                    );
                    CREATE TABLE IF NOT EXISTS archives(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        owner_id TEXT NOT NULL REFERENCES users(id),
                        retention_until TEXT NOT NULL,
                        restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                        required_domains INTEGER NOT NULL DEFAULT 1 CHECK(required_domains >= 1),
                        verify_valid_days INTEGER NOT NULL DEFAULT 30 CHECK(verify_valid_days >= 0),
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS archive_members(
                        archive_id INTEGER NOT NULL REFERENCES archives(id),
                        user_id TEXT NOT NULL REFERENCES users(id),
                        permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                        PRIMARY KEY(archive_id,user_id)
                    );
                    CREATE TABLE IF NOT EXISTS archive_versions(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        archive_id INTEGER NOT NULL REFERENCES archives(id),
                        version INTEGER NOT NULL,
                        state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                        protection_state TEXT NOT NULL DEFAULT 'unprotected'
                            CHECK(protection_state IN ('protected','unprotected','unknown')),
                        created_by TEXT NOT NULL REFERENCES users(id),
                        created_at TEXT NOT NULL,
                        UNIQUE(archive_id,version)
                    );
                    CREATE TABLE IF NOT EXISTS archive_files(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        path TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        content BLOB NOT NULL,
                        UNIQUE(version_id,path)
                    );
                    CREATE TABLE IF NOT EXISTS copies(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        location TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','unconfirmed')),
                        created_at TEXT NOT NULL,
                        last_verified_at TEXT,
                        UNIQUE(version_id,location)
                    );
                    CREATE TABLE IF NOT EXISTS copy_files(
                        copy_id INTEGER NOT NULL REFERENCES copies(id),
                        path TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        content BLOB NOT NULL,
                        PRIMARY KEY(copy_id,path)
                    );
                    CREATE TABLE IF NOT EXISTS migrations(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                        source_path TEXT NOT NULL,
                        target_path TEXT NOT NULL,
                        target_format TEXT NOT NULL,
                        actor_id TEXT NOT NULL REFERENCES users(id),
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS audit_log(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        archive_id INTEGER NOT NULL REFERENCES archives(id),
                        actor_id TEXT NOT NULL REFERENCES users(id),
                        action TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS protection_recompute(
                        version_id INTEGER PRIMARY KEY REFERENCES archive_versions(id),
                        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done'))
                    );
                    """
                )
                if legacy:
                    self._migrate_legacy(conn)
                conn.execute("PRAGMA user_version=1")

    def _drain_pending(self, conn, actor_id: str) -> None:
        """旧数据升级后把队列里的历史版本按当前要求重判（需用户已就绪以写审计）。"""
        rows = conn.execute(
            "SELECT r.version_id,v.archive_id FROM protection_recompute r"
            " JOIN archive_versions v ON v.id=r.version_id WHERE r.status='pending' ORDER BY r.version_id"
        ).fetchall()
        for row in rows:
            self._recompute_version(conn, row["version_id"], actor_id, row["archive_id"])

    def _detect_legacy_schema(self) -> bool:
        """旧库没有保管域列，需要重建 copies 表并回填历史占位域。"""
        path = Path(self.db_path)
        if not path.exists():
            return False
        conn = sqlite3.connect(self.db_path)
        try:
            if conn.execute("PRAGMA user_version").fetchone()[0] >= 1:
                return False
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "copies" not in tables:
                return False
            cols = {r[1] for r in conn.execute("PRAGMA table_info(copies)")}
            return "domain" not in cols
        finally:
            conn.close()

    def _migrate_legacy(self, conn: sqlite3.Connection) -> None:
        # 重建 copies 表以加入 domain 列和新的状态集合；旧的 degraded 归入 corrupt。
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(
            """
            ALTER TABLE copies RENAME TO copies_old;
            CREATE TABLE copies(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                location TEXT NOT NULL,
                domain TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','unconfirmed')),
                created_at TEXT NOT NULL,
                last_verified_at TEXT,
                UNIQUE(version_id,location)
            );
            INSERT INTO copies(id,version_id,location,domain,state,created_at,last_verified_at)
            SELECT id,version_id,location,'__legacy__',
                   CASE state WHEN 'degraded' THEN 'corrupt' ELSE state END,
                   created_at,last_verified_at FROM copies_old;
            DROP TABLE copies_old;
            """
        )
        conn.execute("PRAGMA foreign_keys=ON")
        archive_cols = {r[1] for r in conn.execute("PRAGMA table_info(archives)")}
        if "required_domains" not in archive_cols:
            conn.execute("ALTER TABLE archives ADD COLUMN required_domains INTEGER NOT NULL DEFAULT 1")
        if "verify_valid_days" not in archive_cols:
            conn.execute(f"ALTER TABLE archives ADD COLUMN verify_valid_days INTEGER NOT NULL DEFAULT {DEFAULT_VERIFY_VALID_DAYS}")
        version_cols = {r[1] for r in conn.execute("PRAGMA table_info(archive_versions)")}
        if "protection_state" not in version_cols:
            conn.execute("ALTER TABLE archive_versions ADD COLUMN protection_state TEXT NOT NULL DEFAULT 'unprotected'")
        # 每个已有版本排一次保护重算；重算必须在迁移连接之外走标准流程。
        conn.execute(
            "INSERT OR IGNORE INTO protection_recompute(version_id,status) SELECT id,'pending' FROM archive_versions"
        )

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )
            # 升级旧库时排入的重算，在用户就绪后立即按当前保护要求补跑完。
            self._drain_pending(conn, "owner")

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    @staticmethod
    def _parse_domain(domain: object) -> str:
        domain = str(domain or "").strip()
        if len(domain) < 2:
            raise BusinessError("副本必须登记保管域（domain）", 422, "domain_required")
        if any(ch.isspace() for ch in domain):
            raise BusinessError("保管域不能包含空白字符", 422, "invalid_domain")
        return domain

    @staticmethod
    def _positive_int(value: object, field: str, allow_zero: bool = False) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BusinessError(f"{field} 必须是整数", 422, f"invalid_{field}")
        if value < 0 or (value == 0 and not allow_zero):
            raise BusinessError(f"{field} 必须{'大于等于 0' if allow_zero else '大于 0'}", 422, f"invalid_{field}")
        return value

    def _protection_view(self, conn, version_id: int, at: datetime | None = None) -> dict:
        """按当前保护要求实时判定一个版本的保护状态（纯计算，可安全用于读路径）。"""
        at = at or datetime.now(timezone.utc)
        archive = conn.execute(
            """SELECT a.required_domains,a.verify_valid_days FROM archives a
               JOIN archive_versions v ON v.archive_id=a.id WHERE v.id=?""",
            (version_id,),
        ).fetchone()
        copies = conn.execute(
            "SELECT id,location,domain,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id",
            (version_id,),
        ).fetchall()
        valid_domains: set[str] = set()
        copy_rows = []
        for c in copies:
            fresh = False
            if c["state"] == "healthy" and c["last_verified_at"]:
                last = datetime.fromisoformat(c["last_verified_at"])
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                age_days = (at - last).total_seconds() / 86400
                fresh = age_days < archive["verify_valid_days"]
            if fresh:
                valid_domains.add(c["domain"])
            copy_rows.append(
                {"id": c["id"], "location": c["location"], "domain": c["domain"], "state": c["state"],
                 "legacy": c["domain"] == LEGACY_DOMAIN, "last_verified_at": c["last_verified_at"], "fresh": fresh}
            )
        protection_state = "protected" if len(valid_domains) >= archive["required_domains"] else "unprotected"
        return {
            "protection_state": protection_state,
            "required_domains": archive["required_domains"],
            "verify_valid_days": archive["verify_valid_days"],
            "satisfied_domains": len(valid_domains),
            "domains": sorted(valid_domains),
            "copies": copy_rows,
        }

    def _recompute_version(self, conn, version_id: int, actor: str, archive_id: int | None = None) -> dict:
        """在写事务内按最新要求重判版本保护状态并落库；返回判定结果。"""
        view = self._protection_view(conn, version_id)
        conn.execute("UPDATE archive_versions SET protection_state=? WHERE id=?", (view["protection_state"], version_id))
        conn.execute(
            "INSERT INTO protection_recompute(version_id,status) VALUES(?,'done') "
            "ON CONFLICT(version_id) DO UPDATE SET status='done'",
            (version_id,),
        )
        if archive_id is None:
            archive_id = conn.execute("SELECT archive_id FROM archive_versions WHERE id=?", (version_id,)).fetchone()[0]
        self._audit(conn, archive_id, actor, "protection.recompute", {
            "version_id": version_id, "protection_state": view["protection_state"],
            "required_domains": view["required_domains"], "satisfied_domains": view["satisfied_domains"],
            "domains": view["domains"],
        })
        return {k: v for k, v in view.items() if k != "copies"}

    def _enqueue_archive(self, conn, archive_id: int) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO protection_recompute(version_id,status) "
            "SELECT id,'pending' FROM archive_versions WHERE archive_id=?",
            (archive_id,),
        )

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True,
                       required_domains: int = 1, verify_valid_days: int = DEFAULT_VERIFY_VALID_DAYS) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        required_domains = self._positive_int(required_domains, "required_domains")
        verify_valid_days = self._positive_int(verify_valid_days, "verify_valid_days", allow_zero=True)
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,required_domains,verify_valid_days,created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), required_domains, verify_valid_days, now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {
                "retention_until": retention_until, "restricted": restricted,
                "required_domains": required_domains, "verify_valid_days": verify_valid_days,
            })
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted,
                    "required_domains": required_domains, "verify_valid_days": verify_valid_days}

    def set_protection_requirement(self, actor_id: str, archive_id: int,
                                   required_domains: object = None, verify_valid_days: object = None) -> dict:
        """修改保护要求；在同一写事务内重算全部受影响版本，读到即一致。"""
        updates, params = [], []
        if required_domains is not None:
            value = self._positive_int(required_domains, "required_domains")
            updates.append("required_domains=?"), params.append(value)
        if verify_valid_days is not None:
            value = self._positive_int(verify_valid_days, "verify_valid_days", allow_zero=True)
            updates.append("verify_valid_days=?"), params.append(value)
        if not updates:
            raise BusinessError("至少提供 required_domains 或 verify_valid_days", 422, "no_requirement_change")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
                if not archive:
                    raise BusinessError("档案不存在", 404, "not_found")
                self._access(conn, archive_id, actor, require_write=True)
                conn.execute(f"UPDATE archives SET {','.join(updates)} WHERE id=?", (*params, archive_id))
                self._enqueue_archive(conn, archive_id)
                version_ids = [r[0] for r in conn.execute(
                    "SELECT id FROM archive_versions WHERE archive_id=? ORDER BY id", (archive_id,)
                ).fetchall()]
                results = [self._recompute_version(conn, vid, actor_id, archive_id) for vid in version_ids]
                self._audit(conn, archive_id, actor_id, "protection.requirement.set", {
                    "required_domains": required_domains, "verify_valid_days": verify_valid_days,
                    "affected_versions": version_ids,
                })
                return {"archive_id": archive_id, "affected_versions": results}
            except Exception:
                conn.rollback()
                raise

    def recompute_protection(self, actor_id: str, archive_id: int | None = None,
                             limit: int = 100, fail_after: int | None = None) -> dict:
        """从重算队列拉取待处理版本逐个提交；中途失败后再次调用会从未完成项继续。"""
        limit = self._positive_int(limit, "limit")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            if archive_id is not None:
                self._access(conn, archive_id, actor, require_write=True)
        processed: list[dict] = []
        for _ in range(limit):
            with self.connect() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    query = (
                        "SELECT r.version_id,v.archive_id FROM protection_recompute r"
                        " JOIN archive_versions v ON v.id=r.version_id WHERE r.status='pending'"
                    )
                    params: tuple = ()
                    if archive_id is not None:
                        query += " AND v.archive_id=?"
                        params = (archive_id,)
                    query += " ORDER BY r.version_id LIMIT 1"
                    row = conn.execute(query, params).fetchone()
                    if not row:
                        conn.commit()
                        break
                    if fail_after is not None and len(processed) >= fail_after:
                        # 测试/演练注入点：保留当前及后续条目为 pending，下次调用接着跑。
                        raise BusinessError("批量重算按计划中断", 500, "recompute_interrupted")
                    result = self._recompute_version(conn, row["version_id"], actor_id, row["archive_id"])
                    conn.commit()
                    processed.append({"version_id": row["version_id"], **result})
                except Exception:
                    conn.rollback()
                    raise
        with self.connect() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM protection_recompute WHERE status='pending'").fetchone()[0]
        return {"processed": processed, "processed_count": len(processed), "remaining": remaining,
                "complete": remaining == 0}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                conn.execute(
                    "INSERT INTO protection_recompute(version_id,status) VALUES(?,'done')", (version_id,)
                )
                self._recompute_version(conn, version_id, actor_id, archive_id)
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str, domain: object = None) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        domain = self._parse_domain(domain)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,domain,created_at,last_verified_at) VALUES(?,?,?,?,?)",
                    (version_id, location, domain, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                protection = self._recompute_version(conn, version_id, actor_id, version["archive_id"])
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {
                    "copy_id": copy_id, "version_id": version_id, "location": location, "domain": domain,
                })
                return {"id": copy_id, "version_id": version_id, "location": location, "domain": domain,
                        "state": "healthy", "protection": protection}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            # 读路径实时判定，与落库状态、状态接口共用同一套规则。
            view = self._protection_view(conn, version_id)
            version_dict = dict(version)
            version_dict["protection_state"] = view["protection_state"]
            return {
                "version": version_dict,
                "archive": dict(archive),
                "files": [dict(x) for x in files],
                "copies": view["copies"],
                "protection": {k: v for k, v in view.items() if k != "copies"},
            }

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                repaired = False
                if not corrupt_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "corrupt"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            repaired, result_state = True, "healthy"
                    if result_state == "corrupt":
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                # 先写者生效：在同一 IMMEDIATE 事务内读取当前保护要求并重判，
                # 后到的校验会按最新要求重新计算，不会用旧快照覆盖。
                protection = self._recompute_version(conn, copy["version_id"], user_id, version["archive_id"])
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                     "repaired": repaired, "protection_state": protection["protection_state"]},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                        "repaired": repaired, "protection": protection}
            except Exception:
                conn.rollback()
                raise

    def mark_unreadable(self, user_id: str, copy_id: int, reason: str = "") -> dict:
        """介质读不出来的副本记为待确认：不算损坏也不算健康，不参与保护计数。"""
        with self.connect() as conn:
            actor = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor)
                # 待确认不刷新校验时间，避免被当成一次有效校验。
                conn.execute("UPDATE copies SET state='unconfirmed' WHERE id=?", (copy_id,))
                protection = self._recompute_version(conn, copy["version_id"], user_id, version["archive_id"])
                self._audit(conn, version["archive_id"], user_id, "copy.mark_unreadable", {
                    "copy_id": copy_id, "reason": reason.strip(), "protection_state": protection["protection_state"],
                })
                return {"copy_id": copy_id, "state": "unconfirmed", "protection": protection}
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                conn.execute(
                    "INSERT INTO protection_recompute(version_id,status) VALUES(?,'done')", (target_version_id,)
                )
                self._recompute_version(conn, target_version_id, actor_id, source_version["archive_id"])
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute(
                "SELECT id,version,state,protection_state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version",
                (archive_id,),
            ).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            version_rows = []
            for v in versions:
                view = self._protection_view(conn, v["id"])
                # 与版本详情页共用同一实时判定，并以其为准回写落库状态。
                if v["protection_state"] != view["protection_state"]:
                    conn.execute(
                        "UPDATE archive_versions SET protection_state=? WHERE id=?", (view["protection_state"], v["id"])
                    )
                version_rows.append({
                    "id": v["id"], "version": v["version"], "state": v["state"], "created_at": v["created_at"],
                    "file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                    "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0],
                    "protection_state": view["protection_state"],
                    "required_domains": view["required_domains"],
                    "satisfied_domains": view["satisfied_domains"],
                    "domains": view["domains"],
                })
            pending = conn.execute(
                """SELECT COUNT(*) FROM protection_recompute r JOIN archive_versions v ON v.id=r.version_id
                   WHERE r.status='pending' AND v.archive_id=?""",
                (archive_id,),
            ).fetchone()[0]
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": version_rows,
                "recompute_pending": pending,
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.1"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(
                user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True)),
                d.get("required_domains", 1), d.get("verify_valid_days", DEFAULT_VERIFY_VALID_DAYS),
            ))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
            if parts[3] == "protection":
                d = self._body()
                return self._send(200, store.set_protection_requirement(
                    user, archive_id, d.get("required_domains"), d.get("verify_valid_days")))
            if parts[3] == "recompute":
                d = self._body()
                return self._send(200, store.recompute_protection(
                    user, archive_id, limit=d.get("limit", 100), fail_after=d.get("fail_after")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", ""), d.get("domain")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if parts == ["api", "protection", "recompute"] and method == "POST":
            d = self._body()
            return self._send(200, store.recompute_protection(
                user, None, limit=d.get("limit", 100), fail_after=d.get("fail_after")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "unconfirmed" and method == "POST":
            d = self._body()
            return self._send(200, store.mark_unreadable(user, int(parts[2]), d.get("reason", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
