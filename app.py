"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024

# 历史占位域：旧数据中没有保管域的副本统一归入此域，仍可查看和校验。
LEGACY_DOMAIN = "__legacy__"
RESERVED_DOMAIN_PREFIX = "__"
DEFAULT_REQUIRED_DOMAINS = 1
DEFAULT_VERIFY_MAX_AGE_DAYS = 365


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        with self._lock, self.connect() as conn:
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
                    required_domains INTEGER NOT NULL DEFAULT 1 CHECK(required_domains>=1),
                    verify_max_age_days INTEGER NOT NULL DEFAULT 365 CHECK(verify_max_age_days>=0),
                    requirement_revision INTEGER NOT NULL DEFAULT 1,
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
                    protected INTEGER NOT NULL DEFAULT 0 CHECK(protected IN (0,1)),
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
                    domain TEXT,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded','pending')),
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
                CREATE TABLE IF NOT EXISTS recompute_jobs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running','done','failed')),
                    total INTEGER NOT NULL DEFAULT 0,
                    done INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recompute_job_items(
                    job_id INTEGER NOT NULL REFERENCES recompute_jobs(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','failed')),
                    error TEXT,
                    PRIMARY KEY(job_id,version_id)
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._migrate(conn)

    def _table_columns(self, conn: sqlite3.Connection, table: str) -> list[str]:
        return [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """旧库升级：补齐列、重建含 pending 状态约束的 copies 表、回填历史占位域。"""
        # 先补齐缺失列（copies 重建时需要 domain 列）
        for table, column, ddl in [
            ("archives", "required_domains", "ALTER TABLE archives ADD COLUMN required_domains INTEGER NOT NULL DEFAULT 1"),
            ("archives", "verify_max_age_days", "ALTER TABLE archives ADD COLUMN verify_max_age_days INTEGER NOT NULL DEFAULT 365"),
            ("archives", "requirement_revision", "ALTER TABLE archives ADD COLUMN requirement_revision INTEGER NOT NULL DEFAULT 1"),
            ("archive_versions", "protected", "ALTER TABLE archive_versions ADD COLUMN protected INTEGER NOT NULL DEFAULT 0"),
            ("copies", "domain", "ALTER TABLE copies ADD COLUMN domain TEXT"),
        ]:
            if column not in self._table_columns(conn, table):
                conn.execute(ddl)
        # 旧 copies 表的状态约束不含 pending，需要重建（在事务外切换外键）
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='copies'").fetchone()
        if row and "pending" not in (row["sql"] or ""):
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute(
                """
                CREATE TABLE copies_new(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    domain TEXT,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded','pending')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                )
                """
            )
            conn.execute(
                "INSERT INTO copies_new(id,version_id,location,domain,state,created_at,last_verified_at) "
                "SELECT id,version_id,location,domain,state,created_at,last_verified_at FROM copies"
            )
            conn.execute("DROP TABLE copies")
            conn.execute("ALTER TABLE copies_new RENAME TO copies")
            conn.execute("PRAGMA foreign_keys=ON")
        # 没有保管域的副本归入历史占位域，升级后仍可查看和校验
        conn.execute("UPDATE copies SET domain=? WHERE domain IS NULL OR domain=''", (LEGACY_DOMAIN,))

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
    def _validate_domain(domain: object) -> str:
        if domain is None or (isinstance(domain, str) and not domain.strip()):
            return LEGACY_DOMAIN
        if not isinstance(domain, str):
            raise BusinessError("保管域必须是字符串", 422, "invalid_domain")
        domain = domain.strip()
        if not domain or len(domain) > 64 or domain.startswith(RESERVED_DOMAIN_PREFIX):
            raise BusinessError("保管域名称不合法", 422, "invalid_domain")
        return domain

    @staticmethod
    def _protection_domains(conn, version_id: int, required_domains: int, verify_max_age_days: int) -> set[str]:
        """统计版本下健康且校验未过期的副本所覆盖的独立保管域；同一域只算一份。"""
        cutoff = None
        if verify_max_age_days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=verify_max_age_days)
        domains: set[str] = set()
        for r in conn.execute("SELECT domain,state,last_verified_at FROM copies WHERE version_id=?", (version_id,)).fetchall():
            if r["state"] != "healthy":  # 损坏、降级、待确认都不计入
                continue
            if not r["last_verified_at"]:
                continue
            if cutoff is not None:
                try:
                    verified = datetime.fromisoformat(r["last_verified_at"])
                except ValueError:
                    continue
                if verified < cutoff:  # 校验过期，不计入
                    continue
            domains.add(r["domain"] or LEGACY_DOMAIN)
        return domains

    def _recompute_version_protection(self, conn, version_id: int, required_domains: int, verify_max_age_days: int) -> tuple[bool, set[str]]:
        domains = self._protection_domains(conn, version_id, required_domains, verify_max_age_days)
        protected = len(domains) >= required_domains
        conn.execute("UPDATE archive_versions SET protected=? WHERE id=?", (1 if protected else 0, version_id))
        return protected, domains

    def _recompute_all_protection(self, conn, archive_id: int) -> dict[int, tuple[bool, set[str]]]:
        req = conn.execute(
            "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (archive_id,)
        ).fetchone()
        results = {}
        for v in conn.execute("SELECT id FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall():
            results[v["id"]] = self._recompute_version_protection(conn, v["id"], req["required_domains"], req["verify_max_age_days"])
        return results

    @staticmethod
    def _protection_summary(conn, archive_id: int) -> dict:
        archive = conn.execute(
            "SELECT required_domains,verify_max_age_days,requirement_revision FROM archives WHERE id=?", (archive_id,)
        ).fetchone()
        rows = conn.execute("SELECT protected FROM archive_versions WHERE archive_id=?", (archive_id,)).fetchall()
        return {
            "required_domains": archive["required_domains"],
            "verify_max_age_days": archive["verify_max_age_days"],
            "revision": archive["requirement_revision"],
            "protected": sum(1 for r in rows if r["protected"]),
            "unprotected": sum(1 for r in rows if not r["protected"]),
        }

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True,
                       required_domains: int = DEFAULT_REQUIRED_DOMAINS,
                       verify_max_age_days: int = DEFAULT_VERIFY_MAX_AGE_DAYS) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        if not isinstance(required_domains, int) or isinstance(required_domains, bool) or required_domains < 1:
            raise BusinessError("required_domains 必须是不小于 1 的整数", 422, "invalid_requirement")
        if not isinstance(verify_max_age_days, int) or verify_max_age_days < 0:
            raise BusinessError("verify_max_age_days 必须是非负整数", 422, "invalid_requirement")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    """INSERT INTO archives(name,owner_id,retention_until,restricted,required_domains,verify_max_age_days,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (name, user_id, retention_until, int(bool(restricted)), required_domains, verify_max_age_days, now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create",
                        {"retention_until": retention_until, "restricted": restricted,
                         "required_domains": required_domains, "verify_max_age_days": verify_max_age_days})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted,
                    "required_domains": required_domains, "verify_max_age_days": verify_max_age_days}

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
                req = conn.execute(
                    "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (archive_id,)
                ).fetchone()
                protected, domains = self._recompute_version_protection(conn, version_id, req["required_domains"], req["verify_max_age_days"])
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "protected": protected, "domains": sorted(domains),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest),
                        "protected": protected, "domains": sorted(domains)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str, domain: str | None = None) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        domain = self._validate_domain(domain)
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
                req = conn.execute(
                    "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (version["archive_id"],)
                ).fetchone()
                protected, domains = self._recompute_version_protection(conn, version_id, req["required_domains"], req["verify_max_age_days"])
                self._audit(conn, version["archive_id"], actor_id, "copy.create",
                            {"copy_id": copy_id, "version_id": version_id, "location": location,
                             "domain": domain, "protected": protected, "domains": sorted(domains)})
                return {"id": copy_id, "version_id": version_id, "location": location, "domain": domain,
                        "state": "healthy", "protected": protected, "domains": sorted(domains)}
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
            copies = conn.execute(
                "SELECT id,location,domain,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files], "copies": [dict(x) for x in copies]}

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
                expected = conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (copy["version_id"],)
                ).fetchall()
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                stored_by_path = {r["path"]: r for r in stored}
                # 读不出来的副本算待确认：不算损坏也不算健康
                unreadable_paths = [
                    r["path"] for r in expected
                    if r["path"] not in stored_by_path or stored_by_path[r["path"]]["content"] is None
                ]
                repaired = False
                if unreadable_paths:
                    conn.execute("UPDATE copies SET state='pending',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "pending"
                    corrupt_paths = []
                else:
                    corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                    if not corrupt_paths:
                        conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                        result_state = "healthy"
                    else:
                        conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                        healthy = conn.execute(
                            "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                            (copy["version_id"], copy_id),
                        ).fetchone()
                        result_state = "degraded"
                        if healthy:
                            donor = conn.execute(
                                "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                            ).fetchall()
                            donor_by_path = {r["path"]: r for r in donor}
                            expected_by_path = {r["path"]: r for r in expected}
                            if set(donor_by_path) == set(expected_by_path) and all(
                                hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected_by_path[p]["sha256"]
                                for p in expected_by_path
                            ):
                                conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                                conn.execute(
                                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                       SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                    (copy_id, healthy["id"]),
                                )
                                conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                                repaired, result_state = True, "healthy"
                        if result_state == "degraded":
                            conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                # 校验后按当前保护要求重判；要求已被并发更新时，这里读到的就是新要求
                req = conn.execute(
                    "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (version["archive_id"],)
                ).fetchone()
                protected, domains = self._recompute_version_protection(
                    conn, copy["version_id"], req["required_domains"], req["verify_max_age_days"]
                )
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                     "unreadable_paths": unreadable_paths, "repaired": repaired,
                     "protected": protected, "domains": sorted(domains)},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                        "unreadable_paths": unreadable_paths, "repaired": repaired,
                        "protected": protected, "domains": sorted(domains)}
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

    def simulate_unreadable(self, user_id: str, copy_id: int) -> dict:
        """仅用于演示和测试：清空副本内容，模拟底层介质读不出来（待确认）。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
            conn.execute("UPDATE copies SET state='pending' WHERE id=?", (copy_id,))
            req = conn.execute(
                "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (version["archive_id"],)
            ).fetchone()
            protected, domains = self._recompute_version_protection(conn, copy["version_id"], req["required_domains"], req["verify_max_age_days"])
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_unreadable",
                        {"copy_id": copy_id, "protected": protected, "domains": sorted(domains)})
            return {"copy_id": copy_id, "state": "pending", "protected": protected, "domains": sorted(domains)}

    def set_protection_requirement(self, actor_id: str, archive_id: int, required_domains: int,
                                    verify_max_age_days: int | None = None, expected_revision: int | None = None) -> dict:
        """声明档案需要几个独立保管域。并发时先写入的一方生效，后到的按新要求重判。"""
        if not isinstance(required_domains, int) or isinstance(required_domains, bool) or required_domains < 1:
            raise BusinessError("required_domains 必须是不小于 1 的整数", 422, "invalid_requirement")
        if verify_max_age_days is not None and (not isinstance(verify_max_age_days, int) or verify_max_age_days < 0):
            raise BusinessError("verify_max_age_days 必须是非负整数", 422, "invalid_requirement")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
                if not archive:
                    raise BusinessError("档案不存在", 404, "not_found")
                self._access(conn, archive_id, actor, require_write=True)
                current_rev = archive["requirement_revision"]
                if expected_revision is not None and expected_revision != current_rev:
                    # 后到的一方：要求已被别人先改掉，不覆盖，按当前新要求重判受影响版本
                    results = self._recompute_all_protection(conn, archive_id)
                    summary = self._protection_summary(conn, archive_id)
                    self._audit(conn, archive_id, actor_id, "protection.rejudge",
                                {"expected_revision": expected_revision, "revision": current_rev,
                                 "required_domains": archive["required_domains"],
                                 "protected": summary["protected"], "unprotected": summary["unprotected"]})
                    return {"archive_id": archive_id, "required_domains": archive["required_domains"],
                            "verify_max_age_days": archive["verify_max_age_days"], "revision": current_rev,
                            "rejudged": True, "protected": summary["protected"], "unprotected": summary["unprotected"]}
                new_max_age = verify_max_age_days if verify_max_age_days is not None else archive["verify_max_age_days"]
                conn.execute(
                    "UPDATE archives SET required_domains=?,verify_max_age_days=?,requirement_revision=requirement_revision+1 WHERE id=?",
                    (required_domains, new_max_age, archive_id),
                )
                results = self._recompute_all_protection(conn, archive_id)
                summary = self._protection_summary(conn, archive_id)
                self._audit(conn, archive_id, actor_id, "protection.requirement",
                            {"required_domains": required_domains, "verify_max_age_days": new_max_age,
                             "revision": current_rev + 1, "protected": summary["protected"], "unprotected": summary["unprotected"]})
                return {"archive_id": archive_id, "required_domains": required_domains,
                        "verify_max_age_days": new_max_age, "revision": current_rev + 1,
                        "rejudged": False, "protected": summary["protected"], "unprotected": summary["unprotected"]}
            except Exception:
                conn.rollback()
                raise

    def recompute_protection(self, actor_id: str, archive_id: int, job_id: int | None = None, batch_size: int = 50) -> dict:
        """批量重算保护状态；中途失败后可凭 job_id 接着重试未完成的部分。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                archive = conn.execute("SELECT id FROM archives WHERE id=?", (archive_id,)).fetchone()
                if not archive:
                    raise BusinessError("档案不存在", 404, "not_found")
                self._access(conn, archive_id, actor, require_write=True)
                job = None
                if job_id is not None:
                    job = conn.execute("SELECT * FROM recompute_jobs WHERE id=? AND archive_id=?", (job_id, archive_id)).fetchone()
                    if not job:
                        raise BusinessError("重算任务不存在", 404, "not_found")
                else:
                    job = conn.execute(
                        "SELECT * FROM recompute_jobs WHERE archive_id=? AND status='running' ORDER BY id DESC LIMIT 1",
                        (archive_id,),
                    ).fetchone()
                if not job:
                    versions = conn.execute("SELECT id FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
                    cur = conn.execute(
                        "INSERT INTO recompute_jobs(archive_id,actor_id,status,total,created_at,updated_at) VALUES(?,?, 'running', ?,?,?)",
                        (archive_id, actor_id, len(versions), now(), now()),
                    )
                    job_id = cur.lastrowid
                    for v in versions:
                        conn.execute(
                            "INSERT INTO recompute_job_items(job_id,version_id,status) VALUES(?,?,'pending')",
                            (job_id, v["id"]),
                        )
                    job = {"id": job_id, "status": "running", "total": len(versions), "done": 0, "failed": 0}
                else:
                    job_id = job["id"]
                if job["status"] == "done":
                    return {"job_id": job_id, "status": "done", "total": job["total"],
                            "done": job["done"], "failed": job["failed"], "processed": 0}
                req = conn.execute(
                    "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (archive_id,)
                ).fetchone()
                items = conn.execute(
                    "SELECT * FROM recompute_job_items WHERE job_id=? AND status IN ('pending','failed') ORDER BY version_id LIMIT ?",
                    (job_id, batch_size),
                ).fetchall()
                processed = 0
                for item in items:
                    try:
                        conn.execute("SAVEPOINT recompute_item")
                        self._recompute_version_protection(conn, item["version_id"], req["required_domains"], req["verify_max_age_days"])
                        conn.execute("UPDATE recompute_job_items SET status='done',error=NULL WHERE job_id=? AND version_id=?",
                                     (job_id, item["version_id"]))
                        conn.execute("RELEASE SAVEPOINT recompute_item")
                        processed += 1
                    except Exception as exc:
                        conn.execute("ROLLBACK TO SAVEPOINT recompute_item")
                        conn.execute("UPDATE recompute_job_items SET status='failed',error=? WHERE job_id=? AND version_id=?",
                                     (str(exc)[:500], job_id, item["version_id"]))
                counts = conn.execute(
                    "SELECT SUM(status='done') AS done,SUM(status='failed') AS failed,"
                    "SUM(status IN ('pending','failed')) AS remaining FROM recompute_job_items WHERE job_id=?",
                    (job_id,),
                ).fetchone()
                status = "done" if counts["remaining"] == 0 else "running"
                conn.execute(
                    "UPDATE recompute_jobs SET status=?,done=?,failed=?,updated_at=? WHERE id=?",
                    (status, counts["done"], counts["failed"], now(), job_id),
                )
                if status == "done":
                    self._audit(conn, archive_id, actor_id, "protection.recompute",
                                {"job_id": job_id, "done": counts["done"], "failed": counts["failed"]})
                return {"job_id": job_id, "status": status, "total": job["total"],
                        "done": counts["done"], "failed": counts["failed"], "processed": processed}
            except Exception:
                conn.rollback()
                raise

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
                req = conn.execute(
                    "SELECT required_domains,verify_max_age_days FROM archives WHERE id=?", (source_version["archive_id"],)
                ).fetchone()
                protected, domains = self._recompute_version_protection(conn, target_version_id, req["required_domains"], req["verify_max_age_days"])
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip(),
                     "protected": protected, "domains": sorted(domains)},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id,
                        "target_path": converted["path"], "protected": protected, "domains": sorted(domains)}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,protected,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "protection": self._protection_summary(conn, archive_id),
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

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
                d.get("required_domains", DEFAULT_REQUIRED_DOMAINS),
                d.get("verify_max_age_days", DEFAULT_VERIFY_MAX_AGE_DAYS)))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "protection-requirements" and method == "POST":
            d = self._body()
            return self._send(200, store.set_protection_requirement(
                user, int(parts[2]), d.get("required_domains"), d.get("verify_max_age_days"), d.get("expected_revision")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "recompute-protection" and method == "POST":
            d = self._body()
            return self._send(200, store.recompute_protection(user, int(parts[2]), d.get("job_id"), int(d.get("batch_size", 50))))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", ""), d.get("domain")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-unreadable" and method == "POST":
            return self._send(200, store.simulate_unreadable(user, int(parts[2])))
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
