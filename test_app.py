import base64
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, LEGACY_DOMAIN, PreservationStore


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive(
            "owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat(),
            required_domains=2,
        )
        self.store.grant("owner", self.archive["id"], "archivist", "write")
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": b64(self.raw)},
            {"path": "README.txt", "content_b64": b64(b"archive readme")},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a", "dc-east")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b", "dc-west")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _version_protection(self):
        return self.store.get_version("owner", self.version["id"])["protection"]

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            b64(b"<html><body><p>1</p></body></html>"),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a", "dc-north")
        self.assertEqual(ctx.exception.code, "copy_exists")

    def test_independent_domains_same_domain_counts_once(self):
        # 两个独立保管域：满足 required_domains=2。
        self.assertEqual(self._version_protection()["protection_state"], "protected")
        # 第三份副本与 copy1 同机房（同保管域），遇到火灾一起丢，不增加独立域数。
        self.store.add_copy("owner", self.version["id"], "offline-disk-c", "dc-east")
        p = self._version_protection()
        self.assertEqual(p["satisfied_domains"], 2)
        self.assertEqual(p["protection_state"], "protected")
        # copy 登记必须写明保管域。
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-d", "")
        self.assertEqual(ctx.exception.code, "domain_required")

    def test_expired_verification_not_counted(self):
        # 校验有效期设为 0 天：所有既有校验立刻过期，没有域再计入；即便立刻重校，0 天有效期下仍然过期。
        res = self.store.set_protection_requirement("owner", self.archive["id"], verify_valid_days=0)
        self.assertEqual(res["affected_versions"][0]["protection_state"], "unprotected")
        detail = self.store.get_version("owner", self.version["id"])
        self.assertEqual(detail["protection"]["satisfied_domains"], 0)
        self.assertTrue(all(c["fresh"] is False for c in detail["copies"]))
        self.store.verify_copy("owner", self.copy1)
        self.store.verify_copy("owner", self.copy2)
        detail = self.store.get_version("owner", self.version["id"])
        self.assertEqual(detail["protection"]["satisfied_domains"], 0)
        # 把有效期恢复为 30 天：刚刚完成的校验重新变新鲜，两个独立域恢复计数。
        res = self.store.set_protection_requirement("owner", self.archive["id"], verify_valid_days=30)
        self.assertEqual(res["affected_versions"][0]["protection_state"], "protected")
        self.assertEqual(self._version_protection()["satisfied_domains"], 2)

    def test_requirement_change_recomputes_and_views_stay_consistent(self):
        self.store.set_protection_requirement("owner", self.archive["id"], required_domains=3)
        detail = self.store.get_version("owner", self.version["id"])
        status = self.store.archive_status("owner", self.archive["id"])
        status_v = next(v for v in status["versions"] if v["id"] == self.version["id"])
        self.assertEqual(detail["version"]["protection_state"], "unprotected")
        self.assertEqual(detail["protection"]["protection_state"], "unprotected")
        self.assertEqual(status_v["protection_state"], "unprotected")
        self.assertEqual(status_v["satisfied_domains"], 2)
        # 降回 1 个域要求后立刻恢复受保护，两个读口结果一致。
        self.store.set_protection_requirement("owner", self.archive["id"], required_domains=1)
        detail = self.store.get_version("owner", self.version["id"])
        status = self.store.archive_status("owner", self.archive["id"])
        status_v = next(v for v in status["versions"] if v["id"] == self.version["id"])
        self.assertEqual(detail["version"]["protection_state"], "protected")
        self.assertEqual(status_v["protection_state"], "protected")

    def test_unreadable_copy_is_unconfirmed_not_corrupt_nor_healthy(self):
        # copy2 所在介质读不出来：待确认，不参与域计数，版本因此少一个独立域。
        mark = self.store.mark_unreadable("archivist", self.copy2, "介质离线无法挂载")
        self.assertEqual(mark["state"], "unconfirmed")
        detail = self.store.get_version("owner", self.version["id"])
        c2 = next(c for c in detail["copies"] if c["id"] == self.copy2)
        self.assertEqual(c2["state"], "unconfirmed")
        self.assertFalse(c2["fresh"])
        # 版本健康状态（哈希层面）不受影响：仍 verified；保护层面 unprotected。
        self.assertEqual(detail["version"]["state"], "verified")
        self.assertEqual(detail["protection"]["protection_state"], "unprotected")
        self.assertEqual(detail["protection"]["satisfied_domains"], 1)
        # 待确认副本不算损坏：不会触发 degraded，也没有损坏路径。
        status = self.store.archive_status("owner", self.archive["id"])
        v = next(x for x in status["versions"] if x["id"] == self.version["id"])
        self.assertEqual(v["state"], "verified")
        # 介质恢复后重新校验，通过即回到健康并重新计入。
        verify = self.store.verify_copy("owner", self.copy2)
        self.assertEqual(verify["state"], "healthy")
        self.assertEqual(verify["protection"]["protection_state"], "protected")

    def test_corrupt_copy_excludes_domain_and_repair_restores(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        verify = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(verify["state"], "healthy")
        self.assertTrue(verify["repaired"])
        self.assertEqual(verify["protection"]["protection_state"], "protected")
        # 没有健康捐赠方时，损坏副本的域被剔除且版本 degraded。
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        self.store.simulate_corruption("owner", self.copy2, "records/one.xml")
        r1 = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(r1["state"], "corrupt")
        r2 = self.store.verify_copy("owner", self.copy2)
        self.assertEqual(r2["state"], "corrupt")
        self.assertEqual(r2["protection"]["protection_state"], "unprotected")
        self.assertEqual(r2["protection"]["satisfied_domains"], 0)

    def test_batch_recompute_resumes_after_failure(self):
        # 制造第二个版本，并把两个版本都重新排进重算队列。
        v2 = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "second.txt", "content_b64": b64(b"v2")},
        ])["id"]
        with self.store.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO protection_recompute(version_id,status) VALUES(?,'pending')", (self.version["id"],))
            conn.execute("INSERT OR REPLACE INTO protection_recompute(version_id,status) VALUES(?,'pending')", (v2,))
        # 第一批在处理 1 个后注入失败，已提交的进度保留。
        with self.assertRaises(BusinessError) as ctx:
            self.store.recompute_protection("owner", self.archive["id"], fail_after=1)
        self.assertEqual(ctx.exception.code, "recompute_interrupted")
        with self.store.connect() as conn:
            done = conn.execute("SELECT COUNT(*) FROM protection_recompute WHERE status='done'").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM protection_recompute WHERE status='pending'").fetchone()[0]
        self.assertGreaterEqual(done, 1)
        self.assertEqual(pending, 1)
        # 接着重试没做完的部分。
        again = self.store.recompute_protection("owner", self.archive["id"])
        self.assertTrue(again["complete"])
        self.assertEqual(again["remaining"], 0)

    def test_concurrent_requirement_and_verify_first_writer_wins(self):
        outcomes = []
        barrier = threading.Barrier(2)

        def change_requirement():
            barrier.wait()
            outcomes.append(("set3", self.store.set_protection_requirement(
                "owner", self.archive["id"], required_domains=3)["affected_versions"][0]["protection_state"]))

        def verify():
            barrier.wait()
            outcomes.append(("verify", self.store.verify_copy("owner", self.copy1)["protection"]["protection_state"]))

        t1, t2 = threading.Thread(target=change_requirement), threading.Thread(target=verify)
        t1.start(); t2.start(); t1.join(); t2.join()
        # 无报错（没有 SQLITE_BUSY 500），且最终状态以最新要求为准：3 域要求下未受保护。
        final = self.store.get_version("owner", self.version["id"])["protection"]["protection_state"]
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertEqual(final, "unprotected")
        self.assertEqual(status["versions"][0]["protection_state"], "unprotected")
        self.assertEqual(len(outcomes), 2)

    def test_legacy_copies_get_placeholder_domain_and_remain_usable(self):
        legacy_db = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(legacy_db)
        conn.executescript(
            """
            CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL);
            CREATE TABLE archives(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,owner_id TEXT,
                retention_until TEXT,restricted INTEGER DEFAULT 1,created_at TEXT);
            CREATE TABLE archive_members(archive_id INTEGER,user_id TEXT,permission TEXT,PRIMARY KEY(archive_id,user_id));
            CREATE TABLE archive_versions(id INTEGER PRIMARY KEY AUTOINCREMENT,archive_id INTEGER,version INTEGER,
                state TEXT DEFAULT 'verified',created_by TEXT,created_at TEXT,UNIQUE(archive_id,version));
            CREATE TABLE archive_files(id INTEGER PRIMARY KEY AUTOINCREMENT,version_id INTEGER,path TEXT,
                sha256 TEXT,size INTEGER,content BLOB,UNIQUE(version_id,path));
            CREATE TABLE copies(id INTEGER PRIMARY KEY AUTOINCREMENT,version_id INTEGER,location TEXT,
                state TEXT DEFAULT 'healthy',created_at TEXT,last_verified_at TEXT,UNIQUE(version_id,location));
            CREATE TABLE copy_files(copy_id INTEGER,path TEXT,sha256 TEXT,size INTEGER,content BLOB,PRIMARY KEY(copy_id,path));
            CREATE TABLE migrations(id INTEGER PRIMARY KEY AUTOINCREMENT,source_version_id INTEGER,target_version_id INTEGER UNIQUE,
                source_path TEXT,target_path TEXT,target_format TEXT,actor_id TEXT,created_at TEXT);
            CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,archive_id INTEGER,actor_id TEXT,
                action TEXT,detail TEXT,created_at TEXT);
            INSERT INTO users VALUES('owner','负责人','owner');
            INSERT INTO archives VALUES(1,'旧档案','owner','2099-01-01',1,'2026-01-01');
            INSERT INTO archive_versions VALUES(1,1,1,'verified','owner','2026-01-01');
            INSERT INTO archive_files(id,version_id,path,sha256,size,content)
            VALUES(1,1,'a.txt','pending',1,X'61');
            INSERT INTO copies VALUES(1,1,'旧磁带','healthy','2026-01-01','2026-01-01');
            INSERT INTO copy_files VALUES(1,'a.txt','pending',1,X'61');
            """
        )
        conn.execute("UPDATE archive_files SET sha256=? WHERE id=1", (hashlib.sha256(b"a").hexdigest(),))
        conn.execute("UPDATE copy_files SET sha256=? WHERE copy_id=1", (hashlib.sha256(b"a").hexdigest(),))
        conn.commit()
        conn.close()

        legacy_store = PreservationStore(legacy_db)
        legacy_store.seed()  # 触发升级：无域副本归入历史占位域并重算
        detail = legacy_store.get_version("owner", 1)
        self.assertEqual(detail["copies"][0]["domain"], LEGACY_DOMAIN)
        self.assertTrue(detail["copies"][0]["legacy"])
        self.assertEqual(detail["protection"]["required_domains"], 1)
        # 历史占位域副本仍可校验；校验刚通过、在默认 30 天有效期内，故视为受保护。
        verify = legacy_store.verify_copy("owner", 1)
        self.assertEqual(verify["state"], "healthy")
        self.assertEqual(verify["protection"]["protection_state"], "protected")
        # 也可以登记新保管域副本。
        created = legacy_store.add_copy("owner", 1, "新机房机柜", "dc-new")
        self.assertEqual(created["protection"]["satisfied_domains"], 2)

    def test_write_permission_required_for_requirement_and_batch(self):
        self.store.grant("owner", self.archive["id"], "archivist", "read")
        with self.assertRaises(BusinessError) as ctx:
            self.store.set_protection_requirement("archivist", self.archive["id"], required_domains=5)
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.recompute_protection("archivist", self.archive["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.set_protection_requirement("owner", self.archive["id"])
        self.assertEqual(ctx.exception.code, "no_requirement_change")


if __name__ == "__main__":
    unittest.main()
