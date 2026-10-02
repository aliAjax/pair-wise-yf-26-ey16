import base64
import hashlib
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


def _raw(payload: bytes = b"<record><id>1</id></record>"):
    return base64.b64encode(payload).decode()


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
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
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")


class ProtectionDomainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive(
            "owner", "多域保护档案", (date.today() + timedelta(days=3650)).isoformat(),
            required_domains=2, verify_max_age_days=365,
        )
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "a.xml", "content_b64": _raw()},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def _add(self, location, domain):
        return self.store.add_copy("owner", self.version["id"], location, domain)

    def test_same_domain_counts_as_one_copy(self):
        self._add("disk-a1", "room-a")
        self._add("disk-a2", "room-a")  # 同域副本再多也只算一份
        result = self.store.get_version("owner", self.version["id"])
        self.assertFalse(result["version"]["protected"])
        self.assertEqual(result["copies"][0]["domain"], "room-a")

    def test_distinct_domains_protect(self):
        self._add("disk-a", "room-a")
        created = self._add("disk-b", "room-b")
        self.assertTrue(created["protected"])
        self.assertEqual(set(created["domains"]), {"room-a", "room-b"})
        # 再来一个同域副本，保护状态不变
        extra = self._add("disk-a2", "room-a")
        self.assertTrue(extra["protected"])

    def test_expired_verification_does_not_count(self):
        a = self._add("disk-a", "room-a")
        b = self._add("disk-b", "room-b")
        self.assertTrue(b["protected"])
        # 把校验有效期设为 0 天，并把副本校验时间拨到过去
        self.store.set_protection_requirement("owner", self.archive["id"], 2, verify_max_age_days=0)
        with self.store.connect() as conn:
            conn.execute("UPDATE copies SET last_verified_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", a["id"]))
            conn.execute("UPDATE copies SET last_verified_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", b["id"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertEqual(status["protection"]["required_domains"], 2)
        self.assertEqual(status["protection"]["unprotected"], 1)
        self.assertFalse(status["versions"][0]["protected"])
        # 恢复长有效期后重新校验，又受保护
        self.store.set_protection_requirement("owner", self.archive["id"], 2, verify_max_age_days=3650)
        self.store.verify_copy("owner", a["id"])
        self.store.verify_copy("owner", b["id"])
        self.assertTrue(self.store.get_version("owner", self.version["id"])["version"]["protected"])

    def test_unreadable_copy_is_pending_not_corrupt(self):
        a = self._add("disk-a", "room-a")
        b = self._add("disk-b", "room-b")
        self.assertTrue(b["protected"])
        # 读不出来 -> 待确认，不算损坏也不算健康，该域不再计入
        self.store.simulate_unreadable("owner", a["id"])
        result = self.store.verify_copy("owner", a["id"])
        self.assertEqual(result["state"], "pending")
        self.assertEqual(result["unreadable_paths"], ["a.xml"])
        self.assertFalse(result["protected"])
        detail = self.store.get_version("owner", self.version["id"])
        self.assertEqual(detail["copies"][0]["state"], "pending")
        self.assertEqual(detail["version"]["state"], "verified")  # 待确认不标记为损坏降级

    def test_legacy_copies_get_placeholder_domain(self):
        # 直接插入一个没有保管域的旧副本（含副本文件）
        with self.store.connect() as conn:
            cur = conn.execute(
                "INSERT INTO copies(version_id,location,state,created_at,last_verified_at) VALUES(?,?, 'healthy',?,?)",
                (self.version["id"], "old-disk", "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00"),
            )
            copy_id = cur.lastrowid
            conn.execute(
                "INSERT INTO copy_files(copy_id,path,sha256,size,content) SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?",
                (copy_id, self.version["id"]),
            )
        # 重新初始化（升级迁移）
        self.store.init_schema()
        detail = self.store.get_version("owner", self.version["id"])
        legacy = next(c for c in detail["copies"] if c["id"] == copy_id)
        self.assertEqual(legacy["domain"], "__legacy__")
        # 升级后仍能查看和校验
        result = self.store.verify_copy("owner", copy_id)
        self.assertEqual(result["state"], "healthy")

    def test_requirement_change_recomputes_and_reads_consistent(self):
        self._add("disk-a", "room-a")
        self._add("disk-b", "room-b")
        self.assertTrue(self.store.get_version("owner", self.version["id"])["version"]["protected"])
        # 保护要求一变，受影响版本立即重算
        changed = self.store.set_protection_requirement("owner", self.archive["id"], 3)
        self.assertFalse(changed["protected"])
        detail = self.store.get_version("owner", self.version["id"])
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertEqual(detail["version"]["protected"], status["versions"][0]["protected"])
        self.assertEqual(status["protection"]["revision"], 2)

    def test_stale_requirement_rejudges_instead_of_overwriting(self):
        self._add("disk-a", "room-a")
        self._add("disk-b", "room-b")
        first = self.store.set_protection_requirement("owner", self.archive["id"], 3, expected_revision=1)
        self.assertFalse(first["rejudged"])
        self.assertEqual(first["revision"], 2)
        # 后到的一方拿着旧版本号提交：不覆盖，按新要求重判
        stale = self.store.set_protection_requirement("owner", self.archive["id"], 5, expected_revision=1)
        self.assertTrue(stale["rejudged"])
        self.assertEqual(stale["revision"], 2)
        self.assertEqual(stale["required_domains"], 3)

    def test_recompute_job_can_resume(self):
        v2 = self.store.ingest_version("owner", self.archive["id"], [{"path": "b.xml", "content_b64": _raw(b"v2")}])
        self._add("disk-a", "room-a")
        self.store.set_protection_requirement("owner", self.archive["id"], 3)
        # 小批量逐次重算，模拟中途失败后接着重试
        job = self.store.recompute_protection("owner", self.archive["id"], batch_size=1)
        self.assertEqual(job["status"], "running")
        self.assertEqual(job["processed"], 1)
        job = self.store.recompute_protection("owner", self.archive["id"], job_id=job["job_id"], batch_size=1)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["done"], 2)
        # 重算结果与实时读取一致
        status = self.store.archive_status("owner", self.archive["id"])
        for v in status["versions"]:
            self.assertEqual(v["protected"], self.store.get_version("owner", v["id"])["version"]["protected"])

    def test_concurrent_requirement_writes_first_wins(self):
        self._add("disk-a", "room-a")
        self._add("disk-b", "room-b")
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def change(required):
            try:
                barrier.wait()
                results.append(self.store.set_protection_requirement(
                    "owner", self.archive["id"], required, expected_revision=1))
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=change, args=(3,))
        t2 = threading.Thread(target=change, args=(4,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertFalse(errors)
        rejudged = [r for r in results if r["rejudged"]]
        applied = [r for r in results if not r["rejudged"]]
        self.assertEqual(len(applied), 1)
        self.assertEqual(len(rejudged), 1)
        # 先写入的一方生效，后到的按新要求重判（不覆盖）
        self.assertIn(applied[0]["required_domains"], (3, 4))
        self.assertEqual(rejudged[0]["required_domains"], applied[0]["required_domains"])
        self.assertEqual(self.store.archive_status("owner", self.archive["id"])["protection"]["required_domains"],
                         applied[0]["required_domains"])


if __name__ == "__main__":
    unittest.main()
