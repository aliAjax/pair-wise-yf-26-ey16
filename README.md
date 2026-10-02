# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。副本按独立保管域计数，同一机房/域的副本再多也只算一份；校验过期或读不出来的副本不计入保护。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 保管域与保护状态

- 档案创建时可声明 `required_domains`（需要几个独立保管域，默认 1）和 `verify_max_age_days`（校验有效期，默认 365 天）。
- 副本登记（`POST /api/versions/{id}/copies`）时用 `domain` 写明保管域；同一保管域只算一份。
- 只有状态为 `healthy` 且 `last_verified_at` 未过期的副本才计入保护；损坏、降级、待确认、过期的副本都不计入。
- 保护要求一变，受影响版本的保护状态立即重算；`GET /api/versions/{id}` 与 `GET /api/archives/{id}/status` 读到的结果一致。
- 并发提交保护要求时，先写入的一方生效；后到的一方携带旧的 `expected_revision`，服务不覆盖，而是按当前新要求重判并返回 `rejudged: true`。
- 批量重算保护状态可分批进行，中途失败后用返回的 `job_id` 接着重试未完成的部分。
- 读不出来的副本校验后标记为 `pending`（待确认），不算损坏也不算健康；可通过 `simulate-unreadable` 演示。
- 旧数据升级时，没有保管域的副本统一归入历史占位域 `__legacy__`，升级后仍可查看和校验。

## 主要接口

- `POST /api/archives`：创建受限档案，可带 `required_domains`、`verify_max_age_days`。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单、副本状态（含保管域）和保护状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容，带 `domain` 保管域。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复；读不出来标记为待确认。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/copies/{id}/simulate-unreadable`：演示/测试介质读不出来（待确认），仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `POST /api/archives/{id}/protection-requirements`：声明保护要求（`required_domains`、`verify_max_age_days`、`expected_revision`）。
- `POST /api/archives/{id}/recompute-protection`：批量重算保护状态，可带 `job_id` 续跑。
- `GET /api/archives/{id}/status`：保留期限、版本状态、保护状态和审计记录。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
