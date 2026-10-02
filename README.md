# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限、访问控制，以及**独立保管域保护要求**。

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

## 独立保管域与保护要求

- 档案声明需要几个**独立保管域**（`required_domains`，建档案时给出，默认 1）与校验有效期（`verify_valid_days`，默认 30 天，0 表示校验立即过期，便于测试）。
- 登记副本必须写明保管域 `domain`；同一保管域内无论多少份副本只算一份——放在同一间机房的两份副本遇到火灾会一起丢，不算冗余。
- 只有**健康且在有效期内**校验过的副本才计入；损坏、待确认、校验过期的副本不计入。
- 版本保护状态为 `protected` / `unprotected`：满足独立域数即受保护。
- 介质**读不出来**的副本记为 `unconfirmed`（待确认）：既不算损坏也不算健康，不触发降级、不参与计数；介质恢复后重新校验通过即回到健康。
- 修改保护要求会在同一事务内重算该档案的全部版本，版本详情与档案状态两个读口始终读到一致结果。
- 保护要求与校验并发提交时由写事务串行化：先写入的一方生效，后到的一方读取最新要求重新判定。
- 批量重算按版本逐个提交并记录到 `protection_recompute` 队列；中途失败后再次调用会跳过已完成项、从未完成部分继续。
- 旧数据库升级时，缺少保管域的副本统一归入**历史占位域** `__legacy__`（响应中 `legacy: true`），仍可正常查看与校验，也可再登记新保管域副本。

## 主要接口

- `POST /api/archives`：创建受限档案，可带 `required_domains`、`verify_valid_days`。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单、副本（含 `domain`/`fresh`）与 `protection` 判定块。
- `POST /api/versions/{id}/copies`：创建独立副本内容，**必须提供 `domain`**；同版本位置唯一。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复，并按最新要求重判保护状态。
- `POST /api/copies/{id}/unconfirmed`：副本介质读不出来时登记为待确认。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/archives/{id}/protection`：修改 `required_domains` / `verify_valid_days`，同事务重算受影响版本。
- `POST /api/protection/recompute` 与 `POST /api/archives/{id}/recompute`：批量重算（全局/单档案），支持断点续跑；`fail_after` 为测试用中断注入点。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态（含每版本保护判定）、重算积压数和审计记录。

档案路径拒绝绝对路径和 `..`；没有健康副本时版本标记为 `degraded`；所有变更与保护重算写入审计日志。
