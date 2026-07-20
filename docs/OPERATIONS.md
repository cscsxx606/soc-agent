# SOC Agent 运维手册

> 本文档提供 SOC Multi-Agent 系统的日常运维、备份恢复、监控告警、故障排查标准流程。

## 📑 目录

- [1. 部署拓扑](#1-部署拓扑)
- [2. 启动 / 停止](#2-启动--停止)
- [3. 配置管理](#3-配置管理)
- [4. 数据库维护](#4-数据库维护)
- [5. 日志管理](#5-日志管理)
- [6. 监控告警](#6-监控告警)
- [7. 备份与恢复](#7-备份与恢复)
- [8. 升级流程](#8-升级流程)
- [9. 故障排查](#9-故障排查)
- [10. 应急处理 SOP](#10-应急处理-sop)

---

## 1. 部署拓扑

### 标准 1 机部署（中小规模）

```
┌─────────────────────────────────────┐
│  ECS (4C8G+ / 阿里云)               │
│  ┌────────────────────────────────┐ │
│  │  Nginx (SSL: 443/80)           │ │
│  │  /opt/soc-agent/                 │ │
│  │  ├─ web/admin (Flask+Gunicorn)  │ │
│  │  │  port 8889 (内部)            │ │
│  │  ├─ edr/app (Flask+Gunicorn)    │ │
│  │  │  port 9000 (内部)            │ │
│  │  ├─ data/admin.db (SQLite WAL)  │ │
│  │  └─ logs/                       │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### 高可用部署（多机）

```
┌────────────────┐   ┌────────────────┐
│  ECS-A 主控    │   │  ECS-B 备用    │
│  Admin + EDR   │   │  Admin + EDR  │
│  SQLite 同步   │   │  同步 (repl)  │
└────────┬───────┘   └────────┬───────┘
         │        共享存储 / db sync
┌────────▼──────────────────▼───────┐
│  PostgreSQL / MySQL (主从)        │
└────────────────────────────────────┘
```

---

## 2. 启动 / 停止

### 一键启动

```bash
# 启动完整服务（Web + EDR）
make all

# 或分别启动
make web      # Web 管理后台 (8889)
make edr      # EDR 探针服务 (9000)
```

### 生产环境启动（systemd）

```bash
# 1. 安装 systemd 单元
sudo cp deploy/soc-admin.service /etc/systemd/system/
sudo cp deploy/soc-edr.service /etc/systemd/system/

# 2. 启用并启动
sudo systemctl daemon-reload
sudo systemctl enable --now soc-admin soc-edr

# 3. 验证
systemctl status soc-admin
curl http://localhost:8889/health
```

### Docker 启动（推荐小规模）

```bash
# 启动容器
make docker-up

# 查看状态
docker ps | grep soc-

# 查看日志
docker logs soc-server
docker logs soc-edr

# 停止
make docker-down
```

### 优雅停止

```bash
# 停止 systemd 服务
sudo systemctl stop soc-admin

# 停止 Docker
docker stop soc-server soc-edr

# 强制清理
pkill -9 -f "gunicorn.*soc"
```

---

## 3. 配置管理

### 配置文件位置

| 路径 | 用途 |
|---|---|
| `/opt/soc-agent/config/.env` | 运行时配置（API key 等敏感信息）|
| `/etc/systemd/system/soc-admin.service` | systemd 服务单元 |
| `/etc/nginx/conf.d/soc-admin.conf` | Nginx 反代配置 |
| `/opt/soc-agent/data/admin.db` | SQLite 数据库 |

### 配置变更流程

1. **修改前备份**:
   ```bash
   cp /opt/soc-agent/config/.env /opt/soc-agent/config/.env.bak.$(date +%Y%m%d)
   ```
2. **修改 .env**:
   ```bash
   vim /opt/soc-agent/config/.env
   ```
3. **重启生效** (不需要 reconfigure):
   ```bash
   sudo systemctl restart soc-admin
   ```
4. **验证**:
   ```bash
   curl http://localhost:8889/health
   ```

### 查看配置中心状态

Admin API: `GET /api/admin/config-center/health`

```json
{
  "status": "warning",
  "issues": [
    {"key": "api.deepseek_key", "severity": "high", "status": "missing"}
  ]
}
```

---

## 4. 数据库维护

### 数据库类型

- **生产**: SQLite (WAL 模式) - `/opt/soc-agent/data/admin.db`
- **不建议生产用**: PostgreSQL/MySQL（迁移需要时间）

### 日常巡检

```bash
# 1. 数据库大小
du -sh /opt/soc-agent/data/

# 2. WAL 文件大小（监控）
ls -lh /opt/soc-agent/data/admin.db*

# 3. 表行数
sqlite3 /opt/soc-agent/data/admin.db "SELECT 'incidents', COUNT(*) FROM incidents UNION ALL SELECT 'audit_logs', COUNT(*) FROM audit_logs;"

# 4. 索引健康
sqlite3 /opt/soc-agent/data/admin.db "ANALYZE; SELECT name FROM sqlite_master WHERE type='index';"
```

### 清理过期数据

#### 保留策略

| 表 | 保留期 | 操作频率 |
|---|---|---|
| `incidents` | 永久 | 不删 |
| `audit_logs` | 90 天 | 每天一次 |
| `scan_results` | 30 天 | 每天一次 |
| `notifications_log` | 30 天 | 每天一次 |

#### 清理脚本（crontab）

```bash
# 每天 03:00 清理过期数据
0 3 * * * sqlite3 /opt/soc-agent/data/admin.db "DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days'); DELETE FROM scan_results WHERE created_at < datetime('now', '-30 days'); VACUUM;"
```

### 性能优化

```bash
# 定期 VACUUM（释放空间）
sqlite3 /opt/soc-agent/data/admin.db "VACUUM;"

# 重建索引
sqlite3 /opt/soc-agent/data/admin.db "REINDEX;"
```

---

## 5. 日志管理

### 日志位置

| 路径 | 内容 |
|---|---|
| `/opt/soc-agent/logs/gunicorn.log` | Web Gunicorn 访问日志 |
| `/opt/soc-agent/logs/gunicorn.error.log` | Web Gunicorn 错误日志 |
| `/var/log/gitlab/nginx/gitlab_access.log` | GitLab nginx（如果有）|
| `journalctl -u soc-admin` | systemd 日志 |

### 日志轮转

- **自动**: Gunicorn 默认 7 天清理（`start.py` 中 `rotate_logs()`）
- **手动清理**:
  ```bash
  # 仅保留最近 3 天
  find /opt/soc-agent/logs/ -name "*.log" -mtime +3 -delete
  find /opt/soc-agent/logs/ -name "*.log.gz" -mtime +14 -delete
  ```

### 日志等级

`.env` 中 `LOG_LEVEL=INFO`:
- `DEBUG`: 开发环境
- `INFO`: 生产环境（默认）
- `WARNING`: 减少日志
- `ERROR`: 只看错误

---

## 6. 监控告警

### Prometheus 集成

#### 暴露指标

```
GET http://<host>:8889/metrics
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

#### 关键指标

| 指标 | 类型 | 告警阈值 |
|---|---|---|
| `soc_http_requests_total` | Counter | - |
| `soc_http_request_duration_seconds` | Histogram | p99 > 2s |
| `soc_http_requests_in_flight` | Gauge | > 100 |
| `soc_system_cpu_percent` | Gauge | > 85% |
| `soc_system_memory_percent` | Gauge | > 90% |
| `soc_system_disk_percent` | Gauge | > 90% |

#### Prometheus 抓取配置

```yaml
scrape_configs:
  - job_name: 'soc-admin'
    static_configs:
      - targets: ['<host>:8889']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

#### Grafana 面板建议

- HTTP 请求量（按 endpoint）
- HTTP 请求 P99 延迟
- 系统 CPU/内存使用率
- 活跃请求数
- Incident 事件总数（按优先级）

### 健康检查

```bash
# 探测端点（无鉴权）
curl http://<host>:8889/health

# 返回 200 + {"status":"ok","db":"ok","service":"soc-admin"}
```

---

## 7. 备份与恢复

### 自动备份

`start.py` 已内置每日 SQLite 备份到 `backups/admin_YYYYMMDD.db`，保留 30 天。

**手动备份**:
```bash
# 创建备份
cp /opt/soc-agent/data/admin.db /opt/soc-agent/backups/admin_$(date +%Y%m%d_%H%M%S).db

# 查看备份列表
ls -la /opt/soc-agent/backups/

# 清理 30 天前
find /opt/soc-agent/backups/ -name "admin_*.db" -mtime +30 -delete
```

### 配置备份

```bash
# .env (脱敏后备份)
grep -v "^API_KEY=" /opt/soc-agent/config/.env > /tmp/soc-env-template-$(date +%Y%m%d).txt

# systemd 单元
cp /etc/systemd/system/soc-admin.service /backup/soc-admin.service.$(date +%Y%m%d)
```

### 恢复流程

1. **停止服务**:
   ```bash
   sudo systemctl stop soc-admin
   ```
2. **备份当前**:
   ```bash
   mv /opt/soc-agent/data/admin.db /opt/soc-agent/data/admin.db.broken
   ```
3. **恢复数据库**:
   ```bash
   cp /opt/soc-agent/backups/admin_20260720_120000.db /opt/soc-agent/data/admin.db
   chown socadmin:socadmin /opt/soc-agent/data/admin.db
   chmod 600 /opt/soc-agent/data/admin.db
   ```
4. **重启服务**:
   ```bash
   sudo systemctl start soc-admin
   ```
5. **验证**:
   ```bash
   curl http://localhost:8889/health
   ```

---

## 8. 升级流程

### 升级前检查

1. **备份**: 包括数据库 + 配置 + 当前代码
2. **确认测试通过**: `make test` 必须全过
3. **CHANGELOG**: 查看 version diff 和 已知问题

### 升级步骤

```bash
# 1. 拉取最新代码
cd /opt/soc-agent
git pull origin main

# 2. 备份
make backup-db
cp -r config .config.bak.$(date +%Y%m%d)

# 3. 装新依赖
make install

# 4. 数据库迁移（如有）
# 查看 data/ 下 migration 文件，运行 sqlite3 <migration.sql>

# 5. 重启服务
sudo systemctl restart soc-admin

# 6. 验证
curl http://localhost:8889/health
curl http://localhost:8889/api/version
make test

# 7. 5 分钟观察
tail -f /opt/soc-agent/logs/gunicorn.log
```

### 回滚流程

```bash
# 1. 停止服务
sudo systemctl stop soc-admin

# 2. 切回旧代码
git checkout <previous-version-tag>

# 3. 还原数据库（必要时）
cp /opt/soc-agent/backups/admin_<time>.db /opt/soc-agent/data/admin.db

# 4. 重启
sudo systemctl start soc-admin
```

---

## 9. 故障排查

### 故障 1: Web 控制台 502/503

**现象**: `curl http://<host>:8889/health` 返回 502

**排查步骤**:
```bash
# 1. 服务进程在吗？
systemctl status soc-admin
ps -ef | grep gunicorn | grep soc

# 2. 端口监听？
ss -tlnp | grep 8889

# 3. 最近错误日志
journalctl -u soc-admin -n 50

# 4. Gunicorn 错误日志
tail -50 /opt/soc-agent/logs/gunicorn.error.log

# 5. 数据库连接
sqlite3 /opt/soc-agent/data/admin.db "SELECT 1"
```

**常见根因**:
- 端口被占用: `lsof -i :8889`
- 数据库锁定: `rm /opt/soc-agent/data/admin.db.init.lock`
- 磁盘满: `df -h`

### 故障 2: API 响应慢

**排查**:
```bash
# 1. 看 P99 延迟
curl -s http://localhost:8889/metrics | grep duration_seconds_bucket

# 2. 查数据库
sqlite3 /opt/soc-agent/data/admin.db "EXPLAIN QUERY PLAN SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 200;"

# 3. 加索引（如缺失）
sqlite3 /opt/soc-agent/data/admin.db "CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp DESC);"
```

### 故障 3: EDR 探针掉线

**排查**:
```bash
# 1. EDR 服务在吗？
systemctl status soc-edr

# 2. 探针注册列表
curl http://localhost:9000/api/hosts/list

# 3. 网络连通性
tcpdump -i any port 9000

# 4. 探针端
osqueryd --tls_hostname=soc.example.com:9000 --enroll_secret_path=/etc/osquery/enroll_secret --debug
```

### 故障 4: 数据库无法写入

**排查**:
```bash
# 1. 磁盘空间
df -h /opt/soc-agent

# 2. SQLite 完整性
sqlite3 /opt/soc-agent/data/admin.db "PRAGMA integrity_check;"

# 3. 修复（谨慎使用！）
sqlite3 /opt/soc-agent/data/admin.db ".recover" > /tmp/recovered.sql
sqlite3 /opt/soc-agent/data/admin.db ".read /tmp/recovered.sql"
```

---

## 10. 应急处理 SOP

### SOP 1: 服务完全挂掉

**触发**: 健康检查连续 3 次失败

**操作**:
1. `systemctl status soc-admin` —— 看进程
2. `journalctl -u soc-admin -n 100` —— 看错误
3. 若是 Gunicorn 死掉: `systemctl restart soc-admin`
4. 若是数据库 lock: 删 `.init.lock` 重启
5. 若是磁盘满: 紧急 `rm logs/*.log.gz` + cleanup
6. 升级: 切到备用 ECS

### SOP 2: 数据损坏

**触发**: `PRAGMA integrity_check` 返回 `not ok`

**操作**:
1. **立即**停止写入: `systemctl stop soc-admin`
2. 备份当前损坏 DB
3. 尝试 restore 最近一次 backup
4. 若 backup 也坏，调 `.recover` 命令
5. 恢复后 `VACUUM` + 验证

### SOP 3: 配置文件泄露

**触发**: 在 git 公网或共享环境发现 .env

**操作**:
1. 立即重置所有 API keys（DeepSeek/Kimi/飞书/Slack 等）
2. 删除 git history（`git filter-branch` 或 BFG Repo-Cleaner）
3. 强制重置数据库（因为 secret 存了一些）
4. 重新部署 .env.example 给用户

### SOP 4: 性能急剧下降

**触发**: P99 > 5s 或 CPU > 95% 持续 5 分钟

**操作**:
1. 看 Grafana：哪个 endpoint 最慢
2. 查数据库: `EXPLAIN QUERY PLAN` 分析
3. 临时缓解: 限制请求 `make web` 重启成单 worker
4. 长期: 加缓存层 + 拆分读写

---

## 附录: 常用命令速查

```bash
# === 服务管理 ===
make help                              # 命令清单
make test                              # 跑测试
make web                               # 启动 Admin
make edr                               # 启动 EDR
make docker-up                         # Docker 启动
make backup-db                         # 备份数据库

# === 监控 ===
curl http://localhost:8889/health      # 健康检查
curl http://localhost:8889/metrics     # Prometheus
curl http://localhost:8889/api/version # 版本
make logs-tail                         # 日志跟踪

# === 数据库 ===
sqlite3 /opt/soc-agent/data/admin.db   # 命令行 DB
                                       # > .tables 看表
                                       # > SELECT COUNT(*) FROM incidents;
                                       # > .exit

# === GitLab ===
cd /opt/gitlab && gitlab-ctl status
```

---

## 联系

- 🐛 Bug 报告: <repo>/issues
- 📧 邮件: yunwei@example.com
- 📞 紧急: 1xxx-xxx-xxxx

---

_文档版本: v1.0 - 2026-07-20_
_与代码同步: commit `b7aa90b` (E2 #10)_
