# EDR 探针部署指南

## 架构说明

```
┌─────────────────┐     Osquery TLS      ┌──────────────────┐
│  被管理主机      │ ◄──────────────────► │  soc-edr (9000)  │
│  (osqueryd)     │     enrollment/log    │  Osquery 管理     │
│                 │     config/query      │                  │
└─────────────────┘                       └────────┬─────────┘
                                                   │ API
                                                   ▼
                                          ┌──────────────────┐
                                          │  soc-server      │
                                          │  (8889)          │
                                          │  管理后台         │
                                          └──────────────────┘
```

## 前置条件

1. Docker 已安装
2. 被管理主机已安装 osquery （`brew install osquery` 或 `apt install osquery`）

## 启动 EDR 服务

```bash
# 一键启动（SOC 管理后台 + EDR 探针管理）
docker-compose up -d

# 单独启动 EDR
docker-compose up -d soc-edr
```

## 在被管理主机上部署 Osquery 探针

### Linux (Debian/Ubuntu)

```bash
# 1. 安装 osquery
curl -L https://pkg.osquery.io/deb/osquery_5.14.1_linux.amd64.deb -o /tmp/osquery.deb
sudo dpkg -i /tmp/osquery.deb

# 2. 配置 enroll secret
echo "your-edr-secret-here" | sudo tee /etc/osquery/enroll_secret

# 3. 配置 osquery.flags
sudo tee /etc/osquery/osquery.flags <<EOF
--tls_hostname=YOUR_SERVER_IP:9000
--tls_enroll_secret=/etc/osquery/enroll_secret
--enroll_secret_path=/etc/osquery/enroll_secret
--host_identifier=hostname
--verbose=false
--logger_tls_endpoint=/api/v1/log
--enroll_tls_endpoint=/api/v1/enroll
--config_plugin=tls
--config_tls_endpoint=/api/v1/config
--logger_plugin=tls
--logger_tls_compress=true
--distributed_plugin=tls
--distributed_tls_read_endpoint=/api/v1/distributed/read
--distributed_tls_write_endpoint=/api/v1/distributed/write
--distributed_interval=60
--disable_distributed=false
EOF

# 4. 启动 osquery
sudo systemctl start osqueryd
sudo systemctl enable osqueryd
```

### macOS

```bash
# 1. 安装 osquery
brew install osquery

# 2. 配置 enroll secret
echo "your-edr-secret-here" | sudo tee /etc/osquery/enroll_secret

# 3. 启动 osquery
sudo osqueryd --flagfile=/etc/osquery/osquery.flags &
```

### 验证

```bash
# 查看已经注册的主机
curl http://localhost:8889/api/edr/hosts
```

## 被管理主机自动上报的数据

| 采集项 | 查询 | 间隔 |
|--------|------|------|
| 进程列表 | SELECT * FROM processes | 5分钟 |
| 网络连接 | SELECT * FROM process_open_sockets | 10分钟 |
| 监听端口 | SELECT * FROM listening_ports | 10分钟 |
| 计划任务 | SELECT * FROM crontab | 1小时 |
| 登录用户 | SELECT * FROM logged_in_users | 5分钟 |

## 在管理后台配置 EDR 数据源

1. 登录管理后台 http://localhost:8889
2. 左侧菜单 → 数据源 → 新增数据源
3. 选择类型: "Osquery EDR"
4. 填写 EDR 服务地址（Docker 内使用 `soc-edr`）和端口 `9000`
5. 点击测试连接 → 确认成功
6. 保存
