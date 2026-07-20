# SOC Multi-Agent Makefile
# 单条命令开发流

.PHONY: help install test run web cli demo lint clean docker-build docker-up docker-down

# === 默认目标 ===
help:
	@echo "╔══════════════════════════════════════════════════════════════════════════╗"
	@echo "║               SOC Multi-Agent 工具命令清单                              ║"
	@echo "╠══════════════════════════════════════════════════════════════════════════╣"
	@echo "║ 安装/初始化                                                            ║"
	@echo "║   make install           安装依赖                                      ║"
	@echo "║   make install-venv      创建虚拟环境并安装                            ║"
	@echo "║   make init-env          初始化 config/.env                            ║"
	@echo "║                                                                          ║"
	@echo "║ 测试                                                                    ║"
	@echo "║   make test              跑全部单元测试                                ║"
	@echo "║   make test-api          仅跑 API 测试                                 ║"
	@echo "║   make test-core         仅跑核心模块测试                              ║"
	@echo "║                                                                          ║"
	@echo "║ 启动服务                                                                ║"
	@echo "║   make web               启动 Admin 控制台 (127.0.0.1:8889)            ║"
	@echo "║   make edr               启动 EDR 探针服务 (0.0.0.0:9000)              ║"
	@echo "║   make all               启动完整服务 (web + edr + gunicorn)           ║"
	@echo "║                                                                          ║"
	@echo "║ CLI 工具                                                                ║"
	@echo "║   make cli PHASE=triage  运行单个 phase                                 ║"
	@echo "║   make demo              加载演示数据                                   ║"
	@echo "║                                                                          ║"
	@echo "║ Docker                                                                  ║"
	@echo "║   make docker-build      构建镜像                                       ║"
	@echo "║   make docker-up         启动容器                                       ║"
	@echo "║   make docker-down       停止容器                                       ║"
	@echo "║                                                                          ║"
	@echo "║ 维护                                                                    ║"
	@echo "║   make backup-db        备份 data/admin.db                              ║"
	@echo "║   make logs-tail         跟踪 Gunicorn 日志                             ║"
	@echo "║   make clean             清理 pycache + 临时文件                       ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════╝"

# === 变量 ===
PYTHON ?= python3
VENV ?= ../soc-agent-env/bin/python3
PORT ?= 8889

# === 安装 ===
install:
	pip install -r requirements.txt

install-venv:
	test -d ../soc-agent-env || python3 -m venv ../soc-agent-env
	$(VENV) -m pip install --upgrade pip
	$(VENV) -m pip install -r requirements.txt

init-env:
	test -f config/.env || cp config/.env.example config/.env
	@echo "✅ config/.env 已创建（请编辑填入真实 API_KEY）"

# === 测试 ===
test:
	$(VENV) -m unittest discover tests/ -v

test-api:
	$(VENV) -m unittest tests.test_api -v

test-core:
	$(VENV) -m unittest tests.test_core -v

# === 服务 ===
web:
	$(VENV) -m gunicorn -w 2 -k gevent -b 0.0.0.0:$(PORT) --timeout 60 web.admin.app:app

edr:
	$(VENV) -m gunicorn -w 2 -k gevent -b 0.0.0.0:9000 --timeout 60 edr.app:app

all:
	@echo "启动 Web 服务在 :$(PORT)，EDR 在 :9000"
	@trap 'kill 0' SIGINT; \
	$(VENV) -m gunicorn -w 2 -k gevent -b 0.0.0.0:$(PORT) --timeout 60 web.admin.app:app & \
	$(VENV) -m gunicorn -w 2 -k gevent -b 0.0.0.0:9000 --timeout 60 edr.app:app & \
	wait

# === CLI ===
cli:
	$(VENV) main.py --phase $(PHASE)

demo:
	$(VENV) seed_demo_data.py

# === Docker ===
docker-build:
	docker build -t soc-agent:latest .

docker-up:
	docker compose up -d
	@echo "✅ 容器已启动："
	@echo "   - Admin: http://localhost:8889"
	@echo "   - EDR: http://localhost:9000"

docker-down:
	docker compose down

# === 维护 ===
backup-db:
	@mkdir -p backups
	cp data/admin.db backups/admin_$$(date +%Y%m%d_%H%M%S).db
	@echo "✅ 数据库已备份到 backups/"

logs-tail:
	tail -f logs/gunicorn.log 2>/dev/null || echo "未找到 logs/gunicorn.log"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache
	@echo "✅ 临时文件已清理"
