# 构建阶段
FROM python:3.13-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 运行阶段
FROM python:3.13-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# 复制 Python 依赖
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 复制应用代码
COPY . .

# 创建数据目录和日志目录
RUN mkdir -p data logs

# 暴露端口
EXPOSE 8889

# Gunicorn 启动
CMD ["gunicorn", "-w", "4", "-k", "gevent", "-b", "0.0.0.0:8889", "--timeout", "120", "--access-logfile", "logs/access.log", "--error-logfile", "logs/error.log", "web.admin.app:app"]
