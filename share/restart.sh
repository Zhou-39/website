#!/bin/bash

echo "正在重启 Gunicorn..."

# 进入项目目录
cd /var/website/share

# 杀掉所有 Gunicorn 进程
pkill -f "gunicorn.*:8002"

# 等待2秒确保进程完全退出
sleep 2

# 重新激活虚拟环境并启动
source .venv/bin/activate
nohup gunicorn -b 127.0.0.1:8002 app:app --timeout 120 > gunicorn.log 2>&1 &

echo "Gunicorn 重启完成！"
echo "查看日志：tail -f /var/website/share/gunicorn.log"
