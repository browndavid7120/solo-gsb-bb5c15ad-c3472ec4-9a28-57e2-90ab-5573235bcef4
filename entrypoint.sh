#!/bin/sh
# 容器启动入口：
# 默认在容器启动时安装/更新 requirements.txt 中的依赖，然后再启动应用。
# 如需跳过（例如离线环境，直接使用镜像内已装好的依赖），
# 设置环境变量 SKIP_STARTUP_INSTALL=1。
set -e

if [ "${SKIP_STARTUP_INSTALL:-0}" != "1" ]; then
    echo "[entrypoint] Installing dependencies from requirements.txt ..."
    pip install --no-cache-dir -r requirements.txt
else
    echo "[entrypoint] SKIP_STARTUP_INSTALL=1, using prebuilt image dependencies."
fi

PORT="${APP_PORT:-8000}"
if [ "$1" = "gunicorn" ]; then
    # 统一注入监听地址，绑定到 APP_PORT（保留其余参数）
    shift
    set -- gunicorn -b "0.0.0.0:${PORT}" "$@"
fi

echo "[entrypoint] Starting: $*"
exec "$@"
