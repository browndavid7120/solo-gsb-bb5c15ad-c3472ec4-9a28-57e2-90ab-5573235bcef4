FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000

WORKDIR /app

# 镜像构建阶段先安装一次，使镜像开箱可用；
# 容器启动时入口脚本默认会再执行一次 pip install（见 entrypoint.sh）。
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY mailtrace ./mailtrace
COPY wsgi.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "-w", "2", "-t", "60", "wsgi:app"]
