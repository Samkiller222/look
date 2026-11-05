FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY look ./look
RUN pip install --no-cache-dir ".[web]"
ENV LOOK_DB=/data/look.db
VOLUME /data
EXPOSE 8000
RUN mkdir -p /data
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "look.web:create_app()"]
