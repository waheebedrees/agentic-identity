# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN pip install --no-cache-dir . 

COPY main.py ./ 

CMD ["python", "main.py"]
