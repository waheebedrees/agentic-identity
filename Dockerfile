# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.5.0 /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ARG-dependent tail (keeps uv sync layer shared across agents)
ARG UID=1000
ARG GID=1000
ARG USERNAME=agent

RUN groupadd -g ${GID} ${USERNAME} \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash ${USERNAME} \
    && chown -R ${UID}:${GID} /app

USER ${UID}:${GID}

CMD ["sleep", "infinity"]