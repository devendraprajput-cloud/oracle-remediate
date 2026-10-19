# ORACLE-REMEDIATE application image
FROM python:3.12-slim
LABEL org.opencontainers.image.title="oracle-remediate" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir ".[oracle,anthropic,openai]"
COPY controls ./controls
COPY config ./config
COPY prompts ./prompts
COPY knowledge ./knowledge
COPY benchmark ./benchmark
RUN useradd --create-home orarem && chown -R orarem /app
USER orarem
ENTRYPOINT ["orarem", "--config", "config/default.yaml"]
CMD ["demo"]
