FROM python:3.12-slim
WORKDIR /argis

ARG VCS_REF
ARG VCS_URL="https://github.com/Mohilisop/Argis"
ARG VERSION_TAG

ENV ARGIS_ENV=docker

LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url=$VCS_URL \
      org.label-schema.name="Argis" \
      org.label-schema.version=$VERSION_TAG

COPY README.md pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . $([ -n "$VERSION_TAG" ] && echo "==$VERSION_TAG")

ENTRYPOINT ["argis"]
