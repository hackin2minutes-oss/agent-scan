# Agent Scan container image. The base image is pinned by digest. The image runs as a non-root user and needs no
# network access to scan: the knowledge base is inside the package.
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

RUN groupadd --gid 1001 scanner && useradd --uid 1001 --gid 1001 --no-create-home scanner

WORKDIR /opt/agent-scan
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir --no-compile . && rm -rf /opt/agent-scan/src /opt/agent-scan/build

USER 1001:1001
WORKDIR /work
ENTRYPOINT ["agent-scan"]
CMD ["--help"]
