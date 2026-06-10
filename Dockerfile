# Deployment-agnostic: the library makes ZERO outbound calls. The container is a
# thin host for whatever stdin/stdout or HTTP shim the operator writes — adding a
# runtime, not behavior. No network is reachable from core at runtime.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
RUN pip install --no-cache-dir .
# Default entrypoint runs the quickstart so `docker run` proves the claims.
ENTRYPOINT ["python", "examples/quickstart.py"]
