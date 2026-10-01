# Dashboard image: firewall + HTMX dashboard on port 8000.
#
# Build:  docker build -t verqen/firewall:latest -f docker/Dockerfile .
# Run:    docker run --gpus all -p 8000:8000 \
#           -v /path/to/checkpoint:/models/verqen:ro \
#           -e VERQEN_CHECKPOINT=/models/verqen verqen/firewall:latest
FROM python:3.12-slim

WORKDIR /app

# Dependencies first for layer caching.
COPY pyproject.toml README.md LICENSE ./
COPY verqen_firewall ./verqen_firewall
RUN pip install --no-cache-dir ".[dashboard]"

# The VerQen engine (torch + model runtime) is optional at build time;
# install it for GPU inference, otherwise only the deterministic
# pre-filter layer will be available.
ARG WITH_VERQEN=0
RUN if [ "$WITH_VERQEN" = "1" ]; then \
      pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cu124 && \
      pip --no-cache-dir install git+https://github.com/ZorQelis-AI/verqen.git; \
    fi

ENV VERQEN_CHECKPOINT=/models/verqen
EXPOSE 8000

CMD ["verqen-firewall", "dashboard", "--host", "0.0.0.0", "--port", "8000"]
