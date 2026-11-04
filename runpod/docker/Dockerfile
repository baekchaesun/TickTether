FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONOPTIMIZE=0
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv gcc binutils libc6-dev libssl3t64 zlib1g ca-certificates && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir runpod==1.7.13
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /opt/ce
COPY shared /opt/ce/shared
COPY runpod/handler.py /opt/ce/runpod/handler.py
RUN python3 -B shared/runtime.py --build-only && useradd --uid 10001 --create-home experiment
USER 10001:10001
WORKDIR /home/experiment
CMD ["python3", "-B", "/opt/ce/runpod/handler.py"]
