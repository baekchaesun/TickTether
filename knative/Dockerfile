FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONOPTIMIZE=0
RUN apt-get update && apt-get install -y --no-install-recommends python3 libssl3t64 zlib1g ca-certificates && ln -s /usr/bin/python3 /usr/local/bin/python && rm -rf /var/lib/apt/lists/*
CMD ["python3"]
