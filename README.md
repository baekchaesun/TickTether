# 탐지 구현 실행

Linux x86-64, Python3.12, GCC·binutils, OpenSSL3·zlib
공유 서버 실험 시 자식의 ptrace/process_vm_readv 허용.

```bash
python3 shared/runtime.py --workload image
python3 shared/runtime.py --workload compression --fault rewind
```

정상 입력은 그대로 재사용, 위반 발견 시 중단하고 주입 없이 재실행.

Knative는 기존 kind·Knative·Kourier 환경에서 실행. 
함수는 capability 없이, 호스트 broker는 PERFMON/SYS_PTRACE 권한 실행.

```bash
docker build -f knative/Dockerfile -t ce-knative:local .
kind load docker-image ce-knative:local --name YOUR_CLUSTER
export CE_KNATIVE_CONTEXT=kind-YOUR_CLUSTER
python3 knative/deploy.py
```

- SHA256=0
- PBKDF2=1
- 압축=2

```json
{"request":{"workload":1,"passes":1,"seed":0,"values":[2,3],"runtime_paths":0,"wait_ms":0},"lab":{"backend":"kernel","scenario":{"family":"rewind","extra":4,"position":"early"}}}
```

Runpod CPU Serverless 이미지 빌드·push 후 본인 endpoint에 지정.

```bash
docker build -f runpod/docker/Dockerfile -t YOUR_REGISTRY/ce-runtime:latest .
docker push YOUR_REGISTRY/ce-runtime:latest
```

worker concurrency=1

```json
{"input":{"request":{"workload":3,"passes":1,"seed":0,"values":[2,3],"runtime_paths":0,"wait_ms":0},"scenario":{"family":"rewind","extra":4,"position":"early"}}}
```
