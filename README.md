# TickTether × Category 1

Category 1의 **정상·정찰·토큰 접근·payload 실행** 시나리오.
원본 셸 스크립트는 그대로 사용하고, 로컬 전송 어댑터가 Pod 명령을 전용 fixture에 실행.

## 실행

Ubuntu 24.04의 **CPython 3.12.3**, Linux x86-64, `strace`, `binutils`, `curl`,
자기 자식 프로세스의 ptrace·메모리 읽기·하드웨어 감시점 권한 필요.

```bash
bash run.sh
```

네 시나리오를 각각 비차단 대조·보호 모드로 실행.
검증 실패 시 종료, 성공·실패 모두 결과와 오류 로그를 압축.
