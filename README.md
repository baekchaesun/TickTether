# TickTether × Category 1

Category 1의 **정상·정찰·토큰 접근·payload 실행** 네 시나리오만 포함한다.
원본 셸 스크립트는 그대로 사용하고, 로컬 전송 어댑터가 Pod 명령을 전용 fixture에 실행한다.
토큰·자격증명·환경 파일은 실험용 값이며 HTTP health check는 loopback을 사용한다.

## 실행

Ubuntu 24.04의 **CPython 3.12.3**, Linux x86-64, `strace`, `binutils`, `curl`,
자기 자식 프로세스의 ptrace·메모리 읽기·하드웨어 감시점 권한이 필요하다.

```bash
bash run.sh
```

네 시나리오를 각각 비차단 대조·보호 모드로 실행한다(기본 8회).
검증 실패 시 종료하고, 성공·실패 모두 결과와 오류 로그를 압축한다.
회수 파일은 마지막에 출력되는 `results/<실행 ID>.tar.gz`다.

## 연결 방법

TickTether가 첫 실행의 제어 상태·네이티브 결과 기록을 검증한다.
관측 대상 요청 worker의 프로세스 생성 시 현재 CPython 프레임과 검증된 `CALL`의 소유 프레임을 연결한다.
이 연결이 없는 추가 셸 실행은 생성 전에 차단한다. 경로·명령어·시나리오 이름은 탐지 조건에 사용하지 않는다.

비정상 시나리오는 미등록 프레임에서 원본 공격 스크립트를 실행하도록 주입한다.
대조 실행의 실제 파일·프로세스 기록과 보호 실행의 차단 기록을 비교한다.
적용 가정은 신뢰하는 커널·CPython·수집기·검증기와, 검증된 요청 밖에서 발생하는 추가 실행이다.
허용된 셸 내부의 모든 작업에 대해서는 별도 syscall 기록을 수집한다.

VM 관측 밀도 계약 `D ≤ (B+1)E+B`는 기존 검증기를 사용해 실행 접두부마다 감사한다.
셸 자식 프로세스의 작업은 프로세스 출처 검사와 행위 기록으로 확인한다.

## 파일과 결과

- `scenarios/`: 변경하지 않은 Category 1 스크립트 4개.
- `engine/`: TickTether 검증기와 프로세스 출처 연결부.
- `bin/kubectl`: fixture용 로컬 전송 어댑터.
- `run.py`, `run.sh`: 실행·감사·결과 수집.
- `ORIGIN.json`, `SOURCE_SHA256SUMS`: 원본 출처와 배포 소스 해시.
- `VERIFIED.json`: 이 패키지 버전의 로컬 연결 검증 결과.

결과의 `summary.json`·`results.csv`에 시나리오별 판정과 CPU·경과시간,
`trials/`에 VM 증거·프로세스 출처·감사 결과, `behavior/`에 실제 syscall 기록을 저장한다.
`SHA256SUMS`로 결과 파일을 검증한다. 이전 버전 수치는 합산하지 않는다.

## Knative 적용 범위

현재 실행 경로는 로컬 fixture 재현이다. Knative 배포에는 요청용 HTTP 진입점,
함수 이미지·Knative Service, 관측 권한 확인을 추가한다. 기존 Category 1은 보존한다.
저장소의 별도 서버리스 설치 구성은 기반 환경 참고용이며, 이 패키지는 네 시나리오만 사용한다.
