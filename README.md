# Defense-follow: 내부자 정보유출 방어 모의 시스템

쿠팡(2025.11, 내부 접근통제 미흡)과 롯데카드(2025.8, 탐지 지연) 개인정보 유출 사고의 교훈을 **로컬 가상 환경에서 재현하고, 방어 장치가 막는 과정과 한계를 수치로 측정**한 프로젝트입니다.

> 모든 데이터는 무작위 더미이며 로컬 실행 전용입니다. 공격 시뮬레이터는 정상 API를 정상 계정으로 호출해 대량 조회·반출 행동만 재현합니다.

| 정상 상태 | 공격 탐지·자동 차단 |
|---|---|
| ![정상](docs/screenshots/01-dashboard-normal.jpg) | ![탐지](docs/screenshots/02-dashboard-attack-detected.jpg) |

## 핵심 결과 (방어 OFF → ON)
| 지표 | 방어 OFF | 방어 ON |
|---|---|---|
| 상담원 대량 조회로 확보한 건수 | 805건 (담당 고객 전부) | **300건**에서 차단 |
| 조회 후 반출된 건수 | 5,250건 | **1,250건** (1회 후 계정 잠금) |
| 첫 경보까지 | 경보 없음 | 약 80~105ms |
| 정상 요청 평균 응답 | 13.42ms | 13.31ms |

**측정으로 확인한 한계:** 저속 공격(분당 30건 미만)은 R1이 놓치고, 정상 업무에서도 오탐 0.67%가 나왔으며, 첫 반출은 막지 못합니다. 임계값을 올리면 오탐은 줄지만 유출 건수가 늘어나는 트레이드오프도 정리했습니다. 자세한 내용은 [사고 분석·대응 보고서](docs/사고분석-대응보고서.md)와 [비교 결과](docs/benchmark.md)를 보세요.

## 구성
```
[공격 시뮬레이터] -> [FastAPI 고객정보 서비스 + SQLite(더미)]
                        |- JWT 인증 / RBAC / 마스킹 / 조회 상한
                        |- 감사 로그 (DB + JSON Lines, 해시 체인)
                        v
                   [탐지 엔진: YAML 규칙 R1~R4] -> [자동 대응: 계정 잠금] -> [대시보드]
```

| 규칙 | 설명 | 기본 기준 | 심각도 |
|---|---|---|---|
| R1 | 대량 조회 (쿠팡형) | 10분 내 300건 이상 | high |
| R2 | 비정상 시간대 접근 | 00:00~05:59 KST | medium |
| R3 | 휴면·퇴사·잠금 계정 접근 | 비활성 계정의 로그인·토큰 사용 | high |
| R4 | 대량 조회 후 외부 전송 (롯데카드형) | 30분 내 200건 조회 후 내보내기 | critical |

규칙은 [rules/rules.yaml](rules/rules.yaml)에서 조정하며, 규칙마다 MITRE ATT&CK 기법 번호를 붙였습니다.

## 빠른 시작 (Windows PowerShell, Python 3.12)
```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python scripts\seed.py                      # 더미 데이터 생성
.venv\Scripts\python -m uvicorn app.main:app --port 8000   # 서버 실행
```
- 대시보드: http://127.0.0.1:8000/dashboard (`admin01` 또는 `admin02`로 로그인)
- API 문서: http://127.0.0.1:8000/docs
- 비교 보고서: http://127.0.0.1:8000/report
- 테스트 계정: `agent01`~`agent05`, `admin01`, `admin02`, `dba01` (비밀번호는 `scripts/seed.py`의 `DEMO_PASSWORD`, 로컬 전용 더미 값)

## 시연 순서
1. 서버를 켜고 대시보드에 `admin02`로 로그인합니다 (정상 상태, 모든 수치 0).
2. 다른 터미널에서 공격을 실행합니다.
   ```powershell
   .venv\Scripts\python scripts\attack_sim.py
   ```
3. 대시보드가 3초 안에 갱신됩니다: 경보 → 계정 자동 잠금 → 이벤트 기록.
4. "잠금 해제" 버튼으로 오탐을 복구합니다. 이후 [대응 플레이북](docs/대응플레이북.md) 순서로 범위를 산정합니다.
5. 방어 OFF/ON 비교는 `scripts\benchmark.py`를 실행하면 `docs/`에 결과가 생성됩니다 (약 1~2분).

## API 요약
| 엔드포인트 | 권한 | 설명 |
|---|---|---|
| `POST /auth/login` | 전체 | 로그인(JWT) |
| `GET /customers` | agent, admin | 목록(마스킹, 최대 50건/요청) |
| `GET /customers/search?q=` | agent, admin | 이름·이메일 앞부분 검색(와일드카드 제외 2글자 이상) |
| `GET /customers/{id}` | agent(담당만), admin | 상세 (`unmask=true&reason=`은 admin만) |
| `GET /customers/export?limit=&reason=` | admin | 마스킹된 내보내기(사유 필수, 최대 1,000건) |
| `GET /audit` | admin | 감사 로그 조회 |
| `GET /alerts` | admin | 경보 조회 |
| `GET /stats` | admin | 대시보드 집계 |
| `POST /admin/users/{username}/unlock` | admin | 자동 잠금 해제 (휴면 계정은 불가) |

## 설계 포인트
- **최소 권한:** 상담원은 담당 고객만, DBA는 API 접근 불가, 마스킹 해제는 관리자 + 사유 필수
- **우회 차단:** 검색 와일드카드(`%%`)로 전수 조회하는 경로를 테스트 중 발견해 막음
- **매 요청 상태 재확인:** 토큰이 유효해도 DB의 계정 상태를 확인하므로 잠금이 즉시 적용
- **변조 탐지:** 감사 로그 해시 체인 (`scripts/verify_audit.py`)
- **저장형 XSS 방지:** 대시보드는 로그의 모든 값을 이스케이프해 표시 (공격자가 입력한 로그인 아이디로 확인)
- **방어 스위치:** `DEFENSE_MODE=off`로 탐지·자동 차단만 끄고 전후 비교

## 폴더 구조
```
app/          FastAPI 서비스, 탐지 엔진(detection.py), 자동 대응(response.py), 대시보드(static/)
rules/        탐지 규칙 (rules.yaml)
scripts/      seed.py, attack_sim.py, detect.py, benchmark.py, verify_audit.py
tests/        pytest (일차별 test_day1~6)
docs/         보고서, 플레이북, 비교 결과, 스크린샷
기획서.md      프로젝트 기획서
```

## 테스트
```powershell
.venv\Scripts\python -m pytest -q
```

## 한계와 향후 과제
- 저속 공격 대응: 일·주간 누적 조회량 규칙, 사용자별 기준선(UEBA)
- 반출 사전 차단: 내보내기 직전에 직전 조회량을 검사
- 오탐 완화: 단계적 대응(경고 → 추가 인증 → 잠금), 잠금 전 관리자 확인
- 운영 환경 연동: ELK(Elasticsearch/Kibana), Sigma 규칙 포맷, Docker Compose 배포
- 측정은 합성 로그와 단일 PC 인프로세스 기준이며, 실제 업무 패턴과 네트워크 지연은 반영하지 않았습니다.
