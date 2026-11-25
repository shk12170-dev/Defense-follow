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
| 조회 후 반출된 건수 | 5,250건 | **250건** (내보내기는 실행 전에 거부) |
| 분당 10건 저속 공격 8시간 유출 | 4,800건 (탐지 못함) | **2,000건**에서 차단 |
| 첫 경보까지 | 경보 없음 | 약 80~100ms |
| 정상 요청 평균 응답 | 13.62ms | 13.86ms |

**2차 보완:** 1차 구현의 한계를 측정으로 확인한 뒤, ① 하루 누적 조회량 규칙(R5 경고 → R6 차단, 단계적 대응) ② 대량 조회 직후 내보내기 사전 차단(R7)을 추가했습니다. 1차에서는 첫 내보내기 1,000건이 유출된 뒤에야 계정이 잠겼고, 분당 30건 미만의 저속 공격은 탐지하지 못했습니다.

**남은 한계:** 하루 1,200건 미만(분당 약 2.5건 이하)으로 천천히 빼가면 여전히 차단하지 못하고, 정상 업무에서도 계정 잠금 오탐 0.67%가 나옵니다. 임계값을 올리면 오탐은 줄지만 유출 건수가 늘어나는 트레이드오프도 정리했습니다. 자세한 내용은 [사고 분석·대응 보고서](docs/사고분석-대응보고서.md)와 [비교 결과](docs/benchmark.md)를 보세요.

![반출 사전 차단](docs/screenshots/05-export-preblock.jpg)

## 구성
```
[공격 시뮬레이터] -> [FastAPI 고객정보 서비스 + SQLite(더미)]
                        |- JWT 인증 / RBAC / 마스킹 / 조회 상한
                        |- 감사 로그 (DB + JSON Lines, 해시 체인)
                        v
                   [탐지 엔진: YAML 규칙 R1~R7] -> [단계적 대응: 경고 / 잠금 / 반출 사전 차단] -> [대시보드]
```

| 규칙 | 설명 | 기본 기준 | 심각도 |
|---|---|---|---|
| R1 | 대량 조회 (쿠팡형) | 10분 내 300건 이상 | high |
| R2 | 비정상 시간대 접근 | 00:00~05:59 KST | medium |
| R3 | 휴면·퇴사·잠금 계정 접근 | 비활성 계정의 로그인·토큰 사용 | high |
| R4 | 대량 조회 후 외부 전송 (롯데카드형) | 30분 내 200건 조회 후 내보내기 | critical |
| R5 | 일일 누적 조회 (경고, 1단계) | 24시간 누적 1,200건 이상 | medium (잠금 없음) |
| R6 | 일일 누적 조회 (차단, 2단계) | 24시간 누적 2,000건 이상 | high (잠금) |
| R7 | 대량 조회 직후 내보내기 사전 차단 | 직전 30분 200건 조회 후 내보내기 시도 | critical (반출만 막고 잠금 없음) |

규칙은 [rules/rules.yaml](rules/rules.yaml)에서 조정하며, 규칙마다 MITRE ATT&CK 기법 번호를 붙였습니다.

### Sigma 규칙 (SIEM 간 이식용, [sigma/](sigma/))
R1~R7 모두 Sigma 형식으로도 제공합니다. 정확한 기준은 `rules/rules.yaml`이며, 합계(`rows`)를 셀 수 없는 Sigma의 한계 때문에 일부는 근사입니다.

| 규칙 | Sigma 파일 | 표현 | 검증 |
|---|---|---|---|
| R1 | defense_bulk_access_correlation.yml | 근사: 50건 이상 조회 6회/10분 | 구조 검증 |
| R2 | defense_offhours_data_access.yml | 정확 (`local_hour` 필드 필요) | 엔진과 탐지 결과 일치 확인 |
| R3 | defense_inactive_account_access.yml | 정확 | 엔진과 탐지 결과 일치 확인 |
| R4 | defense_bulk_then_export_correlation.yml | 근사: 대량 조회 후 30분 내 내보내기 | 구조 검증 |
| R5 | defense_daily_cumulative_correlation.yml | 근사: 50건 이상 조회 24회/24시간 (≈1,200건) | 50건 단위 조회에서 엔진 발동 시점과 일치 확인 |
| R6 | defense_daily_cumulative_correlation.yml | 근사: 50건 이상 조회 40회/24시간 (≈2,000건) | 50건 단위 조회에서 엔진 발동 시점과 일치 확인 |
| R7 | defense_export_preblock.yml | 정확: 차단 이벤트 하나로 매칭 | 엔진과 탐지 결과 일치 확인 |

pySigma 등 변환 도구로 실제 쿼리를 만들어 SIEM에서 돌려 본 것은 아닙니다 (형식·논리 검증만 했습니다).

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
| `GET /customers/export?limit=&reason=` | admin | 마스킹된 내보내기(사유 필수, 최대 1,000건). 직전 30분에 200건 이상 조회했다면 403으로 사전 차단 |
| `GET /audit` | admin | 감사 로그 조회 |
| `GET /alerts` | admin | 경보 조회 |
| `GET /stats` | admin | 대시보드 집계 |
| `POST /admin/users/{username}/unlock` | admin | 자동 잠금 해제 (휴면 계정은 불가) |

## ELK·Docker (선택)
`docker compose up --build`로 앱 + Elasticsearch + Kibana + Filebeat를 한 번에 실행합니다. 감사 로그와 경보를 Kibana에서 검색·시각화하고, 탐지 규칙은 [Sigma 형식](sigma/)으로도 제공합니다. 자세한 내용은 [docs/ELK.md](docs/ELK.md)를 보세요 (로컬 전용, 메모리 약 3GB 필요).

![Kibana 대시보드](docs/screenshots/04-kibana-dashboard.jpg)

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
scripts/      seed.py, attack_sim.py, detect.py, benchmark.py, verify_audit.py, kibana_setup.py, docker_start.py
elk/          Filebeat 설정
sigma/        Sigma 형식 탐지 규칙
tests/        pytest (test_day1~6, test_day8_elk, test_day9)
docs/         보고서, 플레이북, 비교 결과, 스크린샷
기획서.md      프로젝트 기획서
```

## 테스트
```powershell
.venv\Scripts\python -m pytest -q
```

## 한계와 향후 과제
- 더 느린 공격: 하루 1,200건 미만은 아직 못 잡습니다 → 주간 누적, 사용자별 평소 패턴(기준선, UEBA) 대비 탐지
- 오탐 완화: R1 잠금 오탐(0.67%)이 남아 있습니다 → 잠금 전 관리자 확인, 추가 인증 단계
- 조회 사전 차단: 내보내기는 사전 차단하지만, 조회는 R1 임계값(300건)까지는 확보할 수 있습니다
- R5~R7은 Kibana 저장된 검색·대시보드에 아직 반영하지 않았습니다 (R1~R4만 반영, Sigma는 R1~R7 모두 작성)
- ELK·Docker Compose는 실제 기동까지 확인했습니다. Sigma 규칙은 변환·실행 도구로 돌려 보지는 않았습니다 ([docs/ELK.md](docs/ELK.md) 참고)
- 측정은 합성 로그와 단일 PC 인프로세스 기준이며, 실제 업무 패턴과 네트워크 지연은 반영하지 않았습니다.
