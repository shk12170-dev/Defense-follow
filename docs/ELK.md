# ELK·Docker 연동

앱이 남기는 로그를 Filebeat → Elasticsearch로 수집하고 Kibana에서 검색·시각화합니다. **로컬 모의 환경 전용**입니다(Elasticsearch 보안 기능을 끄고, 모든 포트를 `127.0.0.1`에만 공개).

## 구성
```
app ──(logs/audit.jsonl, logs/alerts.jsonl)──> Filebeat ──> Elasticsearch ──> Kibana
 └ 공유 볼륨 app-logs                          defense-audit-* / defense-alerts-*
```
| 서비스 | 역할 | 주소 |
|---|---|---|
| app | FastAPI 서비스 + 대시보드 | http://127.0.0.1:8000/dashboard |
| elasticsearch | 로그 저장·검색 (단일 노드, 힙 512MB) | http://127.0.0.1:9200 |
| kibana | 검색·대시보드 | http://127.0.0.1:5601 |
| filebeat | 로그 수집 (`elk/filebeat.yml`) | - |
| kibana-setup | 데이터 뷰·저장된 검색·대시보드 자동 생성 (1회 실행 후 종료) | - |

필요 자원: 메모리 약 3GB 이상, 이미지 다운로드 수 GB (Elasticsearch·Kibana 8.15.3, Filebeat 8.15.3).

## 실행
```powershell
docker compose up --build
```
1. app이 더미 데이터를 만들고 시작합니다.
2. 공격을 실행합니다 (컨테이너의 app은 호스트 8000번으로 접근).
   ```powershell
   .venv\Scripts\python scripts\attack_sim.py
   ```
3. Kibana → Dashboards → "Defense 보안 관제"에서 확인합니다.
4. 종료: `docker compose down` (데이터까지 지우려면 `-v`)

## 수집 필드
- 감사 로그(`defense-audit-*`): `username, action, result, rows, resource, detail, ip, local_hour` (`local_hour`는 Filebeat가 계산한 KST 시각 0~23)
- 경보(`defense-alerts-*`): `rule_id, rule_name, severity, mitre, username, detail`

## Sigma 규칙 (`sigma/`)
| 파일 | 규칙 | 비고 |
|---|---|---|
| defense_inactive_account_access.yml | R3 | 탐지 엔진과 같은 이벤트를 잡는지 테스트로 검증 |
| defense_offhours_data_access.yml | R2 | `local_hour` 필드 필요 (Filebeat가 계산), 테스트로 검증 |
| defense_bulk_access_correlation.yml | R1 근사 | Sigma 상관 규칙은 합계를 세지 못해 "50건 이상 조회 6회/10분"으로 근사 |
| defense_bulk_then_export_correlation.yml | R4 근사 | 대량 조회 후 30분 내 내보내기 (`temporal_ordered`) |

정확한 기준은 `rules/rules.yaml`입니다. Sigma 파일은 SIEM 간 이식을 위한 표현이며, 변환·실행 도구(pySigma 등)로 실제 쿼리를 만들어 돌려 본 것은 아닙니다.

## 포트 충돌
Kibana 기본 포트 5601을 다른 프로그램이 쓰고 있으면 환경변수로 바꿉니다.
```powershell
$env:KIBANA_PORT = "5602"; docker compose up -d
```

## 검증 상태
**실제 기동 확인 (2026-11-25, Docker Desktop, Elasticsearch·Kibana·Filebeat 8.15.3)**
- 5개 서비스가 정상 기동하고, `attack_sim.py`를 컨테이너의 앱에 실행한 결과 감사 로그 22건과 경보 7건이 Elasticsearch에 적재됐습니다 (거절된 이벤트 0건).
- `kibana-setup`이 데이터 뷰 2개, 저장된 검색 7개, 대시보드 1개를 만들었고, Chrome에서 "Defense 보안 관제" 대시보드를 열어 경보·자동 잠금·R3 후보 패널을 확인했습니다 ([스크린샷](screenshots/04-kibana-dashboard.jpg)).
- `local_hour`가 UTC→KST로 올바르게 계산되는 것을 확인했습니다 (UTC 23:29 → 8시).

**기동하면서 발견해 고친 문제**
1. Filebeat 8.x는 기본이 데이터 스트림 방식이라 `defense-audit-날짜` 형태의 인덱스와 충돌해 이벤트가 버려졌습니다 → `setup.dsl.enabled: false` 추가.
2. 감사 로그의 `hash` 필드가 Filebeat 기본 템플릿(ECS)에서 객체 필드라 문자열이 거절돼 감사 로그가 0건이었습니다 → `chain_hash`, `chain_prev`로 이름 변경.
3. 5601 포트가 다른 프로그램에 사용 중이라 Kibana가 시작되지 않았습니다 → `KIBANA_PORT` 환경변수 추가.

**테스트로 검증 (`tests/test_day8_elk.py`)**: 구성 파일 정합성, Kibana 설정 요청 내용, Sigma R2·R3 탐지 결과 일치.

**아직 확인하지 못한 것**
- 저장된 검색 중 "R2 후보(새벽 접근)"와 "로그인 실패"는 시연 시각과 시나리오 때문에 결과가 0건이라, 실제 데이터로 화면에 나오는 것은 확인하지 못했습니다 (필드 타입과 쿼리 형식은 확인).
- Sigma 파일은 pySigma 등으로 변환해 실행해 보지 않았습니다.
- 대시보드의 패널은 표 형태의 검색 결과이며, 시계열 차트 같은 시각화는 만들지 않았습니다.
