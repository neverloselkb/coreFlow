# 🛡️ 보안 정책 (Security Policy)

CoreFlow 프로젝트의 보안과 안전성 유지에 관심을 가져주셔서 감사합니다.

---

## 📌 보안 업데이트 지원 버전 (Supported Versions)

현재 보안 패치 및 취약점 수정은 최신 릴리스 버전을 기준으로 제공됩니다.

| 버전 | 지원 여부 | 비고 |
| :--- | :---: | :--- |
| **v1.0.11 (최신)** | ✅ 지원 | SHA-256 업데이트 무결성 검증 및 표준 Win32 API 적용 |
| **v1.0.10 이하** | ❌ 미지원 | 앱 내 자동 업데이트 또는 [최신 릴리스](https://github.com/neverloselkb/coreFlow/releases) 설치 권장 |

---

## 🔒 핵심 보안 설계 원칙

1. **로컬 전용 통신 격리 (`127.0.0.1`)**
   - 내장 웹 대시보드 서버는 외부 네트워크에 노출되지 않으며 오직 로컬 루프백(`127.0.0.1`)에서만 바인딩됩니다.
   - 모든 상태 변경 API 요청에는 실행 시마다 무작위로 생성되는 세션 토큰 검증이 적용됩니다.
2. **자동 업데이트 무결성 검증**
   - 공식 GitHub 저장소(`https://github.com/neverloselkb/coreFlow/`) 외의 경로에서 내려받는 업데이트를 차단합니다.
   - 다운로드된 설치 파일은 실행 전 64비트 PE 헤더(`MZ` / `PE\0\0`) 및 GitHub Releases API의 공식 **SHA-256 다이제스트(`digest`)** 일치 여부를 검증합니다.
3. **최소 권한 원칙**
   - 일반 하드웨어 모니터링 및 대시보드 구동 시 관리자 권한을 강제하지 않으며(`asInvoker`), 설치 폴더(`C:\Program Files\CoreFlow`) 파일 교체가 필요한 경우에만 Windows 표준 UAC(`ShellExecuteW`)를 통해 명시적 동의를 요청합니다.

---

## 🚨 보안 취약점 제보 방법 (Reporting a Vulnerability)

보안 취약점을 발견하신 경우 공개 이슈(Public Issue) 대신 아래 방법으로 제보해 주시기 바랍니다.

1. **GitHub 비공개 취약점 제보 (권장)**
   - 저장소 상단 **[Security] ➔ [Advisories] ➔ [Report a vulnerability]** 버튼을 통해 비공개로 상세 내용을 제출해 주세요.
2. **제보 시 포함할 내용**
   - 취약점이 발생하는 버전 및 운영체제 환경 (Windows / macOS)
   - 재현 단계 (Steps to Reproduce) 또는 개념 증명(PoC)
   - 예상되는 보안 영향도

접수된 보안 제보는 확인 후 신속하게 패치 및 릴리스 노트에 반영됩니다.
