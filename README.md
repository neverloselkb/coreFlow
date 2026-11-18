# ⚡ CoreFlow (코어플로우)

<div align="center">

**Rust 기반의 초경량 멀티플랫폼 올인원 하드웨어 모니터 & 게이밍 성능/플레이타임 스튜디오**

[![Language](https://img.shields.io/badge/Language-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20(Universal)-0078D6?logo=apple)](https://github.com/neverloselkb/coreFlow/releases)
[![Version](https://img.shields.io/badge/Release-v1.0.9-blue?logo=github)](https://github.com/neverloselkb/coreFlow/releases)
[![License](https://img.shields.io/badge/License-MIT-green)](#)

</div>

---

## 📖 프로젝트 소개

**CoreFlow**는 **Windows** 및 **macOS (Apple Silicon M1/M2/M3/M4 & Intel Mac)** 환경에서 **CPU(점유율/온도) · RAM · GPU(점유율/온도/VRAM/전력) · 실시간 게임 FPS(1% Low 포함) · 네트워크(속도/인게임 핑) · 디스크 I/O**를 한눈에 모니터링하고, 게임 플레이 타임과 세션별 성능 지표(`평균 FPS`, `1% Low FPS`, `최고 GPU 온도`)를 자동으로 기록해 주는 **초경량 데스크톱 하드웨어 & 게이밍 스튜디오**입니다.

무거운 일렉트론(Electron) 런타임 없이 **순수 Rust 네이티브 백엔드**를 기반으로 동작하여 백그라운드 리소스 점유율을 1% 미만으로 최소화했으며, **실시간 투명도 조절 슬라이더가 탑재된 컴팩트 미니 HUD 모드(`F10`)**, **그래프 뷰 & 수치 그리드 뷰 전환**, **화면·HUD 표시 항목 커스터마이징**, **실제 프로그램 아이콘 추출**, **원클릭 인앱 무인 자동 업데이트(SHA-256 무결성 검증)**를 지원합니다.

---

## ✨ 주요 기능

### 1. 🌡️ 실시간 하드웨어 핵심 지표 & '점유율 / 온도' 일체형 모니터링
- **직관적인 `점유율 / 온도` 통합 표기**:
  - CPU 및 GPU 카드에 `20.5% / 45°C` 형태로 부하율과 온도를 한눈에 볼 수 있게 통합 표시하며, 카드 상단 공통 가이드를 통해 깔끔한 레이아웃을 제공합니다.
- **CPU 정밀 모니터링 & 동적 열역학 온도 엔진**:
  - 전체 부하율(%), 물리/논리 코어 수, 코어별 개별 부하 매트릭스 및 상위 점유 프로세스를 실시간 추적합니다.
  - **Intel 및 AMD Ryzen 전 프로세서 지원**: Windows 하드웨어 센서(WMI / LHM·OHM) 및 macOS(`ioreg` / `powermetrics` / `sysctl`) 연동은 물론, 센서 드라이버 접근이 제한된 환경에서도 정밀한 **동적 열역학 모델 기반 실시간 온도 산출 엔진**이 자동으로 동작합니다.
- **멀티 벤더 GPU (NVIDIA · AMD Radeon · Intel Arc · Apple Silicon) 완전 지원**:
  - **NVIDIA GPU**: NVML / `nvidia-smi` 기반 코어 사용률(%), 전용 VRAM, 코어 온도(°C), 소비 전력(W), 클럭(MHz) 정밀 연동
  - **AMD Radeon & Intel Arc / 내장 GPU**: Windows Performance Counter(`GPU Engine` 3D/Copy/Compute 엔진 합산 및 `GPU Adapter Memory`)와 센서 폴백을 통해 그래픽카드 종류에 관계없이 점유율·VRAM·온도를 추적합니다.
  - **macOS GPU**: Apple Silicon(M1~M4) 통합 메모리 아키텍처 및 `IOAccelerator` 기반 GPU 부하·온도 실시간 연동
  - **VRAM 상단 헤더 배치**: VRAM 용량 표기가 긴 수치에서도 잘리지 않도록 카드 우측 상단 헤더에 최적 배치했습니다.
- **RAM & 가상 메모리(Swap)**: 물리 메모리 사용량/전체 용량(GB) 및 스왑 메모리 실시간 추적
- **실시간 뷰 전환 (`📈 그래프 뷰` ↔ `🔢 수치 그리드`) & 상세 분석 모달**:
  - 메인 대시보드 및 각 부품 카드 더블클릭 시 열리는 상세 분석 화면에서 **시각적인 타임라인 차트 뷰**와 **정밀 수치/테이블 그리드 뷰**를 원클릭으로 전환할 수 있습니다.

### 2. 🎮 하드웨어 ETW 실시간 FPS 엔진 & 지능형 게임 로거
- **그래픽카드 무관(NVIDIA / AMD / Intel) 범용 하드웨어 FPS 측정**:
  - Windows 커널 **ETW (`Microsoft-Windows-DXGI` 및 `Microsoft-Windows-D3D9`) Present 이벤트**를 실시간 캡처하여 PresentMon과 동일한 방식으로 **실시간 FPS**, **프레임 타임(ms)**, **1% Low FPS(스터터링 지표)**를 정확히 산출합니다.
  - 멀티코어 CPU 버퍼 플러시 순서 보정 및 순수 하드웨어 QPC 타임스탬프 간격 계산을 통해 오차 없는 프레임을 표시합니다.
- **지능형 게임 프로세스 자동 감지 및 커스텀 등록**:
  - 실행 중인 게임을 자동 감지하며, 캡처 도구나 브라우저/메신저 등 비게임 프로세스는 스마트하게 필터링합니다.
  - 원하는 프로그램을 직접 **사용자 정의 게임(`⭐ 영구 등록`)**으로 추가하거나 즉시 모니터링 타겟으로 지정할 수 있습니다.
- **세션별 자동 성능 집계 (`logs/game_play_log.tsv`) & 기간별 랭킹**:
  - 게임 종료 시 플레이 시간(`HH:MM:SS`)과 함께 **평균 FPS**, **1% Low FPS**, **최고 GPU 온도(°C)**, **피크 CPU/RAM 점유율**이 자동 저장되며, `오늘` / `최근 7일` / `최근 30일` / `전체` 기간별 플레이 랭킹을 분석합니다.

### 3. 🗗 실시간 투명도 슬라이더가 탑재된 컴팩트 미니 HUD (`F10`)
- **원클릭 미니 HUD 전환**: 상단 **`🗗 미니 HUD`** 버튼 또는 **`F10`** 단축키로 언제든 게임/작업 위에 띄워두는 오버레이 창(Always-on-Top)으로 전환됩니다.
- **👻 상단 바 인라인 투명도 막대바(슬라이더)**:
  - 미니 HUD 상단 바에 배치된 슬라이더(`👻 ──●── 30%~100%`)를 마우스로 드래그하여 창 투명도를 실시간으로 부드럽게 조절할 수 있습니다 (Win32 `SetLayeredWindowAttributes` 네이티브 알파 블렌딩 적용).
  - 미니 HUD 모드 진입 시 내부 일반 대시보드 DOM을 완전히 격리·은닉(`display: none !important`)하여, 투명도를 낮췄을 때 앱 내부 잔상 없이 **오직 실제 게임 화면이나 바탕화면만 깨끗하게 투과**됩니다.
  - 투명하게 설정된 상태에서도 마우스를 HUD 위에 올리면 자동으로 선명해져 조작이 편리합니다.
- **2가지 레이아웃 즉시 전환 & 화면 맞춤 설정 (`⚙️ 설정`)**:
  - **`컴팩트 2단 박스형`**과 **`슬림 1줄 가로 바형`** 레이아웃을 상단 버튼 하나로 즉시 전환할 수 있습니다.
  - 대시보드와 미니 HUD에서 원하는 하드웨어 카드(FPS, CPU, GPU, RAM, 네트워크/핑, 디스크)만 선택하여 표시하거나 숨길 수 있으며, 창 크기와 위치·투명도가 모두 자동 저장됩니다.

### 4. 🌐 고정밀 네트워크(트래픽 & 인게임 서버 핑) + 💽 디스크 I/O 모니터
- **실시간 게임 서버 핑(Ping) & 지터(Jitter) 스마트 산출**:
  - 실행 중인 게임 프로세스의 실제 활성 TCP 소켓 커널 RTT를 추적하고, 다중 연결 중 실제 게임 트래픽이 흐르는 최저 지연시간(Min-RTT) 연결을 가중 필터링하여 정확한 인게임 체감 핑을 표시합니다.
- **디스크 드라이브 용량 & 프로세스별 실시간 I/O**:
  - 모든 드라이브의 파티션 용량 게이지와 함께 현재 디스크 읽기/쓰기(`MB/s`)를 발생시키는 상위 프로세스를 실시간 추적합니다.

### 5. 🔄 원클릭 인앱 무인 자동 업데이트 & 보안 무결성 검증 (Windows & macOS)
- **전 플랫폼 원클릭 자동 업데이트**:
  - 새 릴리스가 감지되면 상단 업데이트 알림 버튼을 클릭하는 것만으로 최신 패키지 다운로드 → 기존 설치 경로 덮어쓰기(macOS는 `/Applications/CoreFlow.app` 번들 교체 및 Gatekeeper 격리 속성 자동 해제) → 자동 재시작까지 한 번에 진행됩니다.
- **SHA-256 해시 & 64비트 PE 헤더 무결성 검증**:
  - 다운로드된 업데이트 설치 파일을 실행하기 전, 64비트 Windows PE 헤더(`MZ` / `PE\0\0` / `AMD64`) 유효성을 검사하고 순수 Rust 기반 SHA-256 해시를 계산하여 GitHub Releases API의 공식 `digest`(`sha256:...`)와 일치할 때만 안전하게 실행합니다.
- **레거시 업데이트 자가 복구 및 시작 프로그램 경로 통합**:
  - 구버전(v1.0.5 이하)에서 업데이트를 실행하더라도 새 바이너리가 스스로 설치 폴더(`C:\Program Files\CoreFlow\CoreFlow.exe`)를 최신화하고 시작 프로그램 레지스트리(`HKCU\...\Run\CoreFlow`)를 단일 경로로 동기화하여 재부팅 후 구버전으로 롤백되는 현상을 원천 차단합니다.
- **정식 Windows PE 메타데이터(`VS_VERSIONINFO`) 및 매니페스트(`RT_MANIFEST`) 내장**:
  - `build.rs`에서 컴파일 시점에 멀티해상도 아이콘, 제품/버전/저작권 리소스(`RT_VERSION`), Windows 10/11 호환성 매니페스트(`RT_MANIFEST`, `asInvoker`)를 COFF `.rsrc` 섹션으로 직접 생성·링크하여 백신 오탐 가능성을 최소화했습니다.

### 6. 🖼️ 실제 프로그램 아이콘 자동 추출 · 🔴 CSV 녹화 스튜디오 · ❓ 초보자 진단 가이드
- **실제 실행 파일 아이콘 추출 및 2단계 캐싱**: 모든 프로세스 목록에서 실제 프로그램 아이콘을 추출하여 백엔드/프론트엔드에 캐싱하므로 1초 주기 갱신에도 깜빡임이나 부하가 없습니다.
- **CSV 녹화 및 분석 스튜디오**: 하드웨어 상태를 초 단위 UTF-8 CSV로 녹화하고, 내장 분석 뷰어에서 구간별 평균/피크/타임라인 차트를 즉시 확인합니다.
- **스마트 경고 알림 & 내장 도움말(`F1`)**: 온도·부하 임계치 초과 시 실시간 알림 배너 및 히스토리 로그를 제공하며, `F1` 키(또는 `❓ 도움말` 버튼)로 하드웨어 지표 해석 가이드와 문제 해결 방법을 언제든 열람할 수 있습니다.

---

## 📋 최근 주요 업데이트 내역 (Changelog)

- **`v1.0.9`**: 언인스톨러(`Uninstall_CoreFlow.exe`) 버전 및 Windows '설치된 앱' 레지스트리(`DisplayVersion`) 자동 동기화, 프로그램 완전 제거 시 `%TEMP%` 호스트 이관 및 하위 `nvidia-smi` 프로세스 정리를 통한 설치 폴더(`C:\Program Files\CoreFlow`) 100% 완전 삭제 및 창 자동 종료 지원
- **`v1.0.8`**: Windows 백신 오탐 방지 강화 — `VS_VERSIONINFO` 버전 리소스 및 `RT_MANIFEST` 내장, 업데이트 파일 SHA-256 해시/PE64 헤더 무결성 검증 추가, 외부 셸 호출 제거 및 표준 Win32 API(`ShellExecuteW`) 일원화
- **`v1.0.7`**: 구버전(v1.0.5 이하) 업데이터로 업데이트 시 발생하던 재부팅 후 버전 롤백 현상 자가 복구 엔진 추가, 시작 프로그램 레지스트리 키 통합 및 자동 동기화
- **`v1.0.6`**: 미니 HUD 상단 바 실시간 투명도 조절 슬라이더(막대바) 탑재 및 배경 잔상/비침 완전 차단, CPU/GPU `점유율 / 온도` 통합 표기, GPU VRAM 상단 헤더 재배치, AMD Ryzen 온도 엔진 및 AMD Radeon / Intel Arc 호환성 강화, macOS 온도 센서 폴백 완비
- **`v1.0.5`**: macOS 원클릭 인앱 자동 업데이트(Self-Update) 엔진 및 Gatekeeper 격리 속성 자동 해제 탑재
- **`v1.0.4`**: macOS Universal (Apple Silicon M1~M4 & Intel) 공식 지원 및 멀티플랫폼 자동 릴리스 CI/CD 파이프라인 구축

---

## 🖥️ 시스템 요구 사항 (System Requirements)

| 항목 | Windows 요구 사양 | macOS 요구 사양 |
| :--- | :--- | :--- |
| **운영체제 (OS)** | Windows 10 (버전 1803 이상) 또는 Windows 11 (64-bit) | macOS 10.15 Catalina 이상 (macOS 11~15 Sequoia 호환) |
| **아키텍처** | x86_64 (64-bit) | Apple Silicon (M1/M2/M3/M4) 및 Intel x86_64 Universal |
| **런타임 엔진** | Microsoft Edge 또는 Chrome (Windows 기본 내장 지원) | Chrome, Edge, Brave, Arc, Safari 등 웹 뷰어 |
| **그래픽카드** | NVIDIA, AMD Radeon, Intel Arc 및 내장 그래픽 전 기종 | Apple Silicon 통합 GPU 및 Intel Mac GPU |

---

## 📥 설치 및 다운로드 방법

최신 버전 바이너리는 **[GitHub Releases](https://github.com/neverloselkb/coreFlow/releases)** 페이지에서 바로 다운로드하실 수 있습니다.

### 🪟 Windows 사용자
1. **`CoreFlow_Setup.exe`** 다운로드 후 실행 (권장 — `C:\Program Files\CoreFlow` 자동 설치, 바탕화면/시작 메뉴 바로가기 및 시작 프로그램 등록 지원)
2. 또는 설치가 필요 없는 **`CoreFlow.exe`** 포터블 버전을 다운로드하여 원하는 폴더에서 바로 실행
3. 이후 새 버전이 출시되면 앱 상단의 **인앱 업데이트 버튼** 클릭 한 번으로 자동 업데이트됩니다.

> 💡 **Windows SmartScreen 안내**:  
> 최초 실행 시 *"Windows의 PC 보호"* 알림이 뜨면 **`[추가 정보]` → `[실행]`**을 누르시면 됩니다.

### 🍎 macOS 사용자
1. **`CoreFlow-macOS-universal.zip`** 다운로드 후 압축 해제
2. 해제된 **`CoreFlow.app`**을 `/Applications` (응용 프로그램) 폴더로 이동하여 실행
3. 이후 업데이트는 앱 내에서 원클릭으로 자동 진행됩니다.

---

## 🚀 소스코드 빌드 방법 (Build from Source)

### 1. 사전 준비
- [Rust Toolchain (rustup)](https://rustup.rs/) 설치

### 2. 저장소 클론
```bash
git clone https://github.com/neverloselkb/coreFlow.git
cd coreFlow
```

### 3. 플랫폼별 릴리스 빌드

#### 🪟 Windows 환경
```powershell
# 1) CoreFlow 메인 애플리케이션 빌드
cargo build --release --bin CoreFlow

# 2) CoreFlow_Setup 설치 마법사 빌드 (빌드된 CoreFlow.exe를 내부에 자동 패키징)
cargo build --release --bin CoreFlow_Setup
```

#### 🍎 macOS 환경
```bash
# Apple Silicon & Intel Universal 바이너리 빌드
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin --bin CoreFlow
cargo build --release --target x86_64-apple-darwin --bin CoreFlow

# lipo를 통한 Universal 바이너리 및 앱 번들 생성
mkdir -p CoreFlow.app/Contents/MacOS
lipo -create \
  target/aarch64-apple-darwin/release/CoreFlow \
  target/x86_64-apple-darwin/release/CoreFlow \
  -output CoreFlow.app/Contents/MacOS/CoreFlow
chmod +x CoreFlow.app/Contents/MacOS/CoreFlow
```

---

## 📂 프로젝트 구조

```text
coreFlow/
├── .github/
│   └── workflows/
│       └── release.yml        # Windows & macOS Universal 자동 빌드 및 GitHub Release 배포 CI/CD
├── assets/
│   └── coreflow.ico           # 앱 및 인스톨러 멀티해상도 아이콘 리소스 (build.rs 자동 생성)
├── src/
│   └── bin/
│       ├── tui_app.rs         # CoreFlow 메인 엔진 (하드웨어 센서·ETW FPS·내장 서버·대시보드/미니 HUD·자동 업데이터)
│       └── setup.rs           # CoreFlow_Setup 전용 GUI 설치/제거 마법사 및 무인 업데이트 관리자
├── build.rs                   # Windows COFF(.rsrc) 아이콘·VS_VERSIONINFO·RT_MANIFEST 순수 Rust 생성기
├── Cargo.toml                 # Rust 패키지 및 바이너리 타겟 메타데이터 (v1.0.9)
└── README.md                  # 프로젝트 소개 및 매뉴얼 문서
```

---

## 📝 라이선스 (License)

이 프로젝트는 [MIT 라이선스](LICENSE) 하에 자유롭게 사용할 수 있습니다.
