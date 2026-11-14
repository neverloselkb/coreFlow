# ⚡ CoreFlow (코어플로우)

<div align="center">

**Rust 기반의 초경량 올인원 하드웨어 모니터 & 게이밍 성능/플레이타임 스튜디오**

[![Language](https://img.shields.io/badge/Language-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(64--bit)-0078D6?logo=windows)](https://github.com/neverloselkb/coreFlow)
[![License](https://img.shields.io/badge/License-MIT-green)](#)

</div>

---

## 📖 프로젝트 소개

**CoreFlow**는 Windows 환경에서 **CPU · RAM · GPU · 게임 FPS · 네트워크(속도/실시간 핑) · 디스크 I/O**를 한눈에 모니터링하고, 게임 플레이 타임과 세션별 성능 지표(`평균 FPS`, `1% Low FPS`, `최고 GPU 온도`)를 자동으로 기록해 주는 **초경량 데스크톱 모니터링 유틸리티**입니다.

무거운 외부 런타임 없이 **순수 Rust 네이티브 백엔드 + Windows 표준 API(Win32 / Shell32 / GDI32 / IPHLPAPI / NVML)** 기반으로 동작하여 백그라운드 리소스 점유율을 최소화했으며, 직관적인 **그래프 뷰 & 수치 그리드 뷰 전환**, **실제 프로그램 아이콘 추출 표시**, **컴팩트 미니 HUD 모드(`F10`)**를 제공합니다.

---

## ✨ 주요 기능

### 1. 📊 실시간 하드웨어 4대 핵심 지표 & 상세 분석 뷰
- **CPU 모니터링**: 전체 부하율(%), 물리/논리 코어 수, 코어별 개별 부하 매트릭스 및 상위 점유 프로세스 실시간 추적
- **RAM & 가상 메모리**: 물리 메모리 사용량/가용량(GB) 및 가상 메모리(Swap) 실시간 점유율
- **GPU 정밀 연동 (NVIDIA NVML 내장)**: 코어 사용률(%), 전용 VRAM 사용량, **실시간 코어 온도(°C)**, 소비 전력(W), 그래픽 코어 클럭(MHz)
- **실시간 뷰 전환 (`📈 그래프 뷰` ↔ `🔢 수치 그리드`)**:
  - 메인 대시보드 및 각 부품별 상세 보기(카드 더블클릭)에서 **시각적인 차트 화면**과 **정밀 수치/테이블 중심의 그리드 화면**을 원클릭으로 전환할 수 있습니다.

### 2. 🎮 지능형 게임 감지 & 플레이타임/성능 자동 로거
- **자동 게임 프로세스 감지 및 오탐 방지**:
  - 실행 중인 게임을 자동으로 감지하며, Windows 캡처 도구(`SnippingTool`, `ScreenClippingHost`)나 브라우저/메신저 등 비게임 오버레이는 스마트하게 필터링합니다.
  - 원하는 프로세스를 직접 **사용자 정의 게임(`⭐ 영구 등록`)**으로 추가하거나 즉시 타겟으로 지정할 수 있습니다.
- **세션별 자동 성능 집계 (`logs/game_play_log.tsv`)**:
  - 게임을 플레이하면 `시:분:초(HH:MM:SS)` 단위의 플레이 시간과 함께 **평균 FPS**, **1% Low FPS**, **최고 GPU 온도(°C)**, **피크 CPU/RAM 점유율**이 자동 기록됩니다.
- **기간별 플레이 랭킹**: `오늘` / `최근 7일` / `최근 30일` / `전체` 기간별로 가장 많이 플레이한 게임 순위와 점유율을 분석합니다.

### 3. 🌐 고정밀 네트워크(트래픽 & 게임 서버 핑) + 💽 디스크 I/O 모니터
- **실시간 게임 서버 핑(Ping) & 지터(Jitter) 스마트 산출**:
  - 실행 중인 게임 프로세스의 실제 활성 TCP 연결(`GetExtendedTcpTable` + `GetPerTcpConnectionEStats` 커널 RTT)을 추적합니다.
  - 게임 프로세스 내 다수의 연결(글로벌 로그인/인증 서버 vs 실제 로컬 게임 매치 서버)이 동시에 열려 있을 때, **활성 트래픽 유무 및 최저 지연시간(Min-RTT) 가중 필터링**을 통해 실제 인게임 체감 핑을 정확히 표시합니다.
- **디스크 드라이브 & 프로세스별 I/O**:
  - 연결된 모든 드라이브의 용량 게이지와 함께, 현재 디스크 읽기/쓰기(`MB/s`)를 발생시키는 상위 프로세스를 실시간으로 추적합니다.

### 4. 🖼️ 실제 프로그램 아이콘(`.exe`) 자동 추출 및 캐싱
- 대시보드, 상세 보기(CPU/RAM), 디스크 I/O 목록, 게임 탐지 모달 등 모든 프로세스 목록에서 실행 파일(`.exe`)의 **실제 프로그램 아이콘**을 Win32/GDI32 API로 직접 추출해 표시합니다.
- 추출된 아이콘은 백엔드 메모리 캐시(`ICON_CACHE`)와 프론트엔드 브라우저 캐시에 저장되어 1초 주기 갱신 시에도 깜빡임이나 추가 부하가 없습니다.

### 5. 🗗 컴팩트 미니 HUD 모드 (`F10` 단축키)
- 상단의 **`🗗 미니 HUD`** 버튼 또는 **`F10`** 단축키로 언제든 작은 오버레이 창(Always-on-Top)으로 전환할 수 있습니다.
- `3×2 박스형(450×265)` 및 `6×1 가로 슬림 바(760×168)` 두 가지 레이아웃을 지원합니다.

### 6. 🔴 CSV 녹화 분석 스튜디오 & 🔔 스마트 경고 알림
- **녹화 및 분석 스튜디오**: 하드웨어 상태를 초 단위 UTF-8 CSV로 녹화하고, 내장된 분석 뷰어에서 구간별 평균/피크/타임라인 차트를 바로 확인할 수 있습니다.
- **스마트 경고 알림 & 히스토리 로그**: GPU 온도, CPU/RAM/VRAM 과부하, 장시간 게임 플레이 시 알림음과 배너로 경고를 띄우며, 발생 내역을 히스토리 로그에서 언제든 다시 확인할 수 있습니다.
- **집중 타이머(뽀모도로) & 할 일(Todo) 보드**: 작업과 학습을 돕는 타이머 및 체크리스트 기능을 함께 제공합니다.

---

## 🖥️ 시스템 요구 사항 (System Requirements)

| 항목 | 요구 사양 |
| :--- | :--- |
| **운영체제 (OS)** | Windows 10 (버전 1803 이상) 또는 Windows 11 (64-bit) |
| **런타임 엔진** | **Microsoft Edge** 또는 **Microsoft Edge WebView2 런타임** (Windows 10/11 기본 내장) |
| **그래픽카드 (선택)** | NVIDIA 그래픽카드 사용 시 드라이버 기본 내장 `nvml.dll`을 통해 온도/전력/클럭 자동 연동 |

> 💡 **타 PC에서 실행이 안 될 때 체크리스트**:
> 1. **Windows SmartScreen 차단 해제**: 최초 실행 시 *"Windows의 PC 보호"* 창이 뜨면 **`[추가 정보]` → `[실행]`**을 클릭하세요.
> 2. **Edge 브라우저 / WebView2 확인**: Windows에서 Edge가 강제 제거된 구형 환경인 경우 Microsoft 공식 [Edge WebView2 런타임](https://developer.microsoft.com/ko-kr/microsoft-edge/webview2/)이 필요합니다.

---

## 🚀 빌드 및 실행 방법 (Build from Source)

### 1. 사전 준비
- [Rust Toolchain (rustup)](https://rustup.rs/) 설치 (Windows 64-bit)

### 2. 저장소 클론
```bash
git clone https://github.com/neverloselkb/coreFlow.git
cd coreFlow
```

### 3. 릴리스 빌드
```powershell
# 1) CoreFlow 메인 애플리케이션 빌드
cargo build --release --bin CoreFlow

# 2) CoreFlow_Setup 설치 마법사 패키지 빌드 (선택)
cargo build --release --bin CoreFlow_Setup
```
- 빌드된 실행 파일은 `target/release/CoreFlow.exe` 및 `target/release/CoreFlow_Setup.exe`에 생성됩니다.

---

## 📂 프로젝트 구조

```text
coreFlow/
├── assets/
│   └── coreflow_icon.png      # 앱 및 트레이 원본 아이콘 에셋
├── src/
│   └── bin/
│       ├── tui_app.rs         # CoreFlow 메인 애플리케이션 (백엔드 모니터링 엔진 + UI/HUD)
│       └── installer.rs       # CoreFlow_Setup 전용 GUI 설치 마법사 및 언인스톨러 생성기
├── build.rs                   # Windows 실행 파일(.exe) 멀티해상도 아이콘 리소스 임베딩 스크립트
├── Cargo.toml                 # Rust 패키지 및 바이너리 타겟 설정
└── README.md                  # 프로젝트 소개 문서
```

---

## 📝 라이선스 (License)

이 프로젝트는 개인 및 오픈소스 학습·활용 목적으로 자유롭게 사용할 수 있습니다.
