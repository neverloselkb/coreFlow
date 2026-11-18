# ⚡ CoreFlow (코어플로우)

<div align="center">

**Rust 기반의 초경량 멀티플랫폼 올인원 하드웨어 모니터 & 게이밍 성능/플레이타임 스튜디오**

[![Language](https://img.shields.io/badge/Language-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20(Universal)-0078D6?logo=apple)](https://github.com/neverloselkb/coreFlow/releases)
[![Version](https://img.shields.io/badge/Release-v1.0.7-blue?logo=github)](https://github.com/neverloselkb/coreFlow/releases)
[![License](https://img.shields.io/badge/License-MIT-green)](#)

</div>

---

## 📖 프로젝트 소개

**CoreFlow**는 **Windows** 및 **macOS (Apple Silicon M1/M2/M3/M4 & Intel Mac)** 환경에서 **CPU · RAM · GPU · 게임 FPS · 네트워크(속도/실시간 핑) · 디스크 I/O**를 한눈에 모니터링하고, 게임 플레이 타임과 세션별 성능 지표(`평균 FPS`, `1% Low FPS`, `최고 GPU 온도`)를 자동으로 기록해 주는 **초경량 데스크톱 모니터링 유틸리티**입니다.

무거운 일렉트론(Electron) 등의 런타임 없이 **순수 Rust 네이티브 백엔드**를 기반으로 동작하여 백그라운드 리소스 점유율을 1% 미만으로 최소화했으며, 직관적인 **그래프 뷰 & 수치 그리드 뷰 전환**, **실제 프로그램 아이콘 추출 표시**, **컴팩트 미니 HUD 모드(`F10`)**, **시스템 다크/라이트 테마 자동 동기화**를 지원합니다.

---

## ✨ 주요 기능

### 1. 🍎 macOS 완전 지원 및 원클릭 인앱 자동 업데이트
- **Universal 바이너리 배포**: Apple Silicon(M1/M2/M3/M4)과 Intel Mac을 단일 바이너리로 지원하여 모든 Mac에서 네이티브 속도로 동작합니다.
- **원클릭 인앱 자동 업데이트**: 업데이트 감지 시 클릭 한 번으로 최신 패키지 다운로드부터 앱 번들 교체 및 재시작까지 완전 무인 진행.
- **Apple Silicon Unified Memory 연동**: 통합 메모리 구조에 맞춘 실시간 VRAM 점유량 및 GPU 연동 지표를 정확히 표시합니다.
- **macOS 시스템 테마 자동 동기화**: OS의 다크 모드 / 라이트 모드 전환(`AppleInterfaceStyle`)을 실시간 감지하여 UI 테마를 동기화합니다.
- **독립 데스크톱 웹앱 창 모드**: Chrome, Edge, Brave, Arc 등 설치된 브라우저 엔진을 감지하여 브라우저 주소창 없는 깔끔한 독립 윈도우로 구동됩니다.
- **로그 및 설정 경로 표준화**: macOS 표준 디렉터리(`~/Library/Application Support/CoreFlow`, `~/Library/Logs/CoreFlow`) 및 `LaunchAgents` 자동 시작 지원.

### 2. 📊 실시간 하드웨어 4대 핵심 지표 & 상세 분석 뷰
- **CPU 모니터링**: 전체 부하율(%), 물리/논리 코어 수, 코어별 개별 부하 매트릭스 및 상위 점유 프로세스 실시간 추적
- **RAM & 가상 메모리**: 물리 메모리 사용량/가용량(GB) 및 가상 메모리(Swap) 실시간 점유율
- **GPU 정밀 연동**: 
  - Windows: NVIDIA NVML / `nvidia-smi` 실시간 코어 사용률(%), 전용 VRAM, **코어 온도(°C)**, 소비 전력(W), 클럭(MHz)
  - macOS: Apple Silicon GPU 및 통합 메모리 점유 현황 실시간 감지
- **실시간 뷰 전환 (`📈 그래프 뷰` ↔ `🔢 수치 그리드`)**:
  - 메인 대시보드 및 각 부품별 상세 보기(카드 더블클릭)에서 **시각적인 차트 화면**과 **정밀 수치/테이블 중심의 그리드 화면**을 원클릭으로 전환할 수 있습니다.

### 3. 🎮 지능형 게임 감지 & 플레이타임/성능 자동 로거
- **자동 게임 프로세스 감지 및 오탐 방지**:
  - 실행 중인 게임을 자동으로 감지하며, 캡처 도구나 브라우저/메신저 등 비게임 오버레이는 스마트하게 필터링합니다.
  - 원하는 프로세스를 직접 **사용자 정의 게임(`⭐ 영구 등록`)**으로 추가하거나 즉시 타겟으로 지정할 수 있습니다.
- **세션별 자동 성능 집계 (`logs/game_play_log.tsv`)**:
  - 게임을 플레이하면 `시:분:초(HH:MM:SS)` 단위의 플레이 시간과 함께 **평균 FPS**, **1% Low FPS**, **최고 GPU 온도(°C)**, **피크 CPU/RAM 점유율**이 자동 기록됩니다.
- **기간별 플레이 랭킹**: `오늘` / `최근 7일` / `최근 30일` / `전체` 기간별로 가장 많이 플레이한 게임 순위와 점유율을 분석합니다.

### 4. 🌐 고정밀 네트워크(트래픽 & 게임 서버 핑) + 💽 디스크 I/O 모니터
- **실시간 게임 서버 핑(Ping) & 지터(Jitter) 스마트 산출**:
  - 실행 중인 게임 프로세스의 실제 활성 TCP 연결 커널 RTT를 추적합니다.
  - 게임 프로세스 내 다수의 연결이 열려 있을 때, **활성 트래픽 유무 및 최저 지연시간(Min-RTT) 가중 필터링**을 통해 실제 인게임 체감 핑을 정확히 표시합니다.
- **디스크 드라이브 & 프로세스별 I/O**:
  - 연결된 모든 드라이브의 용량 게이지와 함께, 현재 디스크 읽기/쓰기(`MB/s`)를 발생시키는 상위 프로세스를 실시간으로 추적합니다.

### 5. 🖼️ 실제 프로그램 아이콘(`.exe`) 자동 추출 및 캐싱
- 대시보드, 상세 보기(CPU/RAM), 디스크 I/O 목록, 게임 탐지 모달 등 모든 프로세스 목록에서 실행 파일의 **실제 프로그램 아이콘**을 직접 추출해 표시합니다.
- 추출된 아이콘은 백엔드 메모리 캐시(`ICON_CACHE`)와 프론트엔드 캐시에 저장되어 1초 주기 갱신 시에도 깜빡임이나 추가 부하가 없습니다.

### 6. 🗗 컴팩트 미니 HUD 모드 (`F10` 단축키)
- 상단의 **`🗗 미니 HUD`** 버튼 또는 **`F10`** 단축키로 언제든 작은 오버레이 창(Always-on-Top)으로 전환할 수 있습니다.
- `3×2 박스형(450×265)` 및 `6×1 가로 슬림 바(760×168)` 두 가지 레이아웃을 지원하며, 복귀 시 원래 창 크기와 위치가 정확히 복원됩니다.

### 7. 🔴 CSV 녹화 분석 스튜디오 & 🔔 스마트 경고 알림
- **녹화 및 분석 스튜디오**: 하드웨어 상태를 초 단위 UTF-8 CSV로 녹화하고, 내장된 분석 뷰어에서 구간별 평균/피크/타임라인 차트를 바로 확인할 수 있습니다.
- **스마트 경고 알림 & 히스토리 로그**: GPU 온도, CPU/RAM/VRAM 과부하, 장시간 게임 플레이 시 알림음과 배너로 경고를 띄우며, 발생 내역을 히스토리 로그에서 언제든 다시 확인할 수 있습니다.
- **집중 타이머(뽀모도로) & 할 일(Todo) 보드**: 작업과 학습을 돕는 타이머 및 체크리스트 기능을 함께 제공합니다.

---

## 🖥️ 시스템 요구 사항 (System Requirements)

| 항목 | Windows 요구 사양 | macOS 요구 사양 |
| :--- | :--- | :--- |
| **운영체제 (OS)** | Windows 10 (버전 1803 이상) 또는 Windows 11 (64-bit) | macOS 10.15 Catalina 이상 (macOS 11~15 Sequoia 호환) |
| **아키텍처** | x86_64 (64-bit) | Apple Silicon (M1/M2/M3/M4) 및 Intel x86_64 공용 |
| **런타임 엔진** | Microsoft Edge 또는 WebView2 (Windows 기본 내장) | Safari, Chrome, Edge, Brave, Arc 등 웹 뷰어 |
| **그래픽카드** | NVIDIA GPU 사용 시 드라이버 내장 모니터링 연동 | Apple Silicon 통합 GPU 실시간 연동 |

---

## 📥 설치 및 다운로드 방법

최신 버전 바이너리는 **[GitHub Releases](https://github.com/neverloselkb/coreFlow/releases)** 페이지에서 바로 다운로드하실 수 있습니다.

### 🪟 Windows 사용자
1. `CoreFlow_Setup.exe` 다운로드 후 실행 (원클릭 설치 관리자)
2. 또는 설치가 필요 없는 `CoreFlow.exe` 포터블 버전을 다운로드하여 원하는 폴더에서 바로 실행

> 💡 **Windows SmartScreen 안내**:  
> 최초 실행 시 *"Windows의 PC 보호"* 알림이 뜨면 **`[추가 정보]` → `[실행]`**을 누르시면 됩니다.

### 🍎 macOS 사용자
1. `CoreFlow-macOS-universal.zip` 다운로드 후 압축 해제
2. 해제된 `CoreFlow.app`을 `/Applications` (응용 프로그램) 폴더로 드래그하여 이동
3. `CoreFlow.app`을 실행합니다.

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

# 2) CoreFlow_Setup 설치 마법사 빌드
cargo build --release --bin CoreFlow_Setup
```

#### 🍎 macOS 환경
```bash
# Apple Silicon & Intel Universal 바이너리 빌드
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin --bin CoreFlow
cargo build --release --target x86_64-apple-darwin --bin CoreFlow

# lipo를 통한 Universal 바이너리 합치기
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
│       └── release.yml        # Windows & macOS Universal 자동 빌드 및 배포 CI/CD
├── assets/
│   └── coreflow.ico           # 앱 및 인스톨러 멀티해상도 아이콘 리소스
├── src/
│   └── bin/
│       ├── tui_app.rs         # CoreFlow 메인 엔진 (백엔드 모니터링 + 내장 웹 서버 + UI/HUD)
│       └── setup.rs           # CoreFlow_Setup 전용 GUI 설치 마법사 및 자동 업데이트 관리자
├── build.rs                   # Windows COFF 아이콘 임베딩 및 빌드 설정 스크립트
├── Cargo.toml                 # Rust 패키지 및 바이너리 타겟 메타데이터
└── README.md                  # 프로젝트 소개 및 매뉴얼 문서
```

---

## 📝 라이선스 (License)

이 프로젝트는 [MIT 라이선스](LICENSE) 하에 자유롭게 사용할 수 있습니다.
