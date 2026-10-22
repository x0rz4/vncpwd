# vncpwd 2.0 — VNC 凭据与安全审查工具

[English](README.md) | **中文**

按 VNC 产品识别本地保存的凭据、判断实际使用的认证方式，并给出安全风险评级。

本工具只读取**本机已有**的配置文件与注册表，不连接网络、不尝试登录、不实现
RA2 与 VeNCrypt 握手。

最初版本 `vncpwd 0.2` 是 Luigi Auriemma 的 VNC Password Decoder
（GPL-2.0-or-later），只能处理经典 VNC 固定密钥 DES 格式。

---

## 为什么不是"再加几种解密算法"

VNC 相关的密码数据分三类，混淆它们会导致错误结论：

| 类别 | 位置 | 能否本地还原 |
|---|---|---|
| 服务端保存的密码 | 注册表 / `ultravnc.ini` / `~/.vnc/passwd` | 经典 VNC 格式可以（固定密钥 DES） |
| Viewer 保存的连接凭据 | `*.vnc` / `*.remmina` | 部分可以，取决于客户端 |
| 远程认证协议 | RA2 / RA2_256 / VeNCrypt / MS-Logon / SSO | **不能**，本地没有可解材料 |

所以 2.0 的目标是：能解的准确解出，不能解的说清楚**为什么不能**，并指出配置上的风险。

## 已支持的格式与位置

| 产品 | 位置 | 格式 | 认证审计 |
|---|---|---|---|
| RealVNC 4–8 | `HKLM\SOFTWARE\RealVNC\vncserver{4,}`、`HKCU\Software\RealVNC` | REG_SZ hex / REG_BINARY | `Authentication`、`Encryption`、`SecurityTypes` |
| TightVNC 2.x | `HKCU`/`HKLM\Software\TightVNC\Server` | `Password`、`PasswordViewOnly` | — |
| TigerVNC（Windows） | `HKCU`/`HKLM\...\TigerVNC\WinVNC4` | REG_SZ hex | `SecurityTypes`（RA2 / RA2_256 / VeNCrypt） |
| TigerVNC（Unix） | `~/.vnc/passwd` | 8 或 16 字节 | 文件权限 |
| UltraVNC | `ultravnc.ini` 的 `passwd`、`passwd2`、`[admin] passwd` | hex | `MSLogonRequired`、`DSMPlugin`、`AuthRequired`、`UseRegistry` |
| UltraVNC | `HKLM`/`HKCU\SOFTWARE\ORL\WinVNC3` | hex / binary | `UseRegistry=1` 回退路径 |
| x11vnc / libvncserver | `~/.vnc/passwd` | 8 或 16 字节 | 文件权限 |
| TurboVNC | `~/.vnc/passwd` | 8 或 16 字节 | 文件权限 |
| Viewer 连接文件 | `*.vnc`、`~/.remmina/*.remmina` | hex、base64(hex) | — |

`--deep` 会递归遍历产品注册表子树，抓取名称含 `pass` 的非标准值。

## 构建

需要 CMake ≥ 3.16 与 C17 编译器。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Windows 上直接产出 `build\Release\vncpwd.exe`（MSVC 或 MinGW 均可）。

## 用法

```sh
# 扫描本机
vncpwd scan
vncpwd scan --json
vncpwd scan --product tightvnc --show
vncpwd scan --deep

# 审计：只输出风险项，适合脚本判断
vncpwd audit
vncpwd audit --json

# 检查单个密文 / 文件
vncpwd inspect --hex dbd83cfd727a1458
vncpwd inspect --raw '12345678'
vncpwd inspect --file saved.vnc
vncpwd inspect path/to/ultravnc.ini

# 列出已注册的产品标识
vncpwd list
```

| 选项 | 说明 |
|---|---|
| `--show` | 输出明文密码；默认脱敏为 `p*** (len 8)` |
| `--json` / `--csv` | 机器可读输出 |
| `--product <id>` | 限定单个产品 |
| `--deep` | 递归遍历注册表子树 |
| `-q` | 去掉横幅（不影响结果输出） |

退出码：`0` 无高危项，`1` 存在 high/critical，`2` 用法或 I/O 错误。
可直接用于 CI 或巡检脚本。

## 输出示例

```
[TightVNC] Software\TightVNC\Server \ Password
  auth: vnc-password  encoding: binary  cipher: 8 bytes
  password: p******* (len 8)  (confidence 95%)
  note: primary password

Findings
--------
  [high    ] RECOVERABLE-VNC-PASSWORD password stored with the public fixed DES key
             at Software\TightVNC\Server\Password
  [medium  ] WEAK-PASSWORD          password is short or uses a single character class
  [info    ] MAX-LENGTH-PASSWORD    protocol caps the password at 8 characters
```

## 置信度

DES 没有 MAC、没有填充校验，任何 8 字节密文都能"解出"8 字节。
因此解密成功不等于密码正确。工具按以下规则打分：

- 明文中含**非可打印字节** → 判定失败（`confidence 0.05`），通常是错误猜测的特征
- 明文为**全零块** → 视为"未设置密码"，不当作空密码
- 全可打印 ASCII → `0.80` 起，8 字节再 `+0.10`，4 字节以上 `+0.05`
- 低于 `0.60` 的一律标记为"不可还原"，不输出猜测结果

## 安全说明

- 默认**不打印明文**，需要显式 `--show`。请勿把带 `--show` 的输出写入共享日志或工单。
- 只读访问：不修改任何注册表键或配置文件。
- 工具本身不包含任何远程探测或凭据喷洒能力。

**仅可用于你拥有或已获授权的系统。**

## 项目结构

```
include/          公共头文件
src/core/         DES、编码、格式校验、格式识别、工具函数
src/parsers/      注册表、INI、连接文件解析
src/providers/    各产品的位置表与认证审计
src/reports/      文本 / JSON / CSV 输出
src/inspector.c   scan / inspect 调度
tests/            单元测试与 CLI 端到端测试
.github/workflows/build.yml
```

## CI

`.github/workflows/build.yml` 在 GitHub 上执行：

- **test** — Ubuntu / macOS / Windows，Debug + `-Werror`
- **sanitizers** — Clang + ASan + UBSan + `-Werror`
- **gcc** — GCC 13 Release + `-Werror`
- **windows** — MSVC x64 与 x86，运行测试并上传制品
- **linux** — x86_64 与 aarch64 静态链接二进制
- **release** — 推送 `v*` 标签时汇总产物并生成校验和

## 许可证

MIT，见 [LICENSE](LICENSE)。

`src/core/des.c` 源自 Richard Outerbridge 的公有领域实现 D3DES，VNC 部分的修改
版权归 AT&T Laboratories Cambridge。相关声明与 MIT 授权的适用范围收录在
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

VNC、RealVNC、TightVNC、TigerVNC、UltraVNC、TurboVNC 等名称归各自权利人所有，
本项目与它们无隶属关系。
