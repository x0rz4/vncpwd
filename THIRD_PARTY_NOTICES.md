# Third-party notices / 第三方声明

This project is distributed under the MIT License (see `LICENSE`). This file
records the works the code derives from and reproduces their notices.

本项目以 MIT 许可证发布（见 `LICENSE`）。本文件记录代码的来源，并转载其原始声明。

---

## D3DES — `src/core/des.c`

The DES implementation in `src/core/des.c` is a rewrite of D3DES V5.09, as
modified for VNC by AT&T Laboratories Cambridge. The rewrite narrows the
arithmetic to `uint32_t`; the algorithm, tables and structure are unchanged.

`src/core/des.c` 是 D3DES V5.09 的重写版本。原始 D3DES 曾由 AT&T Laboratories
Cambridge 为 VNC 改造。重写只把运算宽度收窄为 `uint32_t`，算法、置换表与结构均未改动。

```
D3DES (V5.09) - A portable, public domain, version of the Data Encryption
Standard.

Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
(GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.

Changes for VNC, and reversal of the bytebit[] array:
Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

D3DES is public domain with the permissive notice above, so it can be
redistributed under the MIT License.

D3DES 为公有领域代码，附带上文的宽松声明，因此可以按 MIT 许可证再分发。

The previous `d3des.c` / `d3des.h` from vncpwd 0.2 have been removed. They used
`unsigned long` for DES arithmetic, which is 64 bits on LP64 platforms and
produced incorrect results there; `src/core/des.c` replaces them.

vncpwd 0.2 原有的 `d3des.c` / `d3des.h` 已删除。它们使用 `unsigned long` 进行 DES
运算，在 LP64 平台上为 64 位，会导致结果错误；现已由 `src/core/des.c` 取代。

---

## vncpwd 0.2 — original CLI (not part of this distribution)

The 2.0 codebase is a new implementation. Its purpose and command-line shape
follow vncpwd 0.2 by Luigi Auriemma, which was released under the GNU General
Public License, version 2 or later:

2.0 代码库为全新实现，其用途与命令行形态沿用 Luigi Auriemma 的 vncpwd 0.2。
原始版本以 GNU 通用公共许可证第 2 版或更高版本发布：

```
Copyright 2006 Luigi Auriemma

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

The vncpwd 0.2 sources (`vncpwd.c`, `d3des.c`, `d3des.h`) and its compiled
`vncpwd.exe` have been removed from this repository. They remain available
under GPL-2.0-or-later from the upstream project and from this repository's
git history up to the commit that removed them. No GPL-licensed code is
compiled into the current binaries.

vncpwd 0.2 的源码（`vncpwd.c`、`d3des.c`、`d3des.h`）及其编译产物 `vncpwd.exe`
已从本仓库移除。这些文件仍可按 GPL-2.0-or-later 从上游项目获取，或从本仓库删除
它们的提交之前的 git 历史中获取。当前构建的二进制中不包含任何 GPL 代码。

---

## Scope / 授权范围

Everything in this repository — `include/`, `src/`, `tests/`, the build files
and the documentation — is covered by the MIT License, except where a notice
above states otherwise.

本仓库的全部内容——`include/`、`src/`、`tests/`、构建脚本与文档——均适用 MIT
许可证；上文另有声明的部分除外。
