# SECMI

**SECMI** 提供 SM2、SM3、SM4 等能力的 **纯 C 实现**，经 [Emscripten](https://emscripten.org/) 编译为单文件 **`gm.js`**，可在浏览器中通过 JavaScript 调用，配套静态页面提供在线工具与说明。

### 克隆下来后 点开/web/index.html进行调试使用

**仓库地址：** [https://github.com/npcxl/SecMi](https://github.com/npcxl/SecMi)

```bash
git clone https://github.com/npcxl/SecMi.git
cd SecMi
```

---

## 简介

SECMI 将 SM2、SM3、SM4 等算法以可读、可审计的 C 代码实现，统一在 `gm.c` 中导出 `gm_*` API，再编译为浏览器可用的 `gm.js`。前端页面（`web/`）仅负责 UI 与输入校验，**运算在本地 WASM 中完成**，默认不向服务器上传密钥与业务数据。

---

## 能力概览

| 模块 | 说明 |
|------|------|
| **SM3** | 杂凑、HMAC-SM3 |
| **SM4** | CBC / ECB（PKCS#7）、CTR、OFB、CFB；S 盒可选现行版 / 早期印刷版 |
| **SM2** | 密钥生成、签名 / 验签、公钥加解密（C1C2C3 / C1C3C2）、ECDH 共享密钥 |

实现遵循相关国标与常见工程约定（如 GB/T 32918 系列、SM3/SM4 标准等），具体以源码与注释为准。

---

## 目录结构（摘要）

| 路径 | 说明 |
|------|------|
| `gm.c` | Emscripten / 本地共用入口，导出 `gm_sm3_*`、`gm_sm4_*`、`gm_sm2_*` 等 |
| `sm2.c` / `sm2.h` / `sm2_z256.*` | SM2 与域运算 |
| `sm3.c` / `sm3.h` | SM3 |
| `sm4.c` / `sm4.h` | SM4 |
| `gm_types.h` | 公共类型与宏 |
| `gmssl_compat.c` | 兼容层 |
| `build.bat` / `build.ps1` / `build.sh` | 调用 `emcc` 生成根目录 `gm.js` |
| `web/index.html` | 站点入口 |
| `web/main/*.html` | 各算法在线工具页（懒加载 `gm.js`） |
| `test.html` | 本地全功能测试页（开发用） |

构建成功后，**项目根目录**应生成 **`gm.js`**，供 `web/` 内页面通过相对路径引用（如 `../../gm.js`）。

---

## 构建要求

- [Emscripten](https://emscripten.org/docs/getting_started/downloads.html)（`emcc` 在 `PATH` 中，或已执行 `emsdk` 的环境脚本）
- Windows 可用 **PowerShell** 运行 `build.ps1`，或双击/运行 `build.bat`
- Linux / macOS 可执行：`chmod +x build.sh && ./build.sh`

### 构建命令

```powershell
# Windows（PowerShell，在项目根目录）
.\build.ps1
```

```bash
# Linux / macOS
./build.sh
```

成功后在仓库根目录得到 **`gm.js`**（单文件输出，含 asm.js，当前脚本配置为 `-s WASM=0` 等，详见 `build.ps1`）。

---

## 使用 Web 界面

1. 先完成上述构建，确认根目录存在 **`gm.js`**。
2. 用本地静态服务器打开 `web/`（避免部分浏览器对 `file://` 限制），例如：
   - `npx serve web` 或
   - VS Code Live Server 等，将站点根指向 `web` 或项目根并按实际路径访问。
3. 浏览器打开首页后，进入 **SM2 / SM3 / SM4** 等子页即可在本地运算。

---

## 安全与隐私说明

- 本仓库前端设计为**本地计算**；请勿在不可信环境输入真实生产密钥。
- `gm.js` 与页面可从任意静态托管部署；是否 HTTPS、是否缓存由部署方决定。
- 算法实现仅供学习、联调与合规评估参考；生产环境请结合审计、渗透与合规要求使用。

---

## 许可证

若未另行添加 `LICENSE` 文件，默认以仓库后续补充的许可证为准；使用前请留意根目录许可证声明。

---

## 相关链接

- **GitHub：** [https://github.com/npcxl/SecMi](https://github.com/npcxl/SecMi)
- **克隆：** `git clone https://github.com/npcxl/SecMi.git`
