# Delta 简体中文汉化包

给 [Zed Industries 的 Delta](https://delta.dev)（macOS 版 AI 编程 Agent 客户端）做的社区简体中文汉化。

Delta 是闭源应用，界面文字直接编译在主程序二进制里，官方没有提供任何语言包机制。
本项目通过分析 Mach-O 二进制、精确定位每一条 UI 字符串并原地替换 / 搬迁的方式实现汉化，
**不需要源码，也不修改 Delta 的功能**。

- 词典：`translations.json`，1150+ 条，覆盖菜单栏、侧栏、设置全部页面、命令面板、会话视图、
  分享 / 审查 / 文件窗格、常见提示与错误信息。
- 工具：`delta_i18n.py`，一条命令打补丁，一条命令还原。

## 使用

要求：macOS（Apple Silicon）、已安装 Delta、Python 3 与 numpy。

```bash
git clone https://github.com/<你的用户名>/delta-zh-cn.git
cd delta-zh-cn
pip3 install numpy          # 只需要这一个依赖
```

先**退出 Delta**，然后：

```bash
python3 delta_i18n.py apply
```

工具会：

1. 把原版主程序备份到 `~/Library/Application Support/delta-zh-cn/delta-<版本>.orig`；
2. 分析二进制、写入译文；
3. 用 ad-hoc 签名重新签名（修改后原签名必然失效）。

重新打开 Delta 即可看到中文界面。

还原为英文原版：

```bash
python3 delta_i18n.py restore
```

只看会打多少补丁、不改动任何文件：

```bash
python3 delta_i18n.py check
```

### Delta 自动更新之后

Delta 更新后主程序会被官方版本覆盖，界面变回英文，重新执行 `apply` 即可。
工具每次都实时分析当前二进制，不依赖固定地址，通常直接可用；若新版本改了文案，
`check` 会列出"未找到"的词条，欢迎提 PR 补充。

### 关于"应用管理"权限

macOS 不允许普通进程直接改写其它 App 包内的文件。工具在遇到这种拒绝时会自动改为
"复制整个 Delta.app → 在副本里打补丁 → 整包换回 `/Applications`"，无需手动授权。

## 已知限制

- **4–5 字节的极短词无法翻译**（如 `Pane`、`Code`、`Theme`、`Copy`、`Proxy`）：原位替换要求译文字节数不超过
  原文，中文一个字 3 字节；而这些词的引用方式又不允许搬迁。它们会保留英文。
- **命令面板里的部分命令名**（如 `Edit Global Rules`、`Send Comment`）是运行时从动作标识符
  自动生成的，二进制里没有对应字符串，无法翻译。
- 极少数词条在同一版本里有多处副本，其中某一处的引用方式不安全时会保留英文（`check` 里的"部分"）。
- 只支持 macOS arm64 单架构的 Delta 发行版。
- 改过的 Delta 使用 ad-hoc 签名，Delta 自带的自动更新仍然可用；若遇到 Gatekeeper 提示，
  在 Finder 里右键 → 打开一次即可。

## 原理

1. **定位字符串**。Rust 的 `&str` 没有结尾符，长度存放在引用它的地方。工具扫描
   `__TEXT,__text` 里的 `adrp + add`（取地址）与 `adrp + ldr`（拷贝）指令对、附近给出长度的 `movz`，
   以及 `__DATA_CONST` 里经 chained fixups 重定位的 `(ptr, len)` 胖指针，得到每条字面量精确的
   起点和长度。
2. **原位替换**。译文不长于原文时直接覆写，不足的字节用零宽字符（U+200B / U+034F / U+E0001）补齐，
   渲染时不可见。替换前会用该字面量所有可能的读取长度做 UTF-8 校验，避免把多字节汉字切断。
3. **搬迁**。译文更长时，把它写到二进制里无人使用的填充区（Mach-O 头页余量、`__TEXT` /
   `__DATA_CONST` 段尾的对齐空洞，共约 14 KB），然后改写所有引用：`adrp`/`add` 立即数、`movz` 长度、
   胖指针的目标与长度。只有当每一处引用都能被安全改写（长度寄存器与指针成对存储 / 传参、
   中途未被复用）时才搬迁，否则保留英文。
4. **重新签名**。`codesign --sign -`，保留原有 entitlements 与硬化运行时。

## 参与翻译

`translations.json` 是一个扁平的 `{"英文原文": "中文"}` 字典，键必须和二进制里的字符串**逐字节相同**。
导出当前版本所有可翻译的字符串：

```bash
python3 delta_i18n.py dump > strings.tsv
```

改完后 `python3 delta_i18n.py check` 看是否都能应用（译文太长又无法搬迁的会被列出），
然后 `apply` 实际验证。

术语约定：Thread → 会话，Subagent → 子代理，Worktree → 工作树，Runner → 运行器，
Review → 审查，Pane → 窗格，Command Palette → 命令面板，Profile → 配置档案，
Compaction → 压缩上下文，Checkout → 检出目录。

## 许可

本仓库的工具与词典以 MIT 协议发布。Delta 本身归 Zed Industries 所有，本项目不分发任何 Delta 的二进制文件。
