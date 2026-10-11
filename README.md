# Malody 判定逆向（PC + Android）

Malody 判定逻辑逆向的脚本与笔记。

- **PC 端** —— Windows x86，目标 `malody.exe`（PE32，基址 0x400000）
- **Android 端** —— arm64，目标 `libmalodycpp.so`（从 `base.apk` 解出）

两版**同源**，`base` 阶梯完全一致，只有窗口槽位表不同。

---

## 目录结构

```
pc/        桌面 x86 脚本
android/   手机 arm64 脚本
docs/      逆向笔记
```

### `android/` —— 手机端

| 文件 | 用途 |
|---|---|
| `malody_judge_android.js` | **主脚本**。hook 判定函数，实时打印 delta / 档位 / 早晚；检测到窗口变化（换判定等级）自动重新 dump |
| `malody_judge_run.py` | **驱动**。连远程 device，spawn `re.frida.Gadget`，日志落盘。带单实例锁 |
| `arm64_dis.py` | 带注释的 arm64 反汇编器（adrp+add 折叠成字符串、bl 标目标）|
| `arm64_xref.py` | adrp+add 字符串交叉引用查找（可续跑，绕过 capstone 遇坏字停下的问题）|
| `find_judge_fn.py` | 按"行为签名"打分找判定函数 |
| `find_judge_ctor.py` | 找判定对象构造函数；生成 `insns.pkl` 指令缓存 |
| `find_judge_android.py` / `find_judge_android2.py` | 早期的常量序列扫描（桌面槽位常量在 arm64 上全零命中，保留作记录）|
| `find_window_consts.py` | **按窗口常量立即数定位窗口配置函数**（最终靠它找到等级公式）|

### `pc/` —— 桌面端

| 文件 | 用途 |
|---|---|
| `frida_read_judge.py` | 判定读取器（手机端脚本的原型）|
| `frida_judge.py` / `frida_judge4.py` | 判定 hook，读原始栈取 note / time |
| `frida_allbest*.py` | 全 best 实验 |
| `frida_guard*.py` | 数值守卫实验 |
| `frida_disasm*.py` / `frida_dump_config.py` | 反汇编与配置 dump |
| `frida_hook.py` | 最早期探针 |
| `find_boundaries.py` / `find_low_boundary.py` | 从日志统计边界 |

---

## 关键结论

**窗口 = 槽位 + base**，四段为 best / cool / good / worst，超出阈值即不判定（`mask = 0x40000000`）。

| 等级 | base | 桌面槽位 36/76/110/160 | 手机槽位 45/85/130/170 |
|---|---|---|---|
| A | 20 | 0-56 / 57-96 / 97-130 / 131-180 | 0-65 / 66-105 / 106-150 / 151-190 |
| B | 10 | 0-46 / 47-86 / 87-120 / 121-170 | 0-55 / 56-95 / 96-140 / 141-180 |
| C | 0 | 0-36 / 37-76 / 77-110 / 111-160 | 0-45 / 46-85 / 86-130 / 131-170 |
| D | −8 | 0-28 / 29-68 / 69-102 / 103-152 | 0-37 / 38-77 / 78-122 / 123-162 |
| E | −16 | 0-20 / 21-60 / 61-94 / 95-144 | 0-29 / 30-69 / 70-114 / 115-154 |

- **手机五档全部实测**，与代码里的等级公式零偏差
- 手机槽位比桌面宽 9~20ms（good 档 +20ms）
- `base = (2-level)*10`（level ≤ 1）／`0`（level = 2）／`(2-level)*8`（level ≥ 3），见 `docs/` §E

**mask 结构**（两版一致）：低 5 位档位 `2`=best `4`=cool `8`=good `1`=worst；`0x40`=早 `0x20`=晚；`0x40000000`=无判定。

---

## 跑手机端

前置：先用 JsHook 把 Gadget 挂起来（连接标识是 `re.frida.Gadget`，不是包名）：

```powershell
& 'C:\Users\lenov\frida-diagnosis\Connect-JsHookGadget.ps1' -PackageName 'me.mugzone.malody' -RestartApp
& 'F:\frida16\Scripts\python.exe' -u 'C:\Users\lenov\malody_re\malody-judge-re\android\malody_judge_run.py'
```

按等级分文件存日志：加 `--label A` → `judge_android_A.txt`；`--append` 可改为追加。

**换判定等级**：退出谱面 → 改设置 → 重进谱面即可，**不需要重启 App**。
每换一档打 1~2 个音符，日志会出现一行 `[窗口#N] best=.. cool=.. good=.. cutoff=..`。

---

## 环境

- Frida 16.7.19（客户端与 Gadget 版本须一致），Python 绑定位于 `F:\frida16\Scripts\`
- capstone 5.0.7（objdump 不支持 AArch64，静态分析全走 capstone）

## 不在仓库里的文件

体积大，留在上级目录 `C:\Users\lenov\malody_re\`，脚本以绝对路径引用：

| 文件 | 说明 |
|---|---|
| `libmalodycpp.so` | arm64 引擎，静态分析目标（从 `base.apk` 解出）|
| `base.apk` | 从手机拉取的安装包 |
| `insns.pkl` | `.text` 全量解码缓存，由 `find_judge_ctor.py` 生成 |
| `judge_android_log.txt` | 手机端判定日志（驱动写入）|
