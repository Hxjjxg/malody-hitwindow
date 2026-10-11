# Malody 4.3.7 Key 模式判定逆向 — 完整发现

> 目标：定位 Key 模式判定代码，还原判定窗口，验证社区实测的 **B判 ≈ ±46.5ms**。
> 状态：**✅ 判定函数已定位，窗口已还原，实测验证完成**
> 更新：2026-08-18

---

## 0. 一句话结论

> **Malody Key 模式最佳判定(A)的窗口边界是精确的 46ms**（`judgeObj[4]+judgeObj[8] = 10+36`，整数毫秒比较）。
> 社区实测的 **B判 ±46.5ms** 就是这条 A/B 边界（46.5 与 46 的 0.5ms 差异来自测量方法/输入延迟）。

---

## 1. 判定函数（已定位）

| 函数 | IDA 地址 | 作用 |
|------|---------|------|
| `sub_535C40` | 0x535C40 | **Key-down 判定**（点击判定） |
| `sub_535D50` | 0x535D50 | Key-up 判定（长按/释放） |
| `sub_535DA0` | 0x535DA0 | 自动判定（note 滑过判定线→Miss） |

判定对象 `judgeObj` 挂在 base play 对象 +764，vtable = **0xbe019c**：
- vtable[2] (offset 8) = sub_535C40
- vtable[3] (offset 12) = sub_535D50
- vtable[4] (offset 16) = sub_535DA0

调用点（sub_5AC1B0 / sub_5AD7F0 内）：
```c
mask = judgeObj->vtable[2](judgeObj, note, currentTime_int);
if (mask != 0x40000000)              // 0x40000000 = "无判定" 哨兵
    playObj->vtable[184](playObj, note, mask);   // 应用判定事件
```

---

## 2. 判定窗口（judge_level=1 实测）

### 反编译还原（sub_535C40 核心逻辑）

```c
int __thiscall sub_535C40(_DWORD *this /*judgeObj*/, _DWORD *a2 /*note*/, int a3 /*currentTime*/)
{
    if (a2[29] & 1) return 0x40000000;          // note 已判定过 → 无判定
    v7  = a2[19] - a3;                          // ★ delta = noteTime - currentTime (ms)
    if (v7 > this[4] + this[11]) return 0x40000000; // 太早 (>170ms) → 等
    n64 = (v7 <= 0) ? 0x20 : 0x40;              // 晚=0x20 / 早=0x40 标记
    v10 = |v7|;
    if      (v10 <= this[4] + this[8])  n8 = 2; // 最佳判
    else if (v10 <= this[4] + this[9])  n8 = 4;
    else if (v10 <= this[4] + this[10]) n8 = 8;
    else                                n8 = 1; // 最差可接受判
    return n8 | n64;                            // 档位位 | 早/晚位
}
```

### 运行时实读 judgeObj 字段

| 字段 | 值 | 含义 |
|------|-----|------|
| this[4] | 10 | 基准 |
| this[8] | 36 | → **46ms** |
| this[9] | 76 | → **86ms** |
| this[10] | 110 | → **120ms** |
| this[11] | 160 | → **170ms**（太早上限） |

### 最终窗口表（|delta| ≤ X 进档，整数 ms）

| 档位位 | 窗口 | 推断字母 |
|--------|------|---------|
| bit 2 | **\|delta\| ≤ 46ms** | **A**（最佳） |
| bit 4 | 46 < \|delta\| ≤ 86ms | B |
| bit 8 | 86 < \|delta\| ≤ 120ms | C |
| bit 1 | 120 < \|delta\| | D |
| — | delta > 170ms | 太早，不判（等 note 靠近） |
| — | note 滑过未击中 | Miss（见 §2.6，普通note≠sub_535DA0） |

> ⚠️ 字母映射为推断（按 5 计数器顺序 bit2→counter+32→judge-0）。**待肉眼确认：delta≈46 是否显示 A、47 显示 B。**

---

## 2.5 判定区间数据的静态存储位置（关键）

### 判定区间数据硬编码在 `malody.exe` 的 `.text` 段构造函数里

| Judge 类 | 构造函数 | vtable | [8]/[9]/[10]/[11] | 说明 |
|---------|---------|--------|-------------------|------|
| **JudgeKey** | `sub_535B80` | JudgeKey::vftable | **36 / 76 / 110 / 160** | 正常 Key 判定 |
| **JudgeKeyFair** | `sub_535E00` | JudgeKeyFair::vftable | **45 / 85 / 120 / 170** | "公平"判定（图表属性触发）|
| JudgeSlide | `sub_536A20` | JudgeSlide::vftable | 36 / 76 / 110 / 160 | 滑键 |
| JudgePad | `sub_5B02A0` | JudgePad::vftable | [12..15]=45/85/230/160 | Pad |
| JudgeJubeat | `sub_535FD0` | JudgeJubeat::vftable | 40 / 80 / 160 / 383 | Jubeat |

- `JudgeKey` 构造函数核心：`this[8]=36; this[9]=76; this[10]=110; this[11]=160`
- `JudgeKeyFair` 在 JudgeKey 基础上覆写为 `45/85/120/170`
- **Fair 触发条件**：`chartData[13] > -1 && (*chartData & 0x400)`（图表/Mod 属性），见 `sub_5A77C0`/`sub_59D580`/`sub_5AF950`/`sub_5AFBD0`
- 判定对象在 play 对象 +764（或 +772）创建，vtable 在 `.data` 虚拟区

### 窗口基准 this[4]（随 user_judge_level 缩放）

**实测 5 档 judge_level 窗口（用户逐档实测，整数 ms）：**

| 档 | best | cool | good | miss(4档) | 基准[4] |
|----|------|------|------|----------|--------|
| **B**(默认=1) | 0-46 | 47-86 | 87-120 | 121+ | **+10** |
| **A** | 0-56 | 57-96 | 97-130 | 131+ | **+20** |
| **C** | 0-36 | 37-76 | 77-110 | 111+ | **0** |
| **D** | 0-28 | 29-68 | 69-102 | 103+ | **−8** |
| **E** | 0-20 | 21-60 | 61-94 | 95+ | **−16** |

- 公式统一：`best ≤ [4]+36，cool ≤ [4]+76，good ≤ [4]+110，miss 上限 [4]+160`
- **[4] 是唯一随档位变化的字段**（构造后写入，代码里非简单立即数）
- [4] 序列：`20, 10, 0, −8, −16`（A→B→C 每档 −10，C→D→E 每档 −8，疑似分段公式或查找表）
- **待确认**：代码里 [4]=f(judge_level) 的具体公式/表（IDA MCP 断连，需恢复后查 `[4]` 写入点）

### 静态寻找的"看哪里"清单
1. **malody.exe**（唯一逻辑文件；skin.dll 是资源容器，无代码）
2. **`.text` 段**（RVA 0x1000 / 文件偏移 0x400）：judge 构造函数 + 判定函数 `sub_535C40` + play 设置 `sub_5A77C0` 等
3. **`.data` 段**：**VSize=0xc29d08(12MB) 但 FileSize 仅 0x23400(144KB)**，绝大部分是运行时填充的虚拟内存——JudgeKey vtable(0xbe019c)、config 全局(0xc31210)都在这里，**文件字节里 grep 不到**
4. **`.rdata` 段**：字符串常量（"user_judge_level" 等配置键）

### 关键教训
> 这个 exe 的 `.data` 段 95% 是运行时构造的（vtable/全局对象），所以**对文件做字节 grep 找不到 vtable 和判定常量**。必须：IDA 虚拟镜像里找构造函数 → 反编译确认硬编码值；或运行时用 Frida 读内存。

---

## 2.6 Miss 路径 + 全 best 实现（2026-08-19 实测成功）

### 反常识发现：普通 note 的 miss 不走 judge 函数

之前以为"滑过未击中 → judge vtable[4]=sub_535DA0 → miss(0x80)"。**实测为错**：

- `sub_535DA0` **只处理长条(hold)note**：第一行 `if ((note[27] & 0x80) == 0) return 0x40000000;`（note+108 bit7=长条flag），普通 tap note 直接返回无判定。长条漏判返回 `0x80`
- **普通 tap note 的漏判在每帧循环 `sub_5AC1B0` 内联处理**（不走任何 judge vtable）：
  ```c
  // sub_5AC1B0 内, 遍历 note 列表:
  if ( note时间 < 当前线 ) {                       // 已滑过判定线
      if ( (note[116] & 1) == 0 ) {               // 未判定
          note[116] |= 1;                          // 标记已判定
          playObj->vtable[184](playObj, note, 33); // ★ 直接传掩码 33 = 0x21 (晚+最差档)
      }
  }
  ```
- **判定结算统一入口 = `playObj->vtable[184]` = `sub_5ADC90`**（RVA 0x1adc90）。所有判定掩码（点击0x42/0x22…、普通漏判0x21、长条漏判0x80）都流经它

### 全 best 实现（frida_allbest_v2.py）

核心 1 个 hook + 2 个兜底：
| 钩 | 地址(RVA) | 作用 |
|----|-----------|------|
| 结算入口 vtable[184] | 0x1adc90 | 掩码强制 `(mask&0x60)\|0x2`，覆盖普通漏判 0x21 |
| key-down judge | 0x135c40 | 点击判定强制 best |
| 长条 auto | 0x135da0 | 长条漏判 0x80 强制 best |

`sub_5AC1B0` 每帧钩用来动态发现 play 对象 → 解出 vtable[184] 函数再静态挂 hook（因 ASLR 每次启动变化）。

**实测结果：进图完全不按，结算全 best、零 miss。**

---

## 3. 动态实测验证

### 实测 (delta, 档位位) 数据

| delta (ms) | 实测 mask | 档位位 | 与公式 |
|-----------|----------|--------|--------|
| -40 | 0x42 | 2 | ≤46 ✓ |
| 82 | 0x24 | 4 | 46~86 ✓ |
| 30 | 0x22 | 2 | ≤46 ✓ |
| 34 | 0x22 | 2 | ≤46 ✓ |
| -43 | 0x42 | 2 | ≤46 ✓ |

mask 结构：`档位位(低5位) | 早/晚`，0x40=早、0x20=晚。
- 0x42 = 早 + bit2（A 判）
- 0x22 = 晚 + bit2（A 判）
- 0x24 = 晚 + bit4（B 判）

### 用户肉眼观察

> **"46 和 47 的判定档位不同"** → 边界在 46/47 之间 = 精确 46ms。与代码常量 10+36=46 完全一致。

---

## 4. 社区数据对比

| 来源 | 值 | 对应 |
|------|-----|------|
| 社区（随机信号理论） | B判 ±46.5ms | A/B 边界 |
| 代码常量 | **46ms** | judgeObj[4]+[8] |
| 用户实测 | 46 vs 47 档位不同 | 边界 = 46 |

0.5ms 差异解释：社区的随机信号推断包含输入/音频延迟；代码是整数毫秒精确比较 `|delta| <= 46`。

---

## 5. 调用链与对象布局

### 击打流程
```
按键 → sub_537300(column) → 找 note (sub_5371E0 按列查哈希表)
     → data->vtable[1] → sub_5AD7F0(note, 按键状态)
     → judgeObj->vtable[2](judgeObj, note, currentTime) = sub_535C40  ★判定
     → mask ≠ 0x40000000 → playObj->vtable[184] → sub_5AD7F0 结算链
     → sub_53C1D0/sub_53CEF0/sub_53D6E0/sub_53DFE0 (HP/分数/连击/计数)
```

### 每帧自动判定（sub_5AC1B0）
```
note 时间 (note+76, int) >= 当前时间 (playObj+824, double) 前
若 note 未击中且滑过 → judgeObj->vtable[4](...) = sub_535DA0 → Miss (mask=0x80)
```

### 关键对象字段
- base play 对象：+764 = judgeObj；+816/+824 = 当前时间(double)；+1316 = note 列表
- judgeObj（vtable=0xbe019c）：[4]=基准10、[8]=36、[9]=76、[10]=110、[11]=160
- HitObjectKey note：+76 = 时间(int, ms)、+108 = 标志(bit7=长条)、+116 = 状态、+124 = 列
- Key play 结算对象：+32/+36/+40/+44/+48 = 五档计数

---

## 6. 关键地址速查表

| 地址 | 说明 |
|------|------|
| 0x400000 | 镜像基址（IDA）|
| 0x535C40 / 0x535D50 / 0x535DA0 | 判定函数 down/up/auto |
| 0xbe019c | judgeObj vtable |
| 0x5AC1B0 | 每帧 note 更新循环（含自动判定调用） |
| 0x5AD7F0 | 击打处理（含判定调用）|
| 0x537300 / 0x5371E0 | 按列击打 / 找 note |
| 0x53C1D0 / 0x53CEF0 / 0x53D6E0 / 0x53DFE0 | 判定结算（HP/分数/计数）|
| 0x7bcab0 | base play 对象 vtable（322 项）|
| 0x511000 | UI 资源加载器（judge-%d 等）|

**Frida 运行时换算**：`运行时地址 = 0x830000(运行时基址, ASLR) + (IDA地址 - 0x400000)`

---

## 7. 方法记录（本次逆向用到的工具）

1. **IDA Pro 9.2 + ida-pro-mcp**：字符串锚点（`judge-%d`/`hit-slow`）→ xref → 反编译
2. **Frida 17.9.1**（注意 17 版 API 变化：`Process.getModuleByName` 替代 `Module.findBaseAddress`，`frida.get_local_device()` 替代 `frida.enumerate_processes`）：
   - hook 结算函数拿栈回溯 → 定位调用链
   - hook `sub_5AC1B0`（每帧跑）读 judgeObj → 发现判定函数地址
   - hook `sub_535C40` 读原始栈 `context.esp` 拿 note/time → 实读 judgeObj 窗口字段
3. **注意**：`args[]` 在部分函数上会错位（诊断显示 args[1]=0x510 非指针），**必须用 `context.esp` 读原始栈参数**

---

## 8. 待办

- [ ] 确认字母映射（delta≈46→A、47→B 的肉眼观察）
- [ ] 测不同 `user_judge_level`（0/1/2）下 judgeObj 字段如何变化
- [ ] 确认长条 note（key-up, sub_535D50）的判定逻辑
- [x] 手机版：测不同 `user_judge_level` 下窗口是否缩放 —— 见 §E，槽位恒定、只有 base 变
- [x] 手机版：A/D/E 三档实测复核 —— 五档全部实测，公式零偏差

---

# 手机版（Android arm64）判定逆向

**目标**：`me.mugzone.malody`，引擎 `lib/arm64-v8a/libmalodycpp.so`（14,215,856 字节）
与桌面版同源（`judge-%d` / `hit-slow` / `user_judge_level` 字符串锚点一致），但**判定窗口常量不同**。

## A. 判定函数（RVA = ELF vaddr）

| RVA | 作用 | 特征 |
|---|---|---|
| **0x30e6e4** | 单点/tap 判定（本次 430 次全命中这里）| 89 insns，含 `ldr [x0,#0x20]` + `ldr [x0,#0x3c]` + `mov w?,#0x40000000` + csel 链 |
| **0x30ee84** | 长条/hold 判定（本次未触发）| 98 insns，同签名，note 标志位分支不同 |

**arm64 调用约定**：`x0 = judgeObj`，`x1 = note`，`w2 = currentTime(ms)`，返回 `w0 = mask`

定位方法：静态扫描全部 `.text`（capstone 解出 2,082,812 条），按"行为签名"找函数——
`0x40000000` 哨兵 + `sub w4,w7,w2` 算 delta + `0x40/0x20` csel + `2/4/8/1` 档位链。
注意：**桌面版的窗口常量 36/76/110/160 在 arm64 二进制里完全不存在**（多种 stride 扫描均为 0 命中），必须运行时读。

## B. 对象布局（运行时 dump 确认）

```
judgeObj:
  +0x00   vptr
  +0x20   base = 0
  +0x28   170      +0x2c  170        (早/晚 上限副本)
  +0x30   45       +0x34  85         (best / cool 窗口)
  +0x38   130      +0x3c  170        (good / early-cutoff)
  +0x40+  5 个间隔 0x4000 的堆指针

note:
  +0x00   vptr
  +0x30   noteTime(ms)          <- 已由快照 +0x30=8360 == 首条 noteT 验证
  +0x48   noteTime 副本
  +0x50   =1        +0x5c  INT_MAX(0x7FFFFFFF)
```

## C. 判定窗口实测（430 次判定，边界与槽位完全吻合）

| 档位 | mask 低5位 | \|delta\| 实测 | 边界 |
|---|---|---|---|
| best | 2 | 0 – 45 | ≤ 45 |
| cool | 4 | 46 – 85 | 46 – 85 |
| good | 8 | 86 – 130 | 86 – 130 |
| worst | 1 | 131 – 169 | 131 – 170 |
| 无判定 | — | >170 | 返回 `0x40000000` 哨兵 |

**桌面 vs 手机**：

| | A/best | B/cool | C/good | D/worst |
|---|---|---|---|---|
| 桌面 malody.exe | 46 | 86 | **120** | 170 |
| 手机 arm64 | 45 | 85 | **130** | 170 |

A/B 差 1ms；**C 边界差 10ms（手机"good"档明显更宽松）**。桌面那 10 是 `[4]` base，手机 base=0 直接用绝对窗口。

**mask 语义（与桌面一致，已实测验证）**：
- 低 5 位档位：`2`=best `4`=cool `8`=good `1`=worst
- `0x40` = 早，`0x20` = 晚（`delta = noteTime - now`，`delta>0` 即按早了 → `0x40`）
- `0x40000000` = 无判定

实例：`delta=+45 → mask=0x42` (best|早)、`delta=-47 → mask=0x24` (cool|晚)

## D. 工具与脚本

| 文件 | 用途 |
|---|---|
| `malody_judge_android.js` | 判定读取 Frida 脚本（hook 两个 RVA，输出 delta/档位/早晚 + 首判定对象快照）|
| `malody_judge_run.py` | 驱动脚本（远程 device 127.0.0.1:27042，spawn `re.frida.Gadget`；带单实例锁）|
| `judge_android_log.txt` | 判定日志输出 |
| `find_judge_fn.py` / `find_judge_ctor.py` | 行为签名扫描器（打分找判定函数 / 找构造函数）|
| `arm64_xref.py` / `arm64_dis.py` | adrp+add 字符串交叉引用 / 带注释的 arm64 反汇编 |

**环境**：objdump 不支持 AArch64，改用 `capstone 5.0.7`（`F:\frida16\Scripts\pip.exe install capstone`）自建工具链；
Frida 16.7.19 客户端 == Gadget 16.7.19。

**Gadget 注入注意**：JsHook 方案下连接标识是 `re.frida.Gadget`（不是包名），
脚本里 `Process.findModuleByName('libmalodycpp.so')` **必须在脚本加载时同步调用一次**——
库往往在 Gadget 挂起前就已映射，`attachModuleObserver` 只对"之后新加载"的模块触发，永远等不到。

## E. 判定等级 → base（关键结论，可推全五档）

**`0x30dbfc` = 等级→base 函数**：`w1` = 等级 index(0..4)，`x0` = judgeObj

```asm
cmp w1,#4 ; b.hi ret          ; level > 4 不处理
cmp w1,#1 ; b.le L10
cmp w1,#2 ; b.ne L8
        str wzr,[x0,#0x20]    ; level == 2 -> base = 0
L10: (2-level)*8 + (2-level)*2 = (2-level)*10
L8:  (2-level)*8
```

| 等级 | A | B | C | D | E |
|---|---|---|---|---|---|
| index | 0 | 1 | 2 | 3 | 4 |
| **base** | **20** | **10** | **0** | **−8** | **−16** |

**窗口 = 槽位 + base**。槽位由各判定类的构造函数写死（互不相同）：

| 构造函数 | 槽位 (+0x30/34/38/3c) | 判定类 |
|---|---|---|
| **0x30e1d0** | **45 / 85 / 130 / 170** | **Key（手机实测确认）** |
| 0x30e220 | 45 / 85 / 120 / 170 | 变体 |
| 0x30e270 | 45/85/130/170 ＋ 45/85/230/170 | 带长条 |
| 0x30e2d4 | 40 / 80 / 160 / 383 | JudgeJubeat |

**桌面槽位 36/76/110/160，手机槽位 45/85/130/170**（手机 good 档宽 20ms）。
用桌面槽位 + 上表 base 复算，与桌面判定表 A–E 五行**逐位吻合**，公式得证。

手机 Key 五档（**五档全部实测，公式零偏差**）：

```
A 0-65  66-105 106-150 151+     base=20
B 0-55  56-95  96-140  141+     base=10
C 0-45  46-85  86-130  131+     base=0
D 0-37  38-77  78-122  123+     base=-8
E 0-29  30-69  70-114  115+     base=-16
```

**换档生效方式**（实测确认）：**退出谱面 → 改判定设置 → 重进谱面**即可，
判定对象在加载谱面时重建，**不需要重启 App**（驱动/Frida 会话不掉）。
中途在设置里改、当前这局不会变。
