# malody-hitwindow

> Reverse-engineered Malody hit-judgment windows for PC (x86) and Android (arm64):
> judge functions, window tables and per-level offsets — all five judgment levels verified on-device.

English | [中文](README.md)

Scripts and notes from reverse-engineering Malody's hit-judgment logic.

- **PC** — Windows x86, target `malody.exe` (PE32, image base 0x400000)
- **Android** — arm64, target `libmalodycpp.so` (extracted from `base.apk`)

The two builds share a codebase: **identical `base` ladder**, differing only in the window slot table.

---

## Layout

```
pc/        Desktop x86 scripts
android/   Android arm64 scripts
docs/      Reverse-engineering notes (Chinese)
```

### `android/`

| File | Purpose |
|---|---|
| `malody_judge_android.js` | **Main script.** Hooks the judge functions, prints delta / tier / early-late per hit; auto re-dumps whenever the windows change (i.e. on a judgment-level switch) |
| `malody_judge_run.py` | **Driver.** Connects to the remote device, spawns `re.frida.Gadget`, writes the log. Single-instance lock |
| `arm64_dis.py` | Annotated arm64 disassembler (folds `adrp`+`add` into string comments, labels `bl` targets) |
| `arm64_xref.py` | `adrp`+`add` string cross-reference finder (resumable — works around capstone stopping at the first bad word) |
| `find_judge_fn.py` | Scores functions by "behavioural signature" to locate the judge functions |
| `find_judge_ctor.py` | Finds judge-object constructors; also builds the `insns.pkl` instruction cache |
| `find_judge_android.py` / `find_judge_android2.py` | Early constant-sequence scans — the desktop slot constants are absent from the arm64 build (every scan returned zero); kept for the record |
| `find_window_consts.py` | **Locates the window-config function by its immediate constants** — this is what eventually revealed the level formula |

### `pc/`

| File | Purpose |
|---|---|
| `frida_read_judge.py` | Judge reader — the prototype the Android script was ported from |
| `frida_judge.py` / `frida_judge4.py` | Judge hooks; read the raw stack for note / time |
| `frida_allbest*.py` | All-best experiments |
| `frida_guard*.py` | Value-guard experiments |
| `frida_disasm*.py` / `frida_dump_config.py` | Disassembly and config dumps |
| `frida_hook.py` | Earliest probe |
| `find_boundaries.py` / `find_low_boundary.py` | Boundary statistics from logs |

---

## Key findings

**window = slot + base**, with four segments best / cool / good / worst.
Beyond the no-judgment threshold nothing is judged (`mask = 0x40000000`).

| Level | base | Desktop slots 36/76/110/160 | Android slots 45/85/130/170 |
|---|---|---|---|
| A | 20 | 0-56 / 57-96 / 97-130 / 131-180 | 0-65 / 66-105 / 106-150 / 151-190 |
| B | 10 | 0-46 / 47-86 / 87-120 / 121-170 | 0-55 / 56-95 / 96-140 / 141-180 |
| C | 0 | 0-36 / 37-76 / 77-110 / 111-160 | 0-45 / 46-85 / 86-130 / 131-170 |
| D | −8 | 0-28 / 29-68 / 69-102 / 103-152 | 0-37 / 38-77 / 78-122 / 123-162 |
| E | −16 | 0-20 / 21-60 / 61-94 / 95-144 | 0-29 / 30-69 / 70-114 / 115-154 |

- **All five Android levels measured on-device**, matching the in-code level formula exactly
- Android slots are 9–20 ms wider than desktop (good tier +20 ms)
- `base = (2-level)*10` (level ≤ 1) / `0` (level = 2) / `(2-level)*8` (level ≥ 3) — see §E in `docs/`

**mask layout** (identical on both builds): low 5 bits = tier — `2`=best `4`=cool `8`=good `1`=worst;
`0x40`=early `0x20`=late; `0x40000000`=no judgment.

---

## Running the Android side

Prerequisite: bring the Gadget up via JsHook first. The connect identity is `re.frida.Gadget`, **not** the package name:

```powershell
& 'C:\Users\lenov\frida-diagnosis\Connect-JsHookGadget.ps1' -PackageName 'me.mugzone.malody' -RestartApp
& 'F:\frida16\Scripts\python.exe' -u 'C:\Users\lenov\malody_re\malody-hitwindow\android\malody_judge_run.py'
```

Split the log per level with `--label A` (writes `judge_android_A.txt`); `--append` appends instead of truncating.

**Switching judgment level**: exit the chart → change the setting → re-enter the chart. **No app restart needed.**
Play 1–2 notes per level; the log gains a line `[窗口#N] best=.. cool=.. good=.. cutoff=..`.

---

## Environment

- Frida 16.7.19 — client and Gadget versions must match; Python bindings at `F:\frida16\Scripts\`
- capstone 5.0.7 — objdump has no AArch64 support, so all static analysis goes through capstone

## Not in this repo

Large files live in the parent directory `C:\Users\lenov\malody_re\` and are referenced by absolute path:

| File | Notes |
|---|---|
| `libmalodycpp.so` | The arm64 engine — the static-analysis target (extracted from `base.apk`) |
| `base.apk` | The package pulled from the phone |
| `insns.pkl` | Full `.text` decode cache, built by `find_judge_ctor.py` |
| `judge_android_log.txt` | Android judgment log (written by the driver) |
