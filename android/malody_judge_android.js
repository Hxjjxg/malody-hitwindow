'use strict';
/*
 * Malody Android (arm64) 判定读取器  — 对应桌面版 frida_read_judge.py
 *
 * 用法:
 *   F:\frida16\Scripts\python.exe malody_judge_run.py
 *   或: frida.exe -H 127.0.0.1:27042 -f re.frida.Gadget -l <本文件>
 *
 * 已定位 (libmalodycpp.so, RVA = ELF vaddr):
 *   0x30e6e4  单点/tap 判定       0x30ee84  长条/hold 判定
 *
 * arm64 调用约定:
 *   x0 = judgeObj      x1 = note      w2 = currentTime(ms)     返回 w0 = mask
 *
 * judgeObj 窗口布局 (与桌面 32-bit 不同):
 *   +0x20 base   +0x30 best   +0x34 cool   +0x38 good   +0x3c early-cutoff
 * note: +0x30 noteTime(ms)   +0x50 flags
 *
 * mask: 低5位 2=best 4=cool 8=good 1=worst | 0x40=早 0x20=晚 | 0x40000000=无判定
 *
 * 多档位测试: 判定等级改变后窗口值会变, 脚本检测到变化会自动重新 dump,
 *             每次输出一行 "[窗口#N] best=.. cool=.. good=.. cutoff=.. base=.."
 */

var MODULE = 'libmalodycpp.so';
var JUDGE_RVAS = [0x30e6e4, 0x30ee84];
var TIER_NAME = { 2: 'best', 4: 'cool', 8: 'good', 1: 'worst' };

var mod = null;
var hooked = false;
var winIdx = 0;         // 见到第几套窗口
var lastSig = null;
var counts = {};
var total = 0;

function pad(s, n) { s = '' + s; while (s.length < n) s += ' '; return s; }
function L(s) { send(String(s)); }

// 读窗口槽位 -> 签名串, 用于检测判定等级变化
function windowSig(j) {
    try {
        return [j.add(0x20).readS32(), j.add(0x30).readS32(), j.add(0x34).readS32(),
                j.add(0x38).readS32(), j.add(0x3c).readS32()].join('/');
    } catch (e) { return null; }
}

function reportWindows(j) {
    try {
        var base = j.add(0x20).readS32();
        var w = [j.add(0x30).readS32(), j.add(0x34).readS32(),
                 j.add(0x38).readS32(), j.add(0x3c).readS32()];
        L('[窗口#' + winIdx + '] best=' + (base + w[0]) + ' cool=' + (base + w[1])
            + ' good=' + (base + w[2]) + ' cutoff=' + (base + w[3]) + ' base=' + base);
        L('  >> 段: 0-' + (base + w[0]) + ' ' + (base + w[0] + 1) + '-' + (base + w[1])
            + ' ' + (base + w[1] + 1) + '-' + (base + w[2])
            + ' ' + (base + w[2] + 1) + '-  (超 ' + (base + w[3]) + ' 无判定)');
    } catch (e) { L('[!] reportWindows: ' + e); }
}

function dumpJudgeObj(j, note) {
    L('\n===== judgeObj 对象快照 =====');
    L('judgeObj = ' + j);
    try {
        var lines = [];
        for (var off = 0; off < 0x80; off += 4) {
            lines.push('+0x' + ('0' + off.toString(16)).slice(-2) + '=' + j.add(off).readS32());
        }
        for (var i = 0; i < lines.length; i += 4) {
            L('    ' + lines.slice(i, i + 4).join('  '));
        }
    } catch (e) { L('  judgeObj read err: ' + e); }

    try {
        var nl = [];
        for (var o2 = 0; o2 < 0x60; o2 += 4) {
            nl.push('+0x' + ('0' + o2.toString(16)).slice(-2) + '=' + note.add(o2).readS32());
        }
        L('  note[0x00..0x5c]:');
        for (var k = 0; k < nl.length; k += 4) {
            L('    ' + nl.slice(k, k + 4).join('  '));
        }
    } catch (e) { L('  note read err: ' + e); }
    L('==============================\n');
}

function hookAll() {
    if (!mod) { L('[!] hookAll: module not found'); return; }
    L('[*] ' + MODULE + ' base=' + mod.base + ' size=0x' + mod.size.toString(16));
    JUDGE_RVAS.forEach(function (rva, idx) {
        var target = mod.base.add(rva);
        try {
            Interceptor.attach(target, {
                onEnter: function () {
                    this.judgeObj = this.context.x0;
                    this.note = this.context.x1;
                    this.now = this.context.x2.toInt32();
                    this.tag = 'J' + (idx + 1);
                    try {
                        this.noteTime = this.note.add(0x30).readS32();
                        this.flags = this.note.add(0x50).readU32();
                    } catch (e) { this.noteTime = null; this.flags = 0; }
                },
                onLeave: function (retval) {
                    // ---- 窗口变化检测 (判定等级改了会在这里体现) ----
                    var sig = windowSig(this.judgeObj);
                    if (sig !== null && sig !== lastSig) {
                        lastSig = sig;
                        winIdx++;
                        L('\n########## 检测到第 ' + winIdx + ' 套判定窗口 ##########');
                        reportWindows(this.judgeObj);
                        if (winIdx === 1) dumpJudgeObj(this.judgeObj, this.note);
                    }

                    var mask = retval.toInt32() >>> 0;
                    if (mask === 0x40000000) return;
                    if (this.noteTime === null) return;

                    var delta = this.noteTime - this.now;      // >0 = 早
                    var tier = mask & 0x1f;
                    var when = (mask & 0x40) ? '早' : ((mask & 0x20) ? '晚' : '--');
                    var name = TIER_NAME[tier] || ('t' + tier);
                    counts[name] = (counts[name] || 0) + 1;
                    total++;

                    L('[判定] W' + winIdx + ' ' + this.tag
                        + '  delta=' + pad((delta > 0 ? '+' : '') + delta, 6) + 'ms'
                        + '  mask=0x' + mask.toString(16)
                        + '  ' + pad(name, 5) + ' ' + when
                        + '  noteT=' + this.noteTime + ' now=' + this.now
                        + '  noteFlags=0x' + (this.flags >>> 0).toString(16));
                }
            });
            L('[+] hooked judge ' + (idx + 1) + ' @ ' + target + ' (rva 0x' + rva.toString(16) + ')');
        } catch (e) {
            L('[!] hook failed rva 0x' + rva.toString(16) + ': ' + e);
        }
    });
    hooked = true;
    L('[*] 进入 Key 图游玩即可看到判定流。');
}

function tryInit() {
    if (hooked) return true;
    if (!mod) mod = Process.findModuleByName(MODULE);
    if (mod) { hookAll(); return true; }
    return false;
}

// 网 1: 模块观察者
try {
    if (typeof Process.attachModuleObserver === 'function') {
        Process.attachModuleObserver({
            onAdded: function (m) { if (m.name === MODULE) { mod = m; tryInit(); } }
        });
        L('[*] net1 module observer armed');
    }
} catch (e) { L('[!] net1 failed: ' + e); }

// 网 2: dlopen 钩子 (不依赖定时器)
try {
    ['android_dlopen_ext', '__loader_android_dlopen_ext', 'dlopen'].forEach(function (n) {
        var p = Module.findExportByName(null, n);
        if (!p) return;
        try {
            Interceptor.attach(p, { onLeave: function () { tryInit(); } });
            L('[+] net2 loader hook armed: ' + n);
        } catch (e) { }
    });
} catch (e) { L('[!] net2 failed: ' + e); }

// 网 3: 轮询兜底
var iv = setInterval(function () { if (tryInit() && hooked) clearInterval(iv); }, 500);

// ★ 网 0: 加载时同步尝试 (库通常已映射, 这条才会命中)
if (!tryInit()) L('[*] ' + MODULE + ' 尚未加载, 等待中...');

L('[*] malody_judge_android.js loaded (arch=' + Process.arch + ')');
