# -*- coding: utf-8 -*-
"""抓 judgeObj[4] 写入:钩构造函数 + 进游戏play setup, 轮询 [4] 变化。

[4] 偏移 = 0x10 (字段索引4)。构造函数只写 [8..11]=0x20/0x24/0x28/0x2c,
[4] 在进游戏时被写成修正值(20/10/0/-8/-16)。本脚本:
  1. 钩 JudgeKey ctor(sub_535B80) / JudgeKeyFair ctor(sub_535E00)
     -> 记录 judgeObj 地址 + 初始 [4]
  2. 钩 play setup(sub_5A77C0) -> leave 时读 this+0x2fc 处的 judgeObj[4]
  3. setInterval 每 50ms 轮询所有 tracked judgeObj 的 [4], 变化即 log
"""
import frida, sys, time, json

RVA = {
    "JudgeKey ctor sub_535B80": 0x135B80,
    "JudgeKeyFair ctor sub_535E00": 0x135E00,
    "play setup sub_5A77C0": 0x1A77C0,
    "judge creator sub_5AFBD0": 0x1AFBD0,
    "judge config sub_59B570": 0x19B570,
}

RVA_JSON = json.dumps(RVA)

JS = r"""
'use strict';
var RVA = %s;
var BASE = Process.getModuleByName('malody.exe').base;
var TRACKED = {};   // addrStr -> prev[4]

function isMapped(p) {
    try { return Process.findRangeByAddress(p) !== null; }
    catch (e) { return false; }
}
function r32(p) {
    try { return p.readU32(); } catch (e) { return null; }
}
function snapJudge(obj, tag) {
    if (!isMapped(obj)) { send(tag + ': NOT MAPPED ' + obj); return; }
    var vt = r32(obj);
    var v4  = r32(obj.add(0x10));
    var v8  = r32(obj.add(0x20));
    var v9  = r32(obj.add(0x24));
    var va  = r32(obj.add(0x28));
    var vb  = r32(obj.add(0x2c));
    send(tag + ' judge@' + obj + ' vt=' + (vt===null?'?':'0x'+vt.toString(16))
         + ' [4]=' + v4 + ' [8]=' + v8 + ' [9]=' + v9 + ' [10]=' + va + ' [11]=' + vb);
    TRACKED[obj.toString()] = v4;
}

// --- 1. 构造函数: 捕获 this(ecx), leave 时记录对象 ---
Object.keys(RVA).forEach(function (name) {
    if (name.indexOf('ctor') === -1) return;
    var target = BASE.add(RVA[name]);
    try {
        Interceptor.attach(target, {
            onEnter: function () {
                this.obj = this.context.ecx;
                this.sp = this.context.esp;
            },
            onLeave: function () {
                if (!this.obj) return;
                snapJudge(this.obj, 'CTOR(' + name + ')');
                // 返回地址 = 调用者 call 指令的下一条 (ESP 处)
                var ret = this.sp.readPointer();
                send('    RET=' + ret + ' rva=' + ret.sub(BASE));
                // 完整栈回溯
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                var out = [];
                bt.forEach(function (a) { out.push(a.sub(BASE).toString()); });
                send('    STACK=' + out.join(' <- '));
            }
        });
        send('[hook] ' + name + ' @ ' + target);
    } catch (e) { send('[hook-fail] ' + name + ': ' + e); }
});

// --- 2. play setup: leave 时读 this+0x2fc 的 judgeObj[4] ---
try {
    Interceptor.attach(BASE.add(RVA['play setup sub_5A77C0']), {
        onEnter: function () {
            this.play = this.context.ecx;
            send('[enter] sub_5A77C0 play@' + this.play + ' esp=' + this.context.esp);
        },
        onLeave: function () {
            var p = this.play;
            if (!p || !isMapped(p)) { send('[leave] sub_5A77C0 play not mapped'); return; }
            var jptr = r32(p.add(0x2fc));                 // +764 = judgeObj 指针
            send('[leave] sub_5A77C0 play@' + p + ' judgePtr@+764 = ' + jptr);
            if (jptr !== null) {
                var j = ptr(jptr);
                if (isMapped(j)) {
                    snapJudge(j, 'PLAYSETUP-leave');
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    send('[leave] stack:');
                    bt.forEach(function (a) {
                        var rva = a.sub(BASE);
                        send('    ' + rva.toString());
                    });
                }
            }
        }
    });
    send('[hook] play setup sub_5A77C0');
} catch (e) { send('[hook-fail] sub_5A77C0: ' + e); }

// --- 3. 轮询 [4] 变化 ---
setInterval(function () {
    Object.keys(TRACKED).forEach(function (addrStr) {
        var cur = r32(ptr(addrStr).add(0x10));
        var prev = TRACKED[addrStr];
        if (cur !== null && prev !== null && cur !== prev) {
            send('<<< CHANGE [4] judge@' + addrStr + '  ' + prev + ' -> ' + cur + ' >>>');
            TRACKED[addrStr] = cur;
        }
    });
}, 50);
send('[init] judge4 watcher ready');
""" % RVA_JSON


def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n')
        sys.stdout.flush()
    elif msg.get('type') == 'error':
        sys.stdout.write('[JS-ERR] %s\n' % msg.get('description'))
        sys.stdout.flush()


def find_pid(timeout=180):
    d = frida.get_local_device()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            for p in d.enumerate_processes():
                if p.name.lower() == 'malody.exe':
                    return p.pid
        except Exception as e:
            sys.stdout.write('[!] enumerate: %s\n' % e)
        time.sleep(1)
    return None


def main():
    sys.stdout.write('[*] waiting for malody.exe ...\n')
    pid = find_pid()
    if not pid:
        sys.stdout.write('[!] timeout: malody.exe not found\n')
        return
    sys.stdout.write('[*] attaching pid %d\n' % pid)
    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    sys.stdout.write('[*] hooked. 现在进入游戏/选图/游玩...\n')
    sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    session.detach()


if __name__ == '__main__':
    main()
