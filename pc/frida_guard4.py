# -*- coding: utf-8 -*-
"""guard-page 内存陷阱: ctor 返回后立刻给 judgeObj 所在页设 PAGE_GUARD,
捕获随后对该页的每次访问(Frida exception handler 给 EIP), 直到 [4] 被写入。
安全版: 不用 TF 单步, 每次异常后 setTimeout(0) 重新武装(有极小竞态, 但足以抓到写入)。"""
import frida, sys, time, json

CTORS = {"JudgeKey": 0x135B80, "JudgeKeyFair": 0x135E00}
CTORS_JSON = json.dumps(CTORS)

JS = r"""
'use strict';
var CTORS = %s;
var BASE = Process.getModuleByName('malody.exe').base;
var PAGE_GUARD = 0x100, PAGE_RW = 0x04;
var VirtualProtect = new NativeFunction(
    Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect'),
    'int', ['pointer', 'size_t', 'uint32', 'pointer']);
var oldProt = Memory.alloc(4);

var ARMED = null;
var MAX_EXC = 300;

function r32(p) { try { return p.readU32(); } catch (e) { return null; } }

function arm(judge) {
    var target = judge.add(0x10);
    var page = target.and(ptr('0xfffff000'));
    var rc = VirtualProtect(page, 4096, PAGE_RW | PAGE_GUARD, oldProt);
    ARMED = { judge: judge, page: page, prev4: r32(target), count: 0, tag: judge.toString() };
    send('[ARM] judge=' + judge + ' page=' + page + ' [4]=' + ARMED.prev4 + ' vp=' + rc);
    setTimeout(function () { if (ARMED && ARMED.judge.equals(judge)) disarm('timeout3s'); }, 3000);
}

function disarm(reason) {
    if (!ARMED) return;
    var v4 = r32(ARMED.judge.add(0x10));
    send('[DISARM] ' + reason + ' judge=' + ARMED.judge + ' [4]=' + v4 + ' exc=' + ARMED.count);
    try { VirtualProtect(ARMED.page, 4096, PAGE_RW, oldProt); } catch (e) {}
    ARMED = null;
}

Object.keys(CTORS).forEach(function (name) {
    Interceptor.attach(BASE.add(CTORS[name]), {
        onEnter: function () { this.obj = this.context.ecx; },
        onLeave: function () {
            if (!this.obj) return;
            try {
                if (Process.findRangeByAddress(this.obj)) arm(this.obj);
            } catch (e) { send('[arm-err] ' + e); }
        }
    });
});

Process.setExceptionHandler(function (details) {
    if (!ARMED) return false;
    var pc = details.context.pc;
    var rva = pc.sub(BASE);
    if (details.type === 'guard-page' || (details.type === 'access-violation')) {
        ARMED.count++;
        var op = details.memory ? details.memory.operation : '?';
        var addr = details.memory ? details.memory.address.toString() : '?';
        send('[GUARD#' + ARMED.count + '] pc=' + rva + ' op=' + op + ' addr=' + addr + ' type=' + details.type);
        // OS 已清除 guard, 该指令重试会成功。用 setTimeout(0) 重新武装。
        setTimeout(function () {
            if (ARMED) {
                var v4 = r32(ARMED.judge.add(0x10));
                if (v4 !== null && v4 !== ARMED.prev4) {
                    send('<<< [4] WRITTEN! ' + ARMED.prev4 + ' -> ' + v4 + ' (writer likely pc above) >>>');
                    disarm('written');
                } else {
                    try { VirtualProtect(ARMED.page, 4096, PAGE_RW | PAGE_GUARD, oldProt); } catch (e) {}
                    if (ARMED.count > MAX_EXC) disarm('exc-bound');
                }
            }
        }, 0);
        return true;
    }
    return false;
});
send('[init] guard4 safe ready');
""" % CTORS_JSON

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n'); sys.stdout.flush()
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        st = msg.get('stack', '')
        sys.stdout.write('[JS-ERR] %s\n%s\n' % (desc, st)); sys.stdout.flush()

def main():
    d = frida.get_local_device()
    pid = None
    for p in d.enumerate_processes():
        if p.name.lower() == 'malody.exe':
            pid = p.pid; break
    if not pid:
        sys.stdout.write('[!] malody.exe not running\n'); return
    sys.stdout.write('[*] attach pid %d\n' % pid)
    s = d.attach(pid)
    sc = s.create_script(JS)
    sc.on('message', on_message)
    sc.load()
    sys.stdout.write('[*] armed. 进一局图...\n'); sys.stdout.flush()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: pass
    s.detach()

if __name__ == '__main__':
    main()
