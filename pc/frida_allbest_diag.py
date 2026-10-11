# -*- coding: utf-8 -*-
"""全 best + 诊断: 保留强制 best, 同时追踪 sub_535DA0(auto) 调用, 看 miss 是否走它。
sub_535DA0: __thiscall(judgeObj, note, currentTime)。日志: 前 30 次调用。"""
import frida, sys, time, json

RVA = {
    "key-down sub_535C40": 0x135C40,
    "key-up   sub_535D50": 0x135D50,
    "auto     sub_535DA0": 0x135DA0,
}

JS = r"""
'use strict';
var RVA = %s;
var BASE = Process.getModuleByName('malody.exe').base;
var forced = 0, autoCalls = 0;

function isMapped(p) { try { return Process.findRangeByAddress(p) !== null; } catch (e) { return false; } }

var judgeDumped = false;
Object.keys(RVA).forEach(function (name) {
    Interceptor.attach(BASE.add(RVA[name]), {
        onEnter: function (args) {
            if (!judgeDumped && name.indexOf('key-down') !== -1) {
                judgeDumped = true;
                var judge = this.context.ecx;
                try {
                    var vt = judge.readPointer();
                    var out = ['vt=' + vt + ' rva=' + vt.sub(BASE)];
                    for (var i = 0; i <= 8; i++) {
                        try {
                            var e = vt.add(i * 4).readPointer();
                            out.push('[' + i + ']=' + e.sub(BASE).toString());
                        } catch (e2) { out.push('[' + i + ']=<bad>'); }
                    }
                    send('[judge-dump] obj=' + judge + ' ' + out.join(' '));
                } catch (e3) { send('[judge-dump-err] ' + e3); }
            }
            if (name.indexOf('auto') === -1) return;
            if (++autoCalls > 30) return;
            // 原始栈参数: esp+4=note, esp+8=currentTime (thiscall this=ecx)
            var esp = this.context.esp;
            var note = esp.add(4).readPointer();
            var t = esp.add(8).readU32();
            var noteTime = -1;
            if (isMapped(note)) { try { noteTime = note.add(76).readU32(); } catch (e) {} }
            send('[AUTO#' + autoCalls + '] enter judge=' + this.context.ecx
                 + ' note=' + note + ' noteTime=' + noteTime + ' curTime=' + t);
        },
        onLeave: function (retval) {
            var rv = retval.toInt32();
            var tag = (name.indexOf('auto') !== -1) ? ('AUTO ret=' + rv.toString(16)) : name;
            if (rv === 0x40000000) { send('[skip] ' + tag); return; }
            var orig = rv;
            retval.replace((rv & 0x60) | 0x2);
            if (++forced <= 20) send('[allbest] ' + tag + ' 0x' + orig.toString(16)
                                     + ' -> 0x' + retval.toString(16));
        }
    });
});
send('[init] all-best + auto-diag armed');
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n'); sys.stdout.flush()
    elif msg.get('type') == 'error':
        sys.stdout.write('[ERR] %s\n%s\n' % (msg.get('description'), msg.get('stack', '')))
        sys.stdout.flush()

def main():
    d = frida.get_local_device()
    sys.stdout.write('[*] waiting for malody.exe ...\n'); sys.stdout.flush()
    pid = None
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            for p in d.enumerate_processes():
                if p.name.lower() == 'malody.exe':
                    pid = p.pid; break
        except Exception:
            pass
        if pid:
            break
        time.sleep(1)
    if not pid:
        sys.stdout.write('[!] timeout: malody.exe not found\n'); return
    sys.stdout.write('[*] attach pid %d\n' % pid); sys.stdout.flush()
    s = d.attach(pid)
    sc = s.create_script(JS % json.dumps(RVA))
    sc.on('message', on_message)
    sc.load()
    sys.stdout.write('[*] hooked. 进图: 一部分按, 一部分故意不按(miss)。\n')
    sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    s.detach()

if __name__ == '__main__':
    main()
