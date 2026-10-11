# -*- coding: utf-8 -*-
"""反汇编 judge 配置函数：sub_59B570 / sub_5A77C0 / sub_5AFBD0 — 找 [4] 写入"""
import frida, sys, json

TARGETS = {
    "sub_59B570 (judge config?)": 0x19B570,
    "sub_5A77C0 (Key play setup)": 0x1A77C0,
    "sub_5AFBD0 (judge creator)": 0x1AFBD0,
}

JS = r"""
'use strict';
var targets = %s;
var BASE = Process.getModuleByName('malody.exe').base;

function scanBackStart(p) {
    var q = p;
    for (var i = 0; i < 8192; i++) {
        var b0 = q.readU8();
        if (b0 == 0x55) {
            var b1 = q.add(1).readU8();
            if (b1 == 0x8b) {
                var b2 = q.add(2).readU8();
                if (b2 == 0xec || b2 == 0x6c) return q;
            }
        }
        if (b0 == 0x8b && q.add(1).readU8() == 0xff) return q;
        q = q.sub(1);
    }
    return p.sub(64);
}
function disasmRange(start, end) {
    var p = start, out = [], maxn = 500;
    while (p.compare(end) < 0 && maxn-- > 0) {
        try {
            var ins = Instruction.parse(p);
            out.push(p.sub(BASE).toString() + ': ' + ins.mnemonic + ' ' + ins.opStr);
            p = ins.next;
        } catch(e) { out.push(p.sub(BASE).toString() + ': <bad>'); break; }
    }
    return out;
}
Object.keys(targets).forEach(function(name){
    var addr = BASE.add(targets[name]);
    var start = scanBackStart(addr);
    var end = addr.add(0x500);
    console.log('\n===== ' + name + ' @ ' + addr + ' (RVA ' + addr.sub(BASE) + ') =====');
    disasmRange(start, end).forEach(function(l){ console.log('  ' + l); });
});
""" % json.dumps(TARGETS)

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n')
    elif msg.get('type') == 'error':
        sys.stdout.write('[JS-ERR] %s\n' % msg.get('description'))

def main():
    device = frida.get_local_device()
    pid = None
    for p in device.enumerate_processes():
        if p.name.lower() == 'malody.exe':
            pid = p.pid; break
    if not pid:
        sys.stdout.write('[!] malody.exe not running\n'); return
    sys.stdout.write('[*] attaching pid %d\n' % pid)
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    sys.stdout.write('[*] done\n')

if __name__ == '__main__':
    main()
