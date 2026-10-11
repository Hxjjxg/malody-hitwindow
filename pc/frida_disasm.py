# -*- coding: utf-8 -*-
"""用 Frida Instruction API 反汇编运行时地址附近的代码"""
import frida, sys, json

# 目标运行时地址（来自栈回溯）
TARGETS = {
    "sub_1371E0 (note finder)":   0x9671e0,
    "fn@5ADC34":                  0x9ddc34,
    "fn@5ADD90":                  0x9ddd90,
    "fn@5ADE80":                  0x9dde80,
    "fn@5AC991":                  0x9dc991,
}

JS = r"""
'use strict';
var targets = %s;
var BASE = Process.getModuleByName('malody.exe').base;

function scanBackStart(p) {
    // 向前找函数开头：常见 prologue 55 8B EC / 8B FF / 53 55 8B EC / 55 8B 6C
    var q = p;
    for (var i = 0; i < 4096; i++) {
        var b0 = q.readU8();
        if (b0 == 0x55) {
            var b1 = q.add(1).readU8();
            if (b1 == 0x8b) {
                var b2 = q.add(2).readU8();
                if (b2 == 0xec || b2 == 0x6c) { return q; }
            }
        }
        if (b0 == 0x8b && q.add(1).readU8() == 0xff) { return q; }
        q = q.sub(1);
    }
    return p.sub(64);
}

function disasmRange(start, end) {
    var p = start, out = [];
    var maxn = 400;
    while (p.compare(end) < 0 && maxn-- > 0) {
        try {
            var ins = Instruction.parse(p);
            out.push(p.sub(BASE).toString() + ': ' + ins.mnemonic + ' ' + ins.opStr);
            p = ins.next;
        } catch(e) {
            out.push(p.sub(BASE).toString() + ': <bad>');
            break;
        }
    }
    return out;
}

Object.keys(targets).forEach(function(name){
    var addr = ptr(targets[name]);
    console.log('\n===== ' + name + ' @ ' + addr + ' (RVA ' + addr.sub(BASE) + ') =====');
    var start = scanBackStart(addr.sub(20));
    var end = addr.add(320);
    console.log('  [fn start guess ' + start.sub(BASE) + ']');
    disasmRange(start, end).forEach(function(l){ console.log('  ' + l); });
});
""" % json.dumps(TARGETS)

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n')
    elif msg.get('type') == 'error':
        sys.stdout.write('[JS-ERR] %s\n' % msg.get('description'))
    else:
        sys.stdout.write('[JS] %s\n' % msg.get('payload', msg))

def main():
    # 找到运行中的游戏
    device = frida.get_local_device()
    found = None
    for p in device.enumerate_processes():
        if p.name.lower() == 'malody.exe':
            found = p.pid
            break
    if not found:
        sys.stdout.write('[*] malody.exe not running\n')
        return
    sys.stdout.write('[*] attaching to pid %d\n' % found)
    session = device.attach(found)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    sys.stdout.write('[*] done\n')

if __name__ == '__main__':
    main()
