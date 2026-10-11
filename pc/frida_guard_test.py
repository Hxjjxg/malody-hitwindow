# -*- coding: utf-8 -*-
"""自检: Frida 能否捕获 guard-page 异常。分配 scratch 页 → guard → 写 → 看 handler。"""
import frida, sys

JS = r"""
'use strict';
var PAGE_GUARD = 0x100, PAGE_RW = 0x04;
var VirtualProtect = new NativeFunction(
    Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect'),
    'int', ['pointer', 'size_t', 'uint32', 'pointer']);
var oldProt = Memory.alloc(4);

var FIRED = 0;
Process.setExceptionHandler(function (details) {
    FIRED++;
    send('[EXC] type=' + details.type + ' pc=' + details.context.pc
         + ' mem_op=' + (details.memory ? details.memory.operation : '?')
         + ' mem_addr=' + (details.memory ? details.memory.address : '?'));
    return true;
});

var scratch = Memory.alloc(0x2000);
var page = scratch.and(ptr('0xfffff000'));
var rc = VirtualProtect(page, 0x1000, PAGE_RW | PAGE_GUARD, oldProt);
send('[test] armed guard page=' + page + ' vp=' + rc);
scratch.writeU32(0x41414141);
send('[test] after write, FIRED=' + FIRED);
// 再读一次 (guard 已清除)
scratch.readU32();
send('[test] after read, FIRED=' + FIRED);
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n'); sys.stdout.flush()
    elif msg.get('type') == 'error':
        sys.stdout.write('[JS-ERR] %s\n%s\n' % (msg.get('description'), msg.get('stack', ''))); sys.stdout.flush()

def main():
    d = frida.get_local_device()
    pid = None
    for p in d.enumerate_processes():
        if p.name.lower() == 'malody.exe':
            pid = p.pid; break
    if not pid:
        sys.stdout.write('[!] malody.exe not running\n'); return
    s = d.attach(pid)
    sc = s.create_script(JS)
    sc.on('message', on_message)
    sc.load()
    sys.stdout.write('[*] test done\n')
    s.detach()

if __name__ == '__main__':
    main()
