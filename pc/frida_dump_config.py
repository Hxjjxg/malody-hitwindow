# -*- coding: utf-8 -*-
"""dump config 对象 + 找修正值 20/10/0/-8/-16 与 judge_level 字段。
config 指针全局 dword_C311C4 (IDA 0xC311C4, RVA 0x8311C4)。"""
import frida, sys, struct

JS = r"""
'use strict';
var BASE = Process.getModuleByName('malody.exe').base;
var CFG_PTR = BASE.add(0x8311C4);   // dword_C311C4
send('[i] BASE=' + BASE + ' cfgptr_global@' + CFG_PTR);
var cfg = CFG_PTR.readPointer();
send('[i] config @ ' + cfg + '  (readable=' + Process.findRangeByAddress(cfg) + ')');
if (!cfg.isNull()) {
    var n = 0x180;
    var bytes = cfg.readByteArray(n);
    var arr = new Uint8Array(bytes);
    var hex = [];
    for (var i = 0; i < n; i++) hex.push(('0' + arr[i].toString(16)).slice(-2));
    // 16 bytes per row
    var rows = [];
    for (var i = 0; i < n; i += 16)
        rows.push(('0x' + i.toString(16)) + '  ' + hex.slice(i, i + 16).join(' '));
    send('[dump] config 0x0-0x180:\n' + rows.join('\n'));
    // 找 5 个修正值 (int32) 与 0/1/2/3/4 (judge_level 候选)
    var CORR = [20, 10, 0, -8, -16];
    var found = [];
    for (var off = 0; off <= n - 4; off += 4) {
        var v = (arr[off] | (arr[off + 1] << 8) | (arr[off + 2] << 16) | (arr[off + 3] << 24));
        if (CORR.indexOf(v) !== -1 && off != 0) found.push('+0x' + off.toString(16) + '=' + v);
    }
    send('[corr] found at: ' + (found.length ? found.join(', ') : 'none'));
    // judge_level 候选: 在 0x90-0xC0 范围找值 0..4
    for (var off = 0x8c; off <= 0xc0; off += 4) {
        var v = (arr[off] | (arr[off + 1] << 8) | (arr[off + 2] << 16) | (arr[off + 3] << 24));
        if (v >= 0 && v <= 5) send('[jl?] +0x' + off.toString(16) + ' = ' + v);
    }
}
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n')
    elif msg.get('type') == 'error':
        sys.stdout.write('[JS-ERR] %s\n' % msg.get('description'))

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
    s.detach()

if __name__ == '__main__':
    main()
