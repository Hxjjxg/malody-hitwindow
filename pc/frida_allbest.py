# -*- coding: utf-8 -*-
"""Malody 4.3.7 全 best —— 逻辑最小版。

钩 3 个判定函数, onLeave 强制返回值档位 = best(2):
  - 返回值 == 0x40000000 (无判定: 太早/已判过) -> 不动, 保持等 note
  - 否则: 低5位档位 -> 2(best), 保留 0x40=早 / 0x20=晚 标志
sub_535C40 key-down / sub_535D50 key-up / sub_535DA0 auto(miss 也转 best)。
"""
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
var forced = 0;
Object.keys(RVA).forEach(function (name) {
    Interceptor.attach(BASE.add(RVA[name]), {
        onLeave: function (retval) {
            var rv = retval.toInt32();
            if (rv === 0x40000000) return;        // 无判定 -> 不动
            retval.replace((rv & 0x60) | 0x2);    // 档位 -> best, 保留早/晚
            if (++forced <= 5) send('[allbest] ' + name + ' -> 0x' + retval.toString(16));
        }
    });
});
send('[init] all-best armed');
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        sys.stdout.write(str(msg['payload']) + '\n'); sys.stdout.flush()
    elif msg.get('type') == 'error':
        sys.stdout.write('[ERR] %s\n%s\n' % (msg.get('description'), msg.get('stack', '')))
        sys.stdout.flush()

def main():
    d = frida.get_local_device()
    pid = None
    for p in d.enumerate_processes():
        if p.name.lower() == 'malody.exe':
            pid = p.pid; break
    if not pid:
        sys.stdout.write('[!] malody.exe not running\n'); return
    sys.stdout.write('[*] attach pid %d\n' % pid); sys.stdout.flush()
    s = d.attach(pid)
    sc = s.create_script(JS % json.dumps(RVA))
    sc.on('message', on_message)
    sc.load()
    sys.stdout.write('[*] hooked. 进图游玩即可全 best(前5次强制会打日志)\n'); sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    s.detach()

if __name__ == '__main__':
    main()
