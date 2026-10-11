# -*- coding: utf-8 -*-
"""Malody 全 best 最终版。

核心: 判定掩码结算入口 = playObj->vtable[184](play, note, mask)。
所有判定都流经它: 点击(sub_535C40) / 长条漏判(sub_535DA0, 0x80) / 普通漏判(33)。
在这里强制 mask 档位=best, 一个 hook 全 best。

发现流程: 钩 per-frame sub_5AC1B0 (每帧循环), 读 play vtable, 解出 vtable[184],
         动态挂掩码hook (esp+8 = mask 参数)。
"""
import frida, sys, time, json

RVA = {
    "key-down sub_535C40": 0x135C40,
    "hold-auto sub_535DA0": 0x135DA0,
    "per-frame sub_5AC1B0": 0x1AC1B0,
}

JS = r"""
'use strict';
var RVA = %s;
var BASE = Process.getModuleByName('malody.exe').base;
var settleFn = null, forced = 0;

// 结算入口: __thiscall(play, note, mask)  esp+4=note, esp+8=mask
function onSettleEnter() {
    var esp = this.context.esp;
    try {
        var mask = esp.add(8).readU32();
        if (mask === 0x40000000) return;        // 无判定哨兵 -> 不动
        var nb = (mask & 0x60) | 0x2;           // 档位->best(2), 保留早0x40/晚0x20
        if (nb !== mask) {
            esp.add(8).writeU32(nb);            // 覆写栈上的 mask 参数
            if (++forced <= 15) send('[settle] 0x' + mask.toString(16) + ' -> 0x' + nb.toString(16));
        }
    } catch (e) {}
}

// 每帧循环: 首次解出 vtable[184] 后静态挂结算hook
Interceptor.attach(BASE.add(RVA['per-frame sub_5AC1B0']), {
    onEnter: function () {
        if (settleFn) return;
        try {
            var play = this.context.ecx;
            var vt = play.readPointer();
            settleFn = vt.add(184 * 4).readPointer();
            send('[discover] play=' + play + ' vt=' + vt
                 + ' vtable[184]=' + settleFn + ' rva=' + settleFn.sub(BASE));
            Interceptor.attach(settleFn, { onEnter: onSettleEnter });
            send('[init] settlement hooked');
        } catch (e) { send('[discover-err] ' + e); }
    }
});

// 冗余保险: 判定函数直接强制 (若某路径绕过结算入口)
[0x135C40, 0x135DA0].forEach(function (rva) {
    Interceptor.attach(BASE.add(rva), {
        onLeave: function (retval) {
            var rv = retval.toInt32();
            if (rv === 0x40000000) return;
            retval.replace((rv & 0x60) | 0x2);
        }
    });
});
send('[init] all-best v2 ready');
""" % __import__('json').dumps(RVA)


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
    sc = s.create_script(JS)
    sc.on('message', on_message)
    sc.load()
    sys.stdout.write('[*] hooked. 进图游玩即可全 best(含漏判)\n'); sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    s.detach()


if __name__ == '__main__':
    main()
