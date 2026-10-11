# -*- coding: utf-8 -*-
"""发现判定函数 + 诊断 args + 记录 (delta, tier)"""
import frida, sys, os, time

GAME_DIR = r"C:\Users\lenov\Downloads\Compressed\malody_windows_4.3.7"
EXE = os.path.join(GAME_DIR, "malody.exe")
LOG = r"C:\Users\lenov\malody_re\judge_log.txt"

JS = r"""
'use strict';
var base = Process.getModuleByName('malody.exe').base;
var sub_5AC1B0 = base.add(0x1AC1B0);
var sub_5AD7F0 = base.add(0x1AD7F0);

var discovered = false;
var hooked = {};
var diagDone = false;

function S(x) { send('[D] ' + x); }

function isMapped(p) {
    try { return Process.findRangeByAddress(p) !== null; } catch(e) { return false; }
}

function hookJudge(name, fnPtr) {
    if (hooked[name]) return;
    hooked[name] = true;
    try {
        Interceptor.attach(fnPtr, {
            onEnter: function(args) {
                var self = this;
                if (!diagDone) {
                    diagDone = true;
                    S('judge ' + name + ' call args[0]=' + args[0] + ' args[1]=' + args[1] + ' args[2]=' + args[2]);
                    S('  mapped? a0=' + isMapped(args[0]) + ' a1=' + isMapped(args[1]));
                    try { S('  note+76=' + args[1].add(76).readS32()); } catch(e) { S('  note+76 ERR ' + e); }
                    try { S('  note+16f=' + args[1].add(16).readFloat()); } catch(e) { S('  note+16 ERR ' + e); }
                }
                try {
                    var note = args[1];
                    var cur = args[2].toInt32();
                    var noteTime = note.add(76).readS32();
                    self._delta = cur - noteTime;
                    self._ok = true;
                } catch(e) { self._ok = false; }
            },
            onLeave: function(retval) {
                var mask = retval.toInt32();
                if (mask !== 0x40000000 && this._ok) {
                    send('JUDGE ' + name + ' d=' + this._delta + 'ms mask=0x' + (mask>>>0).toString(16) + ' low=' + (mask & 0x1f));
                } else if (mask !== 0x40000000 && !this._ok) {
                    send('JUDGE ' + name + ' d=? mask=0x' + (mask>>>0).toString(16) + ' low=' + (mask & 0x1f));
                }
            }
        });
        S('hooked judge ' + name + ' @ ' + fnPtr + ' rva=' + fnPtr.sub(base));
    } catch(e) { S('hookJudge ' + name + ' FAILED: ' + e); }
}

function tryDiscover(ecx, tag) {
    if (discovered) return;
    try {
        if (!isMapped(ecx)) return;
        var p764 = ecx.add(764);
        if (!isMapped(p764)) return;
        var judgeObj = p764.readPointer();
        if (judgeObj.isNull() || !isMapped(judgeObj)) return;
        var vtable = judgeObj.readPointer();
        if (!isMapped(vtable)) return;
        discovered = true;
        var down = vtable.add(8).readPointer();
        var up   = vtable.add(12).readPointer();
        var auto = vtable.add(16).readPointer();
        S('DISCOVERED via ' + tag + ' judgeObj=' + judgeObj + ' vtable=' + vtable);
        S('down rva=' + down.sub(base) + '  up rva=' + up.sub(base) + '  auto rva=' + auto.sub(base));
        hookJudge('down', down);
        hookJudge('up', up);
        hookJudge('auto', auto);
    } catch(e) { S('discover ERR: ' + e); }
}

Interceptor.attach(sub_5AC1B0, {
    onEnter: function() { tryDiscover(this.context.ecx, '5AC1B0'); }
});
Interceptor.attach(sub_5AD7F0, {
    onEnter: function() {
        var ecx = this.context.ecx;
        if (isMapped(ecx)) tryDiscover(ecx.add(8), '5AD7F0');
    }
});
S('waiting for play...');
"""

def on_message(msg, data):
    p = msg.get('payload', msg)
    line = str(p) + '\n'
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line)
    sys.stdout.write(line)
    sys.stdout.flush()

def main():
    open(LOG, 'w', encoding='utf-8').close()
    sys.stdout.write('[*] spawning\n'); sys.stdout.flush()
    pid = frida.spawn(EXE, cwd=GAME_DIR)
    sys.stdout.write('[*] pid %d\n' % pid); sys.stdout.flush()
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    frida.resume(pid)
    sys.stdout.write('[*] resumed. Enter KEY chart and play.\n'); sys.stdout.flush()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    sys.stdout.write('[*] done\n'); sys.stdout.flush()

if __name__ == '__main__':
    main()
