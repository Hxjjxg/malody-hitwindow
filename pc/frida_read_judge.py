# -*- coding: utf-8 -*-
"""attach 到运行中游戏：hook 判定函数，读原始栈参数 + judgeObj 窗口常量 + delta/tier"""
import frida, sys, time, os

LOG = r"C:\Users\lenov\malody_re\judge_log.txt"

JS = r"""
'use strict';
var base = Process.getModuleByName('malody.exe').base;
var downJudge = base.add(0x135C40);   // sub_535C40
var upJudge   = base.add(0x135D50);   // sub_535D50
var autoJudge = base.add(0x135DA0);   // sub_535DA0
var logged = false;

function log(x) { send('[D] ' + x); }

function hookJudge(name, addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            var esp = this.context.esp;
            var judgeObj = this.context.ecx;
            var note = esp.add(4).readPointer();
            var time = esp.add(8).readS32();
            this._time = time;
            this._note = note;
            this._judgeObj = judgeObj;
            if (!logged) {
                logged = true;
                log(name + ' onEnter: ecx(judgeObj)=' + judgeObj + ' [esp+4](note)=' + note + ' [esp+8](time)=' + time);
                log('  mapped: judgeObj=' + (Process.findRangeByAddress(judgeObj)?1:0) + ' note=' + (Process.findRangeByAddress(note)?1:0));
                try {
                    // judgeObj 窗口字段
                    log('  judgeObj[4]=' + judgeObj.add(16).readS32() + ' [8]=' + judgeObj.add(32).readS32() +
                        ' [9]=' + judgeObj.add(36).readS32() + ' [10]=' + judgeObj.add(40).readS32() + ' [11]=' + judgeObj.add(44).readS32());
                } catch(e) { log('  judgeObj fields ERR: ' + e); }
                try {
                    // note 时间字段探测
                    log('  note+76=' + note.add(76).readS32() + ' note+0=' + note.add(0).readU32());
                } catch(e) { log('  note read ERR: ' + e); }
            }
        },
        onLeave: function(retval) {
            var mask = retval.toInt32();
            if (mask !== 0x40000000) {
                var delta = this._time - this._note.add(76).readS32();
                send('JUDGE ' + name + ' d=' + delta + 'ms time=' + this._time + ' mask=0x' + (mask>>>0).toString(16) + ' low=' + (mask & 0x1f));
            }
        }
    });
}

hookJudge('down', downJudge);
hookJudge('up', upJudge);
hookJudge('auto', autoJudge);
log('hooked down/up/auto judge');
"""

def on_message(msg, data):
    line = str(msg.get('payload', msg)) + '\n'
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line)
    sys.stdout.write(line)
    sys.stdout.flush()

def main():
    GAME_DIR = r"C:\Users\lenov\Downloads\Compressed\malody_windows_4.3.7"
    EXE = os.path.join(GAME_DIR, "malody.exe")
    open(LOG, 'w', encoding='utf-8').close()
    sys.stdout.write('[*] spawning\n'); sys.stdout.flush()
    pid = frida.spawn(EXE, cwd=GAME_DIR)
    sys.stdout.write('[*] pid %d\n' % pid); sys.stdout.flush()
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    frida.resume(pid)
    sys.stdout.write('[*] resumed. Enter KEY chart and play (raw-stack reads active).\n'); sys.stdout.flush()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
