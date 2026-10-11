# -*- coding: utf-8 -*-
"""Malody 判定挂钩 — 记录结算函数触发时的档位掩码 + 栈回溯"""
import frida, sys, os, json, time, threading

GAME_DIR = r"C:\Users\lenov\Downloads\Compressed\malody_windows_4.3.7"
EXE = os.path.join(GAME_DIR, "malody.exe")
LOG = r"C:\Users\lenov\malody_re\hit_log.txt"

# IDA 绝对地址 -> RVA 偏移（IDA 镜像基址 0x400000）
BASE_IDA = 0x400000
HOOKS = {
    "sub_53C0E0": 0x53C0E0 - BASE_IDA,
    "sub_53C1D0": 0x53C1D0 - BASE_IDA,
    "sub_53CEF0": 0x53CEF0 - BASE_IDA,
    "sub_53D6E0": 0x53D6E0 - BASE_IDA,
    "sub_53DFE0": 0x53DFE0 - BASE_IDA,
}

JS_TMPL = r"""
'use strict';
var mod = Process.getModuleByName('malody.exe');
var base = mod.base;
console.log('[*] BASE ' + base + ' size ' + mod.size);
var HOOKS = %s;
var hitCount = 0;

Object.keys(HOOKS).forEach(function(name){
  var off = HOOKS[name];
  var addr = base.add(off);
  Interceptor.attach(addr, {
    onEnter: function(args){
      var mask = args[1].toInt32();
      var ecx = this.context.ecx;
      var low = mask & 0x1f;
      hitCount++;
      var rec = { n: hitCount, fn: name, ecx: ecx.toString(), mask: mask, low: low };
      if (hitCount <= 400) {
        try {
          var bt = Thread.backtrace(this.context, Backtracer.FUZZY);
          rec.bt = bt.slice(0, 6).map(function(x){ return x.toString(); });
        } catch(e) { rec.bt = ['bt_err:'+e]; }
      }
      send('HIT ' + JSON.stringify(rec));
    }
  });
  console.log('[*] HOOKED ' + name + ' @ ' + addr);
});
""" % json.dumps(HOOKS)

def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = msg['payload']
        line = payload + '\n'
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line)
        sys.stdout.write(payload + '\n')
        sys.stdout.flush()
    elif msg.get('type') == 'error':
        line = '[JS-ERR] ' + str(msg) + '\n'
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line)
        sys.stdout.write(line)
        sys.stdout.flush()
    else:
        line = '[JS] ' + str(msg.get('payload', msg)) + '\n'
        sys.stdout.write(line)
        sys.stdout.flush()

def main():
    # 清空日志
    open(LOG, 'w', encoding='utf-8').close()
    sys.stdout.write('[*] spawning %s\n' % EXE); sys.stdout.flush()
    try:
        pid = frida.spawn(EXE, cwd=GAME_DIR)
    except Exception as e:
        sys.stdout.write('[!] spawn failed: %s\n' % e); sys.stdout.flush()
        return
    sys.stdout.write('[*] pid %d\n' % pid); sys.stdout.flush()
    session = frida.attach(pid)
    script = session.create_script(JS_TMPL)
    script.on('message', on_message)
    script.load()
    frida.resume(pid)
    sys.stdout.write('[*] resumed, game window should appear. Recording hits...\n'); sys.stdout.flush()
    # 持续运行，直到进程退出或 Ctrl+C
    try:
        while True:
            time.sleep(2)
            try:
                session.is_detached
            except Exception:
                break
    except KeyboardInterrupt:
        pass
    sys.stdout.write('[*] done\n'); sys.stdout.flush()

if __name__ == '__main__':
    main()
