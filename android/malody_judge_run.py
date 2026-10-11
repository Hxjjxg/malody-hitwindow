# -*- coding: utf-8 -*-
"""驱动 malody_judge_android.js —— 手机版 Malody 判定读取 (对应桌面 frida_read_judge.py)。

前置: 先跑 Connect-JsHookGadget.ps1 -PackageName me.mugzone.malody -RestartApp
      让 Gadget 处于 wait 状态、端口转发就绪。

用法:
  F:\\frida16\\Scripts\\python.exe malody_judge_run.py [--seconds N] [--attach]

  --seconds N  跑 N 秒后自动退出 (默认 0 = 一直跑, Ctrl+C 结束)
  --attach     不 spawn, 直接 attach 已在等待的 Gadget

单实例锁: 绑 127.0.0.1:27999。第二个实例会直接退出而不是把日志清空。
"""
import argparse
import os
import socket
import sys
import time

import frida

# .js 与本脚本同目录 (仓库可整体搬移)
_HERE = os.path.dirname(os.path.abspath(__file__))
JS_PATH = os.path.join(_HERE, 'malody_judge_android.js')

# 日志留在 malody_re 根目录 (与历史日志、监听脚本一致)
LOG = r"C:\Users\lenov\malody_re\judge_android_log.txt"
ENDPOINT = "127.0.0.1:27042"
GADGET = "re.frida.Gadget"
LOCK_PORT = 27999

_lock = None


def acquire_lock():
    """返回 True 表示抢到锁; 否则说明已有实例在跑。"""
    global _lock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
        _lock = s
        return True
    except OSError:
        s.close()
        return False


def on_message(msg, data):
    t = msg.get('type')
    if t in ('send', 'log'):
        line = str(msg.get('payload'))
    elif t == 'error':
        line = '[JS-ERR] %s\n%s' % (msg.get('description'), msg.get('stack', ''))
    else:
        line = '[%s] %s' % (t, msg)
    try:
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception as e:
        sys.stdout.write('[!] log write failed: %s\n' % e)
    sys.stdout.write(line + '\n')
    sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seconds', type=int, default=0)
    ap.add_argument('--attach', action='store_true')
    ap.add_argument('--label', default='', help='判定等级标签, 日志写 judge_android_<label>.txt')
    ap.add_argument('--append', action='store_true', help='不清空日志, 追加')
    args = ap.parse_args()

    global LOG
    if args.label:
        LOG = r"C:\Users\lenov\malody_re\judge_android_%s.txt" % args.label

    if not os.path.exists(JS_PATH):
        sys.stdout.write('[!] missing %s\n' % JS_PATH)
        return 1
    js = open(JS_PATH, encoding='utf-8').read()

    if not acquire_lock():
        sys.stdout.write('[!] 已有 malody_judge_run.py 实例在运行 (锁 %d 被占)。\n'
                         '    先结束它, 否则日志会被清空。\n' % LOCK_PORT)
        return 2

    if args.append:
        open(LOG, 'a', encoding='utf-8').close()
        sys.stdout.write('[*] log 追加 -> %s\n' % LOG)
    else:
        open(LOG, 'w', encoding='utf-8').close()
        sys.stdout.write('[*] log 已重置 -> %s\n' % LOG)

    dev = frida.get_device_manager().add_remote_device(ENDPOINT)
    sys.stdout.write('[*] device: %s\n' % dev)
    sys.stdout.flush()

    pid = None
    try:
        if args.attach:
            sys.stdout.write('[*] attaching to %s ...\n' % GADGET)
            session = dev.attach(GADGET)
        else:
            sys.stdout.write('[*] spawning %s ...\n' % GADGET)
            try:
                pid = dev.spawn([GADGET])
            except Exception as e:
                sys.stdout.write('[!] spawn(list) failed: %s -- trying str\n' % e)
                pid = dev.spawn(GADGET)
            sys.stdout.write('[*] pid %s\n' % pid)
            session = dev.attach(pid)
    except Exception as e:
        sys.stdout.write('[!] 连接 Gadget 失败: %s\n' % e)
        sys.stdout.write('    先重跑 Connect-JsHookGadget.ps1 -PackageName me.mugzone.malody -RestartApp\n')
        sys.stdout.flush()
        return 3

    script = session.create_script(js)
    script.on('message', on_message)
    script.on('destroyed', lambda: sys.stdout.write('[!] script destroyed\n'))
    try:
        script.load()
    except Exception as e:
        sys.stdout.write('[!] script.load 失败: %s\n' % e)
        sys.stdout.flush()
        return 4

    if pid is not None:
        dev.resume(pid)
        sys.stdout.write('[*] resumed. 现在在手机上进入 Key 图并游玩。\n')
    else:
        sys.stdout.write('[*] script loaded (attach 模式)。\n')
    sys.stdout.flush()

    try:
        if args.seconds:
            time.sleep(args.seconds)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        sys.stdout.write('\n[*] interrupted\n')
    finally:
        try:
            session.detach()
        except Exception:
            pass
        sys.stdout.write('[*] log -> %s\n' % LOG)
    return 0


if __name__ == '__main__':
    sys.exit(main())
