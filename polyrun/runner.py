#!/usr/bin/env python3
import pytio
import threading
import sys


def run_lang(lang, code):
    print(f"running {lang}", file=sys.stderr)
    tio = pytio.Tio()
    r = tio.send(pytio.TioRequest(lang=lang, code=code))
    if r.error is not None:
        print(f"[+] {lang} ERROR")
    else:
        print(f"[+] {lang} {r.result}")
    sys.stdout.flush()


code = open("./torun", "r").read()
for lang in pytio.Tio().query_languages():
    run_lang(lang, code)
