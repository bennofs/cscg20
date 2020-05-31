#!/usr/bin/env python3
import requests
import base64
from lxml import html

s = requests.Session()

def getImages(stage):
    doc = html.fromstring(s.get(f"http://hax1.allesctf.net:9200/captcha/{stage}").text)
    return [base64.b64decode(src[len("data:image/png;base64,"):]) for src in doc.xpath("//img/@src")]

def submit(stage, solution):
    r = s.post(
        f"http://hax1.allesctf.net:9200/captcha/{stage}",
        data={str(stage): solution},
        allow_redirects=False,
    )
    r.raise_for_status()
    redirect = r.headers["Location"]
    if "fail" in redirect:
        return redirect.split("=")[1]
    else:
        return int(stage) + 1
