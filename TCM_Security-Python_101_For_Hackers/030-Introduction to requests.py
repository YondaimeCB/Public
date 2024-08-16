import requests

x = requests.get('https://httpbin.org/get')

print(x.headers)
print(x.headers['Server'])
print(x.status_code)

    # {'Date': 'Thu, 08 Aug 2024 14:24:01 GMT', 'Content-Type': 'application/json', 'Content-Length': '307', 'Connection': 'keep-alive', 'Server': 'gunicorn/19.9.0', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'}
    # gunicorn/19.9.0
    # 200


if x.status_code == 200:
    print("Success!")
elif x.status_code == 404:
    print("Not found!")

    # Success!


print(x.elapsed)
print(x.cookies)

    # 0:00:01.014991       
    # <RequestsCookieJar[]>


x = requests.get('http://httpbin.org/get', params={'id':'1'})
print(x.url)

    # http://httpbin.org/get?id=1


x = requests.get('http://httpbin.org/get?id=2')
print(x.url)

    # http://httpbin.org/get?id=2


x = requests.get('http://httpbin.org/get', params={'id':'3'}, headers={'Accept':'application/json'})
print(x.text)

    # {
    # "args": {
    #     "id": "3"
    # },
    # "headers": {
    #     "Accept": "application/json",
    #     "Accept-Encoding": "gzip, deflate",
    #     "Host": "httpbin.org",
    #     "User-Agent": "python-requests/2.32.3",
    #     "X-Amzn-Trace-Id": "Root=1-66b4d88d-26350d43022b7bb3230734c1"
    # },
    # "origin": "x.x.x.x",
    # "url": "http://httpbin.org/get?id=3"
    # }


x = requests.delete('http://httpbin.org/delete')
print(x.text)

    # {
    # "args": {},
    # "data": "",
    # "files": {},
    # "form": {},
    # "headers": {
    #     "Accept": "*/*",
    #     "Accept-Encoding": "gzip, deflate",
    #     "Content-Length": "0",
    #     "Host": "httpbin.org",
    #     "User-Agent": "python-requests/2.32.3",
    #     "X-Amzn-Trace-Id": "Root=1-66b4d933-168aebda210654f843025d43"
    # },
    # "json": null,
    # "origin": "x.x.x.x",
    # "url": "http://httpbin.org/delete"
    # }


x = requests.post('http://httpbin.org/post', data={'a':'b', 'c':'d', 'e':'f'})
print(x.text)

    # {
    # "args": {},
    # "data": "",
    # "files": {},
    # "form": {
    #     "a": "b",
    #     "c": "d",
    #     "e": "f"
    # },
    # "headers": {
    #     "Accept": "*/*",
    #     "Accept-Encoding": "gzip, deflate",
    #     "Content-Length": "3",
    #     "Content-Type": "application/x-www-form-urlencoded",
    #     "Host": "httpbin.org",
    #     "User-Agent": "python-requests/2.32.3",
    #     "X-Amzn-Trace-Id": "Root=1-66b4daf8-3332fd64371c645d58434be0"
    # },
    # "json": null,
    # "origin": "x.x.x.x",
    # "url": "http://httpbin.org/post"
    # }


files = {'file': open('google.png', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

    # {
    # "args": {},
    # "data": "",
    # "files": {
    #     "file": "data:application/octet-stream;base64,iVBORw0KGgoAAAANSUhEUgAAAQMAAADCCAMAAAB6zFdcAAABU1BMVEX//f7///9GgfTfMDT//P43vFD2wwD///38//////wuukf//fz///k8fPOgwPv///getkDs++34wgBFgvJGgPWHzJuHrPXiMDPdMDRtm+70wAD0xQBiyHb///Q7fPFGgvCHzpf5vgA5evZ9zo/a6PfvubvdKCr1z8/v8vneGyBtl/HR5/o5d/JGgPnlTFFOheixyfGYufGDqu99p


x = requests.get('http://httpbin.org/get', auth=('username','password'))
print(x.text)

    # {
    # "args": {},
    # "headers": {
    #     "Accept": "*/*",
    #     "Accept-Encoding": "gzip, deflate",
    #     "Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
    #     "Host": "httpbin.org",
    #     "User-Agent": "python-requests/2.32.3",
    #     "X-Amzn-Trace-Id": "Root=1-66b4e5d4-789a590a4648113e412cb123" 
    # },
    # "origin": "x.x.x.x",
    # "url": "http://httpbin.org/get"
    # }

    # $ echo -ne dXNlcm5hbWU6cGFzc3dvcmQ= | base64 -d  
    # username:password


x = requests.get('https://expired.badssl.com', verify=False)

    # InsecureRequestWarning: Unverified HTTPS request is being made to host 'expired.badssl.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
    #   warnings.warn(


x = requests.get('http://github.com')
print(x.headers)

    # {'Server': 'GitHub.com', 'Date': 'Fri, 09 Aug 2024 15:23:18 GMT', 
    # 'Content-Type': 'text/html; charset=utf-8', 'Vary': 'X-PJAX, X-PJAX-Container, Turbo-Visit, Turbo-Frame, Accept-Language, Accept-Encoding, Accept, X-Requested-With', 'content-language': 'en-US', 'ETag': 'W/"867fc60ac0ea8fa0c27c7e9523278695"', 'Cache-Control': 'max-age=0, private, must-revalidate', 'Strict-Transport-Security': 'max-age=31536000; includeSubdomains; preload', 'X-Frame-Options': 'deny', 'X-Content-Type-Options': 'nosniff', 'X-XSS-Protection': '0', 'Referrer-Policy': 'origin-when-cross-origin, strict-origin-when-cross-origin', 'Content-Security-Policy': "default-src 'none';


x = requests.get('http://github.com', allow_redirects=False)
print(x.headers)

    # {'Content-Length': '0', 'Location': 'https://github.com/'}


x = requests.get('http://httpbin.org/get', timeout=0.01)
print(x.content)

    # ConnectTimeout(e, request=request)
    # requests.exceptions.ConnectTimeout: HTTPConnectionPool(host='httpbin.org', port=80): Max retries exceeded with url: /get (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x000001EC77EB78F0>, 'Connection to httpbin.org timed out. (connect timeout=0.01)'))


x = requests.get('http://httpbin.org/cookies', cookies={'a':'b'})
print(x.content)

    # b'{\n  "cookies": {\n    "a": "b"\n  }\n}\n'


x = requests.Session()
x.cookies.update({'a':'b'})
print(x.get('http://httpbin.org/cookies').text)
print(x.get('http://httpbin.org/cookies').text)

    # {
    #   "cookies": {
    #     "a": "b"
    #   }
    # }

    # {
    #   "cookies": {
    #     "a": "b"
    #   }
    # }


x = requests.get('https://api.github.com/events')
print(x.json())

    # 'created_at': '2024-08-09T15:57:29Z'}, {'id': '40899354665', 'type': 'PushEvent', 'actor': {'id': 33451416, 'login': 'Vsonneveld', 'display_login': 'Vsonneveld', 'gravatar_id': '', 'url': 'https://api.github.com/users/Vsonneveld', 'avatar_url': 'https://avatars.githubusercontent.com/u/33451416?'}, 'repo': {'id': 625580055, 'name': 'Vsonneveld/foroxity-genres', 'url': 'https://api.github.com/repos/Vsonneveld/foroxity-genres'}, 'payload': {'repository_id': 625580055, 'push_id': 19703659369, 'size': 1, 'distinct_size': 1, 'ref': 'refs/heads/main', 'head': '8a16e4e56b708986b130cf4fa042487a66617aa2', 'before': '507aef567fb88d7c5ba682dea741d4d6b2d8a665', 'commits': [{'sha': '8a16e4e56b708986b130cf4fa042487a66617aa2', 'author': {'email': '33451416+Vsonneveld@users.noreply.github.com', 'name': 'Vsonneveld'}, 'message': 'The genre has been updated', 'distinct': True, 'url': 'https://api.github.com/repos/Vsonneveld/foroxity-genres/commits/8a16e4e56b708986b130cf4fa042487a66617aa2'}]}, 'public': True, 'created_at': '2024-08-09T15:57:29Z'}]


x =  requests.get('https://www.google.com/logos/doodles/2024/paris-games-breaking-6753651837110566-la202124.gif')
with open('google2.png', 'wb') as f:
    f.write(x.content)

    # it download the gif and named it as google2.png