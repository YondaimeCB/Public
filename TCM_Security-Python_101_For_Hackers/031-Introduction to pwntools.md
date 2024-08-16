Install pwntools
```shell
pip install pwntools #python
pip3 install pwntools #python3
```


```python
from pwn import *

print(cyclic(50))
print(cyclic_find("laaa"))
```
```shell
└─# python3 031.py
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
44
```


```python
print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))
```
```shell
└─# python3 031.py
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

00000000  6a 68 68 2f  2f 2f 73 68  2f 62 69 6e  89 e3 68 01  │jhh/│//sh│/bin│··h·│
00000010  01 01 01 81  34 24 72 69  01 01 31 c9  51 6a 04 59  │····│4$ri│··1·│Qj·Y│
00000020  01 e1 51 89  e1 31 d2 6a  0b 58 cd 80               │··Q·│·1·j│·X··│
0000002c

```


```python
p = process("/bin/sh")
p.sendline("echo hello;")
p.interactive()
```
```shell
└─# python3 031.py
[+] Starting local process '/bin/sh': pid 66300
/home/kali/Documents/031.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("echo hello;")
[*] Switching to interactive mode
hello
$ id
uid=0(root) gid=0(root) groups=0(root)
```


```python
r = remote("127.0.0.1", 1234)
r.sendline("hello!")
r.interactive()
r.close()
```
```shell
┌──(root㉿kali)-[~]
└─# nc -lnvp 1234
listening on [any] 1234 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 58604
hello!

```


```python
print(p32(0x13371337))
print(hex(u32(p32(0x13371337))))
```
```shell
└─# python3 031.py
b'7\x137\x13'
0x13371337

```


```python
l = ELF('/bin/bash')

print(hex(l.address))
print(hex(l.entry))

print(hex(l.got['write']))
print(hex(l.plt['write']))

for address in l.search(b'/bin/sh\x00'):
		print(hex(address))

print(hex(next(l.search(asm('jmp esp')))))

```
```shell
└─# python3 031.py
[*] '/bin/bash'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

0x0
0x31730
0x12f930
0x2f290
0x31e22
0x31ec1
0x3c1de

```


```python
r = ROP(l)
print(r.rbx)
print("----")
print(xor(xor("A", "B"),"A"))
print(b64e(b"test"))
print(b64d(b"dGVzdA=="))
print(md5sumhex(b"hello"))
print(sha1sumhex(b"hello"))
print("----")
print(bits(b'a'))
print(unbits([0, 1, 1, 0, 0, 0, 0, 1]))

```
```shell
[*] Loaded 119 cached gadgets for '/bin/bash'
Gadget(0x31d48, ['pop rbx', 'ret'], ['rbx'], 0x8)
----
/usr/local/lib/python3.11/dist-packages/pwnlib/util/fiddling.py:327: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  strs = [packing.flat(s, word_size = 8, sign = False, endianness = 'little') for s in args]
b'B'
dGVzdA==
b'test'
5d41402abc4b2a76b9719d911017c592
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
----
[0, 1, 1, 0, 0, 0, 0, 1]
b'a'


```