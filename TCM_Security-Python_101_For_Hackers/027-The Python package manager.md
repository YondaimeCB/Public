
https://pypi.org/project/pwntools/

# pwntools - CTF toolkit

![pwntools logo](https://pypi-camo.freetls.fastly.net/16d82a21c9635a10273ddd2595958d6c66216963/68747470733a2f2f6769746875622e636f6d2f47616c6c6f70736c65642f70776e746f6f6c732f626c6f622f737461626c652f646f63732f736f757263652f6c6f676f2e706e673f7261773d74727565)

[![PyPI](https://pypi-camo.freetls.fastly.net/e8124e6c8cf469c550812ca2613d24b035e13579/68747470733a2f2f696d672e736869656c64732e696f2f707970692f762f70776e746f6f6c733f7374796c653d666c6174)](https://pypi.python.org/pypi/pwntools/) [![Docs](https://pypi-camo.freetls.fastly.net/ffd6d503598c70a60c2e5bb8a7b4d5c707f15908/68747470733a2f2f72656164746865646f63732e6f72672f70726f6a656374732f70776e746f6f6c732f62616467652f3f76657273696f6e3d737461626c65)](https://docs.pwntools.com/) [![GitHub Workflow Status (dev)](https://pypi-camo.freetls.fastly.net/f0f758aa4e55b427b9ae4c13cf05c3cd5292fa2e/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f616374696f6e732f776f726b666c6f772f7374617475732f47616c6c6f70736c65642f70776e746f6f6c732f63692e796d6c3f6272616e63683d646576266c6f676f3d476974487562)](https://github.com/Gallopsled/pwntools/actions/workflows/ci.yml?query=branch%3Adev) [![Coveralls](https://pypi-camo.freetls.fastly.net/6e32669623a627f61612534d6c963119a61d0d4f/68747470733a2f2f696d672e736869656c64732e696f2f636f766572616c6c732f6769746875622f47616c6c6f70736c65642f70776e746f6f6c732f6465763f6c6f676f3d636f766572616c6c73)](https://coveralls.io/github/Gallopsled/pwntools?branch=dev) [![MIT License](https://pypi-camo.freetls.fastly.net/9e5be039daf9eba6b6bc47b88defd227ac24d66b/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6c6963656e73652d4d49542d626c75652e7376673f7374796c653d666c6174)](http://choosealicense.com/licenses/mit/) [![Packaging status](https://pypi-camo.freetls.fastly.net/c2a1fed1987d85d8b1f290727684d8b9f3ec9fc1/68747470733a2f2f696d672e736869656c64732e696f2f7265706f6c6f67792f7265706f7369746f726965732f707974686f6e3a70776e746f6f6c73)](https://repology.org/project/python:pwntools/versions) [![Discord](https://pypi-camo.freetls.fastly.net/5f215c3baec2037f46036776677bdc05c193b273/68747470733a2f2f696d672e736869656c64732e696f2f646973636f72642f3830393539303238353638373938303035323f6c6162656c3d446973636f7264267374796c653d706c6173746963)](https://discord.gg/96VA2zvjCB) [![Twitter](https://pypi-camo.freetls.fastly.net/da582a306681716cb9d35c2ac6479f02ce13baad/68747470733a2f2f696d672e736869656c64732e696f2f747769747465722f666f6c6c6f772f50776e746f6f6c73)](https://twitter.com/pwntools)

Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
```


# Installation

```shell
apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```


```shell
pip list  #list libraries with version
pip freeze  #list libraries with version, compressed
```


```shell
pip install pwntools==4.5.1  #install with version
pip uninstall pwntools==4.5.1  #uninstall witth version
```


Installation using requirements.txt

Save as requirements.txt
```shell
pwntools==4.5.0
py-ubjson==0.16.1
pyasn1==0.4.8
```

Execute
```shell
pip install -r requirements.txt
```