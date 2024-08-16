```python
from pwn import *
import sys

if len(sys.argv) != 2:
    print("Invalid arguments!")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()

wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list:
        for password in password_list:
            password = password.strip("\n").encode('latin-1')
            password_hash = sha256sumhex(password)
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
            if password_hash == wanted_hash:
                p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()
            attempts += 1
        p.failure("Password hash not found!")
```


Output
```shell
└─# echo -ne python | sha256sum
11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1  -

└─# python3 33.py 11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1
[+] Attempting to crack: 11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1!
    : Password hash found after 16470 attempts! python hashes to 11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1!

```


### Step-by-Step Explanation:

```python
from pwn import *
import sys
```
- **`from pwn import *`**: This imports everything from the `pwn` library, which is used for various hacking tools and utilities. In this script, it's used for logging and hash calculations.
- **`import sys`**: This imports the `sys` module, allowing access to command-line arguments and other system-specific parameters.


```python
if len(sys.argv) != 2:
    print("Invalid arguments!")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()
```
- **Argument Check**: The script checks if exactly one command-line argument is provided (the SHA-256 hash to be cracked). If not, it prints an error message and exits.


```python
wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0
```
- **`wanted_hash`**: This stores the SHA-256 hash that you want to crack, which is passed as the command-line argument.
- **`password_file`**: This is the path to the password list file (`rockyou.txt`), a common password list used for brute-force attacks.
- **`attempts`**: This counter tracks the number of password attempts made.


```python
with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
```
- **Progress Logging**: The script starts a progress log using the `pwn` library to show the cracking process. The log will display the hash being attempted.


```python
    with open(password_file, "r", encoding='latin-1') as password_list:
```
- **Open Password File**: The script opens the `rockyou.txt` password file for reading, using `latin-1` encoding to correctly handle any special characters.


```python
        for password in password_list:
            password = password.strip("\n").encode('latin-1')
            password_hash = sha256sumhex(password)
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
```
- **Password Loop**: The script iterates over each password in the `rockyou.txt` file:
    - **`strip("\n")`** removes newline characters.
    - **`encode('latin-1')`** converts the password to bytes.
    - **`sha256sumhex(password)`** computes the SHA-256 hash of the password.
    - **`p.status`** logs the current attempt, showing the attempt number, the password being tried, and its hash.


```python
            if password_hash == wanted_hash:
                p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()
```
- **Hash Comparison**: The script checks if the calculated hash matches the `wanted_hash`:
    - If a match is found, it logs a success message with the number of attempts and the correct password, then exits the script.


```python
            attempts += 1
```
- **Increment Counter**: If the hash doesn't match, the script increments the `attempts` counter and moves on to the next password.


```python
        p.failure("Password hash not found!")
```
- **Failure Logging**: If the script finishes checking all passwords without finding a match, it logs a failure message.