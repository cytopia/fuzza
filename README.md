# fuzza

[![PyPI](https://img.shields.io/pypi/v/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Status](https://img.shields.io/pypi/status/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Format](https://img.shields.io/pypi/format/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - Implementation](https://img.shields.io/pypi/implementation/fuzza)](https://pypi.org/project/fuzza/)
[![PyPI - License](https://img.shields.io/pypi/l/fuzza)](https://pypi.org/project/fuzza/)

Customizable TCP fuzzing tool to test for remote buffer overflows.


## Installation
```bash
pip install fuzza
```


## Usage
```bash
$ fuzza --help

usage: fuzza [-h] [-v] [-c char] [-p str] [-s str] [-l int] [-m int] [-i str]
             [-a str] [-t float] [-d float]
             host port

Customizable TCP fuzzing tool to test for remote buffer overflows.

positional arguments:
  host                      address to connect to.
  port                      port to connect to.

optional arguments:
  -h, --help                show this help message and exit
  -v, --version             Show version information,
  -c char, --char char      Buffer character to send as payload. Default: "A"
  -p str, --prefix str      Prefix string to prepend to buffer. Empty by default.
  -s str, --suffix str      Suffix string to append to buffer. Empty by default.
  -l int, --length int      Initial length to concat buffer string with x*char. Default: 100
  -m int, --multiply int    Round multiplier to concat buffer string with x*char every round.
                            Default: 100
  -i str, --init str        If specified, initializes communication in the form
                            '<send>:<expect>,<send>:<expect>,...'. Where <send> is the data
                            to be sent to the server and <expect> is the answer to be
                            received from the server. Regex supported for <expect> part.
  -a str, --answer str      If specified, will stop if answer is not received from
                            endpoint. Regex supported.
  -t float, --timeout float Timeout for receiving data before declaring the endpoint as
                            crashed. Default: 30.0
  -d float, --delay float   Delay in seconds between each round. Default: 1.0

example:

  The following example illustrates how to use the initial communication by:
      1. Expecting the POP3 server banner
      2. Sending 'USER bob'
      3. Expecting a welcome message
  Additionally before sending the fuzzing characters, it is prepended with 'PASS ',
  so that the actuall fuzzing can be done on the password:
      $ fuzza -i ':.*POP3.*,USER bob:.*welcome.*' -p 'PASS '
```


## Examples

### SLMail 5.5 Buffer overflow

* [CVE-2003-0264](https://www.cvedetails.com/cve/CVE-2003-0264/) - buffer overflow in password.

To see how the raw communication works, have a look at the following netcat snippet:
```bash
$ nc mail.example.tld 110
+OK POP3 server mail.example.tld ready <00001.544405549@mail.example.tld>
USER test
+OK test welcome here
PASS LongPassword
```

In order to fuzz the password, all previous communication must have happened. By using `fuzza`,
this can be achieved with the `-i` argument to specify initial data to be send and received:
```bash
$ fuzz -i ':.*OK POP3.*,USER test:.*test welcome.*' -p 'PASS ' mail.example.tld 110

------------------------------------------------------------
A * 100
------------------------------------------------------------
Init Awaiting: .*OK POP3.*
Init Received: +OK POP3 server mail.example.tld ready <00005.544236132@mail.example.tld>
Init Sending:  USER test
Init Awaiting: test welcome
Init Received: +OK test welcome here
Sending "PASS " + "A"*100 + ""

...

------------------------------------------------------------
A * 4000
------------------------------------------------------------
Init Awaiting: .*OK POP3.*

Remote service (most likely) crashed at 3000 bytes of "A"
Payload sent:
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```


## License

**[MIT License](LICENSE.txt)**

Copyright (c) 2020 **[cytopia](https://github.com/cytopia)**
