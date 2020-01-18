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
```
$ fuzza --help

usage: fuzza [-c char] [-p str] [-s str] [-i int] [-r int] [-d float] host port
             [-h] [-v] 

Customizable TCP fuzzing tool to test for remote buffer overflows.

positional arguments:
  host                       address to connect to.
  port                       port to connect to.

optional arguments:
  -h, --help                 show this help message and exit
  -v, --version              Show version information,
  -c char, --char char       Buffer character to send as payload. Default: "A"
  -p str, --prefix str       Prefix string to prepend to buffer. Empty by default.
  -s str, --suffix str       Suffix string to append to buffer. Empty by default.
  -i int, --init-multi int   Initial multiplier to concat buffer string with
                             x*char. Default: 100
  -r int, --round-multi int  Round multiplier to concat buffer string with x*char
                             every round. Default: 100
  -d float, --delay float    Delay in seconds between each round. Default: 1.0
```


## License

**[MIT License](LICENSE.txt)**

Copyright (c) 2020 **[cytopia](https://github.com/cytopia)**
