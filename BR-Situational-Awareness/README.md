# BR-Situational-Awareness

This repository contains a collection of BRC4 BOFs ported from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF). The repository also provides a list correlating CS BOFs to pre-existing BRC4 Commands. While the core logic of the BOFs remain contant, some modifications have been made to provide more comprehensive outputs, along with  revelant usage instructions.

Most BOFs support the `-h`/`--help`/`/?` flag to print help

| CS-Situational-Awareness-BOF | Usage | BRC4 Equivalent | Notes |
|:-----------------------------| :-----------| :---------------|:-------|
| arp |arp | `arp` command | List ARP table |
| cacls | acl C:\Path\to\file | `acl` command |

| dir                          | dir [directory] [/s]           |  BOFF Implemented!               | List files in a directory. Supports wildcards (e.g. "C:\Windows\S*") unlike the BRC4 `ls` command <br> Use `coffexec dir.o /?` to print help |
| enum_filter_driver           | enum_filter_driver [opt:computer] | BOFF Implemented!             | Enumerate filter drivers. <br> Use `coffexec enum_filter_driver.o /?` to print help |
