# BR-Situational-Awareness

This repository contains a collection of BRC4 BOFs ported from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF). The repository also provides a list correlating CS BOFs to pre-existing BRC4 Commands. While the core logic of the BOFs remain contant, some modifications have been made to provide more comprehensive outputs, along with  revelant usage instructions.

| CS-Situational-Awareness-BOF | Description | BRC4 Equivalent | Notes |
|:-----------------------------| :-----------| :---------------|:-------|
| dir                          | dir [directory] [/s]           |  BOFF Implemented!               | List files in a directory. Supports wildcards (e.g. "C:\Windows\S*") unlike the BRC4 `ls` command <br> Use `coffexec dir.o /?` to print help |
