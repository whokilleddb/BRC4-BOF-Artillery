# BR-Situational-Awareness

This repository contains a collection of BRC4 BOFs ported from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF). The repository also provides a list correlating CS BOFs to pre-existing BRC4 Commands. While the core logic of the BOFs remain contant, some modifications have been made to provide more comprehensive outputs, along with  revelant usage instructions.

Most BOFs support the `-h`/`--help`/`/?` flag to print help

| CS-Situational-Awareness-BOF | BRC4 Equivalent | Usage | Description |
|:-----------------------------| :-----------| :---------------|:-------|
| arp  | `arp` command | `arp` | List ARP entries for all network interfaces on the current host |
| cacls | acl C:\Path\to\file | Closely resembled by the `acl` command | List ACL for an object. While the CS BOF supports wild cards, the BRC4 command does not|
| dir                          |  BOFF Implemented! | dir [directory] [/s]               | List files in a directory. Supports wildcards (e.g. "C:\Windows\S*") unlike the BRC4 `ls` command |
| driversigs                   | BOFF Implemented!   | driversigs            | Enumerate installed services Imagepaths to check the signing cert against known AV/EDR vendors |
| enum_filter_driver           | BOFF Implemented!   | enum_filter_driver [opt:computer] | Enumerate filter drivers. |
