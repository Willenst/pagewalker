# pagewalker

A simple, semi-automated GDB module to print essential information about 4-level page tables.

## Usage:

1. Import the tool in gdb runtime: `source {your_path_to_tool}/pagewalker.py` (or simply add to .gdbinit)
2. In GDB, call: `pgd_scan {virtual_address}`

example:

```
(remote) gef➤  pgd_scan 0xffffffff8315e000

use "monitor xp/gx addr" to check the value

cr3 value 0x11005a000
pgd_index 511
pud_index 510
pmd_index 24
pt_index 350

pgd phys address 0x11005aff8
pud phys address 0x280fff0
pmd phys address 0x28100c0
pt phys adress 0x100110af0
page phys adress 0x315e000
```

## Note: 

It is intended that object is an actual pagetable!

## Example:

0xffff888154cfe000 in pagetable 0xffff88812e791000

### works fine

(remote) gef➤  x/10wx 0xffff88812e791000

0xffff88812e791000:     0x31152067      0x80000001      0x31154067      0x80000001
0xffff88812e791010:     0x3115a067      0x80000001      0x3115d067      0x80000001
0xffff88812e791020:     0x3115c067      0x80000001
(remote) gef➤  pgd_scan 0xffff88812e791000

use "monitor xp/gx addr" to check the value

cr3 value 0x11005a000
pgd_index 273
pud_index 4
pmd_index 371
pt_index 401

pgd phys address 0x11005a888
pud phys address 0x3401020
pmd phys address 0x100273b98
pt phys adress 0x12e6fbc88
page phys adress 0x12e791000
(remote) gef➤  monitor xp/10wx 0x12e791000 

000000012e791000: 0x31152067 0x80000001 0x31154067 0x80000001
000000012e791010: 0x3115a067 0x80000001 0x3115d067 0x80000001
000000012e791020: 0x3115c067 0x80000001

### doesn't work

(remote) gef➤  x/10wx 0xffff888154cfe000

0xffff888154cfe000:     0xcafebabe      0x00000000      0x00000000      0x00000000
0xffff888154cfe010:     0x00000000      0x00000000      0x00000000      0x00000000
0xffff888154cfe020:     0x00000000      0x00000000
(remote) gef➤  pgd_scan 0xffff888154cfe000

use "monitor xp/gx addr" to check the value

cr3 value 0x11005a000
pgd_index 273
pud_index 5
pmd_index 166
pt_index 254

pgd phys address 0x11005a888
pud phys address 0x3401028
1G huge page phys address 0x1400fe000
(remote) gef➤  monitor xp/10wx 0x1400fe000

00000001400fe000: 0x00442b8e 0x00442b8e 0x003f2887 0x00442b8e
00000001400fe010: 0x00442b8e 0x00442b8e 0x00442b8e 0x00442b8e
00000001400fe020: 0x00442b8e 0x00442b8e
