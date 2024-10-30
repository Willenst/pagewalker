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

It is intended that object is an actual address!