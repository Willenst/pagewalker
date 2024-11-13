# pagewalker

A simple, semi-automated GDB module to print essential information about 4-level page tables.

# Usage:

## Analyze Page:

1. Import the tool in gdb runtime: `source {your_path_to_tool}/pagewalker.py` (or simply add to .gdbinit)
2. In GDB, call: `pgd_scan {virtual_address}`

example:

1st address - is the address of the beginning of the search area
2nd address - end address of the end of the search area
3rd address - step
4th address - desired physical address 

```
(remote) gef➤  pgd_scan 0xffffffff8315e000

0xfffffe0000000000  |PGD            |PUD            |PMD            |PT             |PHYS           
-----------------------------------------------------------------------------------------------
index:              |508            |0              |0              |0              |               
-----------------------------------------------------------------------------------------------
address:            |0x100fc0fe0    |0x23fff0000    |0x23ffef000    |0x23ffed000    |0x315d000 
```

## Search virtual address for a physical page:

1-st address - start 

```
(remote) gef➤  pgd_phys_search 0xfffffe0000000000 0xfffffe0000004000 0x1000 0x237c14000
0xfffffe0000002000
```

## Note: 

It is intended that object is an actual address! Tool will be reworked to be more reliable and work with arguments soon!