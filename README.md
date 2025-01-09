# pagewalker

A simple, semi-automated GDB module/plugin for 4-level page tables analyze.

## Usage

### Page walk

1. Import the tool in gdb runtime: `source {your_path_to_tool}/pagewalker.py` (or simply add to .gdbinit)
2. In GDB, call: `pgd_walk {virtual_address}`

```
(remote) gef➤  pgd_walk 0xffffffff8315e000

0xfffffe0000000000  |PGD            |PUD            |PMD            |PT             |PHYS           
-----------------------------------------------------------------------------------------------
index:              |508            |0              |0              |0              |               
-----------------------------------------------------------------------------------------------
address:            |0x100fc0fe0    |0x23fff0000    |0x23ffef000    |0x23ffed000    |0x315d000 
```

### Page walk for range of pages

1st address - is the address of the beginning of the range
2nd address - end address of the end of the range
3rd address - step

```
pgd_range_walk 0x10000000000 0x10062000000 0x200000

0x10000000000       |PGD            |PUD            |PMD            |PT             |PHYS           
-----------------------------------------------------------------------------------------------
index:              |2              |0              |0              |0              |               
-----------------------------------------------------------------------------------------------
address:            |0x101fb2010    |0x14d1ef000    |0x14d1f0000    |0x14d1f1000    |0x14aa4f000    


0x10000200000       |PGD            |PUD            |PMD            |PT             |PHYS           
-----------------------------------------------------------------------------------------------
index:              |2              |0              |1              |0              |               
-----------------------------------------------------------------------------------------------
address:            |0x101fb2010    |0x14d1ef000    |0x14d1f0008    |0x14d253000    |0x15175f000
```

### Search virtual address for a physical page or page table entry

`(Currently slow and unstable)`

1st param - address of the beginning of the search area
2nd param - address of the end of the search area
3rd param - step
4th param - desired physical address 
5th param - type of entry (phys, pt , pmd, pud, pgd)

```
(remote) gef➤  pgd_phys_search 0xfffffe0000000000 0xfffffe0000004000 0x1000 0x237c14000 phys
0xfffffe0000002000
```

## Note: 

It is intended that object is an actual address! Tool will be reworked to be more reliable and work with arguments soon!
