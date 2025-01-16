# pagewalker

A simple, semi-automated GDB module/plugin for analyzing 4-level page tables.

## Installation

1. Place pagewalker.py and its dependencies in a directory of your choice.
2. Import the tool in GDB runtime:: `source {your_path_to_tool}/pagewalker.py`
Alternatively, add it to your .gdbinit file for automatic loading.

## Usage

The tool provides multiple functionalities accessible via the pgw command. Use the -h flag to display help information:

```
pgw -h
```

### Walk a Single Virtual Address

To analyze the page table entries for a specific virtual address:

```
pgw -w <virtual_address>
```

Exmaple:

```
(remote) gef➤  pgw -w 0xffffffff8315e000

0xfffffe0000000000  |PGD            |PUD            |PMD            |PT             |PHYS           
-----------------------------------------------------------------------------------------------
index:              |508            |0              |0              |0              |               
-----------------------------------------------------------------------------------------------
address:            |0x100fc0fe0    |0x23fff0000    |0x23ffef000    |0x23ffed000    |0x315d000 
```

### Walk a Range of Virtual Addresses

To analyze a range of virtual addresses:

```
pgw -r -b <start_address> -e <end_address> [-d <step_size>]
```

`-b`: Start of the address range (hexadecimal).

`-e`: End of the address range (hexadecimal).

`-d`: Step size for the range (default: 0x1000).

### Search for a Physical Address

`(Currently slow and unstable)`
`Can be used to search for any address entry in memory`

To search for a physical address or a page table entry:

```
pgw -r -b <start_address> -e <end_address> [-d <step_size>] -p <physical_address> [-t <table_type>]
```

`-b`: Start of the address range (hexadecimal).

`-e`: End of the address range (hexadecimal).

`-d`: Step size for the range (default: 0x1000).

`-p`: Desired physical address to search for (hexadecimal).

`-t`: Type of entry to search (pgd, pud, pmd, pt, phys, any; default: any).

### Display Page Table Flags
To display the access rights and flags for a specific virtual address:

```
pgw -f <virtual_address>
```

## Notes

Argument Validation: The tool should validete input arguments to ensure correctness. Any invalid inputs will prompt an error message.
Sometimes validation may fail, please try not to break the programm, at least for now.

Errors: The tool may produce errors if used with inconsistent or unsupported inputs. Always validate your addresses.

Performance: Searching through large address ranges may take significant time.

Stablility: Since there are no autotests yet, you are the autotest, write about any bugs you find.

## To be done:

1. Make autotests
2. Refactor code that has already become spaghetti
3. Make more functionality to analyze exploits like PTE spray and search for page table collisions.