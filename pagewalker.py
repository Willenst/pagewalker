import gdb
import sys
import os
import argparse

#hack to import other modules
dirname = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, dirname)

from pagetable_entry import PGDe, PUDe, PMDe, PTe
from utility import spinning_cursor, validate_address, validate_range, normalize_address
#normalize address should be used all along the code

#should be integrated with pagetable_entry.py
class Page:
    cr3_register = None

    def __init__(self, virtual_address):
        self.virtual = int(virtual_address,16)
        self.indexes = None
        self.pgd = None
        self.pud = None
        self.pmd = None
        self.pt = None
        self.huge = ''
        self.phys = None
        self.broken = False
        Page.cr3_register = Page.set_cr3()
        Page.pgd_walk(self, virtual_address)

    @staticmethod
    def is_huge(addr):
        return addr & (1 << 7)

    @staticmethod
    def get_indexes(addr):
        addr = addr >> 12
        return [((addr >> (i * 9)) & 0x1FF) * 8 for i in range(4)][::-1]

    def huge_1gb(self, address):
        addr = address & ~((1 << 30) - 1) & ((1 << 51) - 1)
        addr += self.virtual & ((1 << 30) - 1)
        return addr

    def huge_2mb(self, address):
        addr = address & ~((1 << 21) - 1) & ((1 << 51) - 1)
        addr += self.virtual & ((1 << 21) - 1)
        return addr
    
    def page_4kb(self, address):
        addr = address & ~((1 << 12) - 1) & ((1 << 51) - 1)
        addr += self.virtual & ((1 << 12) - 1)
        return addr

    def get_phys_address(self, address):
        result = gdb.execute(f"monitor xp/gx {address}", to_string=True)
        if 'Cannot access memory' in result:
            return None
        phys_addr = int(result.split(':')[1].strip(), 16)
        if Page.is_huge(phys_addr):
            self.huge = 'HUGE'
            return phys_addr
        return phys_addr & ~((1 << 12) - 1) & ((1 << 51) - 1)

    @staticmethod
    def set_cr3():
        output = gdb.execute("p/x $cr3 & ~0xfff", to_string=True)
        value_str = output.split('=')[1].strip()
        return int(value_str, 16)

#should be integrated with pagetable_entry.py
    def pgd_walk(self, addr):
        self.indexes = Page.get_indexes(self.virtual)
        pgd_begin = Page.cr3_register
        self.pgd = pgd_begin + self.indexes[0]

        pud_begin = Page.get_phys_address(self, self.pgd)
        if pud_begin is None:
            self.broken = True
            return
        self.pud = pud_begin + self.indexes[1]

        pmd_begin = Page.get_phys_address(self, self.pud)
        if pmd_begin is None:
            self.broken = True
            return
        if self.huge:
            self.phys = Page.huge_1gb(self, pmd_begin)
            return
        self.pmd = pmd_begin + self.indexes[2]

        pt_begin = Page.get_phys_address(self, self.pmd)
        if pt_begin is None:
            self.broken = True
            return
        if self.huge:
            self.phys = Page.huge_2mb(self, pt_begin)
            return
        self.pt = pt_begin + self.indexes[3]

        phys_begin = Page.get_phys_address(self, self.pt)
        if phys_begin is not None:
            self.phys = Page.page_4kb(self, phys_begin)
            return
        else:
            self.broken = True

def format_output(out):
    address_list = out
    return_list = []
    for addr in address_list:
        try:
            hexed = hex(addr)
            return_list.append(hexed)
            if int(hexed,16) < 0x1000000: #kernel base offset for sanity 
                return_list = ['N/A' for i in range(len(out)+1)]
                return return_list
        except:
            return_list.append('N/A')
    return return_list

def pgd_walk(address_str):
    page = Page(address_str)

    try:
        hex(page.phys)
    except:
        print(f"{hex(page.virtual):<20} address don't exist")
        return

    print()
    print(f"{hex(page.virtual):<20}|{'PGD':<15}|{'PUD':<15}|{'PMD':<15}|{'PT':<15}|{'PHYS':<15}")
    print('-'*(15*5+20))
    print(f"{'index:':<20}|{page.indexes[0]//8:<15}|{page.indexes[1]//8:<15}|{page.indexes[2]//8:<15}|{page.indexes[3]//8:<15}|{page.huge:<15}")
    print('-'*(15*5+20))
    out = [page.pgd, page.pud, page.pmd, page.pt, page.phys]
    addresses = format_output(out)
    print(f"{'address:':<20}|{addresses[0]:<15}|{addresses[1]:<15}|{addresses[2]:<15}|{addresses[3]:<15}|{addresses[4]:<15}")
    print()

def pgd_virt_search(range_begin, range_end, range_delta, phys_address, table_type):
    '''
    Dumping the entire page tables would be a more efficient approach
    '''
    print(range_begin, range_end, range_delta, phys_address, table_type)
    begin = normalize_address(range_begin)[0]
    end = normalize_address(range_end)[0]
    delta = normalize_address(range_delta)[0]
    phys_address, phys_offset = normalize_address(phys_address)
    print(hex(begin),hex(end),hex(delta),hex(phys_address),hex(phys_offset),)
    fail_counter = 0
    cursor_progress = 0
    all_fields = ['phys', 'pt', 'pmd', 'pgd', 'pud']
    alert = False
    print('Searching')
    for i in range(begin, end, delta):
        page = Page(hex(i))
        cursor_progress = (cursor_progress + 1) % 10000
        spinning_cursor(cursor_progress//1000)
        if page.broken == True:
            fail_counter += 1
            if fail_counter == 500 and alert == False:
                alert = True
                print('Unreadable area, press ctrl+C if you want to stop searching')
            continue
        fail_counter = 0
        if alert == True:
            alert = False
            print('Unreadable area is over, continue scanning')
        if table_type == 'any':
            for field in all_fields:
                if getattr(page, field) is not None:
                    print(phys_address)
                    if phys_address == getattr(page, field):
                        print(f"\033[32m{hex(i+phys_offset)}\033[0m in \033[32m{field}\033[0m")
        elif phys_address == getattr(page, table_type):
            print(f"\033[32m{hex(i+phys_offset)}\033[0m")


def pgd_range_walk(range_begin, range_end, range_delta):
    begin = int(range_begin,16)
    end = int(range_end,16)
    delta = int(range_delta,16)
    for i in range(begin, end, delta):
        pgd_walk(hex(i))

def display_flags(entries):
    print(f"\n{'Flag/Pagetable Entry':<30} |{'PGD':<15} |{'PUD':<15} |{'PMD':<15} |{'PT':<15}")
    print("-" * 100)
    flags = ['Hex','Present', 'Huge', 'ReadWrite', 'UserSupervisor', 'PageWriteThrough', 'PageCacheDisabled', 'Accessed']
    
    for flag in flags:
        row = f"{flag:<30} |"
        for entry in entries:
            value = getattr(entry, flag, '-')
            if isinstance(value, int):
                value = f"0x{value:X}" if flag == 'Hex' else str(value)
            row += f"{value:<15} |"
        print(row)
        print("-" * 100)

    
def page_scan(addr):
    page = Page(addr)
    entries = [
        PGDe(page.pgd) if page.pgd else None,
        PUDe(page.pud) if page.pud else None,
        PMDe(page.pmd) if page.pmd else None,
        PTe(page.pt) if page.pt else None
    ]
    entries = [entry for entry in entries if entry]

    if entries:
        display_flags(entries)
    else:
        print("No valid entries to display flags.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Tool for working with page tables.")

    parser.add_argument("-w", "--walk", metavar="hex", help="Walk page table for a virtual address.")

    parser.add_argument("-r", "--range", action="store_true", help="Walk page table for an address range.")
    parser.add_argument("-b", "--begin", metavar="hex", help="begin of address range.")
    parser.add_argument("-e", "--end", metavar="hex", help="End of address range.")
    parser.add_argument("-d", "--delta", metavar="hex", default="0x1000", help="delta size for the range.")

    parser.add_argument("-s", "--search", action="store_true", help="Search physical address in a range.")
    parser.add_argument("-p", "--phys", metavar="hex", help="Physical address to search for.")
    parser.add_argument("-t", "--table_type", choices=["pgd", "pud", "pmd", "pt", "phys", "any"], default="any",
                        help="Type of table to search, default='any'.")

    parser.add_argument("-f", "--flag-scan", metavar="hex", help="Display page table flags for a virtual address.")

    return parser


class PageTableCommands(gdb.Command):
    """GDB Command for managing page table operations."""
    def __init__(self):
        super(PageTableCommands, self).__init__("pgw", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parser = parse_arguments()
        args = parser.parse_args(arg.split())

        if args.walk:
            validate_address(args.walk)
            pgd_walk(args.walk)
        if args.flag_scan:
            validate_address(args.flag_scan)
            page_scan(args.flag_scan)
        elif args.range:
            print('a')
            validate_range(args.begin, args.end, args.delta)
            print('a')
            pgd_range_walk(args.begin, args.end, args.delta)
        elif args.search:
            validate_range(args.begin, args.end, args.delta)
            validate_address(args.phys)
            pgd_virt_search(args.begin, args.end, args.delta, args.phys, args.table_type)

PageTableCommands()
