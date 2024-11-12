import gdb

class Page:
    cr3_register = None

    def __init__(self, virtual_address):
        self.virtual = virtual_address
        self.indexes = None
        self.pgd = None
        self.pud = None
        self.pmd = None
        self.pt = None
        self.huge = ''
        self.phys = None
        Page.cr3_register = Page.set_cr3()
        Page.pgd_scan(self, virtual_address)

    @staticmethod
    def is_huge(addr):
        return addr & (1 << 7)

    @staticmethod
    def get_indexes(addr):
        addr = addr >> 12
        return [((addr >> (i * 9)) & 0x1FF) * 8 for i in range(4)][::-1]

    @staticmethod
    def huge_1gb(address):
        addr = address & ~((1 << 30) - 1) & ((1 << 51) - 1)
        addr = addr + address & ((1 << 30) - 1)
        return addr

    @staticmethod
    def huge_2mb(address):
        addr = address & ~((1 << 21) - 1) & ((1 << 51) - 1)
        addr = addr + address & ((1 << 21) - 1)
        return addr

    def get_phys_address(self, address):
        phys_addr = int(gdb.execute(f"monitor xp/gx {address}", to_string=True).split(':')[1].strip(), 16)
        if Page.is_huge(phys_addr):
            self.huge = 'HUGE'
            return phys_addr
        cleaned_addr = phys_addr & ~((1 << 12) - 1) & ((1 << 51) - 1)
        return cleaned_addr

    @staticmethod
    def set_cr3():
        output = gdb.execute("p/x $cr3 & ~0xfff", to_string=True)
        value_str = output.split('=')[1].strip()
        return int(value_str, 16)

    def pgd_scan(self, addr):
        address = int(addr,16)
        self.indexes = Page.get_indexes(address)
        pgd_start = Page.cr3_register
        self.pgd = pgd_start + self.indexes[0]

        pud_start = Page.get_phys_address(self, self.pgd)
        self.pud = pud_start + self.indexes[1]

        pmd_start = Page.get_phys_address(self, self.pud)
        if self.huge:
            self.phys = Page.huge_1gb(pmd_start)
            return
        self.pmd = pmd_start + self.indexes[2]

        pt_start = Page.get_phys_address(self, self.pmd)
        if self.huge:
            self.phys = Page.huge_2mb(pt_start)
            return
        self.pt = pt_start + self.indexes[3]

        phys_start = Page.get_phys_address(self, self.pt)
        self.phys = phys_start & ~((1 << 12) - 1) & ((1 << 63) - 1)

def pgd_scan(address_str):
    page = Page(address_str)

    #printing part
    print()
    print(f"{page.virtual:<20}|{'PGD':<15}|{'PUD':<15}|{'PMD':<15}|{'PT':<15}|{'PHYS':<15}")
    print('-'*(15*5+20))
    print(f"{'index:':<20}|{page.indexes[0]//8:<15}|{page.indexes[1]//8:<15}|{page.indexes[2]//8:<15}|{page.indexes[3]//8:<15}|{page.huge:<15}")
    print('-'*(15*5+20))
    print(f"{'address:':<20}|{hex(page.pgd):<15}|{hex(page.pud):<15}|{hex(page.pmd):<15}|{hex(page.pt):<15}|{hex(page.phys):<15}")
    print()

def pgd_phys_search(range_start, range_end, range_step, phys_address):
    start = int(range_start,16)
    end = int(range_end,16)
    step = int(range_step,16)
    for i in range(start,end,step):
        page=Page(hex(i))
        if phys_address == hex(page.phys):
            print(hex(i))

gdb.execute('define pgd_scan\npython pgd_scan("$arg0")\nend')
gdb.execute('define pgd_phys_search\npython pgd_phys_search("$arg0", "$arg1", "$arg2", "$arg3")\nend')
