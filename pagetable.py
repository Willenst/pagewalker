import gdb
import re

class MemoryPage:
    def __init__(self, phys_addr, size):
        self.phys_addr = phys_addr
        self.size = size
        
    def __repr__(self):
        return f"Page(0x{self.phys_addr:x}, {self.size//1024}KB)"

class Base_t:
    def __init__(self, phys_addr, level):
        self.phys_addr = phys_addr
        self.level = level
        self.entries = [None] * 512

    def __getitem__(self, index):
        return self.entries[index]

    def add_entry(self, index, entry):
        self.entries[index] = entry

    def __repr__(self):
        used = sum(1 for e in self.entries if e)
        return f"{self.__class__.__name__}(phys=0x{self.phys_addr:x}, level={self.level}, used={used})"

    @staticmethod
    def is_huge_entry(value):
        return (value & (1 << 7)) != 0

class PGD_t(Base_t):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 0)

class PUD_t(Base_t):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 1)

class PMD_t(Base_t):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 2)

class PTE_t(Base_t):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 3)

class MemoryMapper:
    def __init__(self, cr3):
        self.pgd = PGD_t(cr3 & ~0xfff)
        self.pud_tables = {}
        self.pmd_tables = {}
        self.pte_tables = {}
        self.normal_pages = {}
        self._setup_PGD_e_PUD_t()
        self._setup_PUD_e_PMD_t()
        self._setup_PMD_e_PTE_t()
        self._setup_PTE_e_PHYS()

    @staticmethod
    def parse_table(phys_addr):
        raw = gdb.execute(f"monitor xp/512gx 0x{phys_addr:x}", to_string=True)
        return re.findall(r'0x[0-9a-fA-F]+', raw)

    def _setup_PGD_e_PUD_t(self):
        hex_values = self.parse_table(self.pgd.phys_addr)
        for pgd_idx in range(512):
            value = int(hex_values[pgd_idx], 16)
            if value == 0:
                continue
            addr = value & 0x000ffffffffff000
            pud = PUD_t(addr)
            self.pgd.add_entry(pgd_idx, pud)
            self.pud_tables[pgd_idx] = pud

    def _setup_PUD_e_PMD_t(self):
        for pgd_idx, pud in self.pud_tables.items():
            hex_values = self.parse_table(pud.phys_addr)
            for pud_idx in range(512):
                value = int(hex_values[pud_idx], 16)
                if value == 0:
                    continue
                addr = value & 0x000ffffffffff000
                if Base_t.is_huge_entry(value):
                    page = MemoryPage(addr, 1 << 30)  # 1GB
                    pud.add_entry(pud_idx, page)
                else:
                    pmd = PMD_t(addr)
                    pud.add_entry(pud_idx, pmd)
                    self.pmd_tables[(pgd_idx, pud_idx)] = pmd


    def _setup_PMD_e_PTE_t(self):
        for (pgd_idx, pud_idx), pmd in self.pmd_tables.items():
            hex_values = self.parse_table(pmd.phys_addr)
            for pmd_idx in range(512):
                value = int(hex_values[pmd_idx], 16)
                if value == 0:
                    continue
                addr = value & 0x000ffffffffff000
                if Base_t.is_huge_entry(value):
                    page = MemoryPage(addr, 1 << 21)  # 2MB
                    pmd.add_entry(pmd_idx, page)
                else:
                    pte = PTE_t(addr)
                    pmd.add_entry(pmd_idx, pte)
                    self.pte_tables[(pgd_idx, pud_idx, pmd_idx)] = pte

    def _setup_PTE_e_PHYS(self):
        for (pgd_idx, pud_idx, pmd_idx), pte in self.pte_tables.items():
            hex_values = self.parse_table(pte.phys_addr)
            for pte_idx in range(512):
                value = int(hex_values[pte_idx], 16)
                if value == 0:
                    continue
                addr = value & 0x000ffffffffff000
                page = MemoryPage(addr, 1 << 12)  # 4KB
                pte.add_entry(pte_idx, page)
                self.normal_pages[(pgd_idx, pud_idx, pmd_idx, pte_idx)] = page

    def translate(self, virt_addr):
        idxs = [
            (virt_addr >> 39) & 0x1FF,
            (virt_addr >> 30) & 0x1FF,
            (virt_addr >> 21) & 0x1FF,
            (virt_addr >> 12) & 0x1FF
        ]

        return idxs
        
def gen_virt(pgd, pud, pmd, pt):
    return (0xffff << 48) | (pgd << 39) | (pud << 30) | (pmd << 21) | (pt << 12)

def dump_all_ptes_with_index(mapper):
    for (pgd_idx, pud_idx, pmd_idx), pte in mapper.pte_tables.items():
        for pt_idx, entry in enumerate(pte.entries):
            if isinstance(entry, MemoryPage):
                virt = gen_virt(pgd_idx, pud_idx, pmd_idx, pt_idx)
                print(f"0x{virt:016x} [{pgd_idx:03}|{pud_idx:03}|{pmd_idx:03}|{pt_idx:03}]  phys=0x{entry.phys_addr:x}")

cr3_val = int(gdb.execute("p/x $cr3 & ~0xfff", to_string=True).split('=')[1].strip(), 16)
mapper = MemoryMapper(cr3_val)
dump_all_ptes_with_index(mapper)