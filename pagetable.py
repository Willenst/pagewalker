import gdb
import re

class MemoryPage:
    def __init__(self, phys_addr, size):
        self.phys_addr = phys_addr
        self.size = size
        
    def __repr__(self):
        return f"Page(0x{self.phys_addr:x}, {self.size//1024}KB)"

class BaseTable:
    def __init__(self, phys_addr, level):
        self.phys_addr = phys_addr
        self.level = level
        self.entries = [0x0000000000000000] * 512

    def __getitem__(self, index):
        return self.entries[index]

    def is_huge(self, entry):
        return (entry.phys_addr & (1 << 7)) != 0 if isinstance(entry, MemoryPage) else False

    def add_entry(self, index, entry):
        if isinstance(entry, MemoryPage) and self.is_huge(entry):
            if self.level not in (1, 2):
                raise ValueError("Huge pages only in PUD/PMD")
        else:
            if self.level == 3 and not isinstance(entry, MemoryPage):
                raise ValueError("PTE must point to MemoryPage")
            if self.level < 3 and not isinstance(entry, BaseTable):
                raise ValueError(f"Level {self.level} must point to BaseTable")

        self.entries[index] = entry
    
    def __repr__(self):
        used = sum(1 for e in self.entries if e)
        return f"{self.__class__.__name__}(phys=0x{self.phys_addr:x}, level={self.level}"


class PGDTable(BaseTable):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 0)

class PUDTable(BaseTable):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 1)

class PMDTable(BaseTable):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 2)

class PTETable(BaseTable):
    def __init__(self, phys_addr):
        super().__init__(phys_addr, 3)

class MemoryMapper:
    def __init__(self, cr3):
        self.pgd = PGDTable(cr3 & ~0xfff)
        self.pud_tables = {}
        self.pmd_tables = {}
        self.pte_tables = {}
        self._setup_PUD()
        self._setup_PMD()
        self._setup_PTE()

    def _setup_PUD(self):
        addr = self.pgd.phys_addr
        raw_entry = gdb.execute(f"monitor xp/512gx 0x{addr:x}", to_string=True)
        hex_values = re.findall(r'0x[0-9a-fA-F]+', raw_entry)
        for pgd_idx in range(512):
            value = int(hex_values[pgd_idx], 16)
            if value == 0:
                continue
            pud = PUDTable(value & 0x000ffffffffff000)
            self.pgd.add_entry(pgd_idx, pud)
            self.pud_tables[pgd_idx] = pud

    def _setup_PMD(self):
        for pgd_idx, pud in self.pud_tables.items():
            addr = pud.phys_addr
            if addr == 0:
                continue
            raw_entry = gdb.execute(f"monitor xp/512gx 0x{addr:x}", to_string=True)
            hex_values = re.findall(r'0x[0-9a-fA-F]+', raw_entry)
            for pud_idx in range(512):
                value = int(hex_values[pud_idx], 16)
                pmd = PMDTable(value & 0x000ffffffffff000)
                if value == 0:
                    continue
                pud.add_entry(pud_idx, pmd)
                self.pmd_tables[(pgd_idx, pud_idx)] = pmd

    def _setup_PTE(self):
        for (pgd_idx, pud_idx), pmd in self.pmd_tables.items():
            addr = pmd.phys_addr
            if addr == 0:
                continue
            raw_entry = gdb.execute(f"monitor xp/512gx 0x{addr:x}", to_string=True)
            hex_values = re.findall(r'0x[0-9a-fA-F]+', raw_entry)
            for pmd_idx in range(512):
                value = int(hex_values[pmd_idx], 16)
                if value == 0:
                    continue
                pte = PTETable(pmd.phys_addr)
                page = MemoryPage(value & 0x000ffffffffff000, 4096)
                pte.add_entry(pmd_idx, page)
                self.pte_tables[(pgd_idx, pud_idx, pmd_idx)] = pte

    def translate(self, virt_addr):
        indices = [
            (virt_addr >> 39) & 0x1FF,
            (virt_addr >> 30) & 0x1FF,
            (virt_addr >> 21) & 0x1FF,
            (virt_addr >> 12) & 0x1FF
        ]
        
        current = self.pgd
        for level in range(4):
            idx = indices[level]
            entry = current[idx]
            
            if not entry:
                return None
                
            if isinstance(entry, MemoryPage):
                if level in (1, 2) and current.is_huge(entry):
                    entry.phys_addr &= ~(1 << 7)
                    return entry
                if level == 3:
                    return entry
                    
            current = entry

def get_address(pgd, pud, pmd, pt):
    return (0xffff << 48) | (pgd << 39) | (pud << 30) | (pmd << 21) | (pt << 12)


def dump_all_pmds_with_index(mapper):
    for (pgd_idx, pud_idx), pmd in mapper.pmd_tables.items():
        used = sum(1 for e in pmd.entries if e)
        print(f"[{pgd_idx:03}|{pud_idx:03}] PMD phys=0x{pmd.phys_addr:x}")

def dump_all_ptes_with_index(mapper):
    for (pgd_idx, pud_idx, pmd_idx), pte in mapper.pte_tables.items():
        for pt_idx, entry in enumerate(pte.entries):
            if isinstance(entry, MemoryPage):
                virt = get_address(pgd_idx, pud_idx, pmd_idx, pt_idx)
                print(f"0x{virt:016x} [{pgd_idx:03}|{pud_idx:03}|{pmd_idx:03}|{pt_idx:03}]  phys=0x{entry.phys_addr:x}")





cr3_val = int(gdb.execute("p/x $cr3 & ~0xfff", to_string=True).split('=')[1].strip(), 16)
mapper = MemoryMapper(cr3_val)
dump_all_ptes_with_index(mapper)