import gdb
import re

VERBOSE = False # TODO: connect to argparse
VERBOSE_TABLES = True  # TODO: connect to argparse, add functionality

REGIONS = {
    "userspace":        [0x0000000000000000, 0x00007fffffffffff],
    "ldt_remap":        [0xffff880000000000, 0xffff887fffffffff],
    "page_offset_base": [0xffff888000000000, 0xffffc87fffffffff],
    "vmalloc_ioremap":  [0xffffc90000000000, 0xffffe8ffffffffff],
    "vmemmap_base":     [0xffffea0000000000, 0xffffeaffffffffff],
    "cpu_entry_area":   [0xfffffe0000000000, 0xfffffe7fffffffff],
    "esp":              [0xffffff0000000000, 0xffffff7fffffffff],
    "efi":              [0xffffffef00000000, 0xfffffffeffffffff],
    "kernel_text":      [0xffffffff80000000, 0xffffffff9fffffff],
    "modules":          [0xffffffffa0000000, 0xfffffffffeffffff],
    "vsyscall":         [0xffffffffff600000, 0xffffffffff600fff],
}

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

def nearby(prev, curr):
    prev_virt, prev_phys, prev_idxs = prev
    curr_virt, curr_phys, curr_idxs = curr

    if prev_idxs[3] is not None:  # PTE level (4KB)
        page_size = 0x1000
    elif prev_idxs[2] is not None:  # PMD level (2MB)
        page_size = 0x200000
    else:  # PUD level (1GB)
        page_size = 0x40000000
 
    #virt_ok = abs(curr_virt - prev_virt) == page_size
    # TODO 
    # 0xffffff1bffd83000                       [510|111|510|387]      phys=0x000100051000
    # 0xffffff1bffd93000                       [510|111|510|403]      phys=0x000100051000
    # 1 Mib step seems buggy, prefer phys group for now

    phys_ok = (abs(curr_phys - prev_phys) == page_size) or (curr_phys == prev_phys)

    return phys_ok

def group_entries_by_range(all_entries):
    if not all_entries:
        return []

    grouped = []
    current_group = [all_entries[0]]

    for curr in all_entries[1:]:
        prev = current_group[-1]
        if nearby(prev, curr):
            current_group.append(curr)
        else:
            grouped.append(current_group)
            current_group = [curr]

    if current_group:
        grouped.append(current_group)

    return grouped


def format_index_range(start_idxs, end_idxs):
    # TODO: Add option to print addreses
    parts = []

    for start, end in zip(start_idxs, end_idxs):
        if start is None and end is None:
            parts.append("---")
        elif start == end:
            parts.append(f"{start:03}")
        elif start is None or end is None:
            parts.append("???")
        else:
            parts.append(f"{start:03}-{end:03}")

    return "|".join(parts)

def format_single_index(idxs):
    parts = []
    for idx in idxs:
        if idx is None:
            parts.append("---")
        else:
            parts.append(f"{idx:03}")
    return "|".join(parts)

def dump_all(mapper, include_regions=None, exclude_regions=None):
    zones = list(REGIONS.keys())
    if not include_regions:
        selected = list(REGIONS.values())
    else:
        selected = [REGIONS[name] for name in include_regions]

    if exclude_regions:
        selected = [REGIONS[name] for name in zones if name not in exclude_regions]

    def in_selected_regions(addr):
        return any(start <= addr <= end for start, end in selected)

    all_entries = []

    for pgd_idx, pud in mapper.pud_tables.items():
        for pud_idx, entry in enumerate(pud.entries):
            if isinstance(entry, MemoryPage):
                virt = gen_virt(pgd_idx, pud_idx, 0, 0)
                if in_selected_regions(virt):
                    all_entries.append((virt, entry.phys_addr, [pgd_idx, pud_idx, None, None]))

    for (pgd_idx, pud_idx), pmd in mapper.pmd_tables.items():
        for pmd_idx, entry in enumerate(pmd.entries):
            if isinstance(entry, MemoryPage):
                virt = gen_virt(pgd_idx, pud_idx, pmd_idx, 0)
                if in_selected_regions(virt):
                    all_entries.append((virt, entry.phys_addr, [pgd_idx, pud_idx, pmd_idx, None]))

    for (pgd_idx, pud_idx, pmd_idx), pte in mapper.pte_tables.items():
        for pte_idx, entry in enumerate(pte.entries):
            if isinstance(entry, MemoryPage):
                virt = gen_virt(pgd_idx, pud_idx, pmd_idx, pte_idx)
                if in_selected_regions(virt):
                    all_entries.append((virt, entry.phys_addr, [pgd_idx, pud_idx, pmd_idx, pte_idx]))

    all_entries.sort(key=lambda x: x[0])

    if VERBOSE:
        for virt, phys, idxs in all_entries:
            idx_str = format_single_index(idxs)
            print(f"0x{virt:016x}  [{idx_str}]  phys=0x{phys:012x}")
    else:
        for group in group_entries_by_range(all_entries):
            start = group[0]
            end = group[-1]
            idx_str = format_index_range(start[2], end[2])

            virt_start = f"0x{start[0]:016x}"
            virt_end   = f"0x{end[0]:016x}"
            phys_start = f"0x{start[1]:012x}"
            phys_end   = f"0x{end[1]:012x}"

            if len(group) == 1:
                print(f"{virt_start}                       [{idx_str}]      phys={phys_start}")
            else:
                if start[1] > end[1]:
                    print(f"{virt_start} - {virt_end}  [{idx_str}]  phys={phys_start} > {phys_end}")
                elif start[1] < end[1]:
                    print(f"{virt_start} - {virt_end}  [{idx_str}]  phys={phys_start} < {phys_end}")
                else:
                    print(f"{virt_start} - {virt_end}  [{idx_str}]  phys={phys_start}")

cr3_val = int(gdb.execute("p/x $cr3 & ~0xfff", to_string=True).split('=')[1].strip(), 16)
mapper = MemoryMapper(cr3_val)
dump_all(mapper)#, exclude_regions=['userspace','page_offset_base','esp','efi'])