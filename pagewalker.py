import gdb

def get_virt_indices(addr):
    pageshift = 12
    addr = addr >> pageshift
    pt, pmd, pud, pgd = (((addr >> (i * 9)) & 0x1FF) for i in range(4))
    return pgd, pud, pmd, pt

def extract_address(addr):
    return addr & ~((1 << 12) - 1) & ((1 << 51) - 1)

def huge_1gb(address,shift):
    addr = address & ~((1<<30)-1) & ((1<<51)-1)
    addr = addr + shift
    print('1G huge page phys address', hex(addr))

def huge_2mb(address,shift):
    addr = address & ~((1<<21)-1) & ((1<<51)-1)
    addr = addr + shift
    print('2MB huge page phys address', hex(addr))

def is_huge(addr):
    return addr & (1<<7)

def get_phys_address(addr):
    return int(gdb.execute(f"monitor xp/gx {addr}", to_string=True).split(':')[1].strip(),16)

def pgd_scan(address_str):
    address = int(address_str,16)
    pgd_index, pud_index, pmd_index, pt_index = get_virt_indices(address)

    output = gdb.execute("p/x $cr3 & ~0xfff", to_string=True)
    value_str = output.split('=')[1].strip()
    cr3_register = int(value_str,16)

    cr3_2mb_shift = address  & ((1 << 21) - 1)
    cr3_1gb_shift = address  & ((1 << 30) - 1)
    print('use "monitor xp/gx addr" to check the value\n')

    print('cr3 value',hex(cr3_register))
    print('pgd_index',pgd_index)
    print('pud_index',pud_index)
    print('pmd_index',pmd_index)
    print('pt_index',pt_index)

    pgd_shift = pgd_index*8
    pgd_position = cr3_register+pgd_shift

    print('\npgd phys address', hex(pgd_position))
    
    pud_address = get_phys_address(pgd_position)
    pud_cleaned = extract_address(pud_address)
    pud_shift = pud_index*8
    pud_position = pud_cleaned + pud_shift
    print('pud phys address', hex(pud_position))

    pmd_address = get_phys_address(pud_position)
    if is_huge(pmd_address):
        huge_1gb(pmd_address,cr3_1gb_shift)
        return
    pmd_cleaned = extract_address(pmd_address)
    pmd_shift = pmd_index*8
    pmd_position = pmd_cleaned + pmd_shift
    print('pmd phys address', hex(pmd_position))

    pt_address = get_phys_address(pmd_position)
    if is_huge(pt_address):
        huge_2mb(pt_address,cr3_2mb_shift)
        return
    pt_cleaned = extract_address(pt_address)
    pt_shift = pt_index*8
    pt_position = pt_cleaned + pt_shift
    print('pt phys adress', hex(pt_position))
    
    phys_address = get_phys_address(pt_position)
    phys_cleaned = extract_address(phys_address)
    phys_position = phys_cleaned & ~((1<<12)-1) & ((1<<63)-1) #clear service bit and align to page
    print('page phys adress', hex(phys_position))

gdb.execute('define pgd_scan\npython pgd_scan("$arg0")\nend')
