import time
import sys

def spinning_cursor(cursor_progress):
    """Create a spinning cursor animation"""
    cursors = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    sys.stdout.write(cursors[cursor_progress])
    sys.stdout.flush()
    sys.stdout.write('\b')


def validate_address(address):
    try:
        addr = int(address, 16)
        if addr < 0 or addr >= 0xffffffffffffffff:
            raise ValueError
    except ValueError:
        print(f"Invalid address: {address}. Must be a hexadecimal within virtual address space.")
        sys.exit(1)
    return address


def validate_range(begin, end, delta):
    begin = validate_address(begin)
    end = validate_address(end)
    try:
        delta = int(delta, 16)
        print('a',delta)
        if delta <= 0 or delta > (1 << 21):  # Upper bound for sanity
            raise ValueError
    except ValueError:
        print(f"Invalid delta: {delta}. Must be a positive hexadecimal and less than 1 GiB")
        sys.exit(1)

    if begin >= end:
        print("begin address must be less than end address.")
        sys.exit(1)