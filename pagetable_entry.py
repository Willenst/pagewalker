import gdb

class BASEe:
    def __init__(self, value):
        value = gdb.execute(f"monitor xp/gx {value}", to_string=True).split(":")[1].strip()
        self.value = int(value, 16)
        self.Hex = f"0x{self.value & ((1 << 12) - 1):03X}"
        self.Present = (self.value >> 0) & 1
        self.ReadWrite = (self.value >> 1) & 1
        self.UserSupervisor = (self.value >> 2) & 1
        self.PageWriteThrough = (self.value >> 3) & 1
        self.PageCacheDisabled = (self.value >> 4) & 1
        self.Accessed = (self.value >> 5) & 1
        self.NX = (self.value >> 63) & 1

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

class PGDe(BASEe):
    def __init__(self, value):
        super().__init__(value)
        self.Huge = 'N/a'

class PUDe(BASEe):
    def __init__(self, value):
        super().__init__(value)
        self.Huge = (self.value >> 7) & 1
        if self.Huge:
            self.Dirty = (self.value >> 6) & 1
            self.Global = (self.value >> 8) & 1
            self.PageAttributeTable = (self.value >> 13) & 1

class PMDe(BASEe):
    def __init__(self, value):
        super().__init__(value)
        self.Huge = (self.value >> 7) & 1
        if self.Huge:
            self.Dirty = (self.value >> 6) & 1
            self.Global = (self.value >> 8) & 1
            self.PageAttributeTable = (self.value >> 13) & 1

class PTe(BASEe):
    def __init__(self, value):
        super().__init__(value)
        self.Huge = 'N/a'
        self.Dirty = (self.value >> 6) & 1
        self.PageAttributeTable = (self.value >> 7) & 1
        self.Global = (self.value >> 8) & 1
