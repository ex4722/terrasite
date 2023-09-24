import binaryninja
import gdb, sys, time
# import binja_fucker

# Janky shit to not import in gef but import for LSP
if 'GenericCommand' not in globals(): 
    from gef import GenericCommand, register, register_external_command, only_if_gdb_running, gef,u8,u16,u32,u64, gef_print


class StackVarible():
    def __init__(self, name: str, address: int, value: int, type, func_name: str, hints=None):
        self.name = name 
        self.address = address
        self.value = value
        self.type= type
        # Stuff like points, and strings
        self.hints = hints
        self.changed = False 
        self.pc = gef.arch.pc
        gdb.set_convenience_variable(self.name, self.value)

    def __str__(self):
        return f"{hex(self.address)}\t{self.name}->{self.value} [*]{self.changed}"

