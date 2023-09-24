import binaryninja
import gdb, sys, time


# Janky shit to not import in gef but import for LSP
if 'GenericCommand' not in globals(): 
    from gef import GenericCommand, register, register_external_command, only_if_gdb_running, gef,u8,u16,u32,u64, gef_print

class StackVarible():
    def __init__(self, name: str, address: int, value: int, type, func_name: str, hints=None):
        self.name = name 
        self.address = address
        self.value = value
        self.type= type
        # Stuff like pointers to strings or regions of memory
        self.hints = hints
        self.changed = False 
        self.pc = gef.arch.pc
        gdb.set_convenience_variable(self.name, self.value)

    def __str__(self):
        return f"{hex(self.address)}\t{self.name}->{self.value} [*]{self.changed}"

class LocalFunction():
    def __init__(self, symbol : list[binaryninja.types.CoreSymbol] ):
        self.name = symbol[0].name
        self.address = symbol[0].address

class Get_stack_view_command(GenericCommand):
    """Get Stack View Command"""
    _cmdline_ = "gsv"
    _syntax_  = f"{_cmdline_}"

    def __init__(self):
        super().__init__(self)
        self.prev_func = None
        self.cur_func = None

        # func_name : vars
        self.vars_dict = {}
        self.pc = 0
        # watch(self.pc)

    @only_if_gdb_running
    # Rename, should only call once, context and do_invoke get different value
    def init_vars(self):
        self.pc = gef.arch.pc
        addr = gef.arch.pc 

        self.cur_func = bv.get_functions_containing(addr)[0]

        # If first time set prev to cur
        if self.prev_func == None:
            self.prev_func = self.cur_func

        if self.prev_func != self.cur_func:
            self.cleanup_vars(self.prev_func)


        var = self.parse_stack_vars(self.cur_func)
        # var = self.parse_stack_vars()

        if self.cur_func.name in self.vars_dict:
            prev_vars = self.vars_dict[self.cur_func.name]
            for prev, cur in zip(prev_vars, var):
                if prev.value == cur.value:
                    cur.changed = False 
                else:
                    cur.changed = True

        self.prev_func = self.cur_func
        self.vars_dict[self.cur_func.name] = var
        return var


    def get_base(self) -> int:
        vmmap = gef.memory.maps 
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        return base_address


    @only_if_gdb_running
    # Need to fetch clean, if user patches memory
    def parse_stack_vars(self, func : binaryninja.Function):
        var_array = []
        for v in func.vars:
            v : binaryninja.variable.Variable = v
            # Storage uses ret addr as offset
            var_addr = v.storage + gef.arch.register('rbp') + 8

            match (v.type.width):
                case 0:
                    # VOID TYPE?
                    val = 0xffffffffffffffff 
                case 1:
                    val = u8(gef.memory.read(var_addr, 1))
                case 2:
                    val = u16(gef.memory.read(var_addr, 2))
                case 4:
                    val = u32(gef.memory.read(var_addr, 4))
                case 8:
                    val = u64(gef.memory.read(var_addr, 8))

                case _:
                    gef_print(f"TYPE UNKNOWN for {v.name}: {v.type.name}")
                    val = 0xffffffffffffffff 


            # gef_print(hex(unpack(gef.memory.read(var_addr,v.type.width),'all')))
            var_array.append(StackVarible(v.name, var_addr, val, v.type, func.name ))
        return var_array

    @only_if_gdb_running
    def do_invoke(self, argv):
        addr = gef.arch.pc

        self.cur_func = bv.get_functions_containing(addr)[0]

        if self.cur_func.name in self.vars_dict and (self.pc == gef.arch.pc):
            # No instr stepped, just recalling
            var = self.vars_dict[self.cur_func.name] 
        else:
            var = self.init_vars()

        cur_line_color = gef.config["theme.source_current_line"]
        changed_color = gef.config["theme.registers_value_changed"]
        for i in var:
            # gef_print(i.name, str(i.changed))
            gef_print(Color.colorify(f" {hex(i.address)} → {i.name}: {hex(i.value)}",changed_color if i.changed else cur_line_color))

    def cleanup_vars(self, func_name):
        gef_print("CLEANUP FOR ", func_name.name)
        for stk_var in func_name.vars:
            gdb.set_convenience_variable(stk_var.name, None)

    def display_pane(self):                    
        # FAKE ARGV LOL
        self.do_invoke([''])

    def title(self):
        return "Stack Varibles"


# class Load_binja_command(GenericCommand):
#     """Get Stack View Command"""
#     _cmdline_ = "lbinja"
#     _syntax_  = f"{_cmdline_}"


#     @only_if_gdb_running         # not required, ensures that the debug session is started
#     def do_invoke(self, argv):
#         bv = binaryninja.open_view("test.bndb")
#         main = bv.get_function_at(bv.symbols["main"][0].address)

class Get_local_functions(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "glf"
    _syntax_  = f"{_cmdline_}"

    def do_invoke(self, argv):

        function_symbols = [ LocalFunction(bv.symbols[x]) for x in bv.symbols if bv.symbols[x][0].type == 0]
        for i in function_symbols:
            gdb.set_convenience_variable(i.name, i.address)


register_external_command(Get_stack_view_command())
register_external_command(Get_local_functions())
register_external_context_pane("Stack Varibles", lambda : gdb.execute("gsv"), lambda : "Stack Varible")

# register_external_command(Load_binja_command())
