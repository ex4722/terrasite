import binaryninja

class LocalFunction():
    def __init__(self, symbol : list[binaryninja.types.CoreSymbol] ):
        self.name = symbol[0].name
        self.address = symbol[0].address


bv = binaryninja.open_view("test.bndb")
# main = bv.get_function_at(bv.symbols["main"][0].address).lowest_address

# function_symbols = [ LocalFunction(bv.symbols[x]) for x in bv.symbols if bv.symbols[x][0].type == 0]


