import lief
import networkx as nx
import capstone 

from util import *

# Capstone 
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

# Prefixes
PREFIXES = ["fix_", "del_", "ref_"]

class pSymbol:
    """
    Define a symbol node that needs to be patched
    """
    def __init__(self, sym_type, address_patch, address_target, operation, pointer):
        self.sym_type = sym_type
        self.address_patch = address_patch
        self.address_target = address_target
        self.operation = operation
        self.pointer = pointer

    def __str__(self):
        return f"{self.sym_type} {hex(self.address_patch)} {hex(self.address_target)} {self.operation}"
    
class pDLFunc:
    """
    Define a dynamic linked function node in object file
    """
    def __init__(self, name, address_patch):
        self.name = name
        self.address_patch = address_patch

    def __str__(self):
        return f"{self.name} {self.address_patch}"

def get_patch_symbols(binary):
    """
    Get the symbols that need to be patched
    """
    patch_symbols = {
        "functions": [],
        "global_vars": [],
    }
    
    for symbol in binary.exported_symbols:
        if symbol.name.startswith(tuple(PREFIXES)):
            operation = symbol.name.split("_")[0]
            try:
                address_target = int(symbol.name.split("_")[1], 16)
            except:
                raise ValueError(f"[!] Address cannot be resolved, perhaps syntax error in {symbol.name}?")

            node = pSymbol(symbol.type, symbol.value, address_target, operation, symbol)
            
            if symbol.type == lief.ELF.Symbol.TYPE.FUNC:
                patch_symbols["functions"].append(node)
    
            elif symbol.type == lief.ELF.Symbol.TYPE.OBJECT:
                patch_symbols["global_vars"].append(node)

            else:
                raise ValueError(f"[!] Type {symbol.type} is not supported")

    return patch_symbols

def get_references(function_code, function_offset, patch_binary):
    references = {
        "call": [],
    }

    for ins in cs.disasm(function_code, function_offset):
        print(f'{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}')

        if ins.mnemonic == "call":
            call_address = int(ins.op_str, 16)
            references["call"].append(call_address)

            print(f"[+] Found a call to {hex(call_address)}")

    return references

def construct_graph(start, patch_symbols, patch_binary):
    """
    Construct a graph of function calls
    """
    print(f"[+] Constructing graph for function at {hex(start.address_patch)}")

    code = bytes(get_function_code(patch_binary, start.address_patch, start.pointer.size))
    references = get_references(code, start.address_patch, patch_binary)

    graph = nx.DiGraph()
    graph.add_node(start)

    # To do...


    
    
    