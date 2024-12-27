import lief 

def get_function_code(binary, address, size):
    """
    Get the code of a function at a given address
    """
    code = binary.get_content_from_virtual_address(address, size)
    return code