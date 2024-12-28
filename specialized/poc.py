import lief # type: ignore
import sys 

# Define prefixes
FIX_PREFIX = "fix_"

patch_binary = lief.parse(sys.argv[1])
target_binary = lief.parse(sys.argv[2])

patch_data_section = patch_binary.get_section(".data")
target_data_section = target_binary.get_section(".data")

new_content = list(target_data_section.content)

for symbol in patch_binary.symbols:
    if symbol.name.startswith(FIX_PREFIX):  
        print("[+] Patching symbol: %s" % symbol.name)      
        symbol_address = int(symbol.name.split('_')[1], 16)
        
        target_offset = symbol_address - target_data_section.virtual_address
        patch_offset = symbol.value - patch_data_section.virtual_address
        patch_content_size = symbol.size

        patch_content = patch_data_section.content[patch_offset:patch_offset + patch_content_size]
        new_content[target_offset:target_offset + patch_content_size] = patch_content

target_binary.get_section(".data").content = new_content
target_binary.write("output")

print("[+] Done.")