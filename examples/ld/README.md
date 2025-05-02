## GNU binutils 2.43 - ld

**Exploit technique:** 
- https://vuldb.com/?submit.489991
- https://vuldb.com/?submit.495407
- https://vuldb.com/?submit.495402

**Bug(s):** 
- **CVE-2025-1153:** A vulnerability classified as problematic was found in GNU Binutils 2.43/2.44. Affected by this vulnerability is the function bfd_set_format of the file format.c. The manipulation leads to memory corruption. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. Upgrading to version 2.45 is able to address this issue. The identifier of the patch is 8d97c1a53f3dc9fd8e1ccdb039b8a33d50133150. It is recommended to upgrade the affected component.

- **CVE-2025-1181:** A vulnerability classified as critical was found in GNU Binutils 2.43. This vulnerability affects the function _bfd_elf_gc_mark_rsec of the file bfd/elflink.c of the component ld. The manipulation leads to memory corruption. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 931494c9a89558acb36a03a340c01726545eef24. It is recommended to apply a patch to fix this issue.

- **CVE-2025-1182:** A vulnerability, which was classified as critical, was found in GNU Binutils 2.43. Affected is the function bfd_elf_reloc_symbol_deleted_p of the file bfd/elflink.c of the component ld. The manipulation leads to memory corruption. It is possible to launch the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. The patch is identified as b425859021d17adf62f06fb904797cf8642986ad. It is recommended to apply a patch to fix this issue.