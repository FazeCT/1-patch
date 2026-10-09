int ref_0x400540_printf(const char *format, ...) {};
int ref_0x400570_scanf(const char *a1, ...) {};
int ref_0x400667_init() {};

int fix_0x4006E8_main() {
  char v4[40];

  ref_0x400667_init();
  ref_0x400540_printf("Input: ");
  if (ref_0x400570_scanf("%39s", v4) != 1) return 1;

  return 0;
}
