// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded RAM-root report. Reached only after the native 4K EL0 fixture has
// stored getpid and HW_PAGESIZE results in _results/_user_page_size.
//
// The report is a deliberate userspace panic so a tablet without a usable
// serial console still produces observable evidence. It runs only when every
// checked value is the expected native-4K value; otherwise it falls through to
// the ordinary idle checkpoint.
  ldr x0, [x19]
  cmp x0, #1
  b.ne 1f
  ldr x9, [x19, #16]
  tbnz w9, #29, 1f
  ldr x0, [x19, #8]
  cbnz x0, 1f
  ldr x9, [x19, #24]
  tbnz w9, #29, 1f
  adrp x0, _user_page_size@PAGE
  add x0, x0, _user_page_size@PAGEOFF
  ldr x0, [x0]
  cmp x0, #4096
  b.ne 1f
  adrp x0, _old_length@PAGE
  add x0, x0, _old_length@PAGEOFF
  ldr x0, [x0]
  cmp x0, #4
  b.ne 1f
  adrp x1, _ram_root_report_message@PAGE
  add x1, x1, _ram_root_report_message@PAGEOFF
  mov x0, #0x804             // RB_PANIC | RB_NOSYNC
  mov x16, #55               // Darwin reboot(opt, msg)
  svc #0x80
1:
  b _checkpoint
.data
.balign 8
.global _ram_root_report_message
_ram_root_report_message:
  .asciz "RAMROOT-EL0 PASS: pid=1 page=4096"
.text
