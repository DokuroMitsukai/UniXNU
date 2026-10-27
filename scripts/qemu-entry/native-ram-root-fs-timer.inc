// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded mockfs read + timer diagnostic.
//
// Runs only after the static EL0 fixture has stored getpid and HW_PAGESIZE
// results. It checks the Darwin syscall carry flags, the sysctl returned
// length, reads the deterministic /probe.bin file in 4 KiB chunks, checks a
// boundary-crossing seek/read, checks EOF, closes and reopens the file, and
// performs one real blocking poll() timeout while measuring cntvct_el0.
//
// Success and each failure class are reported with a deliberate userspace
// panic. This is a test instrument, not a production filesystem or timer test.
  // Baseline values from the getpid and sysctl calls.
  ldr x0, [x19]
  cmp x0, #1
  b.ne Ldiag_fail_baseline
  ldr x9, [x19, #16]
  tbnz w9, #29, Ldiag_fail_baseline
  ldr x0, [x19, #8]
  cbnz x0, Ldiag_fail_baseline
  ldr x9, [x19, #24]
  tbnz w9, #29, Ldiag_fail_baseline
  adrp x0, _user_page_size@PAGE
  add x0, x0, _user_page_size@PAGEOFF
  ldr x0, [x0]
  cmp x0, #4096
  b.ne Ldiag_fail_baseline
  adrp x0, _old_length@PAGE
  add x0, x0, _old_length@PAGEOFF
  ldr x0, [x0]
  cmp x0, #4
  b.ne Ldiag_fail_baseline

  // Record the diagnostic stage for host inspection.
  adrp x20, _ram_root_diagnostic_results@PAGE
  add x20, x20, _ram_root_diagnostic_results@PAGEOFF
  mov x8, #1
  str x8, [x20]

  // Open /probe.bin read-only.
  adrp x0, Ldiag_probe_path@PAGE
  add x0, x0, Ldiag_probe_path@PAGEOFF
  mov x1, #0
  mov x2, #0
  mov x16, #5
  svc #0x80
  b.cs Ldiag_fail_open
  mov x22, x0
  str x22, [x20, #8]
  mov x8, #2
  str x8, [x20]

  // Read the first 4 KiB page, then verify the deterministic byte pattern.
  mov x0, x22
  adrp x10, _diag_buffer@PAGE
  add x10, x10, _diag_buffer@PAGEOFF
  mov x1, x10
  mov x2, #4096
  mov x16, #3
  svc #0x80
  b.cs Ldiag_fail_read
  cmp x0, #4096
  b.ne Ldiag_fail_read
  str x0, [x20, #16]
  mov x9, #0
  mov w11, #0xa0
Ldiag_check_first:
  ldrb w12, [x10, x9]
  cmp w12, w11
  b.ne Ldiag_fail_content
  add x9, x9, #1
  cmp x9, #4096
  b.lo Ldiag_check_first

  // Second page.
  mov x0, x22
  mov x1, x10
  mov x2, #4096
  mov x16, #3
  svc #0x80
  b.cs Ldiag_fail_read
  cmp x0, #4096
  b.ne Ldiag_fail_read
  str x0, [x20, #24]
  mov x9, #0
  mov w11, #0xa1
Ldiag_check_second:
  ldrb w12, [x10, x9]
  cmp w12, w11
  b.ne Ldiag_fail_content
  add x9, x9, #1
  cmp x9, #4096
  b.lo Ldiag_check_second

  // Third page; the fixture file is 12288 bytes.
  mov x0, x22
  mov x1, x10
  mov x2, #4096
  mov x16, #3
  svc #0x80
  b.cs Ldiag_fail_read
  cmp x0, #4096
  b.ne Ldiag_fail_read
  str x0, [x20, #32]
  mov x9, #0
  mov w11, #0xa2
Ldiag_check_third:
  ldrb w12, [x10, x9]
  cmp w12, w11
  b.ne Ldiag_fail_content
  add x9, x9, #1
  cmp x9, #4096
  b.lo Ldiag_check_third

  // EOF after the third page.
  mov x0, x22
  mov x1, x10
  mov x2, #1
  mov x16, #3
  svc #0x80
  b.cs Ldiag_fail_read
  cbnz x0, Ldiag_fail_eof
  str x0, [x20, #40]
  mov x8, #3
  str x8, [x20]

  // Close, then reopen and test a read crossing the 4 KiB boundary.
  mov x0, x22
  mov x16, #6
  svc #0x80
  b.cs Ldiag_fail_read
  adrp x0, Ldiag_probe_path@PAGE
  add x0, x0, Ldiag_probe_path@PAGEOFF
  mov x1, #0
  mov x2, #0
  mov x16, #5
  svc #0x80
  b.cs Ldiag_fail_open
  mov x22, x0
  str x22, [x20, #48]
  mov x8, #4
  str x8, [x20]

  mov x0, x22
  mov x1, #2048
  mov x2, #0
  mov x16, #199
  svc #0x80
  b.cs Ldiag_fail_content
  cmp x0, #2048
  b.ne Ldiag_fail_content
  str x0, [x20, #56]

  mov x0, x22
  adrp x10, _diag_buffer@PAGE
  add x10, x10, _diag_buffer@PAGEOFF
  mov x1, x10
  mov x2, #4096
  mov x16, #3
  svc #0x80
  b.cs Ldiag_fail_read
  cmp x0, #4096
  b.ne Ldiag_fail_read
  str x0, [x20, #64]
  mov x9, #0
  mov w11, #0xa0
Ldiag_check_seek_first:
  ldrb w12, [x10, x9]
  cmp w12, w11
  b.ne Ldiag_fail_content
  add x9, x9, #1
  cmp x9, #2048
  b.lo Ldiag_check_seek_first
  mov w11, #0xa1
Ldiag_check_seek_second:
  ldrb w12, [x10, x9]
  cmp w12, w11
  b.ne Ldiag_fail_content
  add x9, x9, #1
  cmp x9, #4096
  b.lo Ldiag_check_seek_second

  mov x0, x22
  mov x16, #6
  svc #0x80
  b.cs Ldiag_fail_read
  mov x8, #5
  str x8, [x20]

  // One real blocking timer wait with poll(NULL, 0, 50 ms).
  mrs x24, cntvct_el0
  mov x0, #0
  mov x1, #0
  mov x2, #50
  mov x16, #230
  svc #0x80
  b.cs Ldiag_fail_timer
  cbnz x0, Ldiag_fail_timer
  mrs x25, cntvct_el0
  mrs x26, cntfrq_el0
  cbz x26, Ldiag_fail_timer
  sub x27, x25, x24
  mov x28, #100
  mul x28, x27, x28
  cmp x28, x26
  b.lo Ldiag_fail_timer
  cmp x27, x26
  b.hi Ldiag_fail_timer
  str x27, [x20, #72]
  str x26, [x20, #80]
  mov x8, #6
  str x8, [x20]

  // All checks passed.
  adrp x1, Ldiag_pass_message@PAGE
  add x1, x1, Ldiag_pass_message@PAGEOFF
  b Ldiag_panic

Ldiag_fail_baseline:
  adrp x1, Ldiag_fail_baseline_message@PAGE
  add x1, x1, Ldiag_fail_baseline_message@PAGEOFF
  b Ldiag_panic
Ldiag_fail_open:
  adrp x1, Ldiag_fail_open_message@PAGE
  add x1, x1, Ldiag_fail_open_message@PAGEOFF
  b Ldiag_panic
Ldiag_fail_read:
  adrp x1, Ldiag_fail_read_message@PAGE
  add x1, x1, Ldiag_fail_read_message@PAGEOFF
  b Ldiag_panic
Ldiag_fail_content:
  adrp x1, Ldiag_fail_content_message@PAGE
  add x1, x1, Ldiag_fail_content_message@PAGEOFF
  b Ldiag_panic
Ldiag_fail_eof:
  adrp x1, Ldiag_fail_eof_message@PAGE
  add x1, x1, Ldiag_fail_eof_message@PAGEOFF
  b Ldiag_panic
Ldiag_fail_timer:
  adrp x1, Ldiag_fail_timer_message@PAGE
  add x1, x1, Ldiag_fail_timer_message@PAGEOFF
Ldiag_panic:
  mov x0, #0x804             // RB_PANIC | RB_NOSYNC
  mov x16, #55               // Darwin reboot(opt, msg)
  svc #0x80
  b _checkpoint

.data
.balign 8
.global _ram_root_diagnostic_results
_ram_root_diagnostic_results:
  .fill 12, 8, 0
_diag_buffer:
  .space 4096
Ldiag_probe_path:
  .asciz "/probe.bin"
Ldiag_pass_message:
  .asciz "RAMROOT-FST PASS: pid=1 page=4096 fs=read+seek+eof timer=poll"
Ldiag_fail_baseline_message:
  .asciz "RAMROOT-FST FAIL: baseline syscall check"
Ldiag_fail_open_message:
  .asciz "RAMROOT-FST FAIL: open/reopen /probe.bin"
Ldiag_fail_read_message:
  .asciz "RAMROOT-FST FAIL: read/close syscall"
Ldiag_fail_content_message:
  .asciz "RAMROOT-FST FAIL: file content/seek"
Ldiag_fail_eof_message:
  .asciz "RAMROOT-FST FAIL: EOF behavior"
Ldiag_fail_timer_message:
  .asciz "RAMROOT-FST FAIL: blocking timer"
.text
