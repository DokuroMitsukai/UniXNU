#!/usr/bin/env python3
"""Exercise the production menu/input helpers against mocked UEFI services."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "package/UniXNUPkg/Library/UniXNULib/Menu.c").read_text()
# Leave Tools/plugin discovery out of this small host harness.
source = source.split('//\n// The Tools submenu')[0].replace('#include "Internal.h"', '')
header = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#define STATIC static
#define IN
#define OUT
#define VOID void
#define TRUE 1
#define FALSE 0
#define NULL ((void *)0)
typedef int BOOLEAN;
typedef int EFI_STATUS;
typedef uintptr_t UINTN;
typedef intptr_t INTN;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint16_t CHAR16;
typedef void *EFI_HANDLE;
typedef void *EFI_EVENT;
typedef struct { unsigned ScanCode; CHAR16 UnicodeChar; } EFI_INPUT_KEY;
typedef struct Input Input;
typedef Input EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
struct Input { EFI_STATUS (*ReadKeyStroke)(Input *, EFI_INPUT_KEY *); };
#define EFI_ERROR(s) ((s) < 0)
#define EVT_TIMER 1
#define TPL_CALLBACK 8
#define TimerPeriodic 1
#define TimerCancel 0
#define ByProtocol 0
#define EFI_TIMER_PERIOD_MILLISECONDS(x) (x)
#define SCAN_UP 1
#define SCAN_DOWN 2
#define SCAN_HOME 5
#define SCAN_END 6
#define SCAN_RIGHT 3
#define SCAN_ESC 23
#define CHAR_CARRIAGE_RETURN 13
#define CHAR_LINEFEED 10
static int gEfiSimpleTextInProtocolGuid, gEfiDevicePathProtocolGuid;
typedef struct {
  EFI_STATUS (*LocateHandleBuffer)(int, void *, void *, UINTN *, EFI_HANDLE **);
  EFI_STATUS (*HandleProtocol)(EFI_HANDLE, void *, void **);
  EFI_STATUS (*CreateEvent)(int, int, void *, void *, EFI_EVENT *);
  EFI_STATUS (*SetTimer)(EFI_EVENT, int, unsigned);
  EFI_STATUS (*WaitForEvent)(UINTN, EFI_EVENT *, UINTN *);
  EFI_STATUS (*CloseEvent)(EFI_EVENT);
} Services;
static Services *gBS;
static struct { Input *ConIn; } system_table, *gST = &system_table;
typedef struct { char *Id; CHAR16 *Title; } Entry;
typedef struct {
  UINTN EntryCount, DefaultIndex, FallbackTimeout, RotateSeconds;
  INTN Timeout;
  Entry *Entries;
} UNIXNU_CONFIG;
typedef struct { CHAR16 Notice[10]; } UNIXNU_UI;
static const CHAR16 hints[] = {0};
#define PcdGetPtr(x) hints
#define FreePool free
#define UniXNULog(...) ((void)0)
#define UniXNUUiDrawFrame(...) ((void)0)
#define UniXNUUiDrawStatus(...) ((void)0)
#define UnicodeSPrint(...) ((void)0)
static unsigned draws;
#define UniXNUUiDrawEntry(...) (++draws)
static unsigned ticks, physical, reads, closed, fail_timer;
static EFI_INPUT_KEY sequence[20];
static EFI_STATUS read_key(Input *input, EFI_INPUT_KEY *key) {
  reads++;
  if (input == gST->ConIn || ticks >= 20 ||
      (!sequence[ticks].ScanCode && !sequence[ticks].UnicodeChar)) return -1;
  *key = sequence[ticks];
  sequence[ticks] = (EFI_INPUT_KEY){0};
  return 0;
}
static Input keypad = {read_key}, console = {read_key};
static EFI_STATUS locate(int a, void *b, void *c, UINTN *n, EFI_HANDLE **h) {
  *n = physical;
  *h = malloc(sizeof(**h));
  **h = &keypad;
  return 0;
}
static EFI_STATUS protocol(EFI_HANDLE h, void *guid, void **p) {
  *p = h;
  return 0;
}
static EFI_STATUS create(int a, int b, void *c, void *d, EFI_EVENT *e) {
  *e = &keypad; return 0;
}
static EFI_STATUS timer(EFI_EVENT e, int type, unsigned period) {
  return type == TimerPeriodic && fail_timer ? -1 : 0;
}
static EFI_STATUS wait_event(UINTN n, EFI_EVENT *e, UINTN *index) {
  assert(n == 1); assert(++ticks < 200); *index = 0; return 0;
}
static EFI_STATUS close_event(EFI_EVENT e) { closed++; return 0; }
'''
tests = r'''
int main(void) {
  Services services = {locate, protocol, create, timer, wait_event, close_event};
  gBS = &services;
  gST->ConIn = &console;
  Input *inputs[16]; UINTN count, physical_count;
  EFI_INPUT_KEY key;
  physical = 1;
  count = CollectInputDevices(inputs, 16, &physical_count);
  assert(count == 1 && physical_count == 1 && inputs[0] == &keypad);
  // An unconnected system console must not hide the physical keypad.
  ticks = 1; sequence[1] = (EFI_INPUT_KEY){SCAN_UP, 0};
  assert(ReadInputKey(inputs, count, &key) && key.ScanCode == SCAN_UP);
  assert(!ReadInputKey(inputs, count, &key));
  physical = 0;
  count = CollectInputDevices(inputs, 16, &physical_count);
  assert(count == 1 && physical_count == 0 && inputs[0] == &console);
  gST->ConIn = NULL;
  assert(CollectInputDevices(inputs, 16, &physical_count) == 0);
  physical = 1;
  assert(CollectInputDevices(inputs, 16, &physical_count) == 1);
  // A working keypad does not require a system console.
  Entry entries[3] = {{0}};
  UNIXNU_CONFIG config = {3, 0, 1, 0, 1, entries};
  UNIXNU_UI ui = {{0}};
  ticks = 0; sequence[1] = (EFI_INPUT_KEY){SCAN_DOWN, 0};
  sequence[3] = (EFI_INPUT_KEY){0, CHAR_CARRIAGE_RETURN};
  assert(UniXNUMenuRun(&ui, &config, TRUE) == 1 && ticks == 3);
  // Volume up wraps; Home/Esc stops the timer, not "first entry".
  ticks = 0; sequence[1] = (EFI_INPUT_KEY){SCAN_UP, 0};
  sequence[2] = (EFI_INPUT_KEY){SCAN_ESC, 0};
  sequence[12] = (EFI_INPUT_KEY){0, CHAR_CARRIAGE_RETURN};
  assert(UniXNUMenuRun(&ui, &config, TRUE) == 2 && ticks == 12);
  ticks = 0; config.RotateSeconds = 1; config.Timeout = 3;
  assert(UniXNUMenuRun(&ui, &config, TRUE) == 0 && ticks == 30);
  // Confirmation wait polls physical input and closes its timer.
  ticks = 0; sequence[2] = (EFI_INPUT_KEY){0, CHAR_CARRIAGE_RETURN};
  count = CollectInputDevices(inputs, 16, &physical_count);
  unsigned before = closed;
  assert(WaitForInputKey(inputs, count, &key) && ticks == 2);
  assert(closed == before + 1);
  fail_timer = 1; ticks = 0; before = closed;
  assert(UniXNUMenuRun(&ui, &config, TRUE) == 0 && ticks == 0);
  assert(closed == before + 1);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="menu-input-", dir="/tmp/opencode") as directory:
    harness = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    harness.write_text(header + source + tests)
    subprocess.run(["clang", "-fshort-wchar", "-Wno-macro-redefined",
                    str(harness), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
print("PASS: physical input, console fallback, volume/power/Home, countdown, timer cleanup")
