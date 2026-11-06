#!/usr/bin/env bash
# Native personality compiler flags shared by build-xnu-4k-baseline.sh.
# Sourced, not executed. Each function prints the flags for one personality
# and fails closed on a value other than 0 or 1.

xnu_gta4l_emmc_block_flag() {
  case "${XNU_NATIVE_GTA4L_EMMC_BLOCK:-0}" in
    0) ;;
    1) printf '%s\n' '-DXNU_NATIVE_GTA4L_EMMC_BLOCK=1' ;;
    *) printf '%s\n' 'XNU_NATIVE_GTA4L_EMMC_BLOCK must be 0 or 1' >&2; return 1 ;;
  esac
}
