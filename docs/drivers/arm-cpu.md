# ArmCpu

Start with the [adaptation procedure](/porting/platform) for board inputs, source changes, build integration and verification order.

ARM64 CPU, GIC and timer driver. Publishes the CPUs, interrupt controller and architectural timer.

| Repository | Maintainer | Scope |
| --- | --- | --- |
| [ArmCpu](https://github.com/UniXNU/ArmCpu) | [UniXNU](https://github.com/UniXNU) | ARM64 CPU, GIC and timer driver. Publishes the CPUs, interrupt controller and architectural timer. |

## State

The catalog targets ARM GICv3 and the ARM generic timer with the selected XNU ABI. The driver also accepts a GICv2
(`arm,gic-400` or `arm,cortex-a15-gic`) device-tree node and uses its distributor and banked CPU interface. GICv2
bring-up is limited to the boot CPU; secondary-core startup reports `armcpu_smp_fail` 5 and is skipped.

## Build

The selected kernel recipe builds `build/armcpu/libArmCpu.a` through `component:ArmCpu`. Enable its kernel configuration and verify the GIC/timer/PSCI resources using the platform adaptation procedure.

Counter sampling orders `ISB` before `CNTVCT_EL0`. GIC control, SGI and EOI sequences retain their ordered barriers. Multi-instruction inline assembly uses newline separators on Darwin.

Each core enables SGI 0 and architectural timer PPI 27. The periodic interrupt self-probe sends the enabled SGI 0 and consumes its acknowledgement while normal interrupts are masked. With `armcpu-spi-ipi=1`, cross-core signals use software-pended SPIs 1008 through 1015.
