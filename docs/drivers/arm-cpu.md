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
