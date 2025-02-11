#pragma once
// In a common header file (both driver and user mode):
#define IOCTL_UNPROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
