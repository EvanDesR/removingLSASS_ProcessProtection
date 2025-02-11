#include <ntdef.h>
#include <ntifs.h>
#include "Header.h"
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\iDrive");
UNICODE_STRING SymLink = RTL_CONSTANT_STRING(L"\\??\\iDrive");

//
// IMPORTANT: This offset is version-dependent and may not be correct for your target OS.
auto offsetOfProtection = 0x87a; // Verify this offset before using.

typedef struct _PS_PROTECTION {
    UCHAR Level;
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _TARGET_PROCESS {
    int processId;
} TARGET_PROCESS, * PTARGET_PROCESS;

void DriverUnload(PDRIVER_OBJECT driverObj);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP Irp);
NTSTATUS UnprotectProcess(_In_ PTARGET_PROCESS target, _In_ PDEVICE_OBJECT deviceObj, _In_ PIRP Irp);
NTSTATUS IoControl(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP Irp);

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObj, _In_ PUNICODE_STRING registryPath)
{
    KdPrint(("Entered Driver Entry \n"));
    UNREFERENCED_PARAMETER(registryPath);

    PDEVICE_OBJECT deviceObj = nullptr;
    NTSTATUS status;

    KdPrint(("DriverEntry\n"));

    status = IoCreateDevice(
        driverObj,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObj
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("IoCreateDevice failed with status 0x%X\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&SymLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("IoCreateSymbolicLink failed with status 0x%X\n", status));
        IoDeleteDevice(deviceObj);
        return status;
    }

    driverObj->DriverUnload = DriverUnload;
    driverObj->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObj->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
    KdPrint(("Exiting Driver Entry? \n"));

    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT driverObj)
{
    UNREFERENCED_PARAMETER(driverObj);

    IoDeleteSymbolicLink(&SymLink);
    IoDeleteDevice(driverObj->DeviceObject);
    KdPrint(("DriverUnload\n"));
}

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(deviceObj);
    KdPrint(("CreateClose called\n"));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT); //failed at 87
    return STATUS_SUCCESS;
}

NTSTATUS IoControl(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case 0x800:
    {
        // No operation for now
        KdPrint(("IoControl: Code 0x800.... someone screwed up the userland kernel call! \n"));
        break;
    }
    case IOCTL_UNPROTECT_PROCESS:
    {
        KdPrint(("IoControl: Code 0x801 (unprtect process)\n"));
        

        if (stack->Parameters.DeviceIoControl.Type3InputBuffer == NULL)
        {
            KdPrint(("Type3InputBuffer is a null pointer.... \n"));
        }

        PTARGET_PROCESS target = (PTARGET_PROCESS)stack->Parameters.DeviceIoControl.Type3InputBuffer; //problem here?
        if (target == NULL) {
            KdPrint(("Invalid input buffer for IoControl code 0x801\n"));

            status = STATUS_INVALID_PARAMETER;
        }
        else {
            status = UnprotectProcess(target, deviceObject, Irp);
            KdPrint(("UnprotectedProcess function returned with code %d", status));
        }
        break;
    }
    default:
    {
        KdPrint(("IoControl: Unknown code 0x%X\n", stack->Parameters.DeviceIoControl.IoControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS UnprotectProcess(_In_ PTARGET_PROCESS target,
    _In_ PDEVICE_OBJECT deviceObj,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(deviceObj);
    UNREFERENCED_PARAMETER(Irp);

    NTSTATUS status;
    PEPROCESS process = NULL;

    // 1) Lookup the EPROCESS
    status = PsLookupProcessByProcessId((HANDLE)target->processId, &process); //prob here?
    if (!NT_SUCCESS(status)) {
        KdPrint(("PsLookupProcessByProcessId failed (0x%X)\n", status));
        return status;
    }
    KdPrint(("PsLookupProcessByProcessId (0x%X)\n", status));

    // 2) Calculate your pointer
    PPS_PROTECTION protectionPtr =(PPS_PROTECTION)(((ULONG_PTR)process) + offsetOfProtection);  //problem here?
    
    // 3) Read the old value
    PS_PROTECTION oldProt = *protectionPtr;
    KdPrint(("Old PS_PROTECTION for PID %d => Level: %u, Type: %u, Signer: %u, Audit: %u\n",
        target->processId,
        oldProt.Level,
        oldProt.Type,
        oldProt.Signer,
        oldProt.Audit));

    // 4) Zero it out
    protectionPtr->Level = 0;
    protectionPtr->Type = 0;
    protectionPtr->Signer = 0;
    protectionPtr->Audit = 0;

    // 5) Read the new value
    PS_PROTECTION newProt = *protectionPtr;
    KdPrint(("New PS_PROTECTION for PID %d => Level: %u, Type: %u, Signer: %u, Audit: %u\n",
        target->processId,
        newProt.Level,
        newProt.Type,
        newProt.Signer,
        newProt.Audit));

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}
/*
//#include <ntddk.h>
#include <ntdef.h>
#include <ntifs.h>
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\iDrive");
UNICODE_STRING SymLink = RTL_CONSTANT_STRING(L"\\??\\iDrive");



auto offsetOfProtection = 0x87a; //protection member is offset by 0x87a bytes, in the EPROCESS structure. 

typedef struct _PS_PROTECTION //protection, holds a _PS_PROTECTION structure.
{
	UCHAR Level; //1 byte
	UCHAR Type : 3; //3 bits
	UCHAR Audit : 1; // 1 bit
	UCHAR Signer : 4; //4 bit

} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _TARGET_PROCESS
{
	int processId;
}TARGET_PROCESS, *PTARGET_PROCESS;

void cleaning(PDRIVER_OBJECT driverObj);
NTSTATUS createClose(_In_ PDEVICE_OBJECT driverObj, _In_ PIRP Irp);
NTSTATUS UNPROTECT_A_PROCESS(_In_ PTARGET_PROCESS target, _In_ PDEVICE_OBJECT deviceObj, _In_ PIRP Irp);
NTSTATUS control(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP Irp);



extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObj, _In_ PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(registryPath);

	PDEVICE_OBJECT deviceObj;

	KdPrint(("DriverEntry \n"));

	IoCreateDevice( //Create device
		driverObj,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&deviceObj);



	IoCreateSymbolicLink(&SymLink, &deviceName);

	driverObj->DriverUnload = cleaning;
	driverObj->MajorFunction[IRP_MJ_CREATE] = createClose;
	driverObj->MajorFunction[IRP_MJ_CLOSE] = createClose;
	driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = control;

	return STATUS_SUCCESS;
}

void cleaning(PDRIVER_OBJECT driverObj)
{
	UNREFERENCED_PARAMETER(driverObj);



}

NTSTATUS control(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);

	PIO_STACK_LOCATION callStack = IoGetCurrentIrpStackLocation(Irp);
	switch (callStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case(0x800):
	{
		break;
	}
	case(0x801): //unprotect process 
	{
		//if (sizeof(callStack->Parameters.DeviceIoControl.Type3InputBuffer) != NULL) //constant... I wrote it wrong :/
		
			PTARGET_PROCESS target = (PTARGET_PROCESS)callStack->Parameters.DeviceIoControl.Type3InputBuffer;

			UNPROTECT_A_PROCESS(target, deviceObject, Irp);
		
	}
	default:
	{
		break;
	}
	}

	return STATUS_SUCCESS; //case exited successfully
}


NTSTATUS createClose(_In_ PDEVICE_OBJECT deviceObject,_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	KdPrint(("[*] Hello From createClose \n"));

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;


	IoCompleteRequest(Irp, IO_NO_INCREMENT);


	return STATUS_SUCCESS;
}

//MJ Functions
NTSTATUS UNPROTECT_A_PROCESS(_In_ PTARGET_PROCESS target,_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObj);
	UNREFERENCED_PARAMETER(Irp);
	NTSTATUS status;
	PEPROCESS pointerTOEPROCESS;

	status = PsLookupProcessByProcessId((HANDLE)target->processId,&pointerTOEPROCESS);

	if (NT_SUCCESS(status))
	{
		KdPrint(("Successfully, retrieved a pointer from PID %d \n ", target->processId));

		PPS_PROTECTION protectionValue = (PPS_PROTECTION)(((ULONG_PTR)pointerTOEPROCESS) + offsetOfProtection);

		if (protectionValue == nullptr)
		{
			KdPrint(("protectionValue was null \n"));
			status = STATUS_INVALID_PARAMETER;
			ObDereferenceObject(pointerTOEPROCESS); //PsLookupByProcessId is reference counted. This ensures that any reference to the object exists, it cannot be disposed of.
			return STATUS_BAD_DATA;	     			//Only once the kernel sees the reference count decremented (by ObDeferenceObject) will it free the memory. Failing to do this will create memory leak
		}											//otherwise we would have the EPROCESS struct stuck in memory. Because we still have reference to it.
		else //if protectionValue, points to a valid mem address.
		{
			protectionValue->Level = 0;
			protectionValue->Audit = 0;
			protectionValue->Signer = 0;
			protectionValue->Type = 0;

			ObDereferenceObject(pointerTOEPROCESS);
			return STATUS_SUCCESS;
		}
	}
	else
	{
		KdPrint(("PsLookUpProcessByProcessId Failed. \n"));
		return STATUS_ABANDONED;
	}
}


*/