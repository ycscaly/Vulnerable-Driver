#include <ntddk.h>

#define DEVICE_NAME      L"\\Device\\VulnerableDevice"
#define DOS_DEVICE_NAME  L"\\DosDevices\\VulnerableDOSDevice"

#define IOCTL_UPDATE_WHAT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_WHERE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_WRITE_WHAT_WHERE_VULNERABILITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_BYTE_ADDRESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_INCREMENT_ARBITRARY_BYTE_VULNERABILITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_NEW_PROGRAM_COUTNER  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CONTROL_PROGRAM_COUNTER_VULNERABILITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)


static PUINT64 what = NULL, where = NULL;
static PUINT8 byteAddress = NULL;
static void (*programCounter)() = NULL;


NTSTATUS ioctlHandler(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack;
	ULONG ctl, inLen;
	PCHAR input = Irp->AssociatedIrp.SystemBuffer;
	
	stack = IoGetCurrentIrpStackLocation(Irp);

	ctl = stack->Parameters.DeviceIoControl.IoControlCode;
	inLen = stack->Parameters.DeviceIoControl.InputBufferLength;

	DbgPrint("Handling IOCTL\n");

	if (ctl == IOCTL_UPDATE_WHAT)
	{
		DbgPrint("Updating new value");
		if (input)
		{
			DbgPrint("%16llx\n", *input);
			what = *(PUINT64*)input;
		}
	}
	else if (ctl == IOCTL_UPDATE_WHERE)
	{
		DbgPrint("Updating target address");
		if (input)
		{
			DbgPrint("%16llx\n", *input);
			where = *(PUINT64*)input;
		}
	}
	else if (ctl == IOCTL_TRIGGER_WRITE_WHAT_WHERE_VULNERABILITY)
	{
		DbgPrint("Triggering Write What Where Vulnerability ... Are you sure?\n");
		DbgBreakPoint();
		DbgPrint("HOOLLY SHIT\n");
		*where = (UINT64)what;
	}
	else if (ctl == IOCTL_UPDATE_BYTE_ADDRESS)
	{
		DbgPrint("Updating byte address");
		if (input)
		{
			DbgPrint("%16llx\n", *input);
			byteAddress = *(PUINT8*)input;
		}
	}
	else if (ctl == IOCTL_TRIGGER_INCREMENT_ARBITRARY_BYTE_VULNERABILITY)
	{
		DbgPrint("Triggering Arbitrary Byte Increment Vulnerability... Are you sure?\n");
		DbgBreakPoint();
		DbgPrint("Ownage\n");
		*byteAddress += 1;
	}
	else if (ctl == IOCTL_UPDATE_NEW_PROGRAM_COUTNER)
	{
		DbgPrint("Updating program counter to ");
		if (input)
		{
			DbgPrint("%16llx\n", *(PUINT64*)input);
			programCounter = (void(*)())(*(PUINT64*)input);
		}
	}
	else if (ctl == IOCTL_TRIGGER_CONTROL_PROGRAM_COUNTER_VULNERABILITY)
	{
		DbgPrint("Triggering Control PC Vulnerability... Are you sure?\n");
		DbgBreakPoint();

		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		programCounter();
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}

NTSTATUS openCloseHandler(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS st;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING deviceName, dosDeviceName;

	DbgPrint("Vulnerable Driver Entry Point; J.C. In!\n");
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);

	st = IoCreateDevice(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&deviceObject);

	if (!NT_SUCCESS(st))
	{
		DbgPrint("IoCreateDevice failed\n");
		return st;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctlHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = openCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = openCloseHandler;

	RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
	st = IoCreateSymbolicLink(&dosDeviceName, &deviceName);

	if (!NT_SUCCESS(st))
	{
		DbgPrint("IoCreateSymbolicLink failed\n");
		if (deviceObject)
			IoDeleteDevice(deviceObject);
		else
			DbgPrint("IoDeleteDevice failed\n");
		return st;
	}

	return st;
}