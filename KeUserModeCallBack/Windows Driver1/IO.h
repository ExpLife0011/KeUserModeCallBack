#ifndef _IO_H
#define _IO_H

#define CWK_CDO_SYB_NAME  L"\\??\\zty_1997"

// 从应用层给驱动发送一个字符串。
#define  CWK_DVC_SEND_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x911,METHOD_BUFFERED, \
	FILE_WRITE_DATA)

extern VOID Start();
extern VOID CallMessageBox();

NTSTATUS DispatchFunction(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(irp);
	ULONG InLen;
	ULONG RetLen = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		InLen = irpsp->Parameters.DeviceIoControl.InputBufferLength;

		if (irpsp->Parameters.DeviceIoControl.IoControlCode == CWK_DVC_SEND_STR)
		{
        	Start();
		}

		irp->IoStatus.Information = RetLen;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceName;
	UNICODE_STRING LinkName;
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status;
	ULONG i = 0;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\zty_1997");

	RtlInitUnicodeString(&LinkName, CWK_CDO_SYB_NAME);

	status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
		);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("CreateDvice Error！\n"));
		return STATUS_UNSUCCESSFUL;
	}

	IoDeleteSymbolicLink(&LinkName);
	status = IoCreateSymbolicLink(&LinkName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create SymbolLink Error！\n"));
		IoDeleteDevice(DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}


	while (i < IRP_MJ_MAXIMUM_FUNCTION)
	{
		DriverObject->MajorFunction[i] = DispatchFunction;
		++i;
	}
	DeviceObject->Flags = DO_BUFFERED_IO;
	DeviceObject->Flags ^= DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

VOID DeleteDevice(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING SymbolName;
	IoDeleteDevice(DriverObject->DeviceObject);
	RtlInitUnicodeString(&SymbolName, CWK_CDO_SYB_NAME);
	IoDeleteSymbolicLink(&SymbolName);
}

#endif // !_IO_H
