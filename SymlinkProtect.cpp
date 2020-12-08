/*++

Module Name:

    SymlinkProtect.cpp

Abstract:

    This is the main module of the SymlinkProtect miniFilter driver

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "FileNameInformation.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define DRIVER_CONTEXT_TAG 'xcsP'
#define DRIVER_TAG 'sP'

bool IsSymlinkAllowed(_In_ WCHAR* targetName);

#define PT_DBG_PRINT( _dbgLevel, _string )          \
	(FlagOn(gTraceFlags,(_dbgLevel)) ?              \
		DbgPrint _string :                          \
		((int)0))

/*************************************************************************
   Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
SymlinkProtectUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
SymlinkProtectPreFSControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

EXTERN_C_END

//
// Assign text sections for each routine
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SymlinkProtectUnload)
#endif

//
// Operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, SymlinkProtectPreFSControl, nullptr },
    { IRP_MJ_OPERATION_END }
};

//
// This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),  // Size
    FLT_REGISTRATION_VERSION,  // Version
    0,                         // Flags
    nullptr,                   // Context
    Callbacks,
    SymlinkProtectUnload,
    nullptr,                   // InstanceSetup
    nullptr,                   // InstanceQueryTeardown
    nullptr,                   // InstanceTeardownStart
    nullptr,                   // InstanceTeardownComplete,
    nullptr,                   // GenerateFileName
    nullptr,                   // GenerateDestinationFileName
    nullptr                    // NormalizeNameComponent
};

/*************************************************************************
   Helper functions
*************************************************************************/

bool
IsSymlinkAllowed(
    _In_ WCHAR* targetName
)
{
    auto allowSymlink = true;

    WCHAR dest[512] = { 0 };
    wcsncpy_s(dest, targetName, _TRUNCATE);
    _wcslwr(dest);

    if (wcsstr(dest, L"\\rpc control") != nullptr ||
        wcsstr(dest, L"\\basenamedobjects") != nullptr ||
        wcsstr(dest, L"\\appcontainernamedobjects") != nullptr ||
        wcsstr(dest, L":\\program") != nullptr ||
        wcsstr(dest, L":\\windows") != nullptr)
    {
        allowSymlink = false;
    }

    return allowSymlink;
}

/*************************************************************************
    MiniFilter initialization and unload routines
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("SymlinkProtect!DriverEntry: Entered\n"));

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (NT_SUCCESS(status))
    {
        status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(gFilterHandle);
        }
    }

    return status;
}

NTSTATUS
SymlinkProtectUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("SymlinkProtect!SymlinkProtectUnload: Entered\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
SymlinkProtectPreFSControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("SymlinkProtect!SymlinkProtectPreFSControl: Entered\n"));

    if (Data->RequestorMode == KernelMode ||
        Data->Iopb->Parameters.DeviceIoControl.Buffered.IoControlCode != FSCTL_SET_REPARSE_POINT)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG maxSize = 32767 * sizeof(WCHAR);
    auto& params = Data->Iopb->Parameters.DeviceIoControl;
    auto* reparseBuffer = (REPARSE_DATA_BUFFER*)params.Buffered.SystemBuffer;

    if (reparseBuffer->ReparseTag != IO_REPARSE_TAG_MOUNT_POINT ||
        reparseBuffer->MountPointReparseBuffer.SubstituteNameLength > maxSize)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    auto targetName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, maxSize + sizeof(WCHAR), DRIVER_TAG);
    if (targetName == nullptr)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try
    {
        RtlZeroMemory(targetName, maxSize + sizeof(WCHAR));
        auto offset = reparseBuffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
        auto count = reparseBuffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR);
        wcsncpy_s(targetName, 1 + maxSize / sizeof(WCHAR), &reparseBuffer->MountPointReparseBuffer.PathBuffer[offset], count);

        if (!IsSymlinkAllowed(targetName))
        {
            FilterFileNameInformation linkNameInfo(Data);
            if (linkNameInfo && NT_SUCCESS(linkNameInfo.Parse()))
            {
                KdPrint(("[SymlinkProtect] Junction prevented for %wZ <<===>> %ws\n", &linkNameInfo->Name, targetName));
            }

            Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Data->IoStatus.Information = 0;

            return FLT_PREOP_COMPLETE;
        }
    }
    __finally
    {
        ExFreePool(targetName);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
