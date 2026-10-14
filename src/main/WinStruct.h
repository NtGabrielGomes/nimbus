#ifndef WINSTRUCT_H
#define WINSTRUCT_H

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef LONG KPRIORITY;

typedef enum class _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum class _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,

        FileRenameInformationBypassAccessCheck,
        FileLinkInformationBypassAccessCheck,

            FileVolumeNameInformation,
            FileIdInformation,
            FileIdExtdDirectoryInformation,
            FileReplaceCompletionInformation,
            FileHardLinkFullIdInformation,
            FileIdExtdBothDirectoryInformation,
            FileDispositionInformationEx,
            FileRenameInformationEx,
            FileRenameInformationExBypassAccessCheck,
            FileDesiredStorageClassInformation,
            FileStatInformation,
            FileMemoryPartitionInformation,
            FileStatLxInformation,
            FileCaseSensitiveInformation,
            FileLinkInformationEx,
            FileLinkInformationExBypassAccessCheck,
            FileStorageReserveIdInformation,
            FileCaseSensitiveInformationForceAccessCheck,
            FileKnownFolderInformation,

            FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4201)
#endif
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef
VOID
(NTAPI* PIO_APC_ROUTINE)(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    _Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    _Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef enum class _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
} KEY_INFORMATION_CLASS;

typedef enum class _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation = 1,
    KeyValueFullInformationAlign64 = 2,
    KeyValuePartialInformation = 3,
    KeyValuePartialInformationAlign64 = 4,
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    ULONG ClassLength;
    ULONG ClassOffset;
    WCHAR Name[1];
} KEY_NODE_INFORMATION, * PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
} KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    ULONG         ReparsePointTag;
    FILE_ID_128   FileId;
    WCHAR         FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, * PFILE_ID_EXTD_DIR_INFORMATION;

#endif
