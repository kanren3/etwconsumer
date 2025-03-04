#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <initguid.h>
#include <windows.h>
#include <evntprov.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")
#include "etwconsumer.h"

inline ULONG get_heuristic_size(
    const BYTE* propertyStart,
    const EVENT_PROPERTY_INFO& propertyInfo,
    const EVENT_RECORD& record)
{
    ULONG propertyLength = 0;
    PBYTE pRecordEnd = (PBYTE)record.UserData + record.UserDataLength;

    // The calls to Tdh are kind of expensive, especially when krabs is
    // included in a managed assembly as this call will be a thunk.
    // The following _very_ common property types can be short-circuited
    // to prevent the expensive call.

    // Be careful! Check IN and OUT types before making an assumption.

    // Strings that appear at the end of a record may not be null-terminated.
    // If a string is null-terminated, propertyLength includes the null character.
    // If a string is not-null terminated, propertyLength includes all bytes up
    // to the end of the record buffer.

    if (propertyInfo.nonStructType.OutType == TDH_OUTTYPE_STRING)
    {
        if (propertyInfo.nonStructType.InType == TDH_INTYPE_UNICODESTRING)
        {
            auto p = (const wchar_t*)propertyStart;
            auto pEnd = (const wchar_t*)pRecordEnd;
            while (p < pEnd) {
                if (!*p++) {
                    break;
                }
            }
            propertyLength = static_cast<ULONG>(((PBYTE)p) - propertyStart);
        }
        else if (propertyInfo.nonStructType.InType == TDH_INTYPE_ANSISTRING)
        {
            auto p = (const char*)propertyStart;
            auto pEnd = (const char*)pRecordEnd;
            while (p < pEnd) {
                if (!*p++) {
                    break;
                }

            }
            propertyLength = static_cast<ULONG>(((PBYTE)p) - propertyStart);
        }
    }

    return propertyLength;
}

USHORT GetEventPropertyLength(PEVENT_RECORD EventRecord, PTRACE_EVENT_INFO EventInformation, PEVENT_PROPERTY_INFO EventPropertyInfo, PBYTE UserData)
{
    USHORT LengthPropertyIndex;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    ULONG PropertySize;
    ULONG PropertyLength;

    if (EventPropertyInfo->Flags & PropertyParamLength) {
        LengthPropertyIndex = EventPropertyInfo->lengthPropertyIndex;
        DataDescriptor.PropertyName = reinterpret_cast<ULONGLONG>(EventInformation) + EventInformation->EventPropertyInfoArray[LengthPropertyIndex].NameOffset;

        DataDescriptor.ArrayIndex = ULONG_MAX;
        TdhGetPropertySize(EventRecord, 0, nullptr, 1, &DataDescriptor, &PropertySize);
        TdhGetProperty(EventRecord, 0, nullptr, 1, &DataDescriptor, PropertySize, reinterpret_cast<PBYTE>(&PropertyLength));
    }
    else {
        if (EventPropertyInfo->length > 0) {
            PropertyLength = EventPropertyInfo->length;
        }
        else {

            //
            // This has bug
            //

            if (TDH_INTYPE_BINARY == EventPropertyInfo->nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == EventPropertyInfo->nonStructType.OutType) {

                //
                // sizeof(IN6_ADDR) == 16
                //

                PropertyLength = 16;
            }
            else {
                PropertyLength = get_heuristic_size(UserData, *EventPropertyInfo, *EventRecord);
            }
        }
    }

    return static_cast<USHORT>(PropertyLength);
}

std::wstring GetEventPropertyString(PEVENT_RECORD EventRecord, PTRACE_EVENT_INFO EventInformation, PEVENT_PROPERTY_INFO EventPropertyInfo, PBYTE UserData, PUSHORT UserDataConsumed)
{
    ULONG Status = ERROR_SUCCESS;
    ULONG PointerSize;
    USHORT PropertyLength;
    PWSTR EventMapName;
    ULONG EventMapInformationSize;
    PEVENT_MAP_INFO EventMapInformation = nullptr;
    ULONG BufferSize = 0;
    PWCHAR Buffer;
    std::wstring PropertyString;
    
    PointerSize = EventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    PropertyLength = EventPropertyInfo->length;

    if (TDH_INTYPE_BINARY == EventPropertyInfo->nonStructType.InType &&
        TDH_OUTTYPE_IPV6 == EventPropertyInfo->nonStructType.OutType) {
        PropertyLength = 16;
    }

    if ((EventPropertyInfo->Flags & PropertyStruct) == 0 &&
        (EventPropertyInfo->Flags & PropertyHasCustomSchema) == 0) {

        if (EventPropertyInfo->nonStructType.MapNameOffset > 0) {
            EventMapName = reinterpret_cast<PWCHAR>(reinterpret_cast<PUCHAR>(EventInformation) + EventPropertyInfo->nonStructType.MapNameOffset);
            Status = TdhGetEventMapInformation(EventRecord, EventMapName, nullptr, &EventMapInformationSize);

            if (ERROR_INSUFFICIENT_BUFFER == Status) {
                EventMapInformation = reinterpret_cast<PEVENT_MAP_INFO>(malloc(EventMapInformationSize));

                if (nullptr != EventMapInformation) {
                    Status = TdhGetEventMapInformation(EventRecord, EventMapName, EventMapInformation, &EventMapInformationSize);
                }
            }
        }

        if (ERROR_SUCCESS == Status) {
            Status = TdhFormatProperty(EventInformation,
                                       EventMapInformation,
                                       PointerSize,
                                       EventPropertyInfo->nonStructType.InType,
                                       EventPropertyInfo->nonStructType.OutType,
                                       PropertyLength,
                                       EventRecord->UserDataLength,
                                       UserData,
                                       &BufferSize,
                                       nullptr,
                                       UserDataConsumed);

            if (ERROR_INSUFFICIENT_BUFFER == Status) {
                Buffer = reinterpret_cast<PWCHAR>(malloc(BufferSize));

                if (nullptr != Buffer) {
                    Status = TdhFormatProperty(EventInformation,
                                               EventMapInformation,
                                               PointerSize,
                                               EventPropertyInfo->nonStructType.InType,
                                               EventPropertyInfo->nonStructType.OutType,
                                               PropertyLength,
                                               EventRecord->UserDataLength,
                                               UserData,
                                               &BufferSize,
                                               Buffer,
                                               UserDataConsumed);

                    if (ERROR_SUCCESS == Status) {
                        PropertyString = std::wstring(Buffer, BufferSize / 2);
                    }

                    free (Buffer);
                }
            }

            if (nullptr != EventMapInformation) {
                free(EventMapInformation);
            }
        }
    }

    return PropertyString;
}

std::unordered_map<std::wstring, std::wstring> EventParseProperty(PEVENT_RECORD EventRecord)
{
    ULONG Status;
    ULONG EventInformationSize = 0;
    PTRACE_EVENT_INFO EventInformation;
    PEVENT_PROPERTY_INFO EventPropertyInfo;
    PBYTE UserData;
    USHORT UserDataConsumed;
    std::wstring PropertyName;
    std::wstring PropertyString;
    std::unordered_map<std::wstring, std::wstring> PropertyMap;

    UserData = reinterpret_cast<PBYTE>(EventRecord->UserData);
    Status = TdhGetEventInformation(EventRecord, 0, nullptr, nullptr, &EventInformationSize);

    if (ERROR_INSUFFICIENT_BUFFER == Status) {
        EventInformation = reinterpret_cast<PTRACE_EVENT_INFO>(malloc(EventInformationSize));

        if (nullptr != EventInformation) {
            Status = TdhGetEventInformation(EventRecord, 0, nullptr, EventInformation, &EventInformationSize);

            if (ERROR_SUCCESS == Status) {
                for (ULONG Index = 0; Index < EventInformation->TopLevelPropertyCount; Index++) {
                    EventPropertyInfo = &EventInformation->EventPropertyInfoArray[Index];

                    if (EventPropertyInfo->NameOffset != 0) {
                        PropertyName = reinterpret_cast<PWCHAR>(reinterpret_cast<PUCHAR>(EventInformation) + EventPropertyInfo->NameOffset);

                        if (PropertyName == L"CommandLine") {
                            __debugbreak();
                        }

                        UserDataConsumed = 0;
                        PropertyString = GetEventPropertyString(EventRecord, EventInformation, EventPropertyInfo, UserData, &UserDataConsumed);
                        PropertyMap.insert({ PropertyName , PropertyString });
                        UserData += UserDataConsumed;
                    }
                }
            }

            free (EventInformation);
        }
    }

    return PropertyMap;
}

VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord)
{
    std::unordered_map<std::wstring, std::wstring> EventProperty;
    EventProperty = EventParseProperty(EventRecord);

    for (const auto &Item : EventProperty) {
        printf("%ws:%ws\r\n", Item.first.c_str(), Item.second.c_str());
    }

    printf("\r\n");
}

ULONG WINAPI EventBufferCallback(PEVENT_TRACE_LOGFILEW Logfile)
{
    return 0;
}

VOID ProcessTraceWorker()
{
    ULONG Status = ERROR_SUCCESS;
    TRACEHANDLE TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    EVENT_TRACE_LOGFILEW EventTraceLogFile = { 0 };

    EventTraceLogFile.LoggerName = L"Eventlog-Security";
    EventTraceLogFile.ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;
    EventTraceLogFile.ProcessTraceMode |= PROCESS_TRACE_MODE_EVENT_RECORD;
    EventTraceLogFile.BufferCallback = EventBufferCallback;
    EventTraceLogFile.EventRecordCallback = EventRecordCallback;

    TraceHandle = OpenTraceW(&EventTraceLogFile);

    if (INVALID_PROCESSTRACE_HANDLE != TraceHandle) {
        while (ERROR_SUCCESS == Status) {
            Status = ProcessTrace(&TraceHandle, 1, NULL, NULL);
        }
        CloseTrace(TraceHandle);
    }
}

ULONG RegisterLogger()
{
    ULONG Status = ERROR_SUCCESS;
    TRACEHANDLE TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    ULONG PropertiesSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(RURIWO_LOGGER_NAME) + 2;
    PEVENT_TRACE_PROPERTIES Properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(PropertiesSize));

    while (TRUE) {
        RtlZeroMemory(Properties, PropertiesSize);

        Properties->Wnode.BufferSize = PropertiesSize;
        Properties->Wnode.Guid = RuriwoLoggerGuid;
        Properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        Properties->Wnode.ClientContext = 1;

        Properties->LogFileMode |= EVENT_TRACE_REAL_TIME_MODE;

        Properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        Properties->FlushTimer = 1;

        Status = StartTraceW(&TraceHandle, RURIWO_LOGGER_NAME, Properties);

        if (ERROR_SUCCESS == Status) {
            EnableTraceEx(&SecurityAuditingProviderGuid,
                          nullptr,
                          TraceHandle,
                          EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                          TRACE_LEVEL_VERBOSE,
                          0xFFFFFFFFFFFFFFFF,
                          0,
                          0,
                          nullptr);
            break;
        }
        else if (ERROR_ALREADY_EXISTS == Status) {
            Status = ControlTraceW(0, RURIWO_LOGGER_NAME, Properties, EVENT_TRACE_CONTROL_STOP);

            if (ERROR_SUCCESS != Status) {
                break;
            }
        }
        else {
            break;
        }
    }

    free(Properties);
    return Status;
}

int main(int argc, char *argv[])
{
    if (ERROR_SUCCESS == RegisterLogger()) {
        std::thread TraceWorker(ProcessTraceWorker);
        TraceWorker.detach();
    }

    getchar();
    return 0;
}
