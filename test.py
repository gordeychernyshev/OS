import sys
import ctypes
from ctypes import c_void_p, c_int, c_char

def parse_key(s: str) -> int:
    if len(s) == 1:
        return ord(s) & 0xFF
    base = 16 if s.lower().startswith("0x") else 10
    return int(s, base=base) & 0xFF

def main():
    if len(sys.argv) != 5:
        sys.exit(2)

    lib_path, key_s, in_path, out_path = sys.argv[1:5]
    key = parse_key(key_s)

    lib = ctypes.CDLL(lib_path)
    lib.set_key.argtypes = [c_char]
    lib.set_key.restype = None
    lib.caesar.argtypes = [c_void_p, c_void_p, c_int]
    lib.caesar.restype = None

    with open(in_path, "rb") as f:
        data = f.read()

    src = ctypes.create_string_buffer(data, len(data))
    dst = ctypes.create_string_buffer(len(data))

    lib.set_key(bytes([key]))
    lib.caesar(ctypes.byref(src), ctypes.byref(dst), len(data))

    with open(out_path, "wb") as f:
        f.write(dst.raw)

if __name__ == "__main__":
    main()
