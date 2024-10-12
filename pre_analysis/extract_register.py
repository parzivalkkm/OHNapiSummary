import io, os, shutil, json, zipfile, sys, time, logging
from elf_analysis import so_analysis


def main():
    so_path = "D:\\WorkSpace\\ArkTS_Native\\libentry.so"
    with open(so_path, 'rb') as f:
        stream = io.BytesIO(f.read())
    registers, imp, exp = so_analysis(stream)
    print(registers)
    # print(imp)
    # print(exp)


if __name__ == '__main__':
    main()
