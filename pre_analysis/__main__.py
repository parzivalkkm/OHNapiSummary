import json
import logging
import os
from collections import OrderedDict
from zipfile import ZipFile

from .elf_analysis import so_analysis

logger = logging.getLogger(__name__)

arch_supported = ['arm64-v8a', 'armeabi-v7a', 'armeabi']  # , 'x86_64'?
arch_supported_prefer_32 = ['armeabi-v7a', 'armeabi', 'arm64-v8a']
debug_prefer_32 = os.getenv("NS_PREFER_32", "False").lower() != "false"
if debug_prefer_32:
    print("PREFER_32: prefer 32bit arm")
    def_arch_supported = arch_supported_prefer_32
else:
    def_arch_supported = arch_supported

NS_SELECT_ARCH = os.getenv("NS_SELECT_ARCH", False)
if NS_SELECT_ARCH:
    print("Force arch selection to: " + NS_SELECT_ARCH)
    assert NS_SELECT_ARCH in arch_supported, "NS_SELECT_ARCH env arch selection is not supported!"
    def_arch_supported = [NS_SELECT_ARCH]


def select_abi(hap_zip, prefer_32=None):
    has_so = True

    so_arch_counter = OrderedDict()
    # print(f"prefer_32: {prefer_32}")
    if prefer_32 is None:
        my_arch_supported = def_arch_supported
    elif prefer_32:
        my_arch_supported = arch_supported_prefer_32
    else:
        my_arch_supported = arch_supported
    for i in my_arch_supported:
        so_arch_counter[i] = 0
    for name in hap_zip.namelist():
        # count so under arch
        if name.startswith('libs/') and name.endswith(".so"):
            path_parts = name.split("/")
            if len(path_parts) != 3: logger.warning("Warning: irregular path in zip file: " + name)
            arch = path_parts[1]
            if arch in so_arch_counter:
                so_arch_counter[arch] += 1
            # else:
            #     logger.warning("Warning: irregular arch in zip file:" + name)
    # If multiple items are maximal, the function returns the first one encountered
    arch_selected = max(so_arch_counter, key=so_arch_counter.get)
    if so_arch_counter[arch_selected] == 0:
        logger.error("No .so file in abi-dir.")
        has_so = False
    return arch_selected, has_so


def hap_pre_analysis(hap_path, prefer_32=None):
    """
    resolve static binding. print result.
    if analyse_dex is False, dex will be None
    """
    # so_name -> (checksum, recognized_java_symbols, import, export)
    so_stat = dict()
    has_so = True
    has_register = False
    hap = None

    # 2 收集Native侧Java_开头的符号，依次处理。
    hap_zip = ZipFile(hap_path)
    arch_selected, has_so = select_abi(hap_zip, prefer_32)
    if has_so:
        logger.info(f"Select arch {arch_selected} for analysis.")

    for so_info in hap_zip.infolist():
        if so_info.filename.startswith("libs/" + arch_selected) and so_info.filename.endswith(".so"):
            path_parts = so_info.filename.split("/")
            if len(path_parts) != 3: logger.warning("Warning: irregular path in zip file: " + so_info.filename)
            # update so_info
            filename = path_parts[-1]
            checksum = so_info.CRC
            # print(filename)
            registers, imp, exp = so_analysis(hap_zip.open(so_info))
            so_stat[filename] = (checksum, registers, imp, exp)
            if registers is not None and len(registers) > 0:
                has_register = True

    tags = {'has_so': has_so, 'has_register': has_register}
    return hap_zip, arch_selected, so_stat, tags


def get_resolve_report(hap_path, dex, arch_selected, so_stat):
    result = dict()
    result['file'] = hap_path
    result['arch_selected'] = arch_selected
    result['so_stat'] = so_stat
    # calculated
    result['resolve_percentage'] = dex.resolved_percentage()
    return result


def print_resolve_report(out_path, hap_path, dex, arch_selected, so_stat):
    with open(out_path, 'w') as f:
        report = get_resolve_report(hap_path, dex, arch_selected, so_stat)
        json.dump(report, f)
    return report


# currenly not in use
def set_exc_hook():
    import sys
    def my_except_hook(exctype, value, traceback):
        if exctype == KeyboardInterrupt:
            pass
        sys.__excepthook__(exctype, value, traceback)

    sys.excepthook = my_except_hook


if __name__ == '__main__':
    from .bai import main

    main()
