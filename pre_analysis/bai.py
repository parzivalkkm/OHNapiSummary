# pre-analysis for Ghidra + BinAbsInspector + NativeSummay module
# extract shared objects in hap and generate `<soname>.funcs.json` file specifying jni methods to analysis.

import os, shutil, json, zipfile, sys, time, logging
from zipfile import ZipFile

from .__main__ import hap_pre_analysis

# from .dex_analysis import DexAnalysisCenter, format_method

PREFER_32 = None

PROGRESS_FILENAME = "native_summay.preanalysis.progress"
GLOBAL_STATE = {
    'hap_stat': dict(),
    'progress': set(),  # filenames that finished analyzing
    'bad_count': [],  # hap that failed to analyse
}


# from https://github.com/evilpan/jni_helper
def get_type(atype):
    """
    Retrieve the java type of a descriptor (e.g : I -> jint)
    """
    TYPE_DESCRIPTOR = {
        'V': 'void',
        'Z': 'boolean',
        'B': 'byte',
        'S': 'short',
        'C': 'char',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double',
    }
    res = TYPE_DESCRIPTOR.get(atype)
    if res:
        if res == 'void':
            return res
        else:
            return 'j' + res
    if atype[0] == 'L':
        if atype == 'Ljava/lang/String;':
            res = 'jstring'
        else:
            res = 'jobject'
    elif atype[0] == '[':
        if len(atype) == 2 and atype[1] in 'ZBSCIJFD':
            res = TYPE_DESCRIPTOR.get(atype[1])
        else:
            res = 'object'
        res = 'j%sArray' % res
    else:
        print('Unknown descriptor: "%s".', atype)
        res = 'void'
    return res


# def get_multi_mapping(dex: DexAnalysisCenter):
#     ret = {}
#     for java_mth, resolve_list in dex.mappings.items():
#         if java_mth == DexAnalysisCenter.UNRESOLVED: continue
#         if len(resolve_list) <= 1: continue
#         resolve_list_ = []
#         for it in resolve_list:
#             resolve_list_.append(list(it))
#         ret[format_method(java_mth)] = list(resolve_list)
#     return ret

def tag2index(has_so, has_javasym, has_native):
    # tags = {'is_flutter': is_flutter, 'has_so':has_so, 'has_javasym':has_javasym}
    if has_so:
        if has_javasym:
            so = 0
        else:
            so = 1
    else:
        so = 2
    if has_native:
        native = 0
    else:
        native = 1
    return so * 2 + native


def pre_analysis(hap_path, out_path):
    t = time.time()
    if not os.path.exists(out_path):
        os.makedirs(out_path, exist_ok=True)
    hap_name = os.path.basename(hap_path)

    try:
        hap_zip, arch_selected, so_stat, tags = hap_pre_analysis(hap_path, prefer_32=PREFER_32)
    except zipfile.BadZipFile:
        print("Bad zip file: " + hap_path)
        GLOBAL_STATE['bad_count'].append(hap_name)
        GLOBAL_STATE['progress'].add(hap_name)
        return
    except Exception:
        print("Other error: ")
        import traceback
        print(traceback.format_exc())
        GLOBAL_STATE['bad_count'].append(hap_name)
        GLOBAL_STATE['progress'].add(hap_name)
        return
    zip = hap_zip  # type: ZipFile

    print(f"Selected arch is {arch_selected}")
    extracted_so = set()

    # extract so that contains JNI_OnLoad
    for so_name in so_stat:
        # if already extracted, skip
        if so_name in extracted_so:
            continue
        registers = so_stat[so_name][1]
        if registers is not None and len(registers) > 0:
            # extract so
            so_zip_path = '/'.join(['libs', arch_selected, so_name])
            source = zip.open(so_zip_path)
            target = open(os.path.join(out_path, so_name), "wb")
            with source, target:
                shutil.copyfileobj(source, target)

            json_f = os.path.join(out_path, so_name + '.registers.json')
            with open(json_f, 'w') as f:
                json.dump({
                    'registers': registers
                }, f, indent=2, ensure_ascii=False)

    # statistics
    stat = {}
    stat['has_so'] = tags['has_so']
    stat['has_register'] = tags['has_register']
    stat['selected_arch'] = arch_selected

    stat['so_stat'] = so_stat
    stat['analysis_time'] = time.time() - t
    GLOBAL_STATE['hap_stat'][hap_name] = stat
    # only change progress after everything
    GLOBAL_STATE['progress'].add(hap_name)


def analyze_one(hap_path, out_path=None, redo=False):
    print(f"Processing {hap_path}")
    if out_path is None:
        out_path = hap_path.removesuffix('.hap') + '.native_summary'
    if redo and os.path.exists(out_path):
        from shutil import rmtree
        print(f'deleting {out_path}')
        rmtree(out_path)
    pre_analysis(hap_path, out_path)
    stat = GLOBAL_STATE['hap_stat'][os.path.basename(hap_path)]
    hap_result = os.path.join(out_path, "hap_pre_analysis.json")
    with open(hap_result, 'w') as f:
        json.dump(stat, f, indent=2)
    if len(os.listdir(out_path)) == 0:
        print("empty folder. removing...")
        os.rmdir(out_path)


def restore_progress(path):
    import pickle, os
    global GLOBAL_STATE
    prog_file = os.path.join(path, PROGRESS_FILENAME)
    if os.path.exists(prog_file):
        with open(prog_file, "rb") as f:
            GLOBAL_STATE = pickle.load(f)


def backup_progress(path):
    import pickle, os
    prog_file = os.path.join(path, PROGRESS_FILENAME)
    with open(prog_file, "wb") as f:
        pickle.dump(GLOBAL_STATE, f)


def finalize(path):
    hap_result = os.path.join(path, "hap_result.json")
    with open(hap_result, 'w') as f:
        json.dump(GLOBAL_STATE['hap_stat'], f, indent=4)
    backup_progress(path)
    print(f'analysis spent {time.time() - analysis_start_time}s.')


def set_exc_hook(path):
    import sys
    def my_except_hook(exctype, value, traceback):
        if issubclass(exctype, KeyboardInterrupt):
            finalize(path)
        sys.__excepthook__(exctype, value, traceback)

    sys.excepthook = my_except_hook


def analyze_one_mp_wrapper(arg, q):
    global GLOBAL_STATE
    GLOBAL_STATE = {
        'progress': set(),
        'hap_stat': dict(),
        'bad_count': [],
    }
    analyze_one(*arg)
    q.put(GLOBAL_STATE)


def handle_result(global_state):
    assert len(global_state['progress']) == 1

    for name in global_state['progress']:
        if name in global_state['bad_count']: continue
        GLOBAL_STATE['hap_stat'][name] = global_state['hap_stat'][name]
    GLOBAL_STATE['bad_count'].extend(global_state['bad_count'])
    GLOBAL_STATE['progress'].update(global_state['progress'])


def mp_run(args_list, process_count, out_path):
    from multiprocessing import Process, Queue
    queues = [None for i in range(process_count)]
    processes = [None for i in range(process_count)]
    try:
        for i in range(process_count):
            if len(args_list) > 0:
                queues[i] = Queue()
                # TODO arg
                processes[i] = Process(target=analyze_one_mp_wrapper, args=(args_list.pop(0), queues[i]))
                processes[i].start()
        # 轮询是否结束，结束则处理返回值，并启动新的进程
        while processes.count(None) < process_count:
            for i in range(process_count):
                process = processes[i]  # type: Process
                queue = queues[i]  # type: Queue
                if process != None and (not queue.empty()):
                    result = queue.get_nowait()
                    handle_result(result)
                    if len(args_list) > 0:
                        queues[i] = Queue()
                        processes[i] = Process(target=analyze_one_mp_wrapper, args=(args_list.pop(0), queues[i]))
                        processes[i].start()
                    else:
                        processes[i] = None
                        queues[i] = None
                    break
            else:
                time.sleep(3)
    except KeyboardInterrupt:
        # 如果遇到异常，则终止所有进程并finalize
        for i in range(process_count):
            process = processes[i]  # type: Process
            if process != None:
                process.terminate()
    finally:
        finalize(out_path)


analysis_start_time = None


def main():
    logging.basicConfig(level=logging.WARNING)
    global analysis_start_time
    analysis_start_time = time.time()
    global PREFER_32
    hap_path = None
    out_path = None
    import argparse
    parser = argparse.ArgumentParser(
        description=f'Process some haps, extract so and export related entrypoint to json. this tool will save progress (by hap name) to {PROGRESS_FILENAME}')
    parser.add_argument('hap_path_or_folder', metavar='hap_path_or_folder', type=str,
                        help='hap path or hap folder path for batch processing')
    parser.add_argument('out_folder', nargs='?', metavar='out_folder', type=str,
                        help='output folder path. can be omitted to auto generate when analysing single hap')
    parser.add_argument('--prefer-32', nargs='?', default=None, const="yes", type=str,
                        help="whether to prefer 32 (=yes), or prefer 64 if =no.")
    parser.add_argument('--process', default=1, type=int,
                        help="multiprocessing process count. default: 1 (single process)")

    # if len(sys.argv) == 1:
    #     print(f"Usage: {sys.argv[0]} hap_path_or_folder [out_folder]")
    #     exit(-1)

    args = parser.parse_args()

    if args.prefer_32 == "yes" or args.prefer_32 == "true":
        PREFER_32 = True
    elif args.prefer_32 == "no" or args.prefer_32 == "false":
        PREFER_32 = False
    elif args.prefer_32 is not None:
        print("error, cannot recognize --prefer-32 option")
    hap_path = args.hap_path_or_folder
    out_path = args.out_folder
    if os.path.isfile(hap_path):
        analyze_one(hap_path, out_path)
    else:  # bulk analysis mode
        assert out_path is not None
        restore_progress(out_path)  # restore previous progress
        if not (args.process > 1):
            set_exc_hook(out_path)
        progress = GLOBAL_STATE['progress']
        mp_to_run = []  # for multiprocessing
        for file in os.listdir(hap_path):
            if not file.endswith('.hap'):
                continue
            # if file[:7] <= '5886316':
            #     print("skipping...")
            #     continue
            if file in progress:
                continue

            fpath = os.path.join(hap_path, file)
            out_path_one = None
            if len(sys.argv) > 2:  # 为每个hap文件生成一个文件夹名
                out_path_one = os.path.join(out_path, file.removesuffix('.hap') + '.oh_napi_summary')

            if args.process > 1:
                mp_to_run.append((fpath, out_path_one, True))
            else:  # single_process
                analyze_one(fpath, out_path_one, redo=True)
        if args.process > 1:
            mp_run(mp_to_run, args.process, out_path)
        else:
            finalize(out_path)


if __name__ == '__main__':
    main()
