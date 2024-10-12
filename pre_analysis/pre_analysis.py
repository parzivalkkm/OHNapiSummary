import zipfile
import os
import io
from elf_analysis import so_analysis


def extract_so_files(hap_file_path, output_dir):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(hap_file_path, 'r') as hap_file:
        # Iterate through the files in the .hap archive
        for file_info in hap_file.infolist():
            # Check if the file is in the libs directory and has a .so extension
            if file_info.filename.startswith('libs/') and file_info.filename.endswith('.so'):
                # Extract the .so file to the output directory
                hap_file.extract(file_info, output_dir)
                print(f"Extracted: {file_info.filename}")


def pre_analysis(hap_file_path, output_dir):

    extract_so_files(hap_file_path, output_dir)

    so_stat = {}

    lib_dir = os.path.join(output_dir, 'libs')
    for arch in os.listdir(lib_dir):
        if os.path.basename(arch) == 'arm64-v8a':
            for so_file in os.listdir(os.path.join(lib_dir, arch)):
                so_path = os.path.join(lib_dir, arch, so_file)
                with open(so_path, 'rb') as f:
                    stream = io.BytesIO(f.read())
                registers, imp, exp = so_analysis(stream)
                if len(registers) > 0:
                    so_stat[so_file] = registers
                    print(f"Registers: {registers}")

def main():
    hap_file_path = "D:\\OpenHarmony\\NativeDemo4\\entry\\build\\default\\outputs\\default\\entry-default-unsigned.hap"
    basename = os.path.basename(hap_file_path)
    output_dir = f"{basename}.ohnapi"
    os.mkdir(output_dir)

    pre_analysis(hap_file_path, output_dir)


if __name__ == '__main__':
    main()
