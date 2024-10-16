import os,sys

file_path = os.path.realpath(__file__)
sys.path.insert(1, os.path.dirname(file_path))

from pre_analysis.bai import main

if __name__ == '__main__':
    main()
