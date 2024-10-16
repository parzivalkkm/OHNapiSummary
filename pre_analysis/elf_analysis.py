import logging
from io import BytesIO

from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


# TODO weak symbol?
def get_elf_import_export(stream, in_memory=True):
    """
    arg usually `apk_zip.open(so_info)`
    """
    import_names = list()
    export_names = list()

    # without it, become extremely slow sometimes
    if in_memory:
        import zlib
        try:
            stream = BytesIO(stream.read())
        except zlib.error:
            return import_names, export_names
    dyn = None
    try:
        elf = ELFFile(stream)
        dyn = elf.get_section_by_name('.dynsym')
    except (ELFError, ELFParseError) as e:
        logger.warning(repr(e))
        return None, None

    if dyn is None:
        return None, None
    it = dyn.iter_symbols()
    next(it)
    for sym in it:
        # skip index 0
        if sym['st_shndx'] == 'SHN_UNDEF':  # import
            import_names.append(sym.name)
        else:  # export
            export_names.append(sym.name)
    return import_names, export_names


def so_analysis(stream):
    imp, exp = get_elf_import_export(stream, in_memory=True)
    if exp is not None:
        registers = [i for i in exp if i.startswith('Register') and i.endswith('Module')]
    return registers, imp, exp
