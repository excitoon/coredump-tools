from typing import Callable, Literal, Optional, Union

from utils import read_struct, write_struct, read_bstr, read_str, write_str

import collections
import contextlib
import ctypes
import functools
import inspect
import io
import logging
import mmap
import os
import re
import struct

import boto3
import elftools
import humanize
import iced_x86
import s3path
import sortedcontainers
import unicorn

import syscall
import tracer
import utils


logger = logging.getLogger(__name__)

# FIXME: a lot of these asserts should be exceptions, we should have a class
# FIXME: proper log system

# FIXME: in the memory mapping phase, the code assumes that our
# PAGESIZE is the same as the core dump's:
#  - if ours is higher: mmapping will fail if given an unaligned offset
#  - if core dump's is higher: last-page rounding will not match up with the VMA rounding
# Also, Unicorn engine page size must not be higher, checked below

# FIXME: coredumpctl can tall you the build ids of everything... is that info
# taken from the coredump file alone, or does it collect it from loaded modules
# at the time of dump, and stores it separately?
# FIXME: in any case, allow specifying a dictionary of build-ids to verify

# FIXME: what about vdso vars and env/auxv/argv area? is it given to us in the corefile?
# does it appear at the mappings? do gdb and kernel behave differently? should we
# synthetize it ourselves?

# minimum access required by Unicorn on mapped areas, otherwise behaviour is undefined
REQUIRED_PROT = mmap.PROT_READ | mmap.PROT_WRITE

class EmulationError(Exception):
    pass

class Emulator(object):
    '''Emulator for core dumps.

    Once an instance is constructed and ready for use, see `call()` to invoke
    functions. `call()` is low-level and accepts integer arguments (which may
    be pointers) and returns the result as an integer.

    Use `mem()` to read or write memory of the emulator, and use `reserve()`
    if you need to allocate some space on the stack. Both return a raw I/O
    instance with some convenience methods injected into it, such as
    `read_str()`, `read_bstr()`, `read_struct()` and its `write_` equivalents;
    these are not present in the typings, see the `emucore.utils` module.

    The corefile comes with metadata about the memory mappings and state
    of the process / threads at the time of dump. Properties like `mappings`,
    `auxv`, `threads`, make that info available. There's also the `find_mapping()`
    function to query the mapping that an address falls into.

    EmuCore also attempts to load info about the loaded objects and its symbols.
    This info is available in the `loaded_objects` and `symbols` properties,
    but it's easier to use `get_symbol()` / `get_symbols()` to query a symbol
    by its name. To attempt to find the symbol that an address falls into, use
    `find_symbol()` instead.

    For advanced use cases, the Unicorn instance can be accessed through the
    `emu` property. `emu_ctx` holds a Unicorn context that is restored at the
    start of each `call()` invocation.
    '''

    # open resources (FIXME: make this class a context manager)
    emu: unicorn.Uc
    stack_tracer: 'StackTracer'
    core: elftools.elf.elffile.ELFFile
    core_mm: mmap.mmap
    mappings_mm: dict[bytes, tuple[bytes, mmap.mmap]]

    # parsed info
    threads: list[utils.Prstatus]
    mappings: list[utils.FileMapping]
    auxv: dict[int, int]
    # WARNING: below properties will be absent if __load_symbols() failed
    loaded_objects: list[utils.RtLoadedObject]
    symbols: dict[str, set[utils.Symbol]]
    symbols_by_type_by_addr: dict[
        utils.Symbol.Type,             # for each type...
        tuple[
            list[int],           # keys (addresses)
            list[set[utils.Symbol]],  # values (symbols at an address)
        ]
    ]

    emu_ctx: unicorn.unicorn.UcContext

    # stack management
    stack_base: int
    stack_size: int
    stack_addr: int

    def __init__(
        self, filename: str,
        patch_glibc: bool=True, patch_lock: bool=False, mapping_load_kwargs={},
        stack_addr: int = 0x7f10000000000000, stack_size: int = 16 * 1024 * 1024,
        load_symbols: bool = True, trace_stack: int = 150,
    ):
        '''Parses the corefile, loads the referenced files, and initializes a
        Unicorn emulator instance mapped with its memory.

        Note that all files are opened in read mode (so nothing is tampered with),
        but mapped anonymously so their memory is writable.

        This takes a while, enable INFO log messages to see progress.

        Parameters:

          - `filename`: location of corefile to load

          - `mapping_load_kwargs`: parameters passed to `__load_mappings()` that
            influence how and which files referenced by the corefile (such as
            shared libraries) are loaded. see `__load_mappings()`.

          - `patch_glibc`: attempt to patch glibc codepaths that use SIMD instructions
            we don't have, to prevent invalid instruction errors (default: True)

          - `patch_lock`: patch common pthread calls to lock / unlock mutexes so that
            they always succeed rather than fail, loop or syscall. it won't magically
            make the data protected by them consistent, but can work (default: False)

          - `stack_addr`, `stack_size`: location and size of our custom stack area,
            used by `call()` and `reserve()` to emulate calls. By default a 16MiB
            stack is used, in some cases you may need a bigger size.

          - `load_symbols`: query all loaded objects from the linker and parse their
            files to collect their symbols. isabling this saves some init time but
            means you have to pass raw addresses to `call()` or `mem()` and errors
            won't be as useful. this must be enabled in order for `patch_*` above
            to work (default: True)

          - `trace_stack`: trace stack pointer at basic block boundary to be able to
            reconstruct a sort of call stack. pass the desired capacity (maximum
            entries) or 0 to disable the stack tracer (default: 150)
        '''

        self.__mappings_to_load = sortedcontainers.SortedDict()
        self.__loaded_mappings = sortedcontainers.SortedDict()
        self.__mapping_paths = {}
        self.__symbols = collections.defaultdict(set)
        self.__symbols_by_type_by_addr = collections.defaultdict(sortedcontainers.SortedDict)

        # Start by opening the core file
        self.__s3 = boto3.client('s3')
        self.__s3_path = s3path.S3Path.from_uri(filename)
        self.__filename = filename
        self.__size = self.__s3.head_object(Bucket=self.__s3_path.bucket, Key=self.__s3_path.key)['ContentLength']

        size = min(5*1024*1024, self.__size)
        print(f'Loading header, size {humanize.naturalsize(size)}')
        self.__header = io.BytesIO(self.__s3.get_object(Bucket=self.__s3_path.bucket, Key=self.__s3_path.key, Range=f'bytes=0-{size-1}')['Body'].read())

        self.core = elftools.elf.elffile.ELFFile(self.__header)
        assert self.core['e_ident']['EI_OSABI'] in {'ELFOSABI_SYSV', 'ELFOSABI_LINUX'}, 'only Linux supported'
        assert self.core['e_machine'] == 'EM_X86_64', 'only x86-64 supported'
        assert self.core['e_type'] == 'ET_CORE', 'not a core file'

        # Parse coredump notes
        segs = self.core.iter_segments()
        note_segs = filter(lambda seg: isinstance(seg, elftools.elf.elffile.NoteSegment), segs)
        notes = [n for seg in note_segs for n in seg.iter_notes()]

        # files
        file_note = next((n['n_desc'] for n in notes if n['n_type'] == 'NT_FILE'))
        self.__mappings = [(k.decode(), v) for k, v in utils.sort_and_ensure_disjoint(utils.parse_file_note(file_note), lambda x: x[1])]
        self.__mappings_by_addr = sortedcontainers.SortedDict(((vma.start, i) for i, (k, vma) in enumerate(self.__mappings)))

        # threads
        self.threads = list(map(utils.Prstatus.load, filter(lambda n: n['n_type'] == 'NT_PRSTATUS', notes)))

        # process
        # FIXME: parse PRPSINFO
        self.auxv = utils.parse_auxv_note(next((n for n in notes if n['n_type'] == 'NT_AUXV')))

        # Initialize emulator instance
        self.emu = unicorn.Uc(unicorn.unicorn.uc.UC_ARCH_X86, unicorn.unicorn.uc.UC_MODE_64)

        # restore FS and GS from a random thread (userspace typically
        # stores TCB in FS, any TLS-related stuff will fail if not initialized)
        for reg in {unicorn.unicorn.x86_const.UC_X86_REG_FS_BASE, unicorn.unicorn.x86_const.UC_X86_REG_GS_BASE}:
            self.emu.reg_write(reg, self.threads[0].regs[reg])

        # save clean context
        self.emu_ctx = self.emu.context_save()

        # register hooks
        hooks = [
            (unicorn.unicorn.uc.UC_HOOK_MEM_INVALID, self.__hook_mem),
            (unicorn.unicorn.uc.UC_HOOK_INSN_INVALID, self.__hook_insn_invalid),
            (unicorn.unicorn.uc.UC_HOOK_INTR, self.__hook_intr),
            (unicorn.unicorn.uc.UC_HOOK_INSN, lambda: self.__hook_intr('syscall'), unicorn.unicorn.x86_const.UC_X86_INS_SYSCALL),
            (unicorn.unicorn.uc.UC_HOOK_INSN, lambda: self.__hook_intr('sysenter'), unicorn.unicorn.x86_const.UC_X86_INS_SYSENTER),
        ]
        for hook, cb, *args in hooks:
            self.emu.hook_add(hook, (lambda cb: lambda *args: cb(*args[1:-1]))(cb), None, 1, 0, *args)

        # setup stack tracer
        self.stack_tracer = None
        if trace_stack and tracer.is_stack_tracer_available():
            self.stack_tracer = tracer.StackTracer(256)
            self.stack_tracer.set_attached(True, self.emu)

        # Map everything into emulator
        if (pagesize := self.auxv[utils.AuxvField.PAGESZ.value]) != mmap.PAGESIZE:
            logger.warn(f'coredump page size ({pagesize}) differs from host ({mmap.PAGESIZE})')

        assert self.emu.query(unicorn.unicorn.uc.UC_QUERY_PAGE_SIZE) <= mmap.PAGESIZE
        # (first core segments, then RO mappings over any uncovered areas)
        self.__load_core_segments()
        self.__load_mappings(**mapping_load_kwargs)

        # Load symbols from binary and loaded objects
        if load_symbols:
            self.__load_symbols()

        # Post-load fixups
        logger.info('Performing fixups...')
        if patch_glibc:
            self.__patch_glibc()
        if patch_lock:
            self.__patch_pthreads()

        # Map our stack area
        self.stack_addr, self.stack_size = stack_addr, stack_size
        self.stack_base = stack_addr - stack_size
        self.emu.mem_map(self.stack_base, self.stack_size, unicorn.unicorn.uc.UC_PROT_ALL)


    def load_address_if_needed(self, address):
        try:
            mapping_address = next(self.__loaded_mappings.irange(maximum=address, reverse=True))
            assert mapping_address + self.__loaded_mappings[mapping_address] > address
            return False

        except:
            try:
                to_map_address = next(self.__mappings_to_load.irange(maximum=address, reverse=True))
            except:
                return False

            module, size, prot, offset = self.__mappings_to_load[to_map_address]
            if to_map_address + size > address:
                self.__mappings_to_load.pop(to_map_address)

                if size <= 1024*1024:
                    start_address = to_map_address

                else:
                    start_address = utils.mmapalign(address)
                    self.__mappings_to_load[to_map_address] = (module, start_address-to_map_address, prot, offset)
                    if to_map_address + size - start_address >= 1024*1024:
                        self.__mappings_to_load[start_address+1024*1024] = (module, to_map_address+size-start_address-1024*1024, prot, offset+start_address+1024*1024-to_map_address)
                        size = 1024*1024
                    else:
                        size = size+to_map_address-start_address

                    offset = offset+start_address-to_map_address

                print(f'Loading {hex(start_address)}..{hex(start_address+size)} from {module}, size {humanize.naturalsize(size)}')

                s3_path = s3path.S3Path.from_uri(module)
                data = self.__s3.get_object(Bucket=s3_path.bucket, Key=s3_path.key, Range=f'bytes={offset}-{offset+size-1}')['Body'].read()

                self.emu.mem_map(start_address, size, prot)
                self.emu.mem_write(start_address, data)
                self.__loaded_mappings[start_address] = size
                return True

            else:
                return False


    # MEMORY MAPPING

    def __load_core_segments(self):
        '''Read LOAD segments from core and map them'''

        load_segs = utils.parse_load_segments(self.core)
        logger.info(f'Would map {len(load_segs)} LOAD segments, total size {sum((vma.size for vma, _ in load_segs))}...')

        for vma, flags in load_segs:
            prot = utils.elf_flags_to_uc_prot(flags)
            if vma.offset >= utils.mmapsize(self.__size):
                print(f'Segment {hex(vma.start)}-{hex(vma.start+vma.size)} is outside of file boundaries, looks like the core dump is truncated.')
            elif vma.offset_end > utils.mmapsize(self.__size):
                print(f'Segment {hex(vma.start)}-{hex(vma.start+vma.size)} intersects file boundaries, looks like the core dump is truncated.')
                self.__mappings_to_load[vma.start] = (self.__filename, self.__size-vma.offset, prot, vma.offset)
            else:
                self.__mappings_to_load[vma.start] = (self.__filename, vma.size, prot, vma.offset)


    def __load_mappings(self,
        whitelist: list[str]=[],
        blacklist: list[str]=['/dev/', '/proc/', '/sys/'],
        skip_invalid: bool=True, skip_special: bool=True,
        filename_map: Callable[[bytes], Optional[bytes]] = lambda x: x,
    ):
        '''Read VMAs from core and map the associated files from disk

        Parameters to filter which files to map:
        - skip_special: Skip files whose mapped filename (see below) is found
        on disk, but is not a regular file (devices, directories, etc.) (default is True)
        - skip_invalid: Skip files we can't access, such as deleted
        files and anonymous mappings (default is True)
        - blacklist: List of prefixes to never map (default: /dev/, /proc/, /sys/)
        - whitelist: List of prefixes to always map (default empty, has most priority)

        After filtering as instructed above, a `filename_map` can optionally be provided
        to transform mapped filenames. The function will be called with the original
        filename and must return the filename to access on disk, or None to skip the file.
        '''

        # remove mappings that overlap with already loaded regions
        regions = utils.sort_and_ensure_disjoint(((s, e+1) for s, e, _ in self.emu.mem_regions()))
        mappings = []
        for fname, (start, end, offset) in self.__mappings:
            while True:
                regstart, regend = regions[0] if regions else (end, end)
                if regend > start:
                    if start < regstart:
                        mappings.append((fname, utils.VMA(start, min(end, regstart), offset)))
                    if end <= regend:
                        break
                    start, offset = regend, offset + (regend - start)
                regions.pop(0)

        # collect simplified mappings for each file
        # (note that we keep all files, even if they no longer have VMAs)
        file_mappings: dict[str, list[utils.VMA]] = {fn: [] for fn, _ in self.__mappings}
        for fname, vma in mappings:
            file_mappings[fname].append(vma)

        file_mappings = {k: utils.VMA.simplify(v) for k, v in file_mappings.items()}

        # filter / transform files according to settings
        is_invalid = lambda fn: fn.startswith('anon_inode:') or fn.startswith('/memfd:') or fn.endswith(' (deleted)')
        is_special = lambda fn: (fn := filename_map(fn)) != None and os.path.exists(fn) and not os.path.isfile(fn)
        file_skipped = lambda fn: (skip_invalid and is_invalid(fn)) or (skip_special and is_special(fn)) or any(fn.startswith(pref) for pref in blacklist)
        file_filter = lambda fn: any(fn.startswith(pref) for pref in whitelist) or not file_skipped(fn)
        mapped_filenames = {fn: fn2 for fn in file_mappings if file_filter(fn) and (fn2 := filename_map(fn)) != None}

        skipped_with_vmas = [fn for fn, vmas in file_mappings.items() if fn not in mapped_filenames and vmas]
        if skipped_with_vmas:
            logger.info('Skipped files with VMAs:\n{}'.format('\n'.join((f' - {fn}' for fn in skipped_with_vmas))))
        file_mappings = {fn: v for fn, v in file_mappings.items() if fn in mapped_filenames}
        total_mappings = sum(len(v) for v in file_mappings.values())
        logger.info(f'Mapping {len(file_mappings)} files, {total_mappings} VMAs...')

        for fn, vmas in file_mappings.items():
            try:
                s3_path = s3path.S3Path.from_uri(mapped_filenames[fn])
                size = self.__s3.head_object(Bucket=s3_path.bucket, Key=s3_path.key)['ContentLength']
                self.__mapping_paths[fn] = mapped_filenames[fn]

                print(f'Would load {fn} from {mapped_filenames[fn]}, size {humanize.naturalsize(size)}')

                map_tasks = []

                for vma in vmas:
                    # we know it's not writeable (otherwise it would be in the coredump)
                    # so make it RX (FIXME look into sections?)
                    prot = unicorn.unicorn.uc.UC_PROT_READ | unicorn.unicorn.uc.UC_PROT_EXEC
                    assert vma.offset_end <= utils.mmapsize(size), f'invalid mapping on {fn}: {vma}'
                    map_tasks.append((vma.start, vma.size, prot, vma.offset))

                for start, size, prot, offset in map_tasks:
                    self.__mappings_to_load[start] = (mapped_filenames[fn], size, prot, offset)

            except:
                print(f'Skipping {fn}')
                continue


    def mem(self, start: Union[int, str]=0, size: Optional[int]=None, offset: int=0, buffer_size: int=io.DEFAULT_BUFFER_SIZE):
        '''Returns a binary I/O stream over (a region of) memory

        First two arguments restrict the accessible memory range,
        with `start` being exposed at offset 0.

        The `offset` parameter calls seek() on the returned stream.

        If `start` is a string, it will be resolved as an `OBJECT` symbol
        and `size` will default to the symbol size (if defined).
        If you need more control, call `get_symbol()` directly.
        '''
        if isinstance(start, str):
            if not (syms := self.get_symbols(start, stype=utils.Symbol.Type.OBJECT)):
                raise ValueError(f'no OBJECT symbol found for {start}')
            start, size = syms[0].addr, syms[0].size

        stream = utils.UnicornIO(self, start, size, offset)
        # FIXME: BufferedRandom fails with some obscure exception from native code...
        #stream = BufferedRandom(stream, buffer_size) if buffer_size > 0 else stream
        # inject convenience methods (FIXME: more elegant way?)
        stream.read_struct = lambda *args, **kwargs: read_struct(stream, *args, **kwargs)
        stream.write_struct = lambda *args, **kwargs: write_struct(stream, *args, **kwargs)
        stream.read_bstr = lambda *args, **kwargs: read_bstr(stream, *args, **kwargs)
        stream.read_str = lambda *args, **kwargs: read_str(stream, *args, **kwargs)
        stream.write_str = lambda *args, **kwargs: write_str(stream, *args, **kwargs)

        return stream


    @contextlib.contextmanager
    def reserve(self, size: int, align=8):
        '''Returns a context manager object that allocates memory on our stack area.

        The `align` parameter (default: 8) skips memory before the allocation so
        that its *start* ends up aligned to it.

        Note that these allocations take space from the stack area, i.e.
        functions will have less available space to run. For big allocations
        you may even run out of space in the stack yourself; the area can be
        enlarged through the `stack_size` parameter in the constructor.

        If you don't use the `with` statement, make sure that reservations
        are released in REVERSE ORDER, anything else will raise.

        The address of the allocated area can be get through the `start` attribute.
        '''
        if not size:
            return self.mem(self.stack_addr, 0)
        old_stack_addr = self.stack_addr
        new_stack_addr = self.stack_addr - size
        new_stack_addr -= new_stack_addr % align
        try:
            self.stack_addr = new_stack_addr
            assert self.stack_base <= new_stack_addr
            yield self.mem(self.stack_addr, size)
        finally:
            ret_address = self.stack_addr
            self.stack_addr = max(old_stack_addr, self.stack_addr)
            if ret_address != new_stack_addr:
                raise Exception('stack reservations MUST be released in reverse order')


    def find_mapping(self, addr: int) -> utils.FileMapping:
        try:
            key = next(self.__mappings_by_addr.irange(maximum=addr, reverse=True))
            nested_key = self.__mappings_by_addr[key]
            vma = self.__mappings[nested_key][1]
            if addr < vma.end:
                return vma

        except StopIteration:
            pass

        raise ValueError(f'address {addr:#x} not mapped')


    # SYMBOLS

    def __load_symbols(self):
        '''Find info about loaded objects and load their symbols'''

        for filename in {k for k, _ in self.__mappings}:
            self.__load_symbols_for_mapped_file(filename)

        return
        # FIXME rest of it does not work

        auxv = self.auxv
        elf = self.core

        # First we need to parse the binary ELF. This is essential;
        # without this we can't use the "debugger interface" to find
        # the rest of the objects, so no symbols at all.

        # Use auxv to locate program header of main executable, parse them
        # (we are using the raw structs here and not ELFFile, because this is
        # not the ELF file as seen on disk but its loaded version)
        phdr_base = auxv[utils.AuxvField.PHDR.value]
        phdr_num = auxv[utils.AuxvField.PHNUM.value]
        phdr = utils.parse_program_header(elf.structs, self.mem(phdr_base)#FIXME???
, phdr_num)
        # FIXME: use VMAs to locate base of executable, we'll need it to translate vaddrs, how tf does ld do it??
        _, vma = self.find_mapping(phdr_base)
        main_base = vma.start - vma.offset

        # Find r_debug (debugger interface entry point) through the DT_DEBUG tag
        try:
            dyn_seg = next((seg['p_vaddr'] for seg in phdr if seg['p_type'] == 'PT_DYNAMIC'))
            dt_debug = next(utils.parse_dynamic_section(elf.structs, self.mem(main_base + dyn_seg), 'DT_DEBUG'))['d_ptr']

        except StopIteration:
            logger.warn('cannot find DT_DEBUG tag in binary. either it is a '
                'statically linked executable or it does not conform to the debugger '
                'interface, in which case info about shared libraries will be lost')
            # FIXME: for statically-linked executables, verify that they really don't
            # have a PT_DYNAMIC segment and maybe fall back to loading symbol table
            # by looking through the sections instead of the dynamic segment
            return

        if not dt_debug:
            logger.warn('DT_DEBUG tag not initialized. either linker does not follow debugger interface or who knows')
            return

        # Parse debug interface data
        r_version, r_map, r_brk, r_state, r_ldbase = self.mem(dt_debug).read_struct('<i4xQQi4xQ')
        if r_version != 1:
            logger.warn(f'unexpected/unsupported debugger interface version {r_version}. will try to parse anyway...')
        if r_state != utils.RtState.CONSISTENT.value:
            logger.warn('coredump was taken when loaded objects list was in an unconsistent state. will try to parse anyway...')
        self.loaded_objects = list(utils.RtLoadedObject.iterate(self.mem(), r_map))

        # Actually load the symbols of each object
        logger.info(f'Loading symbols for {len(self.loaded_objects)} objects...')
        self.symbols = collections.defaultdict(lambda: set())
        by_addr = collections.defaultdict(lambda: collections.defaultdict(lambda: set()))
        for obj in sorted(self.loaded_objects, key=lambda x: x.addr):
            self.__load_symbols_for(obj, by_addr)
        self.symbols = dict(self.symbols)
        self.symbols_by_type_by_addr = {stype: list(zip(*sorted(addrs.items()))) for stype, addrs in by_addr.items()}


    def __load_symbols_for_mapped_file(self, filename):
        try:
            s3_path = s3path.S3Path.from_uri(self.__mapping_paths[filename])
            size = self.__s3.head_object(Bucket=s3_path.bucket, Key=s3_path.key)['ContentLength']

            # TODO load from `.gnu_debuglink`
            # TODO load without `pyelftools`
            # TODO don't double load

            print(f'Loading symbols from {self.__mapping_paths[filename]}, size {humanize.naturalsize(size)}')
            header = io.BytesIO(self.__s3.get_object(Bucket=s3_path.bucket, Key=s3_path.key, Range=f'bytes=0-{size-1}')['Body'].read())

            # Try to parse its symbols
            elf = elftools.elf.elffile.ELFFile(header)
            for table in elf.iter_sections():
                if not isinstance(table, elftools.elf.sections.SymbolTableSection):
                    continue
                for sym in table.iter_symbols():
                    sym = utils.Symbol.load(None, sym) # FIXME relocs; check self.__mappings and elf tables; also remove failsafe in `Symbol.addr`
                    if sym.defined:
                        self.__symbols[sym.name].add(sym)
                        self.__symbols_by_type_by_addr[sym.type].setdefault(sym.addr, set()).add(sym)

        except Exception:
            logger.warn(f'failed to parse symbols from {filename}, skipping')
            return


    def __load_symbols_for(self, obj: utils.RtLoadedObject, by_addr: dict[utils.Symbol.Type, dict[int, list[utils.Symbol]]]):
        # Find mapped disk file, open it
        if obj.addr != self.auxv.get(utils.AuxvField.SYSINFO_EHDR.value):
            fname, _ = self.find_mapping(obj.ld)

            print(f'Loading symbols for {fname}')

            if fname not in self.mappings_mm:
                logger.warn(f'mappings for {fname} failed or were skipped, its symbols will not be loaded')
                return

            ofname, mm = self.mappings_mm[fname]
            stream = io.BytesIO(mm)

        else:
            # VDSO is special bc kernel doesn't insert a mapping for it,
            # but its pages are always dumped so we can read from memory
            ofname, stream = b'[vdso]', self.mem(obj.addr)

        # Try to parse its symbols
        try:
            elf = elftools.elf.elffile.ELFFile(stream)
            for table in elf.iter_sections():
                if not isinstance(table, elftools.elf.sections.SymbolTableSection):
                    continue
                for sym in table.iter_symbols():
                    sym = utils.Symbol.load(obj, sym)
                    if sym.defined:
                        self.__symbols[sym.name].add(sym)
                        self.__symbols_by_type_by_addr[sym.type].setdefault(sym.addr, set()).add(sym)

            return obj

        except Exception:
            logger.warn(f'failed to parse symbols from {ofname}, skipping')
            return


    def get_symbols(self, name: str,
        stype: Optional[utils.Symbol.Type]=utils.Symbol.Type.FUNC,
        obj: Optional[utils.RtLoadedObject]=None,
        exposed_only: bool=False,
    ) -> list[utils.Symbol]:

        # FIXME: prioritize global, then weak, then local. also maybe visibility
        matches = lambda sym: (obj is None or obj == sym.obj) and (stype is None or stype == sym.type) and (not exposed_only or sym.is_exposed)
        return [sym for sym in self.__symbols[name] if matches(sym)]

    def get_symbol(self, name: str, *args, **kwargs) -> int:
        """Resolve the address of a symbol (fails if none found)."""

        if not (syms := self.get_symbols(name, *args, **kwargs)):
            raise ValueError(f'no matching symbol found for {repr(name)}')

        return syms[0].addr

    def find_symbol(self, addr: int, stype: utils.Symbol.Type=utils.Symbol.Type.FUNC, look_before: int=5) -> utils.Symbol:
        """Try to find a symbol that addr is in."""

        by_addr = self.__symbols_by_type_by_addr.get(stype, sortedcontainers.SortedDict())
        symbols_it = by_addr.irange(maximum=addr, reverse=True)
        try:
            for _ in range(look_before):
                symbols = by_addr[next(symbols_it)]
                for symbol in symbols:
                    if not symbol or addr-symbol.addr < symbol.size:
                        return symbol

        except StopIteration:
            pass

        raise ValueError(f'no {stype.name} symbol found at {addr:#x}')


    # PATCHES

    def __patch_glibc(self):
        '''Patches glibc functions whose name ends in '_avx2' with a JMP to
        their generic siblings, to prevent unsupported instructions.

        IFUNCs are defined here:
        https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/i386/i686/multiarch/ifunc-impl-list.c
        https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/x86_64/multiarch/ifunc-impl-list.c
        but instead of a hardcoded list, we use a regexp to find them among symbols.
        '''
        # first we have to locate libc among loaded objects
        test_sym = getattr(self, 'symbols', {}).get('strchr', [])
        objs = {sym.obj for sym in test_sym if sym.is_callable and sym.is_exposed}
        if len(objs) != 1:
            logger.warn(f'cannot locate libc, found {len(objs)} candidates. skipping glibc patches...')
            return

        libc_obj = next(iter(objs))

        # collect libc function addresses
        collect_addresses = lambda syms: {sym.addr for sym in syms if sym.obj == libc_obj and sym.is_function}
        libc_syms = {name: addrs for name, syms in self.__symbols.items() if (addrs := collect_addresses(syms))}

        # find candidates to patch
        hunks: list[tuple[int, int]] = []
        for name, addrs in libc_syms.items():
            if not (m := re.fullmatch(r'(.+)_(avx|avx2|avx512)(_.+)?', name)):
                continue
            replacements = ['_sse2', '_sse2_unaligned']
            replacements = [fn for n in replacements if (fn := m.group(1) + n) in libc_syms]
            if not replacements:
                logger.warn(f'cannot find replacement for {name}, not patching')
                continue
            target = next(iter(libc_syms[replacements[0]])) # FIXME: what if multiple?
            hunks += [(addr, target) for addr in addrs]

        # the dynamic linker (also provided by glibc) also has one function
        # responsible for saving the registers. since the available registers
        # depend on implemented SIMD extensions, we should patch that as well.
        # locate dynamic linker through AUXV, then its symbols:
        try:
            ld_obj = next((obj for obj in self.loaded_objects if obj.addr == self.auxv[utils.AuxvField.BASE.value]))

        except StopIteration:
            logger.warn(f'cannot find ld object. skipping ld patches...')

        else:
            ld_hunks = [
                ('_dl_runtime_resolve_xsavec', '_dl_runtime_resolve_fxsave'),
                ('_dl_runtime_resolve_xsave',  '_dl_runtime_resolve_fxsave'),
                ('_dl_runtime_profile_avx512', '_dl_runtime_profile_sse'),
                ('_dl_runtime_profile_avx',    '_dl_runtime_profile_sse'),
            ]
            for hunk in ld_hunks:
                try:
                    hunks.append(tuple((self.get_symbol(n, obj=ld_obj) for n in hunk)))
                except ValueError:
                    logger.warn(f'failed to patch {hunk[0]}, skiping patch...')

        # patch!
        for src, target in hunks:
            # Far jmp QWORD PTR [rip] (jumps to address following instruction).
            asm = b'\xff\x25\x00\x00\x00\x00'
            self.mem(src).write(asm + struct.pack('<Q', target))


    def __patch_pthreads(self):
        """We can't emulate multithreading, but we can patch mutex functions
        so that all mutexes appear unlocked and *maybe* it will work"""

        if not hasattr(self, 'symbols'):
            return

        syms = [
            'mutex_lock', 'mutex_trylock', 'mutex_timedlock', 'mutex_unlock',
            'rwlock_wrlock', 'rwlock_trywrlock', 'rwlock_timedwrlock',
            'rwlock_rdlock', 'rwlock_tryrdlock', 'rwlock_timedrdlock',
            'rwlock_unlock',
            'cond_signal', 'cond_broadcast',
        ]
        for name in syms:
            candidates = self.get_symbols('pthread_' + name)
            if not candidates:
                logger.warn(f'failed to find {name}, skipping patch...')
            for sym in candidates:
                self.mem(sym.addr).write(b'\x48\x31\xC0\xC3') # xor rax, rax; ret


    # EMULATION

    def format_code_addr(self, addr: int):
        """Format a code address nicely by showing it as symbol + offset
        and shared object + offset, if possible."""

        try:
            # Try to find symbol first.
            sym = self.find_symbol(addr)

        except ValueError:
            pass

        else:
            pos = addr - sym.addr
            pos = f'[{pos:#x}]' if pos else ''
            fname = sym.obj and sym.obj.name.decode() or 'fixme' # FIXME
            offset = addr - (sym.obj and sym.obj.addr or 0) # FIXME
            return f'{addr:#x} {sym.name}{pos} ({fname}[{offset:#x}])'

        try:
            # Try mapping next.
            fname, vma = self.find_mapping(addr)

        except ValueError:
            pass

        else:
            offset = vma.offset + (addr - vma.start)
            return f'{addr:#x} ({fname}[{offset:#x}])'

        return f'{addr:#x}'


    def format_exec_ctx(self):
        '''Collect info about the current execution context and return it
        as formatted text. Used for errors.'''
        stack_tracer = self.stack_tracer
        trace = ([] if stack_tracer is None else list(stack_tracer.entries)) + [(
            self.emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RSP),
            self.emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RIP),
        )]
        format_call = lambda sp, ip: f'  at {self.format_code_addr(ip)}, sp={sp:#x}'
        return '\n'.join((format_call(*c) for c in trace))

    def __emulation_error(self, msg: str):
        return EmulationError(f'{msg}\n{self.format_exec_ctx()}')

    def __hook_mem(self, htype: int, addr: int, size: int, value: int):
        access_type, cause = utils.UC_MEM_TYPES[htype]
        faddr = self.format_code_addr(addr)
        text = f'{access_type.lower()} of {size} bytes at {faddr}'

        if cause == 'PROT':
            raise self.__emulation_error(f'{text}, which is protected')

        if cause == 'UNMAPPED':
            if self.load_address_if_needed(addr):
                return True

            rip = self.emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RIP)
            code = self.emu.mem_read(rip, 64)
            iced = iced_x86.Decoder(64, code, ip=rip)
            for instr in iced:
                bytes_str = code[instr.ip-rip:instr.ip-rip+instr.len].hex().upper()
                print(f'{instr.ip:016X} {bytes_str:20} {instr:n}')

            try:
                fname, vma = self.find_mapping(addr)

            except ValueError:
                raise self.__emulation_error(f'{text}, which is invalid') from None

            assert fname not in self.mappings_mm

            raise self.__emulation_error(f'{text}, which belongs to a file that was skipped or failed to load')


    def __hook_insn_invalid(self):
        raise self.__emulation_error('invalid instruction')

    def __hook_intr(self, intno: Union[int, Literal['syscall', 'sysenter']]):
        if intno != 'syscall': # FIXME: x86-32
            raise self.__emulation_error(f'invalid interrupt {intno}')

        nr = self.emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RAX)
        try:
            nr = syscall.SyscallX64(nr)
        except ValueError as e:
            raise self.__emulation_error(f'invalid syscall {nr}') from None

        if not (handler := getattr(self, '_syscall_' + nr.name, None)):
            raise self.__emulation_error(f'"{nr.name}" syscall')
        nparams = len(inspect.signature(handler).parameters)
        result = handler(*(self.emu.reg_read(r) for r in utils.SYSV_AMD_ARG_REGS[:nparams]))
        if isinstance(result, syscall.Errno):
            result = -result.value
        else:
            assert isinstance(result, int) and result >= 0
        self.emu.reg_write(unicorn.unicorn.x86_const.UC_X86_REG_RAX, result)

    # FIXME: implement more archs and calling conventions
    def call(self, func: Union[int, str], *args: int, instruction_limit: int = 10000000, time_limit: int = 0) -> int:
        # FIXME C++ names mangling
        '''Emulate a function call.

        The first parameter is the address of the function to call. If it
        is a string, it will be resolved through `get_symbol()` first. The
        arguments to the function follow, which must be integers.

        If successful, returns the call result as an integer. Otherwise
        `EmulationError` should be raised; other errors possibly indicate a bug.

        Instruction or time limits can be placed on the call; the default is
        only a 10 million instruction limit. This can be changed through the
        `instruction_limit` and `time_limit` parameters. `0` indicate no limit,
        and `time_limit` is in microseconds.
        '''
        emu = self.emu
        func = self.get_symbol(func) if isinstance(func, str) else func
        ret_addr = self.stack_base
        emu.context_restore(self.emu_ctx)
        if self.stack_tracer:
            self.stack_tracer.clear()

        # set up arguments
        assert all(isinstance(x, int) for x in args), 'float and other non-integer arguments not implemented yet'
        assert all(-(1 << 63) <= x < (1 << 64) for x in args), 'arguments must be in u64 or s64 range (128 ints not implemented yet)'
        args = [x & ~((~0) << 64) for x in args]
        arg_regs = utils.SYSV_AMD_ARG_REGS
        for p, reg in zip(args, arg_regs): emu.reg_write(reg, p)
        stack_args = args[len(arg_regs):]

        # finish stack (pad if necessary so that arguments end up on a multiple of 16)
        # (FIXME take advantage if current stack_addr % 16 < 8)
        if len(stack_args) % 1: stack_args.append(0)
        stack_args.insert(0, ret_addr)
        stack_args = struct.pack(f'<{len(stack_args)}Q', *stack_args)

        # emulate!
        with self.reserve(len(stack_args), align=16) as mem:
            mem.write(stack_args)
            emu.reg_write(unicorn.unicorn.x86_const.UC_X86_REG_RSP, mem.start)
            emu.emu_start(func, ret_addr, time_limit, instruction_limit)
            if emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RIP) != ret_addr:
                raise self.__emulation_error(f'Instruction/time limit exhausted')
            assert emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RSP) == mem.start + 8
            return emu.reg_read(unicorn.unicorn.x86_const.UC_X86_REG_RAX)

    # SYSCALLS

    def _syscall_futex(self, uaddr: int, cmd_: int, val: int, timeout: int, uaddr2: int, val3: int):
        try:
            cmd = syscall.FutexCmd.load(cmd_)
        except ValueError:
            raise self.__emulation_error(f'invalid futex syscall {cmd_}') from None

        if cmd.nr in {syscall.FutexCmd.Nr.WAKE, syscall.FutexCmd.Nr.WAKE_BITSET, syscall.FutexCmd.Nr.REQUEUE, syscall.FutexCmd.Nr.CMP_REQUEUE, syscall.FutexCmd.Nr.CMP_REQUEUE_PI, syscall.FutexCmd.Nr.WAKE_OP}:
            # wake operations are easy to implement: there are no other threads / processes, so just return 0
            # for some operations, we have to do prior checks / operations before the wake
            if cmd.nr in {syscall.FutexCmd.Nr.CMP_REQUEUE, syscall.FutexCmd.Nr.CMP_REQUEUE_PI}:
                if val3 >> 32:
                    raise self.__emulation_error('invalid futex CMP_REQUEUE syscall: val3 not u32')
                if self.mem(uaddr).read_struct('<I')[0] != val3:
                    return syscall.Errno.EAGAIN
            if cmd.nr == syscall.FutexCmd.Nr.WAKE_OP:
                try:
                    op = syscall.FutexOp.load(val3)
                except ValueError:
                    raise self.__emulation_error('invalid futex WAKE_OP syscall: val3 holds invalid op')
                oldval = self.mem(uaddr2).read_struct('<I')[0]
                self.mem(uaddr2).write_struct('<I', op.new_value(oldval))
            return 0

        # FIXME: if patch_lock is True, we could also patch out all waits and PI operations too
        raise self.__emulation_error(f'futex syscall {cmd}')
