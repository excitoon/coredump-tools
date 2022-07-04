# `coredump-tools`

Coredump code interpreter.

Originally based on [mildsunrise/emucore](https://github.com/mildsunrise/emucore).

```
$ python3.10 test.py 
Loading header, size 5.2 MB
Segment 0x7f377a400000-0x7f3caa000000 intersects file boundaries, looks like the core dump is truncated.
...
Segment 0x7fff869d8000-0x7fff869da000 is outside of file boundaries, looks like the core dump is truncated.
Segment 0xffffffffff600000-0xffffffffff601000 is outside of file boundaries, looks like the core dump is truncated.
Would load /usr/bin/clickhouse from s3://chebotarev-core-dump/clickhouse, size 326.3 MB
Would load /usr/lib64/libc-2.17.so from s3://chebotarev-core-dump/libc-2.17.so, size 2.2 MB
Skipping /usr/lib64/libc-2.17.so
Would load /usr/lib64/libnss_files-2.17.so from s3://chebotarev-core-dump/libnss_files-2.17.so, size 61.6 kB
Skipping /usr/lib64/libnss_files-2.17.so
Would load /usr/lib/locale/locale-archive from s3://chebotarev-core-dump/locale-archive, size 106.2 MB
Would load /usr/lib64/libm-2.17.so from s3://chebotarev-core-dump/libm-2.17.so, size 1.1 MB
Skipping /usr/lib64/libm-2.17.so
Would load /usr/lib64/libdl-2.17.so from s3://chebotarev-core-dump/libdl-2.17.so, size 19.2 kB
Skipping /usr/lib64/libdl-2.17.so
Would load /usr/lib64/libpthread-2.17.so from s3://chebotarev-core-dump/libpthread-2.17.so, size 142.1 kB
Skipping /usr/lib64/libpthread-2.17.so
Would load /usr/lib64/librt-2.17.so from s3://chebotarev-core-dump/librt-2.17.so, size 43.7 kB
Skipping /usr/lib64/librt-2.17.so
Would load /usr/lib64/ld-2.17.so from s3://chebotarev-core-dump/ld-2.17.so, size 163.3 kB
Loading 0x200000..0x300000 from s3://chebotarev-core-dump/clickhouse, size 1.0 MB
Loading 0x13b08000..0x13c08000 from s3://chebotarev-core-dump/coredump, size 1.0 MB
cannot find DT_DEBUG tag in binary. either it is a statically linked executable or it does not conform to the debugger interface, in which case info about shared libraries will be lost
cannot locate libc, found 0 candidates. skipping glibc patches...
Loading 0xf907000..0xfa07000 from s3://chebotarev-core-dump/clickhouse, size 1.0 MB
Loading 0x7f352d3c9000..0x7f352d4c9000 from s3://chebotarev-core-dump/coredump, size 1.0 MB
000000000F9070B5 498B6D00             mov rbp,[r13]
000000000F9070B9 4D8B7508             mov r14,[r13+8]
000000000F9070BD 4C39F5               cmp rbp,r14
000000000F9070C0 0F845C020000         je near 000000000F907322h
000000000F9070C6 4C8DAC2488000000     lea r13,[rsp+88h]
000000000F9070CE 4C8DBC2489000000     lea r15,[rsp+89h]
000000000F9070D6 4C8D642438           lea r12,[rsp+38h]
000000000F9070DB EB10                 jmp short 000000000F9070EDh
000000000F9070DD 0F1F00               nop dword [rax]
000000000F9070E0 4883C508             add rbp,8
000000000F9070E4 4939EE               cmp r14,rbp
000000000F9070E7 0F8429020000         je near 000000000F907316h
000000000F9070ED 0F57C0               xorps xmm0,xmm0
000000000F9070F0 410F114500           movups [r13],xmm0
Traceback (most recent call last):
  File "/home/vladimir/coredump-tools/test.py", line 17, in <module>
    emu.call(
  File "/home/vladimir/coredump-tools/emucore.py", line 851, in call
    emu.emu_start(func, ret_addr, time_limit, instruction_limit)
  File "/home/vladimir/.local/lib/python3.10/site-packages/unicorn/unicorn.py", line 344, in emu_start
    raise self._hook_exception
  File "/home/vladimir/.local/lib/python3.10/site-packages/unicorn/unicorn.py", line 212, in wrapper
    return func(self, *args, **kwargs)
  File "/home/vladimir/.local/lib/python3.10/site-packages/unicorn/unicorn.py", line 513, in _hook_mem_invalid_cb
    return cb(self, access, address, size, value, data)
  File "/home/vladimir/coredump-tools/emucore.py", line 230, in <lambda>
    self.emu.hook_add(hook, (lambda cb: lambda *args: cb(*args[1:-1]))(cb), None, 1, 0, *args)
  File "/home/vladimir/coredump-tools/emucore.py", line 775, in __hook_mem
    raise self.__emulation_error(f'{text}, which is invalid') from None
emucore.EmulationError: read of 8 bytes at 0x7f3ff388b640, which is invalid
  at 0xf9070c6 (/usr/bin/clickhouse[0xf7060c6]), sp=0x7f0fffffffffffe0
  at 0xf9070b5 (/usr/bin/clickhouse[0xf7060b5]), sp=0x7f0ffffffffffee8
```

## EmuCore

Module that emulates function calls on a coredump.

Features:
 - Simple API
 - Collects symbols
 - Automatically loads mapped files
 - Supports inspecting on different machine
 - Independent of host*
 - Debug info isn't required

(*) Page size should be the same.

### Examples

##### Realistic example: `pango_font_describe`

We want to get font descriptions from a gnome-shell corefile:

```python
from emucore import EmuCore

# opens core file, opens referenced files,
# initializes emulator (takes a while)
emu = EmuCore("/tmp/core.3007")

def get_font_description(font_addr: int) -> str:
    desc = emu.call('pango_font_describe', font_addr)
    dstr = emu.call('pango_font_description_to_string', desc)
    return emu.mem(dstr).read_str()

print(f'Font name: {get_font_description(0x555a4626b4e0)}')
```

If we were to use `get_font_description` a lot of times, we should also free the memory afterwards.

##### Parsing an int

To emulate a call to [`strtoul`](https://linux.die.net/man/3/strtoul), we have to reserve memory for input buffer and output pointer:

```python
def parse_int(text: bytes, base=10):
    with emu.reserve(len(text)+1, align=1) as buf, emu.reserve(8) as endptr:
        buf.write_str(text)
        result = emu.call('strtoul', buf.start, endptr.start, base)
        n_parsed = endptr.read_struct('<Q')[0] - buf.start
        return result, n_parsed

parse_int(b'1841 and stuff')  # prints (1841, 4)
```

Any coredump should work with this example, unless libc is linked statically.


### Limitations

 - Right now it's tied to:

    - Linux
    - x86-64 arch
    - System V AMD64 ABI

   It wouldn't take a lot of work to make it support multiple ABIs, but well, it's work.

   It's also tied lightly to glibc, for e.g. libc patches (see below) and the RTLD debugger interface (to list symbols).

 - As indicated above, anything beyond calculations (i.e. involving the kernel) isn't supported.

   This includes threads / synchronization, memory management, I/O, etc. Some simple/essential syscalls like `mmap`, `sbrk` or even `write` may be implemented in the future.

 - Multithreading can't be emulated, and calls might fail or stall waiting for a mutex that was locked at the time of crash.

   To remediate, there's an option to patch `pthread_mutex_*` and similar calls to bypass locks. It won't magically make whatever data is protected by them consistent, but you can try.  
   In the future, we could explore things like: emulating some threads a bit until a mutex is unlocked.

 - Another inherent limitation of emulating a core file is that the emulated code may use ISA extensions that are unsupported or buggy. At the time of this writing, this has been a problem with AVX2.

   In normal emulation, the code would check the supported features first and use code paths involving supported instructions. However when emulating a core file, that autodetection has probably already been done and if your software / hardware supports these instructions, it's probable you'll hit invalid instruction errors.

   This isn't a big issue since code doesn't usually use extensions, at least not the kind of code you'd want to emulate with EmuCore. The exceptions are libc and the dynamic linker: glibc has e.g. AVX implementations for string functions. This is worked around by looking through its symbols and patching `_avx2` functions with a JMP to their `_sse2` siblings. It's reliable enough, but won't work if your libc/ld is stripped.


### Wishlist

 - Float function arguments
 - More archs / OSes
 - Support for `sbrk` (so that `malloc` can always work)
 - C++ support
 - Make sure it works in Python 3.8 and lower
 - Support for calling IFUNCs directly
 - Test in static binaries, Golang binaries, and non-glibc
 - Loading external symbol files
 - Better errors / backtraces
 - Use debug info if available (for errors, interface)
