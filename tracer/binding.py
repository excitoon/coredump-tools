from typing import Optional
import ctypes
import os

import unicorn


# load shared library

tracer_file = os.path.join(os.path.dirname(__file__), 'tracer.so')

try:
    tracer_file = ctypes.CDLL(tracer_file)
except OSError as e:
    raise ImportError('could not load tracer library') from e

ctypes.cast(tracer_file.uc_reg_read, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(unicorn.unicorn._uc.uc_reg_read, ctypes.c_void_p)
hook_block = ctypes.cast(tracer_file.hook_block, unicorn.unicorn.UC_HOOK_CODE_CB)


class Entry(ctypes.Structure):
    _fields_ = [("sp", ctypes.c_uint64),
                ("ip", ctypes.c_uint64)]

class Data(ctypes.Structure):
    _fields_ = [("capacity", ctypes.c_size_t),
                ("size", ctypes.c_size_t),
                ("entries", ctypes.POINTER(Entry))]

class StackTracer(object):
    data: Data
    handle: Optional[unicorn.unicorn.uc_hook_h]

    def __init__(self, capacity: int):
        self._entries = (Entry * capacity)()
        entries = ctypes.cast(ctypes.byref(self._entries), ctypes.POINTER(Entry))
        self.data = Data(capacity, 0, entries)
        self.handle = None

    def clear(self):
        self.data.size = 0

    @property
    def entries(self) -> list[tuple[int, int]]:
        return [ (self._entries[n].sp, self._entries[n].ip) for n in range(self.data.size) ]

    def set_attached(self, attached: bool, emu: unicorn.unicorn.Uc):
        '''Attach or detach the hooks if needed. Uc instance is passed
        here to avoid creating reference cycles.'''
        if not (self.handle is None) == attached: return
        if attached:
            handle = unicorn.unicorn.uc_hook_h()
            err = unicorn.unicorn._uc.uc_hook_add(
                emu._uch, ctypes.byref(handle), unicorn.unicorn.uc.UC_HOOK_BLOCK, hook_block,
                ctypes.cast(ctypes.byref(self.data), ctypes.c_void_p),
                ctypes.c_uint64(1), ctypes.c_uint64(0)
            )
            if err != unicorn.unicorn.uc.UC_ERR_OK: raise unicorn.unicorn.UcError(err)
            self.handle = handle.value
        else:
            emu.hook_del(self.handle)
            self.handle = None
