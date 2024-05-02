# Based off https://github.com/loriwitt/opack
# License: GPL 3.0
# Adapted from original code to just support dicts,strings,ints,bytes

# This is only here due to a single usage in tunnel_service.py :facepalm:

from construct import (
    Adapter,
    Struct,
    Int8ub,
    Switch,
    this,
    PascalString,
    Int16ub,
    Int32ub,
    Int64ub,
    Prefixed,
    Computed,
    GreedyString,
    GreedyBytes,
    LazyBound,
    Int8ul,
    Int32ul,
    Int64ul,
    Float32l,
    Float64l,
    Array,
)
from enum import Enum, auto
from typing import Mapping, Tuple

class TerminatorObject: pass

def _get_str_object_type(obj) -> int:
    obj_len = len(obj.encode())
    if obj_len <= 0x20:     return 0x40 + obj_len
    elif obj_len <= 0xFF:   return 0x61
    elif obj_len <= 0xFFFF: return 0x62
    elif obj_len < 2 ** 32: return 0x63
    return 0x64

def _get_int_object_type(obj) -> int:
    if obj < 0:
        raise Exception("Negative numbers not implemented")
    elif obj <= 0x27:            return obj + 8
    elif obj.bit_length() <= 8:  return 0x30
    elif obj.bit_length() <= 32: return 0x32
    elif obj.bit_length() <= 64: return 0x33
    raise IntegerOutOfBoundsError(f'{obj} is too big for uint64_t')

def _get_bytes_object_type(obj) -> int:
    obj_len = len(obj)
    if obj_len <= 0x20:     return 0x70 + obj_len
    elif obj_len <= 0xFF:   return 0x91
    elif obj_len <= 0xFFFF: return 0x92
    elif obj_len < 2 ** 32: return 0x93
    elif obj_len < 2 ** 64: return 0x94
    raise Exception(f'bytes are too large ({obj_len})')

def _get_dict_object_type(obj) -> Tuple[int, list]:
    obj_len = len(obj)
    obj = list(obj.items())
    if obj_len < 15:
        return 0xE0 + obj_len, obj
    else:
        obj.append((TerminatorObject(), TerminatorObject()))
        return 0xEF, obj

OBJ_TYPE_MAP = {
    TerminatorObject: lambda: 3,
    str: _get_str_object_type,
    bytes: _get_bytes_object_type,
    dict: _get_dict_object_type,
    int: _get_int_object_type,
}

StringOPack = Switch(
    this.type,
    {
        0x61: PascalString(Int8ub, 'utf8'),
        0x62: PascalString(Int16ub, 'utf8'),
        0x63: PascalString(Int32ub, 'utf8'),
        0x64: PascalString(Int64ub, 'utf8'),
    },
    default=Prefixed(Computed(this.type - 0x40), GreedyString('utf8')),
)

BytesOPack = Switch(
    this.type,
    {
        0x91: Prefixed(Int8ub, GreedyBytes),
        0x92: Prefixed(Int16ub, GreedyBytes),
        0x93: Prefixed(Int32ub, GreedyBytes),
        0x94: Prefixed(Int64ub, GreedyBytes)
    },
    default=Prefixed(Computed(this.type - 0x70), GreedyBytes),
)

IntOPack = Switch(
    this.type, {
        0x30: Int8ul,
        0x32: Int32ul,
        0x33: Int64ul,
        0x35: Float32l,
        0x36: Float64l,
    },
    default=Computed(this.type - 8)
)

class DictionaryAdapter(Adapter):
    def _encode( self, obj, ctx, path ):
        return [ {'key': key, 'value': val} for key, val in obj ]

class OPackObjectAdapter(Adapter):
    def _encode(self, obj, context, path) -> Mapping:
        for type in OBJ_TYPE_MAP:
            if isinstance(obj, type):
                obj_type = OBJ_TYPE_MAP[type](obj)
                if isinstance(obj_type, tuple):
                    obj_type, obj = obj_type
                break
        return {"type": obj_type, "value": obj}  # this is the format OPackObjectAdapter expects

class OPackObjectType(Enum):
    STRING = auto()
    BYTES = auto()
    INT = auto()
    DICT_LENGTHED = auto()
    
    @staticmethod
    def get_type(obj_type) -> 'OPackObjectType':
        if 8 <= obj_type <= 0x36 and obj_type != 0x31 and obj_type != 0x34:
            return OPackObjectType.INT
        if 0x40 <= obj_type <= 0x64:
            return OPackObjectType.STRING
        if 0x70 <= obj_type <= 0x94:
            return OPackObjectType.BYTES
        if 0xE0 <= obj_type <= 0xEF:
            return OPackObjectType.DICT_LENGTHED
        raise Exception(f'Invalid object type: {obj_type}')

DictionaryLengthedOPack = DictionaryAdapter(
    Array(
        this.type - 0xE0,
        Struct(
            'key' / LazyBound(lambda: TinyOPack),
            'value' / LazyBound(lambda: TinyOPack),
        )
    )
)

TinyOPack = OPackObjectAdapter(Struct(
    'type' / Int8ub,
    'value' / Switch(lambda ctx: OPackObjectType.get_type(ctx.type), {
        OPackObjectType.STRING: StringOPack,
        OPackObjectType.BYTES: BytesOPack,
        OPackObjectType.INT: IntOPack,
        OPackObjectType.DICT_LENGTHED: DictionaryLengthedOPack,
    })
))