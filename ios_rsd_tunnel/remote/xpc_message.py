# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL 3.0
import dataclasses
import uuid
from construct import (
    Aligned,
    Array,
    Bytes,
    Const,
    CString,
    Default,
    Double,
    Enum,
    ExprAdapter,
    FlagsEnum,
    GreedyBytes,
    Hex,
    If,
    Int32ul,
    Int64sl,
    Int64ul,
    LazyBound,
    Pass,
    Prefixed,
    Probe,
    Struct,
    Switch,
    this,
)
from construct import Optional as ConstructOptional
from datetime import datetime
from typing import (
    Any,
    List,
    Mapping,
)

XpcMessageType = Enum(
    Hex(Int32ul),
    NULL            = 0x00001000,
    BOOL            = 0x00002000,
    INT64           = 0x00003000,
    UINT64          = 0x00004000,
    DOUBLE          = 0x00005000,
    POINTER         = 0x00006000,
    DATE            = 0x00007000,
    DATA            = 0x00008000,
    STRING          = 0x00009000,
    UUID            = 0x0000a000,
    FD              = 0x0000b000,
    SHMEM           = 0x0000c000,
    MACH_SEND       = 0x0000d000,
    ARRAY           = 0x0000e000,
    DICTIONARY      = 0x0000f000,
    ERROR           = 0x00010000,
    CONNECTION      = 0x00011000,
    ENDPOINT        = 0x00012000,
    SERIALIZER      = 0x00013000,
    PIPE            = 0x00014000,
    MACH_RECV       = 0x00015000,
    BUNDLE          = 0x00016000,
    SERVICE         = 0x00017000,
    SERVICE_INSTANCE= 0x00018000,
    ACTIVITY        = 0x00019000,
    FILE_TRANSFER   = 0x0001a000,
)

XpcFlags = FlagsEnum(
    Hex(Int32ul),
    ALWAYS_SET             = 0x00000001,
    PING                   = 0x00000002,
    DATA_PRESENT           = 0x00000100,
    WANTING_REPLY          = 0x00010000,
    REPLY                  = 0x00020000,
    FILE_TX_STREAM_REQUEST = 0x00100000,
    FILE_TX_STREAM_RESPONSE= 0x00200000,
    INIT_HANDSHAKE         = 0x00400000,
)

AlignedString = Aligned(4, CString('utf8'))
XpcNull = Pass
XpcBool = Int32ul
XpcInt64 = Int64sl
XpcUInt64 = Int64ul
XpcDouble = Double
XpcPointer = None
XpcDate = Int64ul
XpcData = Aligned(4, Prefixed(Int32ul, GreedyBytes))
XpcString = Aligned(4, Prefixed(Int32ul, CString('utf8')))
XpcUuid = Bytes(16)
XpcFd = Int32ul
XpcShmem = Struct('length' / Int32ul, Int32ul)

XpcArray = Prefixed(
    Int32ul, Struct(
        'count' / Int32ul,
        'entries' / Array(this.count, LazyBound(lambda: XpcObject)),
    )
)

XpcDictionaryEntry = Struct(
    'key' / AlignedString,
    'value' / LazyBound(lambda: XpcObject),
)

XpcDictionary = Prefixed(
    Int32ul, Struct(
        'count' / Hex(Int32ul),
        'entries' / If(this.count > 0, Array(this.count, XpcDictionaryEntry)),
    )
)

XpcFileTransfer = Struct(
    'msg_id' / Int64ul,
    'data' / LazyBound(lambda: XpcObject),
)

XpcObject = Struct(
    'type' / XpcMessageType,
    'data' / Switch(this.type, {
        XpcMessageType.DICTIONARY:    XpcDictionary,
        XpcMessageType.STRING:        XpcString,
        XpcMessageType.INT64:         XpcInt64,
        XpcMessageType.UINT64:        XpcUInt64,
        XpcMessageType.DOUBLE:        XpcDouble,
        XpcMessageType.BOOL:          XpcBool,
        XpcMessageType.NULL:          XpcNull,
        XpcMessageType.UUID:          XpcUuid,
        XpcMessageType.POINTER:       XpcPointer,
        XpcMessageType.DATE:          XpcDate,
        XpcMessageType.DATA:          XpcData,
        XpcMessageType.FD:            XpcFd,
        XpcMessageType.SHMEM:         XpcShmem,
        XpcMessageType.ARRAY:         XpcArray,
        XpcMessageType.FILE_TRANSFER: XpcFileTransfer,
    }, default=Probe(lookahead=1000)),
)
XpcPayload = Struct(
    'magic' / Hex(Const(0x42133742, Int32ul)),
    'protocol_version' / Hex(Const(0x00000005, Int32ul)),
    'obj' / XpcObject,
)
XpcWrapper = Struct(
    'magic' / Hex(Const(0x29b00b92, Int32ul)),
    'flags' / Default(XpcFlags, XpcFlags.ALWAYS_SET),
    'message' / Prefixed(
        ExprAdapter(Int64ul, lambda obj, context: obj + 8, lambda obj, context: obj - 8),
        Struct(
            'message_id' / Hex(Default(Int64ul, 0)),
            'payload' / ConstructOptional(XpcPayload),
        )
    )
)


class XpcInt64Type(int):  pass
class XpcUInt64Type(int): pass


@dataclasses.dataclass
class FileTransferType:
    transfer_size: int


def _decode_xpc_dictionary( x ) -> Mapping:
    if x.data.count == 0:
        return {}
    
    return {
        entry.key: decode_xpc_object( entry.value ) for entry in x.data.entries
    }


def _decode_xpc_file_transfer(xpc_object) -> FileTransferType:
    return FileTransferType(
        transfer_size = _decode_xpc_dictionary( xpc_object.data.data )['s']
    )


def decode_xpc_object(xpc_object) -> Any:
    decoders = {
        XpcMessageType.DICTIONARY: _decode_xpc_dictionary,
        XpcMessageType.ARRAY:      lambda arr: [( lambda x: decode_xpc_object(x) )(x) for x in arr],
        XpcMessageType.BOOL:       lambda x: bool(x.data),
        XpcMessageType.INT64:      lambda x: XpcInt64Type(x.data),
        XpcMessageType.UINT64:     lambda x: XpcUInt64Type(x.data),
        XpcMessageType.UUID:       lambda x: uuid.UUID( bytes=x.data ),
        XpcMessageType.STRING:     lambda x: x.data, # str
        XpcMessageType.DATA:       lambda x: x.data, # bytes
        XpcMessageType.DATE:       lambda x: datetime.fromtimestamp(x.data / 1000000000),
        XpcMessageType.FILE_TRANSFER: _decode_xpc_file_transfer,
        XpcMessageType.DOUBLE:     lambda x: x.data, # float
        XpcMessageType.NULL:       lambda x: None,
    }
    decoder = decoders.get(xpc_object.type)
    if decoder is None:
        raise TypeError(f'deserialize error: {xpc_object}')
    return decoder(xpc_object)


def _build_xpc_array(payload: List) -> Mapping:
    entries = [
        _build_xpc_object(x) for x in payload
    ]
    
    return {
        'type': XpcMessageType.ARRAY,
        'data': {
            'count': len(entries),
            'entries': entries
        }
    }


def _build_xpc_dictionary(payload: Mapping) -> Mapping:
    entries = [
        {
          'key': key,
          'value': _build_xpc_object( val ),
        } for key, val in payload.items()
    ]
    
    return {
        'type': XpcMessageType.DICTIONARY,
        'data': {
            'count': len(entries),
            'entries': entries,
        }
    }


def _build_xpc_object(payload: Any) -> Mapping:
    if payload is None:
        return { 'type': XpcMessageType.NULL, 'data': None }
    
    payload_builders = {
        list:            _build_xpc_array,
        dict:            _build_xpc_dictionary,
        bool:            lambda x: { 'type': XpcMessageType.BOOL,   'data': x },
        str:             lambda x: { 'type': XpcMessageType.STRING, 'data': x },
        bytes:           lambda x: { 'type': XpcMessageType.DATA,   'data': x },
        bytearray:       lambda x: { 'type': XpcMessageType.DATA,   'data': x },
        float:           lambda x: { 'type': XpcMessageType.DOUBLE, 'data': x },
        uuid.UUID:       lambda x: { 'type': XpcMessageType.UUID,   'data': x },
        'XpcUInt64Type': lambda x: { 'type': XpcMessageType.UINT64, 'data': x },
        'XpcInt64Type':  lambda x: { 'type': XpcMessageType.INT64,  'data': x },
    }
    builder = payload_builders.get(type(payload), payload_builders.get(type(payload).__name__))
    if builder is None:
        raise TypeError(f'unrecognized type for: {payload} {type(payload)}')
    return builder(payload)


def create_xpc_wrapper(
    d: Mapping,
    message_id: int = 0,
    wanting_reply: bool = False
) -> bytes:
    flags = XpcFlags.ALWAYS_SET
    
    if len(d.keys()) > 0:
        flags |= XpcFlags.DATA_PRESENT
    
    if wanting_reply:
        flags |= XpcFlags.WANTING_REPLY
    
    return XpcWrapper.build({
        'flags': flags,
        'message': {
            'message_id': message_id,
            'payload': {'obj': _build_xpc_object(d)}
        }
    })
