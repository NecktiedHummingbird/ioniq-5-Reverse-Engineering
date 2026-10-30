import struct
import uuid
from pathlib import Path

import pytest

from tools.uk_fw.asf_stream_probe import (
    ASF_FILE_PROPERTIES_GUID,
    ASF_HEADER_FIXED_SIZE,
    ASF_HEADER_GUID,
    ASF_STREAM_FLAGS_OFFSET,
    ASF_STREAM_PROPERTIES_GUID,
    AsfProbeError,
    build_stream_count_probe,
    describe,
    parse_asf,
)


def _obj(guid: bytes, body: bytes) -> bytes:
    return guid + struct.pack("<Q", 24 + len(body)) + body


def _template(stream_objects: int = 1) -> bytes:
    file_body = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes_le
    file_body += struct.pack("<Q", 0) + bytes(64)
    file_obj = _obj(ASF_FILE_PROPERTIES_GUID, file_body)

    stream_body = bytearray(70)
    struct.pack_into("<H", stream_body, ASF_STREAM_FLAGS_OFFSET - 24, 7)
    stream_obj = _obj(ASF_STREAM_PROPERTIES_GUID, bytes(stream_body))
    objects = [file_obj] + [stream_obj] * stream_objects
    body = b"".join(objects)
    header = ASF_HEADER_GUID + struct.pack("<QI", ASF_HEADER_FIXED_SIZE + len(body), len(objects))
    return header + b"\x01\x02" + body + b"TAIL"


def test_builds_33_stream_probe_and_preserves_tail():
    output = build_stream_count_probe(_template(), 33)
    details = describe(output)

    assert details["stream_objects"] == 33
    assert details["stream_ids"] == list(range(1, 34))
    assert details["header_objects"] == 34
    assert output.endswith(b"TAIL")

    parsed = parse_asf(output)
    file_obj = next(obj for obj in parsed.objects if obj.guid == ASF_FILE_PROPERTIES_GUID)
    file_obj_offset = ASF_HEADER_FIXED_SIZE
    assert struct.unpack_from("<Q", output, file_obj_offset + 40)[0] == len(output)
    assert len(file_obj.data) >= 48


def test_rejects_multiple_template_streams():
    with pytest.raises(AsfProbeError, match="exactly one"):
        build_stream_count_probe(_template(stream_objects=2), 33)


@pytest.mark.parametrize("count", [0, 128])
def test_rejects_out_of_range_stream_count(count):
    with pytest.raises(AsfProbeError, match="1..127"):
        build_stream_count_probe(_template(), count)


def test_rejects_truncated_object():
    source = bytearray(_template())
    struct.pack_into("<Q", source, ASF_HEADER_FIXED_SIZE + 16, 0x100000)
    with pytest.raises(AsfProbeError, match="exceeds ASF header"):
        parse_asf(bytes(source))
