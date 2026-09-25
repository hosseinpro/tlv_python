import struct
import hashlib
from typing import Any, Tuple
import json

class Tag:
  BOOL = 0
  INT = 1
  FLOAT = 2
  STRING = 3

def check_buffer_len(buffer: bytes, offset: int, expected_length: int):
    if len(buffer) - offset < expected_length:
      raise ValueError(f"insufficient buffer to consume: buffer len:{len(buffer)}, offset:{offset}, expected length: {expected_length}")

def encode_length(length: int) -> bytes:
  encoded_length = bytearray()
  if length < 0xFF:
    encoded_length.append(length)
  elif length < 0xFFFF:
    encoded_length.append(0xFF)
    encoded_length.extend(length.to_bytes(2, 'big'))
  else:
    raise ValueError(f"unsupported length : {length}")
  return encoded_length

def decode_length(buffer: bytes, offset: int) -> Tuple[int, int]:
  check_buffer_len(buffer, offset, 1)
  length = 0
  if buffer[offset] != 0xFF:
    length = int(buffer[offset])
    offset += 1
  else:
    check_buffer_len(buffer, offset, 3)
    offset += 1
    length = int.from_bytes(buffer[offset:offset + 2], 'big')
    offset += 2
  return length, offset

def encode_element(element) -> bytes:
  # identify T, L, and V
  tag = 0
  value = bytearray()
  if isinstance(element, bool):
    tag = Tag.BOOL
    value.append(int(element))
  elif isinstance(element, int):
    tag = Tag.INT
    length = max(1, (element.bit_length() + 8) // 8)   # /////////////////////////////////////
    value = element.to_bytes(length, 'big', signed=True)
  elif isinstance(element, float):
    tag = Tag.FLOAT
    value = struct.pack(">d", element)
  elif isinstance(element, str):
    tag = Tag.STRING
    value = element.encode("utf-8")
  else:
    raise ValueError(f"type is unsupported: {type(element)}")
  # build TLV
  tlv = bytearray()
  tlv.append(tag)
  length = encode_length(len(value))
  tlv += length
  tlv += value
  return bytes(tlv)

def encode(data: dict) -> bytes:
  # check input be dict
  if isinstance(data, dict) == False:
    raise ValueError("data is not dictionary")
  body = bytearray()
  for key, value in data.items():
    # encode key
    encoded_key = encode_element(key)
    # encode value
    encoded_value = encode_element(value)
    # append to final encoded
    body += encoded_key
    body += encoded_value
  # add version
  version = bytes([1])
  body = version + body
  # calculate checksum
  checksum = hashlib.sha256(bytes(body)).digest()
  # build final buffer
  encoded = checksum + body
  return bytes(encoded)

def decode_element(buffer: bytes, offset: int) -> Tuple[Any, int]:
  # identify T, L, and V
  check_buffer_len(buffer, offset, 1)
  tag = buffer[offset]
  offset += 1
  length, offset = decode_length(buffer, offset)
  check_buffer_len(buffer, offset, length)
  raw_value = buffer[offset:offset + length]
  offset += length
  value = None
  if tag == Tag.BOOL:
    if len(raw_value) != 1:
      raise ValueError(f"len of bool should be 1 but it's {len(raw_value)}")
    value = bool(raw_value[0])
  elif tag == Tag.INT:
    if len(raw_value) < 1:
      raise ValueError(f"len of int should be at least 1 but it's {len(raw_value)}")
    value = int.from_bytes(raw_value, 'big', signed=True)
  elif tag == Tag.FLOAT:
    if len(raw_value) != 8:
      raise ValueError(f"len of float should be 8 but it's {len(raw_value)}")
    value = struct.unpack(">d", raw_value)[0]
  elif tag == Tag.STRING:
    value = raw_value.decode("utf-8")
  else:
    raise ValueError(f"tag is unsupported: {tag}")
  # return result
  return value, offset

def decode(buffer: bytes) -> dict:
  data = dict()
  # verify checksum
  offset = 0
  checksum_len = 32
  check_buffer_len(buffer, offset, checksum_len)
  in_checksum = buffer[:checksum_len]
  body = buffer[checksum_len:]
  offset += checksum_len
  checksum = hashlib.sha256(bytes(body)).digest()
  if in_checksum != checksum:
    raise ValueError(f"invalid checksum: expected = {checksum}, received = {in_checksum}")
  # verify version
  version = buffer[offset]
  if version != 1:
    raise ValueError(f"version {version} is not supported")
  offset += 1
  # decode body
  while offset < len(buffer):
    key, offset = decode_element(buffer, offset)
    value, offset = decode_element(buffer, offset)
    data[key] = value
  # check length match
  if offset != len(buffer):
    raise ValueError(f"unmatched length: offset = {offset}, length = {len(buffer)}")
  # return result
  return data

# Tests

# data = {"name": "hossein", 3: 4, 4.53434: 6.7}
with open("data.json", "r", encoding='utf-8') as f:
  data = json.load(f)

# encoded = encode(data)
# print(f"encoded:\n {encoded.hex(' ')}")

# with open("out.bin", "wb") as f:
#   f.write(encoded)

with open("out.bin", "rb") as f:
  encoded = f.read()

print(encoded.hex(' '))

assert decode(encoded) == data

try:
 decode(bytes([4, 5]))
 raise AssertionError("expected ValueError")
except ValueError:
  pass

