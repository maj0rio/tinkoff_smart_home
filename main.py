import requests
import json
import base64
import sys


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x11d
            else:
                crc <<= 1
    return crc


def encode_varuint(value: int) -> bytes:
    if value == 0:
        return b"\x00"

    encoded = b""
    while value > 0:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        encoded += bytes([byte])

    return encoded


def encode_string(input_string) -> bytearray:
    encoded_bytes = bytearray()
    length_byte = len(input_string) & 0xFF
    encoded_bytes.append(length_byte)
    encoded_bytes.extend(input_string.encode())
    return encoded_bytes


def serialize_dict_values(data: dict) -> bytearray:
    byte_values = bytearray()
    for key, value in data.items():
        if key in ("src", "dst", "serial"):
            byte_values.extend(encode_varuint(value))
        elif key in ("dev_type", "cmd"):
            byte_values.append(value)
        elif key == 'cmd_body':
            for cmd_body_key, cmd_body_values in value.items():
                if cmd_body_key in ('timestamp',):
                    byte_values.extend(encode_varuint(cmd_body_values))
                elif cmd_body_key in ('dev_name',):
                    byte_values.extend(encode_string(cmd_body_values))
    return byte_values


def serialize_packet_values(data: dict) -> bytearray:
    byte_values = bytearray()
    for key, value in data.items():
        if key == 'length':
            byte_values.append(value)
        elif key == 'payload':
            byte_values.extend(serialize_dict_values(value))
        else:
            byte_values.append(value)
    return byte_values


class SmartHub:
    def __init__(self, address) -> None:
        self.address = address
        self.serial = 1

    def who_is_here(self) -> dict:
        payload = {
            "src": self.address,
            "dst": 16383,
            "serial": self.serial,
            "dev_type": 1,
            "cmd": 1,
            "cmd_body": {
                "dev_name": "SmartHub"
            }
        }
        serialized_payload = serialize_dict_values(payload)
        return {
            "length": len(serialized_payload),
            "payload": payload,
            "crc8": crc8(serialized_payload)
        }

    def i_am_here(self) -> dict:
        payload = {
            "src": self.address,
            "dst": 16383,
            "serial": self.serial,
            "dev_type": 1,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "SmartHub"
            }
        }
        serialized_payload = serialize_dict_values(payload)
        return {
            "length": len(serialized_payload),
            "payload": payload,
            "crc8": crc8(serialized_payload)
        }

    def send_data(self, data):
        encoded_data = base64.urlsafe_b64encode(serialize_packet_values(data))
        self.serial += 1
        response = requests.post(
            url=base_url,
            data=encoded_data
        )
        response_code = response.status_code
        response_data = response.text

        if response_code == 200:
            return response_data
        elif response_code == 204:
            exit(0)
        else:
            exit(99)


if __name__ == '__main__':

    base_url = sys.argv[1]
    hub_address = int(sys.argv[2], 16)

    MYHUB = SmartHub(hub_address)
    MYHUB.send_data(MYHUB.who_is_here())




#DPAd_38BAQEIU21hcnRIdWI8
