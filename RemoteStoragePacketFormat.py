import re
from done import done

class GROUP_CONST():
    CONST_GROUP_ID = ""
    @classmethod
    def get_dict(cls, invert = False):
        d = cls.__dict__
        check = lambda attr: True if re.match("^{}[A-Z_]+$".format(cls.CONST_GROUP_ID), attr) else False
        
        actual_keys = filter(check, d.keys())
        actual_dict = {}
        
        get = lambda key: None if actual_dict.update({key: d[key]}) else None 
        list(map(get, actual_keys))
        
        if invert:
            actual_dict = {v: k for k, v in actual_dict.items()}

        return actual_dict

class CONST_TYPE(GROUP_CONST):
    STORE = 0
    CHECK = 1
    RETRIEVE = 2
    RETRIEVE_WITHOUT_CHECK = 3
    STORE_WITHOUT_CHECK = 4 # For debugging
    INPUT = 5
    NOTIFICATION = 6
        
class CONST_STATUS(GROUP_CONST):
    NONE = 0
    ACCEPT = 1
    DENY = 2
    FOUND = 3
    NOT_FOUND = 4
    REQUEST = 5
    INFO = 6
    START = 7
    SUCCESS = 8
    FAILURE = 9

class RSPacket():
    def __init__(self, packet_type, status):
        self.packet_type = packet_type
        self.status = status
        self.optional_header = b""
        self.data = b""

    def append_optional_header(self, value):
        self.optional_header += value

    def set_data(self, data):
        self.data = data

    def append_data(self, data):
        self.data += data

    def create(self):
        packet = b""
        packet += self.packet_type.to_bytes(1, "big")
        packet += self.status.to_bytes(1, "big")

        packet += len(self.optional_header).to_bytes(4, "big")
        packet += self.optional_header

        packet += self.data

        return packet
        
    @staticmethod
    def extract(packet: bytes):
        packet_dict = {}
        packet_dict["TYPE"] = int.from_bytes(packet[0: 1], "big")
        packet_dict["STATUS"] = int.from_bytes(packet[1: 2], "big")

        option_length = int.from_bytes(packet[2: 6], "big")
        packet_dict["OPTION"] = packet[6: 6 + option_length]

        packet_dict["DATA"] = packet[6 + option_length: ]

        return packet_dict
    
    @staticmethod
    def check(packet, expected_type, expected_status, is_dict = False):
        if is_dict:
            packet_dict = packet
        else:
            packet_dict = RSPacket.extract(packet)
        if packet_dict["TYPE"] != expected_type:
            return done(False, {
                "message": "Invalid packet", 
                "debug": CONST_TYPE.get_dict(invert= True)[packet_dict["TYPE"]]
                })
            
        if packet_dict["STATUS"] != expected_status:
            return done(False, {
                "message": "Status has not been expected ({} instead of {})".format(
                    CONST_STATUS.get_dict(invert= True)[packet_dict["STATUS"]],
                    CONST_STATUS.get_dict(invert= True)[expected_status]
                ), 
                "debug": CONST_STATUS.get_dict(invert= True)[packet_dict["STATUS"]]
                })

        return done(True)

if __name__ == "__main__":
    print(CONST_TYPE.get_dict())