import re
import os
import time
import random
import base64
import keyboard
import threading

from SecureFTP import StandardPrint
from SecureFTP import STCPSocket
from SecureFTP import __hash_a_file__
from SecureFTP import LocalNode, ForwardNode
from SecureFTP import SFTPClient, NoCipher, AES_CBC
from SecureFTP.LocalVNetwork.SecureTCP import STCPSocketClosed

from FileEncryptor import BytesGenerator, BMPImage
from FileEncryptor import FileEncryptor, BMPEncryptor

from FileStorage import File

#from File import File, FileStorage

from constant import SIZE_OF_EACH_POSITION_IN_MATCH, N_BYTES_FOR_IDENTIFYING_PATH

KEY = b"0123456789abcdef"
IV = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"


def __split_to_n_part__(s, length_each_part):
    length = len(s)
    padding = b"\n" * (length - (length // length_each_part) * length_each_part)
    s += padding
    for i in range(0, length, length_each_part):
        yield s[i: i + length_each_part]

def __enc_file__(file_name, new_file_name):
    bytes_gen = BMPImage(file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = BMPEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.encrypt_to(bytes_gen, new_file_name)

def __try_enc_file__(file_name, new_file_name):
    try:
        __enc_file__(file_name, new_file_name)
    except FileNotFoundError as e:
        return repr(e), "warning"
    except Exception as e:
        return repr(e), "error"
    return None

class Client(object):
    def __init__(self, server_address, verbosities = ("error", )):
        self.__server_address__ = server_address
        self.socket = STCPSocket()

        self.__print__ = StandardPrint(f"Client connect to {server_address}", verbosities)
        self.__no_input__ = False

        self.__node__ = LocalNode()
        self.__forwarder__ = ForwardNode(self.__node__, self.socket, implicated_die= True)

        self.__signal_from_input__ = random.randint(10 ** 10, 10 ** 11 - 1)

    def __store_step_0__(self, params):
        if len(params) != 2 and params[0] != self.__signal_from_input__:
            self.__node__.send(self.__node__.name, b"$store invalid")
            return False

        file_name = params[1]    
        new_file_name = str(random.randint(10**10, 10**11 - 1))
        err = __try_enc_file__(file_name, new_file_name)
        if err:
            if os.path.isfile(new_file_name):
                os.remove(new_file_name)
            self.__print__(err[0], err[1])
            return False

        self.__store_status__ = {}
        self.__store_status__["file_name"] = file_name
        self.__store_status__["new_file_name"] = new_file_name

        self.__node__.send(self.__forwarder__.name, b"$store")
        return True

    def __store_step_1__(self, params):
        if params != b"request_match":
            os.remove(self.__store_status__["new_file_name"])
            del self.__store_status__
            return False

        return self.match([self.__signal_from_input__, self.__store_status__["file_name"]])

    def __store_step_2__(self, params):
        new_file_name = self.__store_status__["new_file_name"]
        del self.__store_status__
        
        if len(params) != 0:
            os.remove(new_file_name)
            return False
        
        last_bytes = File.get_elements_at_the_end(new_file_name, N_BYTES_FOR_IDENTIFYING_PATH)
        self.__node__.send(self.__forwarder__.name, b"$store " + last_bytes)
        _, data, _ = self.__node__.recv(source= self.__forwarder__.name)

        if data != b"$store accept":
            return False

        cipher = NoCipher()
        ftp_address = self.__server_address__[0], self.__server_address__[1] + 1
        ftpclient = SFTPClient(
            server_address = ftp_address,
            filename= new_file_name,
            cipher= cipher,
            buffer_size= int(2.9 * 1024 ** 2), # 2.9MB
            verbosities= ("error", )
        )

        try:
            ftpclient.start()
        except Exception as e:
            self.__print__(repr(e), "error")
            os.remove(new_file_name)
            return False

        os.remove(new_file_name)
        return True

    def store(self, params):
        total_s = time.time()
        s = time.time()
        success = self.__store_step_0__(params)
        e = time.time()
        #print("Time for storing's step 0: {}".format(e - s))
        if not success:
            return False

        _, data, _ = self.__node__.recv(source = self.__forwarder__.name)
        if data[:6] != b"$store":
            return False

        params = data[7:]
        s = time.time()
        success = self.__store_step_1__(params)
        e = time.time()
        #print("Time for storing's step 1: {}".format(e - s))
        if success:
            os.remove(self.__store_status__["new_file_name"])
            del self.__store_status__
            return False

        success = self.__store_step_2__(())
        if not success:
            return False
        
        return True

    def __match_step_0__(self, params):
        condition = len(params) == 2 and params[0] == self.__signal_from_input__
        if not condition:
            self.__node__.send(self.__node__.name, b"$match invalid")
            return False

        try:
            file_name = params[1]    
            new_file_name = str(random.randint(10**10, 10**11 - 1))
            err = __try_enc_file__(file_name, new_file_name)
            if err:
                if os.path.isfile(new_file_name):
                    os.remove(new_file_name)
                self.__print__(err[0], err[1])
                return False

            file_size = os.path.getsize(new_file_name)
            file_size_in_bytes = file_size.to_bytes(SIZE_OF_EACH_POSITION_IN_MATCH, "big")
            last_bytes = File.get_elements_at_the_end(new_file_name, N_BYTES_FOR_IDENTIFYING_PATH)
            self.__node__.send(self.__forwarder__.name, b"$match \x00 " + file_size_in_bytes + last_bytes)

            self.__match_status__ = {}
            self.__match_status__["new_file_name"] = new_file_name
            self.__match_status__["file_size"] = file_size
        except Exception as e:
            self.__print__(repr(e), "error")
            
            if hasattr(self, "__match_status__"):
                del self.__match_status__

            return False

        return True

    def __match_step_1__(self, params):
        condition = len(params) >= 2 and params[0] == 0

        if not condition:
            self.__node__.send(self.__node__.name, b"$match invalid")
            os.remove(self.__match_status__["new_file_name"])
            del self.__match_status__
            return False

        try:
            params = params[2:]

            to_int = lambda x: int.from_bytes(x, "big")
            positions = list(map(to_int, __split_to_n_part__(params, length_each_part= SIZE_OF_EACH_POSITION_IN_MATCH)))
            
            check = lambda x: x < self.__match_status__["file_size"]
            result = sum(map(check, positions))
            expected_result = len(params) / SIZE_OF_EACH_POSITION_IN_MATCH
            success = result == expected_result
            if not success:
                self.__node__.send(self.__node__.name, b"$match failure Error from server at packet request")
                return

            values = File.get_elements(self.__match_status__["new_file_name"], positions)
            sent_msg = b"$match \x01 " + values
            self.__node__.send(self.__forwarder__.name, sent_msg)
        except Exception as e:
            self.__print__(repr(e), "error")
            return False
        finally:
            os.remove(self.__match_status__["new_file_name"])
            del self.__match_status__

        return True

    def match(self, params):
        total_s = time.time()
        s = time.time()
        success = self.__match_step_0__(params)
        e = time.time()
        #print("Time for matching's step 0: {}".format(e - s))
        if not success:
            return False

        s = time.time()
        _, data, _ = self.__node__.recv(source = self.__forwarder__.name)
        if data[:6] != b"$match":
            return False

        params = data[7:]
        success = self.__match_step_1__(params)
        e = time.time()
        #print("Time for matching's step 1: {}".format(e - s))
        if not success:
            return False

        _, data, _ = self.__node__.recv(source = self.__forwarder__.name)
        command_and_params = data.split()
        command = command_and_params[0]
        params = command_and_params[1:]
        total_e = time.time()
        print("Total time for matching: {}".format(total_e - total_s))

        if command != b"$match" or len(params) == 0 or params[0] not in [b"success", b"failure"]:
            return False

        if params[0] == b"success":
            return True

        return False

    def _recv_from_server(self):
        while True:
            try:
                source, data, obj = self.__node__.recv()
            except STCPSocketClosed as e:
                self.__print__(repr(e), "warning")
                break
            except Exception as e:
                self.__print__(repr(e), "error")
                break

            command_and_params = data.split()
            command = command_and_params[0]
            params = command_and_params[1:]

            if source == self.__node__.name and obj != self.__signal_from_input__:
                print("\r" + data.decode())
                keyboard.press_and_release("enter")
                self.__no_input__ = True
                continue
            
            if obj == self.__signal_from_input__:
                params = [self.__signal_from_input__] + params
                if command == b"$store":
                    success = self.store(params)
                    if success:
                        self.__node__.send(self.__node__.name, b"Store file successfully")
                    else:
                        self.__node__.send(self.__node__.name, b"Some errors occur when storing")

                if command == b"$match":
                    success = self.match(params)
                    if success:
                        self.__node__.send(self.__node__.name, b"Your file is in server now")
                    else:
                        self.__node__.send(self.__node__.name, b"Your file is not in server or some errors occur")

                
    def _recv_from_input(self):
        while True:
            try:
                data = input(">>> ")
            except (KeyboardInterrupt, EOFError):
                self.__no_input__ = False
                data = "$exit"

            if self.__no_input__:
                self.__no_input__ = False
                continue

            if not data:
                continue

            if data == "$exit":
                self.socket.close()
                return

            self.__node__.send(self.__node__.name, data.encode(), self.__signal_from_input__)

    def start(self):
        self.socket.connect(self.__server_address__)
        
        t = threading.Thread(target= self.__forwarder__.start)
        t.start()

        t = threading.Thread(target = self._recv_from_input)
        t.start()

        
        t = threading.Thread(target = self._recv_from_server)
        t.start()