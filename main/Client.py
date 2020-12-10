import re
import os
import time
import struct
import random
import socket
import base64
import hashlib
import keyboard
import threading
import matplotlib.pyplot as plt

from skimage.metrics import structural_similarity

from .Timer import Timer
from .Done import Done # Formated return value

from .SecureFTP import STCPSocket
from .SecureFTP import StandardPrint
from .SecureFTP import __hash_a_file__
from .SecureFTP import LocalNode, ForwardNode
from .SecureFTP import SFTP, NoCipher, AES_CBC
from .SecureFTP.LocalVNetwork.SecureTCP import STCPSocketClosed

from .FileEncryptor import BytesGenerator, BMPImage
from .FileEncryptor import FileEncryptor, BMPEncryptor

from .FileStorage import File, MAX_BUFFER, FileUtils

from .constant import SIZE_OF_INT, N_BYTES_FOR_IDENTIFYING_PATH
from .constant import DEFAULT_N_BLOCKS, DEFAULT_N_PROOFS, DEFAULT_LENGTH_OF_KEY, DEFAULT_N_VERIFIED_BLOCKS

from .RemoteStoragePacketFormat import RSPacket, CONST_STATUS, CONST_TYPE

KEY = b"0123456789abcdef"
IV = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

MIN_VALUES_TO_MATCH = 100
MAX_VALUES_TO_MATCH = 100

TIMER = Timer()

def __split_to_n_part__(s, length_each_part):
    length = len(s)
    padding = b"\n" * (length - (length // length_each_part) * length_each_part)
    s += padding
    for i in range(0, length, length_each_part):
        yield s[i: i + length_each_part]

def __encrypt_bmp__(file_name, new_file_name):
    bytes_gen = BMPImage(file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = BMPEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.encrypt_to(bytes_gen, new_file_name)

def __encrypt_arbitrary_file__(file_name, new_file_name):
    bytes_gen = BytesGenerator("file", file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = FileEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.encrypt_to(bytes_gen, new_file_name)


def __decrypt_bmp_file__(file_name, new_file_name):
    bytes_gen = BMPImage(file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = BMPEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.decrypt_to(bytes_gen, new_file_name)

def __decrypt_arbitrary_file__(file_name, new_file_name):
    bytes_gen = BytesGenerator("file", file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = FileEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.decrypt_to(bytes_gen, new_file_name)

def __encrypt_file__(file_name, new_file_name):
    __encrypt_arbitrary_file__(file_name, new_file_name)

def __decrypt_file__(file_name, new_file_name):
    __decrypt_arbitrary_file__(file_name, new_file_name)

def __try_encrypting_file__(file_name, new_file_name):
    try:
        __encrypt_file__(file_name, new_file_name)
    except FileNotFoundError as e:
        return Done(False, {"message": "Something wrong", "debug": repr(e), "level": "warning"})
    except Exception as e:
        return Done(False, {"message": "Something wrong", "debug": repr(e), "level": "error"})
    return Done(True)

def __try_decrypting_file__(file_name, new_file_name):
    try:
        __decrypt_file__(file_name, new_file_name)
    except FileNotFoundError as e:
        return Done(False, {"message": "Something wrong", "debug": repr(e), "level": "warning"})
    except Exception as e:
        return Done(False, {"message": "Something wrong", "debug": repr(e), "level": "error"})
    return Done(True)


def generate_proof_file(n_proofs, file_name, proof_file_name, n_blocks, n_vblocks, key_size):
    try:
        file_size = os.path.getsize(file_name)
        nbytes_per_block = int(file_size / n_blocks)
        last_bytes = File.get_elements_at_the_end(file_name, N_BYTES_FOR_IDENTIFYING_PATH)

        proof_file = open(proof_file_name, "wb")
        proof_file.write(int(0).to_bytes(SIZE_OF_INT, "big"))           # position of next unused proof (4 bytes)
        proof_file.write(n_blocks.to_bytes(SIZE_OF_INT, "big"))         # the number of blocks (4 bytes)
        proof_file.write(n_vblocks.to_bytes(SIZE_OF_INT, "big"))        # the number of verification blocks (4 bytes)
        proof_file.write(key_size.to_bytes(1, "big"))                   # length of key (1 byte)
        proof_file.write(hashlib.sha1().digest_size.to_bytes(1, "big")) # digest size of hash function (1 byte)
        proof_file.write(len(last_bytes).to_bytes(SIZE_OF_INT, "big"))  # length of last bytes of file (4 bytes)
        proof_file.write(file_size.to_bytes(SIZE_OF_INT, "big"))        # file size (4 bytes)
        proof_file.write(last_bytes)                                    # last bytes of file (variable length)
        
        file = open(file_name, "rb")
        for _ in range(n_proofs):
            file.seek(0, FileUtils.FROM_START)
            random_key = os.urandom(key_size)
            proof_file.write(random_key)

            positions = sorted(random.sample(range(n_blocks), n_vblocks))
            to_bytes = lambda x: int.to_bytes(x, SIZE_OF_INT, "big")
            positions_in_bytes = b"".join(map(to_bytes, positions))
            proof_file.write(positions_in_bytes)

            old_position = 0
            for position in positions:
                file.seek((position - old_position) * nbytes_per_block, FileUtils.FROM_CUR)
                content = random_key + file.read(nbytes_per_block)
                hashvalue = hashlib.sha1(content).digest()
                proof_file.write(hashvalue)
                old_position = position + 1

        file.close()
        proof_file.close()
        return True
    except:
        return False

def extract_proof_file(proof_file_name):
    proof_file = open(proof_file_name, "rb")
    current_proof, n_blocks, n_vblocks, key_size, digest_size, last_bytes_size, file_size = struct.unpack(
        ">IIIBBII",
        proof_file.read(4 + 4 + 4 + 1 + 1 + 4 + 4)
    )
    last_bytes = proof_file.read(last_bytes_size)
    proof_file.close()

    ret_dict = {
        "current_proof": current_proof,
        "n_blocks": n_blocks,
        "n_vblocks": n_vblocks,
        "key_size": key_size,
        "digest_size": digest_size,
        "file_size": file_size,
        "last_bytes_size": last_bytes_size,
        "last_bytes": last_bytes
        }

    return ret_dict

def read_proofs(proof_file_name, proof_dict = None):
    if not proof_dict:
        proof_dict = extract_proof_file(proof_file_name)

    proof_file = open(proof_file_name, "r+b")
    start_byte = SIZE_OF_INT * 5 + 2 + proof_dict["last_bytes_size"] # ignore header 
    start_byte += \
        (
            proof_dict["key_size"] 
            + SIZE_OF_INT * proof_dict["n_vblocks"]
            + proof_dict["digest_size"] * proof_dict["n_vblocks"]
        ) * proof_dict["current_proof"]

    proof_file.seek(start_byte, FileUtils.FROM_START)
    key = proof_file.read(proof_dict["key_size"])
    position_of_vblocks = struct.unpack(
        ">" + "I" * proof_dict["n_vblocks"], # ">IIII...."
        proof_file.read(SIZE_OF_INT * proof_dict["n_vblocks"])
        )

    proof_of_vblocks = []
    for _ in range(proof_dict["n_vblocks"]):
        digest = proof_file.read(proof_dict["digest_size"])
        proof_of_vblocks.append(digest)

    proof_file.seek(0, FileUtils.FROM_START) # return to begin of the proof file and ...
    proof_file.write(int(proof_dict["current_proof"] + 1).to_bytes(SIZE_OF_INT, "big")) # rewrite position of next unused proof
    proof_file.close()

    return key, position_of_vblocks, proof_of_vblocks

class Client(object):
    def __init__(self, 
            server_address,
            n_blocks = DEFAULT_N_BLOCKS,
            n_vblocks = DEFAULT_N_VERIFIED_BLOCKS,
            n_proofs = DEFAULT_N_PROOFS,
            key_size = DEFAULT_LENGTH_OF_KEY,
            verbosities = ("error", )
        ):
        self.__server_address__ = server_address
        self.socket = STCPSocket()

        self.__n_blocks__ = n_blocks
        self.__n_vblocks__ = n_vblocks
        self.__n_proofs__ = n_proofs
        self.__key_size__ = key_size

        self.__print__ = StandardPrint(f"Client connect to {server_address}", verbosities)
        self.__no_input__ = False

        self.__node__ = LocalNode()
        self.__forwarder__ = ForwardNode(self.__node__, self.socket, implicated_die= True)

        self.__signal_from_input__ = random.randint(10 ** 10, 10 ** 11 - 1)

    def store(self, params):
        if len(params) != 1:
            return Done(False, {"message": "Invalid parameters", "where": "Has not yet started storing", "debug": params})
        
        file_name = params[0].decode()
        encrypted_file_name = file_name + ".enc"
        temporary_proof_file_name = encrypted_file_name + ".proof"
        proof_file_name = file_name + ".proof"
        try:
            # Encrypting file
            TIMER.start("store_encrypting_phase")
            result = __try_encrypting_file__(file_name, encrypted_file_name)
            TIMER.end("store_encrypting_phase")
            if result.value == False:
                return Done(result.value, attributes= {"where": "Encrypting file"}, inherit_from= result)

            # Generate temporary proof to check exist of file in server
            TIMER.start("store_generating_temp_proof_phase")
            generate_proof_file(
                n_proofs = 1, 
                file_name= encrypted_file_name,
                proof_file_name= temporary_proof_file_name,
                n_blocks= self.__n_blocks__,
                n_vblocks = self.__n_vblocks__,
                key_size= self.__key_size__
            )
            TIMER.end("store_generating_temp_proof_phase")

            # Checking exist of file in server
            TIMER.start("store_checking_phase")
            result = self.check([temporary_proof_file_name.encode()])
            TIMER.end("store_checking_phase")
            if result.value == True:
                return Done(False, {"message": "File has ready been in server", "where": "Checking phase"})

            # Sending request storing packet
            TIMER.start("store_sending_request")
            last_bytes = File.get_elements_at_the_end(encrypted_file_name, N_BYTES_FOR_IDENTIFYING_PATH)
            packet = RSPacket(
                packet_type= CONST_TYPE.STORE,
                status= CONST_STATUS.REQUEST
            )
            packet.set_data(last_bytes)
            self.__node__.send(self.__forwarder__.name, packet.create())
            TIMER.end("store_sending_request")

            # Receiving response (accept/deny storing request) from server
            TIMER.start("store_receiving_agreement")
            _, response, _ = self.__node__.recv(source= self.__forwarder__.name)
            result = RSPacket.check(response, expected_type = CONST_TYPE.STORE, expected_status= CONST_STATUS.ACCEPT)
            TIMER.end("store_receiving_agreement")
            if result.value == False:
                return Done(result.value, {"where": "Receiving reponse (accept/deny) from server"}, inherit_from= result)

            # Start Secure FTP service
            TIMER.start("store_uploading_phase")
            ftp_address = self.__server_address__[0], self.__server_address__[1] + 1
            ftp = SFTP(
                address= ftp_address,
                address_owner= "partner",
                verbosities= ("error", )
            ) 
            ftp.as_sender(
                file_name= encrypted_file_name,
                cipher= NoCipher(),
                buffer_size= int(2.9 * 1024 ** 2) # 2.9 MB
            )
            success = ftp.start()
            TIMER.end("store_uploading_phase")
            if not success:
                return Done(False, {"message": "Error in upload file", "where": "Upload phase"})

            # Receiving reponse (success/failure) from server
            TIMER.start("store_receiving_result")
            _, response, _ = self.__node__.recv(source= self.__forwarder__.name)
            result = RSPacket.check(response, expected_type= CONST_TYPE.STORE, expected_status= CONST_STATUS.SUCCESS)
            TIMER.end("store_receiving_result")
            if result.value == False:
                return Done(False, {"where": "Receiving reponse (success/failure) from server"}, inherit_from= result)
            
            # Generating proof file for future
            TIMER.start("store_generating_proofs")
            success = generate_proof_file(
                n_proofs = self.__n_proofs__,
                file_name= encrypted_file_name,
                proof_file_name= proof_file_name,
                n_blocks= self.__n_blocks__,
                n_vblocks= self.__n_vblocks__,
                key_size= self.__key_size__
            )
            TIMER.end("store_generating_proofs")
            if not success and os.path.isfile(proof_file_name):
                os.remove(proof_file_name)
                return Done(False, {"message": "An error occurs when generating proof"})

            return Done(True)
        except Exception as e:
            return Done(False, {"message": "Something wrong", "where": "Unknown", "debug": repr(e)})

        finally:
            if os.path.isfile(encrypted_file_name):
                os.remove(encrypted_file_name)

            if os.path.isfile(temporary_proof_file_name):
                os.remove(temporary_proof_file_name)

    def __generate_challenge_packet__(self, proof_file_name):
        if not isinstance(proof_file_name, str):
            return Done(False, {"message": "Invalid parameters", "debug": proof_file_name})

        try:
            proof_dict = extract_proof_file(proof_file_name)
            file_size_in_bytes = proof_dict["file_size"].to_bytes(SIZE_OF_INT, "big")
            
            key, positions, proofs = read_proofs(proof_file_name, proof_dict)
            
            to_bytes = lambda x: int.to_bytes(x, SIZE_OF_INT, "big")
            positions_in_bytes = b"".join(map(to_bytes, positions))
            
            
            data = b""
            data += file_size_in_bytes
            data += len(key).to_bytes(SIZE_OF_INT, "big")
            data += key
            data += proof_dict["last_bytes_size"].to_bytes(SIZE_OF_INT, "big")
            data += proof_dict["last_bytes"]
            data += proof_dict["n_blocks"].to_bytes(SIZE_OF_INT, "big")
            data += len(positions).to_bytes(SIZE_OF_INT, "big")
            data += positions_in_bytes

            packet = RSPacket(
                packet_type = CONST_TYPE.CHECK,
                status= CONST_STATUS.REQUEST
            )
            packet.append_data(data)
            return Done(packet.create(), {"proofs": proofs})
        except Exception as e:
            return Done(None, {"message": "Wrong in get info of file", "debug": repr(e)})

    def check(self, params):
        if len(params) != 1:
            return Done(False, {"message": "Invalid parameters", "where": "Has not yet started storing", "debug": params})
        
        proof_file_name = params[0].decode()
        try:
            # Generating challenge packet and sending it to server
            TIMER.start("check_generating_challenge_packet")
            result = self.__generate_challenge_packet__(proof_file_name)
            TIMER.end("check_generating_challenge_packet")
            if result.value == None:
                return Done(False, {"where": "Generate challenge packet"}, inherit_from= result)
            proofs = result.proofs

            TIMER.start("check_sending_challenge_packet")
            self.__node__.send(self.__forwarder__.name, result.value)
            TIMER.end("check_sending_challenge_packet")

            # Wait for reponse (accept/deny storing request)from server
            TIMER.start("check_receiving_proofs_from_server")
            _, response, _ = self.__node__.recv(self.__forwarder__.name)
            result = RSPacket.check(response, expected_type= CONST_TYPE.CHECK, expected_status= CONST_STATUS.FOUND)
            TIMER.end("check_receiving_proofs_from_server")
            if result.value == False:
                return Done(False, {"where": "Receiving response (proofs) from server"}, inherit_from= result)
            
            # Compare proofs from server
            TIMER.start("check_compare_phase")
            client_proofs = b"".join(proofs)
            server_proofs = RSPacket.extract(response)["DATA"]
            if client_proofs != server_proofs:
                result= Done(False, {"message": "File integrity was compromised"})
            else:
                result = Done(True)
            TIMER.end("check_compare_phase")

            return result
        except Exception as e:
            return Done(False, {"message": "Something wrong", "debug": repr(e), "where": "Unknown"})
            
    def retrieve(self, params):
        if len(params) != 2:
            return Done(False, {"message": "Invalid parameters", "where": "Check input"})

        proof_file_name = params[0].decode()
        storage_path = params[1].decode()

        try:
            # Check exist of file
            TIMER.start("retrieve_checking_phase")
            result = self.check([proof_file_name.encode()])
            TIMER.end("retrieve_checking_phase")

            if result.value == False:
                return Done(False, {"where": "checking phase"}, result)

            # Sending request packet
            TIMER.start("retrieve_send_request")
            packet = RSPacket(
                packet_type= CONST_TYPE.RETRIEVE,
                status= CONST_STATUS.REQUEST
            )
            proof_dict = extract_proof_file(proof_file_name)
            packet.set_data(proof_dict["file_size"].to_bytes(SIZE_OF_INT, "big") + proof_dict["last_bytes"])
            self.__node__.send(self.__forwarder__.name, packet.create())
            TIMER.end("retrieve_send_request")

            # Receiving response (accept/deny retrieving request) from server
            TIMER.start("retrieve_wait_for_accept")
            _, response, _ = self.__node__.recv(self.__forwarder__.name)
            TIMER.end("retrieve_wait_for_accept")

            result = RSPacket.check(response, expected_type= CONST_TYPE.RETRIEVE, expected_status= CONST_STATUS.ACCEPT)
            if result.value == False:
                return Done(False, {"where": "Waiting for response of retrieving request"}, inherit_from = result)

            # Start FTP
            TIMER.start("retrieve_download_phase")
            ftp_address = self.__server_address__[0], self.__server_address__[1] + 1
            ftp = SFTP(
                address= ftp_address,
                address_owner= "partner",
                verbosities= ("error", )
            )
            ftp.as_receiver(
                storage_path= storage_path + ".download",
                cipher= NoCipher(),
                save_file_after= 32 * 1024 ** 2, # 32 MB
                buffer_size= 3 * 1024 ** 2 # 3 MB
            )
            success = ftp.start()
            TIMER.end("retrieve_download_phase")
            if not success:
                return Done(False, {"message": "Error in retrieve file", "where": "Retrieve file"})

            TIMER.start("retrieve_decrypting_phase")
            result = __try_decrypting_file__(storage_path + ".download", storage_path)
            TIMER.end("retrieve_decrypting_phase")
            if result.value == False:
                return Done(False, {"where": "Decrypting phase"}, inherit_from = result)            

            return Done(True)
        except Exception as e:
            return Done(False, {"message": "Something wrong", "where": "Unknown", "debug": repr(e)})
        finally:
            if os.path.isfile(storage_path + ".download"):
                os.remove(storage_path + ".download")
                
    def match(self, params):
        if len(params) != 2:
            return Done(False, {"message": "Invalid input", "where": "Checking input"})

        proof_file_name = params[0].decode()
        destination_file_name = params[1].decode()
        retrieve_file_name = proof_file_name + ".retrieve"

        try:
            TIMER.start("match_retrieving_phase")
            result = self.retrieve([proof_file_name.encode(), retrieve_file_name.encode()])
            TIMER.end("match_retrieving_phase")
            if result.value == False:
                return result

            TIMER.start("match_comparing_phase")
            retrieve_img = plt.imread(retrieve_file_name)
            destination_img = plt.imread(destination_file_name)
            similar_rate = structural_similarity(retrieve_img, destination_img, multichannel= True)
            TIMER.end("match_comparing_phase")

            if similar_rate > 0.5:
                return Done(True, {"message": "Two image is similar (accuracy = {:.2f}%)".format(similar_rate * 100)})
            else:
                return Done(True, {"message": "Two image is different (accuracy = {:2f}%)".format((1 - similar_rate) * 100)})
        except Exception as e:
            return Done(False, {"message": "Something wrong", "where": "Unknown", "debug": repr(e)})
        finally:
            if os.path.isfile(retrieve_file_name):
                os.remove(retrieve_file_name)

    def _recv_from_server(self):
        store_phases = [
            "store_encrypting_phase",
            "store_generating_temp_proof_phase",
            "store_checking_phase",
            "store_sending_request",
            "store_receiving_agreement",
            "store_uploading_phase",
            "store_receiving_result",
            "store_generating_proofs"
        ]
        check_phases = [
            "check_generating_challenge_packet",
            "check_sending_challenge_packet",
            "check_receiving_proofs_from_server",
            "check_compare_phase"
        ]
        retrieve_phases = [
            "retrieve_checking_phase",
            "retrieve_send_request",
            "retrieve_wait_for_accept",
            "retrieve_download_phase",
            "retrieve_decrypting_phase"
        ]
        match_phases = [
            "match_retrieving_phase",
            "match_comparing_phase"
        ]
        while True:
            try:
                source, data, _ = self.__node__.recv()
                packet_dict = RSPacket.extract(data)
            except STCPSocketClosed as e:
                self.__print__(repr(e), "warning")
                break
            except Exception as e:
                self.__print__(repr(e), "error")
                break

            # Receive info from self
            if source == self.__node__.name and packet_dict["TYPE"] == CONST_TYPE.NOTIFICATION:
                print("\r" + packet_dict["DATA"].decode())
                if socket.gethostbyaddr(socket.gethostname())[0] != "raspberrypi":
                    keyboard.press_and_release("enter")
                self.__no_input__ = True
                continue
            
            if packet_dict["TYPE"] == CONST_TYPE.INPUT:  
                command_and_params = packet_dict["DATA"].split()
                command = command_and_params[0]
                params = command_and_params[1:]
                if command == b"$store":
                    result = self.store(params)
                    packet = RSPacket(
                        packet_type = CONST_TYPE.NOTIFICATION,
                        status= CONST_STATUS.NONE
                    )
                    if result.value == True:
                        packet.set_data(b"Store file successfully")
                    else:
                        packet.set_data(result.message.encode())
                        self.__print__("Message: " + result.message, "notification")
                        if hasattr(result, "where"):
                            self.__print__("Where: " + result.where, "notification")
                        if hasattr(result, "debug"):
                            self.__print__("Debug: " + result.debug, "notification")
                    self.__node__.send(self.__node__.name, packet.create())

                    total_time = 0
                    for phase in store_phases:
                        if TIMER.check(phase):
                            elapsed_time = TIMER.get(phase)
                            total_time += elapsed_time
                            self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                    self.__print__("Elapsed time for storing: {}s".format(total_time), "notification")

                if command == b"$check":
                    result = self.check(params)
                    packet = RSPacket(
                        packet_type = CONST_TYPE.NOTIFICATION,
                        status= CONST_STATUS.NONE
                    )
                    if result.value:
                        packet.set_data(b"Your file has been kept integrity")
                    else:
                        packet.set_data(result.message.encode())
                        self.__print__("Message: " + result.message, "notification")
                        if hasattr(result, "where"):
                            self.__print__("Where: " + result.where, "notification")
                        if hasattr(result, "debug"):
                            self.__print__("Debug: " + result.debug, "notification")
                    self.__node__.send(self.__node__.name, packet.create())

                    total_time = 0
                    for phase in check_phases:
                        if TIMER.check(phase):
                            elapsed_time = TIMER.get(phase)
                            total_time += elapsed_time
                            self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                    self.__print__("Elapsed time for checking: {}s".format(total_time), "notification")

                if command == b"$retrieve":
                    result = self.retrieve(params)
                    packet = RSPacket(
                        packet_type = CONST_TYPE.NOTIFICATION,
                        status= CONST_STATUS.NONE
                    )
                    if result.value:
                        packet.set_data("Your file save at {}".format(params[1]).encode())
                    else:
                        packet.set_data(result.message.encode())
                        self.__print__("Message: " + result.message, "notification")
                        if hasattr(result, "where"):
                            self.__print__("Where: " + result.where, "notification")
                        if hasattr(result, "debug"):
                            self.__print__("Debug: " + result.debug, "notification")
                    self.__node__.send(self.__node__.name, packet.create())

                    total_time = 0
                    for phase in retrieve_phases:
                        if TIMER.check(phase):
                            elapsed_time = TIMER.get(phase)
                            total_time += elapsed_time
                            self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                    self.__print__("Elapsed time for retrieving: {}s".format(total_time), "notification")

                if command == b"$match":
                    result = self.match(params)
                    packet = RSPacket(
                        packet_type = CONST_TYPE.NOTIFICATION,
                        status= CONST_STATUS.NONE
                    )
                    if result.value:
                        packet.set_data(result.message.encode())
                    else:
                        packet.set_data(result.message.encode())
                        self.__print__("Message: " + result.message, "notification")
                        if hasattr(result, "where"):
                            self.__print__("Where: " + result.where, "notification")
                        if hasattr(result, "debug"):
                            self.__print__("Debug: " + result.debug, "notification")
                    self.__node__.send(self.__node__.name, packet.create())

                    total_time = 0
                    for phase in match_phases:
                        if TIMER.check(phase):
                            elapsed_time = TIMER.get(phase)
                            total_time += elapsed_time
                            self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                    self.__print__("Elapsed time for matching: {}s".format(total_time), "notification")
            
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

            packet = RSPacket(
                packet_type = CONST_TYPE.INPUT,
                status= CONST_STATUS.NONE,
            )
            packet.set_data(data.encode())

            self.__node__.send(self.__node__.name, packet.create(), self.__signal_from_input__)

    def start(self):
        self.socket.connect(self.__server_address__)
        
        t = threading.Thread(target= self.__forwarder__.start)
        t.start()

        t = threading.Thread(target = self._recv_from_input)
        t.start()

        
        t = threading.Thread(target = self._recv_from_server)
        t.start()