import os
import time
import errno
import random
import hashlib
import threading
import functools

from .Timer import Timer
from .done import done

from .SecureFTP import SFTP
from .SecureFTP import STCPSocket
from .SecureFTP import StandardPrint
from .SecureFTP import __hash_a_file__
from .SecureFTP import LocalNode, ForwardNode
from .SecureFTP import NoCipher, XorCipher, AES_CTR

from .FileStorage import FileStorage, File, MAX_BUFFER, FileUtils

from .constant import SIZE_OF_INT
from .constant import DEFAULT_LENGTH_OF_KEY, DEFAULT_N_BLOCKS

from .RemoteStoragePacketFormat import RSPacket, CONST_STATUS, CONST_TYPE

SERVER_MANAGER_NAME = "SERVER_MANAGER"
LISTEN_SERVER_NAME = "LISTEN_SERVER_NAME"

TIMER = Timer()

def __split_to_n_part__(s, length_each_part):
    length = len(s)
    padding = b"\n" * (length - (length // length_each_part) * length_each_part)
    s += padding
    for i in range(0, length, length_each_part):
        yield s[i: i + length_each_part]


def prove_proofs(file_name, max_n_blocks, blocks_list, key):
    file = open(file_name, "rb")

    if max(blocks_list) >= max_n_blocks:
        raise Exception("There some incorrect block in block list")

    file_size = os.path.getsize(file_name)
    block_size = int(file_size / max_n_blocks)

    last_position_of_block = 0
    proofs = []
    for position_of_block in blocks_list:
        if last_position_of_block > position_of_block:
            raise Exception("Block list must have ascending order")

        offset = (position_of_block - last_position_of_block) * block_size
        file.seek(offset, FileUtils.FROM_CUR)
        block = file.read(block_size)

        digest = hashlib.sha1(key + block).digest()
        proofs.append(digest)

        last_position_of_block = position_of_block + 1

    file.close()

    return proofs

FILE_STORAGE = FileStorage("Storage", n_splits= 100)

class ResponseServer(object):
    def __init__(self, socket:STCPSocket, client_address, server_address, verbosities: tuple = ("error", )):
        self.socket = socket
        self.client_address = client_address
        self.server_address = server_address

        self.__node__ = LocalNode()
        self.forwarder = ForwardNode(self.__node__, self.socket)
        t = threading.Thread(target= self.forwarder.start)
        t.start()

        self.__print__ = StandardPrint(f"Response Server to {client_address}", verbosities)

        # Avoid warning from editor ~~
        self.__match_status__ = {}
        del self.__match_status__

    def store(self, packet_dict):
        TIMER.start("store_packet_checking")
        result = RSPacket.check(
            packet_dict, 
            expected_type = CONST_TYPE.STORE, 
            expected_status = CONST_STATUS.REQUEST, 
            is_dict= True)
        TIMER.end("store_packet_checking")

        if result.value == False:
            return done(False, {"where": "Receiving request store packet"}, inherit_from = result)

        try:
            TIMER.start("store_create_new_path")
            new_file_name = FILE_STORAGE.create_new_path(packet_dict["DATA"])
            packet = RSPacket(
                packet_type= CONST_TYPE.STORE,
                status= CONST_STATUS.ACCEPT
            )
        except Exception as e:
            packet = RSPacket(
                packet_type= CONST_TYPE.STORE,
                status= CONST_STATUS.DENY
            )
            return done(False, {"message": "Wrong in create file name", "where": "Find path to storing", "debug": repr(e)})
        finally:
            TIMER.end("store_create_new_path")
            self.__node__.send(self.forwarder.name, packet.create())

        try:
            TIMER.start("store_get_uploaded_file")
            cipher = NoCipher()
            ftp_address = self.server_address[0], self.server_address[1] + 1
            ftp = SFTP(
                address= ftp_address,
                address_owner= "self"
            )
            ftp.as_receiver(
                storage_path= new_file_name,
                cipher= cipher,
                save_file_after= 32 * 1024 ** 2, # 32 MB
                buffer_size= 3 * 1024 ** 2, # 3 MB
            )
            success = ftp.start()
            TIMER.end("store_get_uploaded_file")
            if success:
                FILE_STORAGE.save_info(new_file_name)
            
            if success:
                STATUS = CONST_STATUS.SUCCESS
            else:
                STATUS = CONST_STATUS.FAILURE

            packet = RSPacket(
                packet_type= CONST_TYPE.STORE,
                status= STATUS
            )
            self.__node__.send(self.forwarder.name, packet.create())
        except Exception as e:
            return done(False, {"message": "Something wrong", "debug": "Unknown", "debug": repr(e)})

    def __generate_reply_packet_for_checking__(self, data):
        try:
            p = 0
            
            file_size = int.from_bytes(data[p : p + SIZE_OF_INT], "big")
            p = p + SIZE_OF_INT
            
            len_key = int.from_bytes(data[p: p + SIZE_OF_INT], "big")
            p = p + SIZE_OF_INT

            key = data[p: p + len_key]
            p = p + len_key

            len_identifier = int.from_bytes(data[p: p + SIZE_OF_INT], "big")
            p = p + SIZE_OF_INT
            
            identifier = data[p : p + len_identifier]
            p = p + len_identifier
            
            n_positions = int.from_bytes(data[p : p + SIZE_OF_INT], "big")
            p = p + SIZE_OF_INT
            
            positions = data[p : p + n_positions * SIZE_OF_INT]
            p = p + n_positions * SIZE_OF_INT
            
            if p != len(data):
                return done(None, {"message": "Invalid packet"})

            to_int = lambda x: int.from_bytes(x, "big")
            positions = list(map(to_int, __split_to_n_part__(positions, length_each_part= SIZE_OF_INT)))

            check_size = lambda file_name: os.path.getsize(file_name) == file_size
            file_names = list(filter(check_size, FILE_STORAGE.iter(identifier)))

            TIMER.start("check_generating_proof")
            STATUS = CONST_STATUS.NOT_FOUND
            if len(file_names) == 1:
                STATUS = CONST_STATUS.FOUND
                proofs = prove_proofs(file_names[0], DEFAULT_N_BLOCKS, positions, key)
            
            TIMER.end("check_generating_proof")
            packet = RSPacket(
                packet_type= CONST_TYPE.CHECK,
                status= STATUS
            )
            if STATUS == CONST_STATUS.FOUND:
                packet.set_data(b"".join(proofs))
            else:
                packet.set_data(len(file_names).to_bytes(2, "big"))
            
            return done(packet.create(), {"status": STATUS})
        except Exception as e:
            return done(None, {"message": "Something wrong", "where": "Unknown", "debug": repr(e)})

    def check(self, packet_dict):
        result = self.__generate_reply_packet_for_checking__(packet_dict["DATA"])
        if result.value == None:
            return done(False, {"where": "Generate reply packet"}, inherit_from = result)

        self.__node__.send(self.forwarder.name, result.value)
        
        if result.status == CONST_STATUS.FOUND:
            return done(True)
        else:
            return done(False, {"message": "File not found"})

    def retrieve(self, packet_dict):
        try:
            TIMER.start("retrieve_checking_phase")
            result = RSPacket.check(
                packet_dict,
                CONST_TYPE.RETRIEVE,
                CONST_STATUS.REQUEST,
                is_dict= True
            )
            TIMER.end("retrieve_checking_phase")
            if result.value == False:
                return done(False, {"where": "Check input packet"}, inherit_from = result)

            TIMER.start("retrieve_get_file_information")
            file_size = int.from_bytes(packet_dict["DATA"][ : SIZE_OF_INT], "big")
            last_bytes = packet_dict["DATA"][SIZE_OF_INT: ]

            check_size = lambda file_name: os.path.getsize(file_name) == file_size
            file_names = list(filter(check_size, FILE_STORAGE.iter(last_bytes)))
            TIMER.end("retrieve_get_file_information")

            STATUS = CONST_STATUS.DENY
            if len(file_names) == 1:
                STATUS = CONST_STATUS.ACCEPT

            packet = RSPacket(
                CONST_TYPE.RETRIEVE,
                STATUS
            )
            if STATUS == CONST_STATUS.ACCEPT:
                packet.set_data(len(file_names).to_bytes(2, "big"))

            self.__node__.send(self.forwarder.name, packet.create())

            if STATUS == CONST_STATUS.DENY:
                return done(False, {"message": "Retrived data is {}-found".format(len(file_names))})

            TIMER.start("retrieve_transport_file")
            ftp_address = self.server_address[0], self.server_address[1] + 1
            ftp = SFTP(
                address= ftp_address,
                address_owner= "self"
            )
            ftp.as_sender(
                file_name= file_names[0],
                cipher= NoCipher(),
                buffer_size= int(2.9 * 1024 ** 2), # 2.9 MB
            )
            success = ftp.start()
            TIMER.end("retrieve_transport_file")

            if success:
                return done(True)
            else:
                return done(False, {"message": "Error in ftp", "where": "Transport file"})
        except Exception as e:
            return done(False, {"message": "Something wrong", "where": "Unknown", "debug": repr(e)})

    def start(self):
        self.__print__("Start reponse...", "notification")
        store_phases = [
            "store_packet_checking",
            "store_create_new_path",
            "store_get_uploaded_file"
        ]
        check_phases = [
            "check_generating_proof"
        ]
        retrieve_phases = [
            "retrieve_checking_phase",
            "retrieve_get_file_information",
            "retrieve_transport_file"
        ]

        while True:
            try:
                source, data, _ = self.__node__.recv()
                if source == None:
                    self.socket.sendall(b"$test alive")
                    # if connection is alive, ignore error and continue
                    self.__print__("Something wrong, source = None", "warning")
                    continue
            except Exception as e:
                if e.args[0] in (errno.ENOTSOCK, errno.ECONNREFUSED, errno.ECONNRESET, errno.EBADF):
                    self.__print__("Connection closed", "warning")
                    break
                raise e

            packet_dict = RSPacket.extract(data)

            if source == self.forwarder.name:
                try:
                    if packet_dict["TYPE"] == CONST_TYPE.STORE:
                        self.store(packet_dict)
                        total_time = 0
                        for phase in store_phases:
                            if TIMER.check(phase):
                                elapsed_time = TIMER.get(phase)
                                total_time += elapsed_time
                                self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                        self.__print__("Elapsed time for retrieving: {}s".format(total_time), "notification")

                    elif packet_dict["TYPE"] == CONST_TYPE.CHECK:
                        self.check(packet_dict)
                        total_time = 0
                        for phase in check_phases:
                            if TIMER.check(phase):
                                elapsed_time = TIMER.get(phase)
                                total_time += elapsed_time
                                self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                        self.__print__("Elapsed time for retrieving: {}s".format(total_time), "notification")

                    elif packet_dict["TYPE"] == CONST_TYPE.RETRIEVE:
                        self.retrieve(packet_dict)
                        total_time = 0
                        for phase in retrieve_phases:
                            if TIMER.check(phase):
                                elapsed_time = TIMER.get(phase)
                                total_time += elapsed_time
                                self.__print__("Elapsed time for {}: {}s".format(phase, elapsed_time), "notification")
                        self.__print__("Elapsed time for retrieving: {}s".format(total_time), "notification")
                    else:
                        self.__print__("Invalid command", "warning")
                except Exception as e:
                    self.__print__(repr(e), "error")
                    break
            else:
                self.__print__("Invalid source of packet", "warning")

        self.__print__("End response...", "notification")
        self.__node__.send(SERVER_MANAGER_NAME, b"$leave")


class ServerManager(object):
    def __init__(self, max_clients, address, verbosities: tuple = ("error", )):
        self.max_clients = max_clients
        self.clients = [None] * self.max_clients

        self.address = address

        self.__node__ = LocalNode(name= SERVER_MANAGER_NAME)
        self.__print__ = StandardPrint("ServerManager", verbosities)

    def start(self):
        while True:
            try:
                source, message, obj = self.__node__.recv()
            except Exception as e:
                self.__print__(repr(e), "error")
                break

            if message == b"$leave":
                leave = False
                for client in self.clients:
                    if client != None and client.__node__.name == source:
                        self.leave(client)
                        leave = True
                if not leave:
                    self.__print__(f"Client {source} cannot leave", "error")
                continue

            if source == LISTEN_SERVER_NAME and b"$join" in message:
                if not hasattr(self, "__join_status__"):
                    self.__join_status__ = True
                    continue
                
                if message == b"$join socket":
                    self.__join_socket__ = obj
                    
                if message == b"$join address":
                    self.__join_address__ = obj
                    
                if hasattr(self, "__join_socket__") and hasattr(self, "__join_address__"):
                    reponse_server = self.join(self.__join_socket__, self.__join_address__)
                    self.__node__.send(LISTEN_SERVER_NAME, b"$join return", reponse_server)

                    del self.__join_address__
                    del self.__join_socket__
                    del self.__join_status__

    def join(self, socket, address):
        try:
            slot = self.clients.index(None)
        except:
            return None

        socketbase = ResponseServer(socket, address, self.address, ("notification", "warning", "error"))
        self.clients[slot] = socketbase
        return socketbase

    def leave(self, client):
        client.__node__.close()
        index = self.clients.index(client)
        self.clients[index] = None


class ListenServer(object):
    def __init__(self, address, server_manager: ServerManager, verbosities = ("error", )):
        self.socket = STCPSocket()
        self.address = address
        self.base = server_manager
        self.__node__ = LocalNode(name = LISTEN_SERVER_NAME)

        self.__print__ = StandardPrint(f"Listen server {self.address}", verbosities)
    
    def __launch_response_server__(self, socket):
        while True:
            try:
                source, message, obj = self.__node__.recv()
            except Exception as e:
                self.__print__(repr(e), "error")
                return False

            if source == SERVER_MANAGER_NAME and message == b"$join return":
                response_server = obj
                if response_server == None:
                    socket.sendall(b"$send Server was out of service")
                    return False

                t = threading.Thread(target= response_server.start)
                t.setDaemon(True)
                t.start()
                return True

    def start(self):
        self.socket.bind(self.address)
        self.socket.listen()
        while True:
            socket, address = self.socket.accept()

            self.__node__.send(SERVER_MANAGER_NAME, b"$join")
            self.__node__.send(SERVER_MANAGER_NAME, b"$join socket", socket)
            self.__node__.send(SERVER_MANAGER_NAME, b"$join address", address)

            self.__launch_response_server__(socket)