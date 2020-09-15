import os
import time
import errno
import random
import threading
import functools

from SecureFTP import SFTPServer
from SecureFTP import STCPSocket
from SecureFTP import StandardPrint
from SecureFTP import __hash_a_file__
from SecureFTP import LocalNode, ForwardNode
from SecureFTP import NoCipher, XorCipher, AES_CTR

from FileStorage import FileStorage, File, MAX_BUFFER

from constant import SIZE_OF_EACH_POSITION_IN_MATCH

SERVER_MANAGER_NAME = "SERVER_MANAGER"
LISTEN_SERVER_NAME = "LISTEN_SERVER_NAME"
MIN_VALUES_TO_MATCH = 100
MAX_VALUES_TO_MATCH = 100


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

        # avoid error warning from vscode
        self.__match_status__ = {}
        del self.__match_status__

    def __store_step_0__(self, params):
        self.__print__("In store step 0", "notification")
        if len(params) != 0:
            self.__node__.send(self.forwarder.name, b"$store invalid")
            return False
        
        self.__node__.send(self.forwarder.name, b"$store request_match")
        return True

    def __store_step_1__(self, params):
        self.__print__("In store step 1", "notification")
        return self.match(params)

    def __store_step_2__(self, params):
        self.__print__("In store step 2", "notification")
        if len(params) == 0:
            return False

        try:
            filename = FILE_STORAGE.create_new_path(params)
            self.__node__.send(self.forwarder.name, b"$store accept")

            cipher = NoCipher()
            ftp_address = self.server_address[0], self.server_address[1] + 1
            ftpserver = SFTPServer(
                address = ftp_address, 
                newfilename = filename, 
                cipher = cipher,
                save_file_after= 32 * 1024 ** 2, # 32MB
                buffer_size= 3 * 1024 ** 2, # 3MB
                verbosities= ("error", )
                )
            success = ftpserver.start()
            if not success:
                self.__node__.send(self.forwarder.name, b"$store failure Some error occurs when transport file")
            else:
                FILE_STORAGE.save_info(filename)
                self.__node__.send(self.forwarder.name, b"$store success Send file successfully")
        except Exception as e:
            self.__print__(repr(e), "error")
            return False

    def store(self, params):
        # step 0: 
        #   client send $store
        #   server send $store request_match
        # step 1: match
        # step 2: if match == success:
        #   client send $store last_bytes
        #   server send $store accept
        #   FTP

        self.__store_step_0__(params)

        _, data, _ = self.__node__.recv(source = self.forwarder.name)
        if data[:6] != b"$match":
            return False

        params = data[7:]
        success = self.__store_step_1__(params)
        if success:
            return False
        
        _, data, _ = self.__node__.recv(source = self.forwarder.name)
        if data[:6] != b"$store":
            return False
        
        params = data[7:]
        success = self.__store_step_2__(params)
        if not success:
            return False
        
        return True

    def __match_step_0__(self, params):
        self.__print__("In match step 0", "notification")
        condition = params[0] == 0 and len(params) > (2 + SIZE_OF_EACH_POSITION_IN_MATCH)
        
        if not condition:
            self.__node__.send(self.forwarder.name, b"$match invalid")
            if hasattr(self, "__match_status__"):
                del self.__match_status__
            return False

        try:
            params_t = []
            params_t.append(params[0:1])
            params_t.append(params[2: 2 + SIZE_OF_EACH_POSITION_IN_MATCH])
            params_t.append(params[2 + SIZE_OF_EACH_POSITION_IN_MATCH: ])
            params = params_t
            
            file_size = int.from_bytes(params[1], "big")
            last_bytes = params[2]
            
            n_values_to_match = random.randint(MIN_VALUES_TO_MATCH, MAX_VALUES_TO_MATCH)
            n_values_to_match = min(n_values_to_match, file_size)
            
            min_value = random.randint(0, file_size - n_values_to_match)
            max_value = min(file_size, MAX_BUFFER)
            
            positions = random.sample(range(min_value, max_value), n_values_to_match)

            to_bytes = lambda x: int.to_bytes(x, SIZE_OF_EACH_POSITION_IN_MATCH, "big")
            request_packet = b"$match \x00 " + b"".join(map(to_bytes, positions))

            self.__node__.send(self.forwarder.name, request_packet)
            self.__match_status__ = {}
            self.__match_status__["file_size"] = file_size
            self.__match_status__["last_bytes"] = last_bytes
            self.__match_status__["positions"] = positions
            self.__match_status__["n_values_to_match"] = n_values_to_match
        except Exception as e:
            if hasattr(self, "__match_status__"):
                del self.__match_status__
            self.__print__(repr(e), "error")
            return False
        
        return True

    def __match_step_1__(self, params):
        self.__print__("In match step 1", "notification")
        condition = params[0] == 1 and len(params[2:]) == self.__match_status__["n_values_to_match"]
        
        if not condition:
            self.__node__.send(self.forwarder.name, b"$match invalid")
            if hasattr(self, "__match_status__"):
                del self.__match_status__
            return False
        
        try:
            # get reply packet
            reply_identifier = params[2:]

            # filter file which file size equals to expected size
            file_size = self.__match_status__["file_size"]
            check_size = lambda file_name: os.path.getsize(file_name) == file_size
            file_names = list(filter(check_size, FILE_STORAGE.iter(self.__match_status__["last_bytes"])))

            # get values at all positions in all filtered file
            positions = self.__match_status__["positions"]
            min_position = min(positions)
            max_position = max(positions)

            get_identifier = lambda file_name: File.get_elements(file_name, positions, min_position, max_position)
            identifiers = map(get_identifier, file_names)

            # compare all identifiers to reply_identifier
            compare_to_reply_identifier = lambda s: s == reply_identifier
            results_in_list = map(compare_to_reply_identifier, identifiers)
            final_result = sum(results_in_list) 

            if final_result == 1:
                sent_msg = b"$match success File found"
            elif final_result == 0:
                sent_msg = b"$match failure File not found"
            else:
                sent_msg = b"$match failure Many file matching"
            self.__node__.send(self.forwarder.name, sent_msg)
        except Exception as e:
            self.__print__(repr(e), "error")
            return False
        finally:
            del self.__match_status__

        if final_result != 1:
            return False
        return True

    def match(self, params):
        # step 0:
        #    client send $match file_size+last_bytes
        #    server send $match pos1pos2pos3pos4...
        # step 1:
        #    client send $match val1val2val3val4...
        #    server send $match success or $match failure 

        success = self.__match_step_0__(params)
        if not success:
            return False

        _, data, _ = self.__node__.recv(source = self.forwarder.name)
        if data[:6] != b"$match":
            return False

        params = data[7:]
        success = self.__match_step_1__(params)
        if not success:
            return False

        return True

    def start(self):
        self.__print__("Start reponse...", "notification")
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

            command_and_params = data.split()
            command = command_and_params[0]
            params = command_and_params[1:]

            if source == self.forwarder.name:
                try:
                    if command == b"$store":
                        self.store(params)
                    elif command == b"$match":
                        params = data[7:]
                        self.match(params)
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