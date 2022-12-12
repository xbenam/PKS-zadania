import os
import socket
import threading
from binascii import crc32
from math import ceil, floor
from time import sleep


class communication_node:
    is_connected = False
    idle = True
    max_size = 1456
    file_location = None
    host = ""
    port = 0
    client_IP = ""
    client_port = ""
    keep_alive_thread = None
    is_listening = True
    switch = False
    mod = ""

    def create_socket(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(100)

    def connect(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.tries = 0
        self.s.settimeout(1)
        while self.tries < 5:
            try:
                self.s
                print(f"Trying to connect to {self.host} on port {self.port}")
                self.s.connect((self.host, self.port))
                self.s.sendto(b"\x00", (self.host, self.port))
                data, add = self.s.recvfrom(1500)
                if (data[0] == 1):
                    print("Successfully connected to a server.")
                    self.is_connected = True
                    self.keep_alive_thread = threading.Thread(target=self.keep_alive)
                    self.keep_alive_thread.start()
                    break
            except:
                self.tries += 1
                sleep(1)
                continue
        self.s.settimeout(100)
    def bind_socket(self, host: str, port: int):
        self.s.bind((host, port))
        self.is_listening = True

    def listening(self):
        while self.is_listening:
            try:
                print(self.s.getsockname())
                data, add = self.s.recvfrom(1500)
                self.client_IP = add[0]
                self.client_port = add[1]
                if (data[0] == 0):
                    self.s.sendto(b"\x01", (self.client_IP, self.client_port))
                    self.is_listening = False
                    self.is_connected = True
                    print(f"\033[0;35mClient IP: {self.client_IP} and port: {self.client_port}\033[0m")
                else:
                    return
            except:
                exit(0)

    def recieve_message(self, fragments):
        message = ""
        i = 0
        j = 0
        while i != fragments:
            try:
                data, add = self.s.recvfrom(1500)
                if int.from_bytes(data[4:8], "big") == crc32(data[8:]):
                    self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                    message += data[8:].decode()
                    print(f"\033[0;32mRecieved {i + 1}/{fragments}.\033[0m Fragment size: [{len(data[8:].decode())} B]")

                    i += 1
                    j += 1
                else:
                    j += 1
                    print(f"\033[0;31mFragment {i + 1} is corruppted.\033[0m")
                    self.s.sendto(b"\x07", (self.client_IP, self.client_port))
            except:
                exit(0)
        print(f"\033[0;34mRecieved: {j} fragments\nAccepted: {i} fragments\nSize of accpeted data: {len(message)} B\033[0m")
        return message

    def recieve_file(self, file_name):
        data, add = self.s.recvfrom(1500)
        if data[0] == 5:
            fragments = int.from_bytes(data[1:4], "big")
            self.s.sendto(b"\x06", (self.client_IP, self.client_port))
        with open(f"{self.file_location}\\{file_name}", "wb") as f:
            data, ad = self.s.recvfrom(1500)
            i = 1
            while True:
                if data[0] == 3 and int.from_bytes(data[4:8], "big") == crc32(data[8:]):
                    f.write(data[8:])
                    print(f"\033[0;32mRecieved [{i}/{fragments}]\033[0m")
                    i += 1
                    self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                else:
                    print(f"\033[0;31mFragment {i} is corruppted.\033[0m")
                    self.s.sendto(b"\x07", (self.client_IP, self.client_port))
                    data, ad = self.s.recvfrom(1500)
                    continue
                if int.from_bytes(data[1:4], "big") + 1 < fragments:
                    data, ad = self.s.recvfrom(1500)
                else:
                    break
        print(f"File saved in {self.file_location}\\{file_name}")

    def recieving(self):
        while self.is_connected:
            try:

                data, add = self.s.recvfrom(1500)
                match data[0]:

                    case 5:     # MESSAGE
                        self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                        fragments = int.from_bytes(data[1:4], "big")
                        print(f"Expected fragments {fragments}")
                        print(f"From {self.client_IP}: {(self.recieve_message(fragments))}")

                    case 4:     # FILE
                        self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                        fragments = int.from_bytes(data[1:4], "big")
                        file_name = self.recieve_message(fragments)
                        print(f"File name: {file_name}")
                        if self.file_location is None:
                            self.file_location = input("Set the path to directory: ")
                            while not os.path.exists(self.file_location):
                                print("Directory does not exist.")
                                self.file_location = input("Set the path to directory: ")
                        elif input(f"Current file location: {self.file_location}\nWould you like to change direcetory? (y/n)\n -> ") == 'y':
                            self.file_location = input("Set the path to directory: ")
                            while not os.path.exists(self.file_location):
                                print("Directory does not exist.")
                                self.file_location = input("Set the path to directory: ")
                        self.recieve_file(file_name)

                    case 8:     # KEEPALIVE
                        self.s.sendto(b"\x09", (self.client_IP, self.client_port))
                        continue

                    case 10:    # SWITCH
                        self.s.sendto(b"\x0f", (self.client_IP, self.client_port))
                        self.switch = True
                        continue

                    case 11:    # DISCONNECT
                        self.s.sendto(b"\x0f", (self.client_IP, self.client_port))
                        print(f"User with {self.client_IP} has disconnected.")
                        self.is_connected = False
                        if self.switch:
                            break
                        elif input("End communication? (y/n)\n -> ") != "y":
                            self.is_listening = True
                            break
                        continue
                if input("Would you like to switch roles? (y/n)\n -> ") == "y":
                    self.s.sendto(b"\x0c", (self.client_IP, self.client_port))
                else:
                    self.s.sendto(b"\x0e", (self.client_IP, self.client_port))

            except:
                exit(0)

    def send_menu(self):
        may = True
        try:
            if self.mod == "":
                self.mod = input("To send message type:\t\033[0;33mMESSAGE or M\n\033[0mTo send file type:\t\033[0;33mFILE or F:\n\033[0m"
                            "To change frag size:\t\033[0;33mCHANGE or C\033[0m\nTo switch roles:\t\033[0;33mSWITCH or S"
                            "\033[0m\nTo disconnect type:\t\033[0;33mQUIT or Q\n\033[0m -> ")
            self.idle = False
            match self.mod.lower():
                case "message" | "m":
                    self.send_message()
                case "file" | "f":
                    self.send_file()
                case "quit" | "q":
                    self.disconnect()
                    may = False
                case "swith" | "s":
                    self.switch = True
                    self.s.sendto(b"\x0a", (self.host, self.port))
                    self.disconnect()
                    may = False
                case "change" | "c":
                    print(f"Current fragment size: {self.max_size}")
                    self.max_size = 0
                    while self.max_size > 1464 or self.max_size <= 0:
                        self.max_size = int(input("Set new maximal fragment size [1-1464]: "))
                    self.mod = ""
                    may = False
            self.mod = ""
            if may:
                print("Wainting for permission to continue as client.")
                data, ad = self.s.recvfrom(1500)
                if data[0] == 12:
                    self.mod = "s"
            self.idle = True

        except:
            exit(0)

    def keep_alive(self):
        while self.is_connected:
            sleep(5)
            if self.idle:
                try:
                    self.s.sendto(b"\x08", (self.host, self.port))
                    data, ad = self.s.recvfrom(1500)
                    if data[0] == 9:
                        continue
                except:
                    print("Server did not respons.")
                    continue

    def disconnect(self):

        try:
            self.s.sendto(b"\x0b", (self.host, self.port))
            data, ad = self.s.recvfrom(1500)
            if data[0] == 15:
                self.is_connected = False
                self.keep_alive_thread.join()
                return
        except:
            exit(0)

    def init_fragments(self, fragments: int, flag: bytes):
        try:
            f = flag
            self.s.sendto(f + fragments.to_bytes(3, "big"), (self.host, self.port))
            data, ad = self.s.recvfrom(1500)
            if data[0] == 6:
                return
        except:
            exit(0)

    def sender(self, fragments, message):
        i = 0
        error = input("would you like send a corrupted fragment? (y/n)\n -> ")
        done = False
        while i != fragments:
            try:
                frag = ""
                if (i + 1) * self.max_size > len(message):
                    frag = message[i * self.max_size:]
                    crc = crc32(frag.encode()).to_bytes(4, "big")
                    if error == 'y' and not done and i == floor(fragments / 2):
                        crc = (1).to_bytes(4, "big")
                        done = True
                    self.s.sendto(b'\x02' + i.to_bytes(3, "big") + crc + message[i * self.max_size:].encode(),
                                  (self.host, self.port))
                else:
                    frag = message[i * self.max_size:(i + 1) * self.max_size]
                    crc = crc32(frag.encode()).to_bytes(4, "big")
                    if error == 'y' and not done and i == floor(fragments / 2):
                        crc = (1).to_bytes(4, "big")
                        done = True
                    self.s.sendto(
                        b'\x02' + i.to_bytes(3, "big") + crc + message[i * self.max_size:(i + 1) * self.max_size].encode(),
                        (self.host, self.port))
                print(f"Sending {i + 1} fragment.", end=' ')
                data, ad = self.s.recvfrom(1500)
                if data[0] == 6:
                    print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
                    i += 1
                else:
                    print(f"\033[0;31mResending {i + 1} fragment.\033[0m")
            except:
                exit(0)

    def send_message(self):
        message = input("Write your message.\n -> ")
        fragments = ceil(len(message) / self.max_size)
        self.init_fragments(fragments, b'\x05')
        self.sender(fragments, message)

    def send_file_name(self, file_name):
        fragments = ceil(len(file_name) / self.max_size)
        self.init_fragments(fragments, b"\x04")
        self.sender(fragments, file_name)

    def send_file(self):
        file_path = input("absolute file path: ")
        while not os.path.isfile(file_path):
            print("File does not exist.")
            file_path = input("absolute file path: ")
        file_name = file_path.split("\\")[-1]
        self.send_file_name(file_name)
        file_size = os.stat(file_path).st_size
        fragments = ceil(file_size / self.max_size)
        self.init_fragments(fragments, b"\x05")
        error = input("would you like send a corrupted fragment? (y/n)\n -> ")
        done = False
        with open(file_path, 'rb') as f:
            try:
                i = 0
                content = f.read(self.max_size)
                while i != fragments:
                    crc = crc32(content).to_bytes(4, "big")
                    a = (b'\x02' + i.to_bytes(3, "big") + crc + content)
                    if error == 'y' and not done and i == floor(fragments / 2):
                        crc = (1).to_bytes(4, "big")
                        done = True
                    self.s.sendto(b'\x03' +
                                  i.to_bytes(3, "big") +
                                  crc +
                                  content, (self.host, self.port))
                    print(f"Sending {i + 1} fragment. [{len(a)} B]", end=' ')
                    data, ad = self.s.recvfrom(1500)
                    if data[0] == 6:
                        print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
                        content = f.read(self.max_size)
                        i += 1
                    else:
                        print(f"\033[0;31mResending {i + 1} fragment.\033[0m")
            except:
                exit(0)

    def client_part(self):
        while self.is_connected:
            self.send_menu()
        try:
            if self.switch:
                p = input("Slect port: ")
                self.s.sendto(b"\x0d" + p.encode(), (self.host, self.port))
                ip = self.s.getsockname()[0]
                self.s.close()
                self.switch = False
                self.run_server(ip, int(p))
        except:
            exit(0)

    def server_part(self):

        while not self.switch and self.is_listening:
            self.listening()
            self.recieving()
        try:
            if self.switch:
                data, add = self.s.recvfrom(1500)
                if data[0] == 13:
                    p = int(data[1:].decode())
                    self.s.close()
                    self.switch = False
                    self.run_client(self.client_IP, p)
        except:
            exit(0)


    def run_client(self, host, port):
        self.create_socket()
        self.connect(host, port)
        self.client_part()

    def run_server(self, host, port):
        self.create_socket()
        self.bind_socket(host, port)
        self.server_part()


