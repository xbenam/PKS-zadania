import os
import socket
import threading
from binascii import crc32
from math import ceil, floor
from time import sleep


# class packet:
#     def __init__(self, flag : bytes, number: Optional[int], data: Optional[bytes]) -> None:
#         self.flag = flag
#         self.num = number
#         self.data = data
#     def __bytes__(self):
#         return b"flag+

class client:
    # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    is_connected = False
    idle = True
    max_size = 1456
    file_location = None
    host = ""
    port = 0
    client_IP = ""
    client_port = ""
    keep_alive_thread = None
    is_listening = False
    switch = False

    def create_socket(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def connect(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.tries = 0
        while self.tries < 5:
            try:
                print(f"trying to connect to {self.host} on port {self.port}")
                self.s.connect((self.host, self.port))
                # pac = packet(b"\x00", None, None)
                self.s.sendto(b"\x00", (self.host, self.port))
                data, add = self.s.recvfrom(1456)
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

    def bind_socket(self, host: str, port: int):
        self.s.bind((host, port))
        self.is_listening = True

    def listening(self):
        while self.is_listening:
            try:
                data, add = self.s.recvfrom(1500)
                self.client_IP = add[0]
                self.client_port = add[1]
                if (data[0] == 0):
                    self.s.sendto(b"\x01", (self.client_IP, self.client_port))
                    self.is_listening = False
                    self.is_connected = True
                    print(f"Client IP: {self.client_IP} and port: {self.client_port}")
                else:
                    return
            except:
                # time.sleep(1)
                continue

    def recieve_message(self, fragments):
        message = ""
        i = 0
        while i != fragments:
            data, add = self.s.recvfrom(1500)
            if int.from_bytes(data[4:8], "big") == crc32(data[8:]):
                self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                message += data[8:].decode()
                print(f"\033[0;32mRecieved {i + 1}/{fragments}.\033[0m")
                i += 1
            else:
                print(f"\033[0;31mFragment {i + 1} is corruppted.\033[0m")
                self.s.sendto(b"\x07", (self.client_IP, self.client_port))
        return message

    def recieve_file(self, file_name):
        data, add = self.s.recvfrom(1500)
        if data[0] == 5:
            fragments = int.from_bytes(data[1:4], "big")
            self.s.sendto(b"\x06", (self.client_IP, self.client_port))
        with open(f"{self.file_location}\\jh{file_name}", "wb") as f:
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
            data, add = self.s.recvfrom(1500)
            match data[0]:

                case 5:
                    self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                    fragments = int.from_bytes(data[1:4], "big")
                    print(f"Expected fragments {fragments}")
                    print(f"from {self.client_IP}: {(self.recieve_message(fragments))}")

                case 4:
                    self.s.sendto(b"\x06", (self.client_IP, self.client_port))
                    fragments = int.from_bytes(data[1:4], "big")
                    file_name = self.recieve_message(fragments)
                    print(f"File name: {file_name}")
                    if self.file_location is None:
                        self.file_location = input("Set the path to directory: ")
                        while not os.path.exists(self.file_location):
                            print("Directory does not exist.")
                            self.file_location = input("Set the path to directory: ")
                    elif input(f"Current file location: {self.file_location}\nWould you like to change direcetory? (y/n)") == 'y':
                        self.file_location = input("Set the path to directory: ")
                        while not os.path.exists(self.file_location):
                            print("Directory does not exist.")
                            self.file_location = input("Set the path to directory: ")
                    self.recieve_file(file_name)

                case 8:
                    self.s.sendto(b"\x09", (self.client_IP, self.client_port))

                case 10:
                    self.s.sendto(b"\x0f", (self.client_IP, self.client_port))
                    self.switch = True

                case 11:
                    self.s.sendto(b"\x0f", (self.client_IP, self.client_port))
                    self.is_connected = False
                    # time.sleep(1)
                    # keep_recieving[0] = False

    def send_menu(self):
        mod = input("\033[0;33mTo send message type:\tMESSAGE or M\nTo send file type:\t\tFILE or F:\n"
                    "To disconnect type:\t\tQUIT or Q\nTo change frag size:\tCHANGE or C\n\033[0m -> ")
        self.idle = False
        match mod.lower():
            case "message" | "m":
                self.send_message()
            case "file" | "f":
                self.send_file()
            case "quit" | "q":
                self.disconnect()
            case "swith" | "s":
                self.switch = True
                self.s.sendto(b"\x0a", (self.host, self.port))
                self.disconnect()
            case "change" | "c":
                print(f"Current fragment size: {self.max_size}")
                self.max_size = 0
                while self.max_size > 1464 or self.max_size <= 0:
                    self.max_size = int(input("Set new maximal fragment size [1-1464]: "))
        self.idle = True

    def keep_alive(self):
        while self.is_connected:
            sleep(5)
            if self.idle:
                try:
                    self.s.sendto(b"\x08", (self.host, self.port))
                    data, ad = self.s.recvfrom(1456)
                    if data[0] == 9:
                        continue
                except:
                    print("Server did not respons.")
                    continue

    def disconnect(self):
        try:
            self.s.sendto(b"\x0b", (self.host, self.port))
            data, ad = self.s.recvfrom(1456)
            if data[0] == 15:
                self.is_connected = False
                self.keep_alive_thread.join()
                return
        except:
            self.disconnect()

    def init_fragments(self, fragments: int, flag: bytes):
        try:
            f = flag
            self.s.sendto(f + fragments.to_bytes(3, "big"), (self.host, self.port))
            data, ad = self.s.recvfrom(1456)
            if data[0] == 6:
                return
        except:
            self.init_fragments(fragments, flag)

    def sender(self, fragments, message):
        i = 0
        error = input("would you like send a corrupted fragment? (y/n)")
        done = False
        while i != fragments:
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
            data, ad = self.s.recvfrom(1456)
            if data[0] == 6:
                print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
                i += 1
            else:
                print(f"\033[0;31mResending {i + 1} fragment.\033[0m")

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
        # a = os.path.isfile(file_path)
        while not os.path.isfile(file_path):
            print("File does not exist.")
            file_path = input("absolute file path: ")
        file_name = file_path.split("\\")[-1]
        self.send_file_name(file_name)
        file_size = os.stat(file_path).st_size
        fragments = ceil(file_size / self.max_size)
        self.init_fragments(fragments, b"\x05")
        error = input("would you like send a corrupted fragment? (y/n)")
        done = False
        with open(file_path, 'rb') as f:
            i = 0
            content = f.read(self.max_size)
            while i != fragments:
                crc = crc32(content).to_bytes(4, "big")
                a = (b'\x02' + i.to_bytes(3, "big") + crc + content)
                # print(len(a))
                if error == 'y' and not done and i == floor(fragments / 2):
                    crc = (1).to_bytes(4, "big")
                    done = True
                self.s.sendto(b'\x03' +
                              i.to_bytes(3, "big") +
                              crc +
                              content, (self.host, self.port))
                print(f"Sending {i + 1} fragment. [{len(a)} B]", end=' ')
                data, ad = self.s.recvfrom(1456)
                if data[0] == 6:
                    print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
                    content = f.read(self.max_size)
                    i += 1
                else:
                    print(f"\033[0;31mResending {i + 1} fragment.\033[0m")

    def client_part(self):
        while self.is_connected:
            self.send_menu()
        if self.switch:
            p = input("Slect port: ")
            self.s.sendto(b"\x0d" + p.encode(), (self.host, self.port))
            ip = self.s.getsockname()[0]
            self.s.close()
            self.switch = False
            self.run_server(ip, int(p))

    def server_part(self):
        print(self.s.getsockname())
        while not self.switch:
            self.listening()
            self.recieving()
        if self.switch:
            data, add = self.s.recvfrom(1500)
            if data[0] == 13:
                p = int(data[1:].decode())
                self.s.close()
                self.switch = False
                self.run_client(self.client_IP, p)


    def run_client(self, host, port):
        self.create_socket()
        self.connect(host, port)
        self.client_part()

    def run_server(self, host, port):
        self.create_socket()
        self.bind_socket(host, port)
        self.server_part()

if __name__ == '__main__':
    cl = client()
    # cl.create_socket()
    x = int(input("port:"))
    cl.run_client("127.0.0.3", x)
    # cl.keep_alive_thread.start()
    # cl.client_part()

    # server
    # sr = client()
    # sr.create_socket()
    # sr.bind_socket("127.0.0.3", 1234)

