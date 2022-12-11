import socket
import time
import math
from binascii import crc32
import threading
import os
import newServer

"""
Fags:
-velkost    1 byte
-interpretovane ako cislo v binarnej sustave
\x00    -   comm request (client to server)
\x01    -   comm replay (server to client)
\x02    -   send message
\x03    -   send file
\x04    -   file name
\x05    -   fragment count
\x06    -   recieved all fragments
\x07    -   request for resend 
\x08    -   keep alive
\x09    -   keep alive respond
\x0a    -   switch
\x0b    -   disconnect from server (client to server)
\x0c    -   disconnect message (server to client)
\x0d    -   [OPEN]
\x0e    -   [OPEN]
\x0f    -   accept

DATA:
[0]     FLAG
[1:4]   Fragment number
[4:8]   CRC
[8:]    data
"""

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
is_connected = False
idle = True
max_size = 250

host = ""
port = 0

def establish_connection(addr):
    global is_connected
    tries = 0
    while tries < 5:
        try:
            print(f"trying to connect to {addr[0]} on port {addr[1]}")
            client_socket.connect(addr)
            client_socket.sendto(b"\x00", addr)
            data, add = client_socket.recvfrom(1456)
            if (data[0] == 1):
                print("Successfully connected to a server.")
                is_connected = True
                return 0
        except:
            tries += 1
            time.sleep(1)
            continue
    return 1


def init_fragments(addr, fragments, flag):
    try:
        f = flag
        client_socket.sendto(f + fragments.to_bytes(3, "big"), addr)
        # time.sleep(1)
        data, ad = client_socket.recvfrom(1456)
        if data[0] == 6:
            return
    except:
        return init_fragments(addr, fragments, flag)


def sender(addr, fragments, content):
    i = 0
    error = input("would you like send a corrupted fragment? (y/n)")
    done = False
    while i != fragments:
        frag = ""
        if (i + 1) * max_size > len(content):
            frag = content[i * max_size:]
            crc = crc32(frag.encode()).to_bytes(4, "big")
            if error == 'y' and not done and i == math.floor(fragments / 2):
                crc = (1).to_bytes(4, "big")
                done = True
            client_socket.sendto(b'\x02' +
                                 i.to_bytes(3, "big") +
                                 crc +
                                 content[i * max_size:].encode(), addr)
        else:
            frag = content[i * max_size:(i + 1) * max_size]
            crc = crc32(frag.encode()).to_bytes(4, "big")
            if error == 'y' and not done and i == math.floor(fragments / 2):
                crc = (1).to_bytes(4, "big")
                done = True
            client_socket.sendto(b'\x02' +
                                 i.to_bytes(3, "big") +
                                 crc +
                                 content[i * max_size:(i + 1) * max_size].encode(), addr)
        print(f"Sending {i + 1} fragment.", end=' ')
        data, ad = client_socket.recvfrom(1456)
        if data[0] == 6:
            print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
            i += 1
        else:
            print(f"\033[0;31mResending {i + 1} fragment.\033[0m")


def send_message(addr):
    message = input("Write your message.\n -> ")
    fragments = math.ceil(len(message) / max_size)
    init_fragments(addr, fragments, b'\x05')
    sender(addr, fragments, message)


def send_file_name(addr, file_name):
    fragments = math.ceil(len(file_name) / max_size)
    init_fragments(addr, fragments, b"\x04")
    sender(addr, fragments, file_name)


def send_file(addr):
    file_path = input("absolute file path: ")
    # a = os.path.isfile(file_path)
    while not os.path.isfile(file_path):
        print("File does not exist.")
        file_path = input("absolute file path: ")
    file_name = file_path.split("\\")[-1]
    send_file_name(addr, file_name)
    file_size = os.stat(file_path).st_size
    fragments = math.ceil(file_size / max_size)
    init_fragments(addr, fragments, b"\x05")
    error = input("would you like send a corrupted fragment? (y/n)")
    done = False
    with open(file_path, 'rb') as f:
        i = 0
        content = f.read(max_size)
        while i != fragments:
            crc = crc32(content).to_bytes(4, "big")
            a = (b'\x02' + i.to_bytes(3, "big") + crc + content)
            # print(len(a))
            if error == 'y' and not done and i == math.floor(fragments / 2):
                crc = (1).to_bytes(4, "big")
                done = True
            client_socket.sendto(b'\x03' +
                                 i.to_bytes(3, "big") +
                                 crc +
                                 content, addr)
            print(f"Sending {i + 1} fragment. [{len(a)} B]", end=' ')
            data, ad = client_socket.recvfrom(1456)
            if data[0] == 6:
                print(f"\033[0;32mFragment {i + 1} arrived.\033[0m")
                content = f.read(max_size)
                i += 1
            else:
                print(f"\033[0;31mResending {i + 1} fragment.\033[0m")


def keep_alive(addr):
    global is_connected
    global idle
    while is_connected:
        time.sleep(5)
        if idle:
            try:
                # client_socket.settimeout(2)
                client_socket.sendto(b"\x08", addr)
                data, ad = client_socket.recvfrom(1456)
                if data[0] == 9:
                    continue
            except:
                print("Server did not respons.")
                continue


def disconnect(addr):
    global is_connected
    try:
        client_socket.sendto(b"\x0b", addr)
        data, ad = client_socket.recvfrom(1456)
        if data[0] == 15:
            is_connected = False
            return
    except:
        disconnect(addr)


def client_program():
    global idle
    global max_size
    # t2 = threading.Thread(target=keep_alive, args=[(host, port)])

    if (establish_connection((host, port))):
        print("Connection failed, server is not responding.")
        return
    # t2.start()
    while is_connected:
        mod = input("\033[0;33mTo send message type:\tMESSAGE or M\nTo send file type:\t\tFILE or F:\n"
                    "To disconnect type:\t\tQUIT or Q\nTo change frag size:\tCHANGE or C\n\033[0m -> ")
        idle = False
        match mod.lower():
            case "message" | "m":
                send_message((host, port))
            case "file" | "f":
                send_file((host, port))
            case "quit" | "q":
                disconnect((host, port))
            case "change" | "c":
                print(f"Current fragment size: {max_size}")
                max_size = 0
                a = max_size
                while max_size > 1464 or max_size <= 0:
                    max_size = int(input("Set new maximal fragment size [1-1464]: "))

        idle = True
    # t2.join()
    client_socket.close()


if __name__ == '__main__':
    max_size = int(input("Set new maximal fragment size [1-1464]: "))
    host = "127.0.0.2"
    port = 1234
    t1 = threading.Thread(target=client_program)
    t1.start()