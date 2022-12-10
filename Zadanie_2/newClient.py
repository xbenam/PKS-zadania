import socket
import time
import math
from binascii import crc32


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
\x09    -   switch
\x0a    -   disconnect from server (client to server)
\x0b    -   disconnect message (server to client)
\x0c    -   [OPEN]
\x0d    -   [OPEN]
\x0e    -   [OPEN]
\x0f    -   [OPEN]

DATA:
[0]     FLAG
[1:4]   Fragment number
[4:8]   CRC
[8:]    data
"""

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
is_connected = False
max_size = 5

def establish_connection(addr):
    global is_connected
    tries = 0
    while tries < 5:
        try:
            print(f"trying to connect to {addr[0]} on port {addr[1]}")
            client_socket.connect(addr)
            client_socket.sendto(b"\x00", addr)
            data, add = client_socket.recvfrom(1024)
            if (data[0] == 1):
                print("Successfully connected to a server.")
                is_connected = True
                return 0
        except:
            tries += 1
            time.sleep(1)
            continue
    return 1

def init_message_fragments(addr, fragments):
    try:
        client_socket.sendto(b'\x05' + fragments.to_bytes(3, "big"), addr)
        data, ad = client_socket.recvfrom(1024)
        if data[0] == 6:
            return
    except:
        return init_message_fragments(addr, fragments)

def send_message(addr):
    message = input(" -> ")
    fragments = math.ceil(len(message) / max_size)
    init_message_fragments(addr, fragments)
    i = 0
    while i != fragments:
        frag = ""
        if (i+1) * max_size > len(message):
            frag = message[i * max_size:]
            crc = crc32(frag.encode()).to_bytes(4, "big")
            client_socket.sendto(b'\x02' +
                                 i.to_bytes(3, "big") +
                                 crc +
                                 message[i * max_size:].encode(), addr)
        else:
            frag = message[i * max_size:(i + 1) * max_size]
            crc = crc32(frag.encode()).to_bytes(4, "big")
            client_socket.sendto(b'\x02' +
                                 i.to_bytes(3, "big") +
                                 crc +
                                 message[i * max_size:(i + 1) * max_size].encode(), addr)
        print(f"Sending {i+1} fragment.",end=' ')
        data, ad = client_socket.recvfrom(1024)
        if data[0] == 6:
            print(f"Fragment {i+1} arrived.")
            i += 1
        else:
            print(f"Resending {i+1} fragment.")

def client_program():
    host = socket.gethostname()
    port = 5000

    if (establish_connection(("127.0.0.2", port))):
        print("Connection failed, server is not responding.")
        return

    while is_connected:
        mod = input("message m, file f:\n")
        match mod:
            case "message" | "m":
                send_message(("127.0.0.2", port))


    client_socket.close()


if __name__ == '__main__':
    client_program()