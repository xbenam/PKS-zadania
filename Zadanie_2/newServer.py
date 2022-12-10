import socket
import time
from binascii import crc32

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def recieve_message(addr, fragments):
    message = ""
    i = 0
    while i != fragments:
        data, addr = server_socket.recvfrom(1024)
        if int.from_bytes(data[4:8], "big") == crc32(data[8:]):
            server_socket.sendto(b"\x06", addr)
            message += data[8:].decode()
            print(f"Recieved {i+1}/{fragments}.")
            i += 1
        else:
            print(f"Fragment {i+1} is invalid or did not arrive at all.")
            server_socket.sendto(b"\x07", addr)

    print("from "+ addr[0] + ": " + message)


def server_program():
    host = socket.gethostname()
    print(host)
    ct = False
    port = 5000

    server_socket.bind(("127.0.0.2", port))

    while not ct:
        data, addr = server_socket.recvfrom(1024)
        if (data[0] == 0):
            server_socket.sendto(b"\x01", addr)
            ct = True
        else:
            return

    while True:
        data, addr = server_socket.recvfrom(1024)
        match data[0]:
            case 5:
                server_socket.sendto(b"\x06", addr)
                fragments = int.from_bytes(data[1:4], "big")
                print(f"Expected fragments {fragments}")
                recieve_message(addr, fragments)
    conn.close()


if __name__ == '__main__':
    while True:
        server_program()