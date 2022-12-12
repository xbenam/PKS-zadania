import os.path
import socket
import time
from binascii import crc32

import newClient

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
file_location = None
max_size = 250

def recieve_message(addr, fragments):
    message = ""
    i = 0
    while i != fragments:
        data, addr = s.recvfrom(1500)
        if int.from_bytes(data[4:8], "big") == crc32(data[8:]):
            s.sendto(b"\x06", addr)
            message += data[8:].decode()
            print(f"\033[0;32mRecieved {i+1}/{fragments}.\033[0m")
            i += 1
        else:
            print(f"\033[0;31mFragment {i+1} is corruppted.\033[0m")
            s.sendto(b"\x07", addr)
    return message


def recieve_file(addr, file_name):
    data, ad = s.recvfrom(1500)
    if data[0] == 5:
        fragments = int.from_bytes(data[1:4], "big")
        s.sendto(b"\x06", addr)
    with open(f"{file_location}\\jh{file_name}", "wb") as f:
        data, ad = s.recvfrom(1500)
        i = 1
        while True:
            if data[0] == 3 and int.from_bytes(data[4:8], "big") == crc32(data[8:]):
                f.write(data[8:])
                print(f"\033[0;32mRecieved [{i}/{fragments}]\033[0m")
                i += 1
                s.sendto(b"\x06", addr)
            else:
                print(f"\033[0;31mFragment {i} is corruppted.\033[0m")
                s.sendto(b"\x07", addr)
                data, ad = s.recvfrom(1500)
                continue
            if int.from_bytes(data[1:4], "big") + 1  < fragments:
                data, ad = s.recvfrom(1500)
            else:
                break
    print(f"File saved in {file_location}\\{file_name}")


def recieve_menu(keep_recieving, data, addr):
    global file_location
    data, addr = s.recvfrom(1500)
    match data[0]:
        case 5:
            s.sendto(b"\x06", addr)
            fragments = int.from_bytes(data[1:4], "big")
            print(f"Expected fragments {fragments}")
            print(f"from {addr[0]}: {(recieve_message(addr, fragments))}")
        case 4:
            s.sendto(b"\x06", addr)
            fragments = int.from_bytes(data[1:4], "big")
            file_name = recieve_message(addr, fragments)
            print(f"File name: {file_name}")
            if file_location is None:
                file_location = input("Set the path to directory: ")
                while not os.path.exists(file_location):
                    print("Directory does not exist.")
                    file_location = input("Set the path to directory: ")
            elif input("Would you like to change direcetory? (y/n)") == 'y':
                file_location = input("Set the path to directory: ")
                while not os.path.exists(file_location):
                    print("Directory does not exist.")
                    file_location = input("Set the path to directory: ")
            recieve_file(addr, file_name)
        case 8:
            s.sendto(b"\x09", addr)
        case 11:
            s.sendto(b"\x0f", addr)
            # time.sleep(1)
            keep_recieving[0] = False


def server_program():
    global file_location
    ct = False
    while not ct:
        try:
            data, addr = s.recvfrom(1500)
            if (data[0] == 0):
                s.sendto(b"\x01", addr)
                ct = True
            else:
                return
        except:
            time.sleep(1)
            continue
    keep_recieving = [True]
    while keep_recieving[0]:
        recieve_menu(keep_recieving, data, addr)



if __name__ == '__main__':
    host = socket.gethostname()
    print(host)
    port = 1234

    s.bind(("127.0.0.3", port))

    while True:
        server_program()