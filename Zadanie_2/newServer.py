import socket


def server_program():
    # get the hostname
    host = socket.gethostname()
    print(host)
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind(("169.254.252.122", port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    # server_socket.listen(1)
    # conn, address = server_socket.accept()  # accept new connection
    # print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        # data = conn.recv(1024).decode()
        data, addr = server_socket.recvfrom(1024)
        if not data:
            # if data is not received break
            break
        print("from "+ addr[0] + ": " + str(data.decode()))
        # data = input(' -> ')
        # conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    while True:
        server_program()