import newClient

if __name__ == '__main__':
    ser = newClient.client()
    # ser.create_socket()
    ser.run_server(input("IP: "), int(input("Port:")))
    # ser.server_part()

