import communication_node

if __name__ == '__main__':
    ser = newClient.communication_node()
    # ser.create_socket()
    ser.run_server(input("IP: "), int(input("Port:")))
    # ser.server_part()

