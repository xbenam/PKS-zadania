import cli

if __name__ == '__main__':
    ser = cli.client()
    # ser.create_socket()
    ser.run_server("127.0.0.3", 1234)
    # ser.server_part()

