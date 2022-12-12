from communication_node import communication_node


if __name__ == '__main__':
    mod = ""
    while mod != "q":
        node = communication_node()
        mod = input("Server\t-> S\nClient\t-> C\nExit\t-> Q\n -> ")
        match mod.lower():
            case "s":
                print("Starting Server:")
                node.run_server(input("IP: "), int(input("Port:")))
            case "c":
                print("Starting Client:")
                node.run_client(input("IP: "), int(input("port:")))
            case "q":
                exit(0)

