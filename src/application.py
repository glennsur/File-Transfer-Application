# Imports libraries
import os
from socket import *
from struct import *
import argparse
import threading as thread
import sys
import time
import struct
from collections import deque

# Packet structure
FLAGS = 0 # Int value that stores bit flags for control messages
WINDOW_SIZE = 64 # Int value that stores the window size
HEADER_FORMAT = "!IIHH" #String value that defines the header format of the DRTP packet

DRTP_PACKET_SIZE = 1472 # Int value representing the size of the DRTP packet
DRTP_HEADER_SIZE = calcsize(HEADER_FORMAT) # Int value representing the size of the DRTP header
DRTP_DATA_SIZE = 1460 # Int value representing the maximum size of the DRTP data payload

# Int values that stores bit flags for control messages
# Can be used in the FLAGS field of the packet
DRTP_RESET = 1 << 0
DRTP_FIN = 1 << 1
DRTP_ACK = 1 << 2
DRTP_SYN = 1 << 3


def send_packet(s: socket, addr, packet):
    '''
    Description:
    Sends a UDP packet to the specified address using the specified socket.

    Input Parameters:
    - 's': a socket object representing the UDP socket to use for sending the packet.
    - 'addr': a tuple representing the IP address and port number of the destination for the packet.
    - 'packet': a bytes object representing the packet to send.

    Output Parameters:
    None.

    Returns:
    None.

    Exceptions:
    This function does not raise any exceptions.
    '''
    s.sendto(packet, addr)


def receive_packet(s: socket):
    '''
    Description:
    Receives a UDP packet from the specified socket and extracts the header and data portions of the packet.

    Input Parameters:
    - 's': a socket object representing the UDP socket to receive the packet from.

    Output Parameters:
    - 'header': a bytes object representing the header portion of the received packet.
    - 'data': a bytes object representing the data portion of the received packet.

    Returns:
    A tuple containing the header and data portions of the received packet.

    Exceptions:
    This function raises an exception if an error occurs while receiving the packet from the socket.
    '''
    # Receive a packet from the socket
    packet = s.recvfrom(DRTP_PACKET_SIZE)[0]

    # Separate the packet into header and data
    header = packet[:DRTP_HEADER_SIZE]  # Extract the header from the packet
    data = packet[DRTP_HEADER_SIZE:]  # Extract the data from the packet

    # Return the header and data
    return header, data


# Connection establishment
def send_syn(s, addr):
    '''
    Description:
    Sends a SYN packet to the specified address using the specified socket.

    Input Parameters:
    - 's': a socket object representing the UDP socket to use for sending the packet.
    - 'addr': a tuple representing the IP address and port number of the destination for the packet.

    Output Parameters:
    None.

    Returns:
    None.

    Exceptions:
    This function does not raise any exceptions.
    '''
    # Create a SYN (synchronization) packet
    # The sequence number is 0, the acknowledgment number is 0, the flag is DRTP_SYN indicating a SYN packet,
    # the window size is 0 (irrelevant for a SYN packet), and there is no payload data
    syn_packet = create_packet(0, 0, DRTP_SYN, 0, b'')

    # Send the SYN packet to the server
    # 's' is the socket, 'addr' is the address of the server
    send_packet(s, addr, syn_packet)


def send_syn_ack(s, addr):
    '''
    Description:
    Sends a SYN-ACK packet to the specified address using the specified socket.

    Input Parameters:
    - 's': a socket object representing the UDP socket to use for sending the packet.
    - 'addr': a tuple representing the IP address and port number of the destination for the packet.

    Output Parameters:
    None.

    Returns:
    None.

    Exceptions:
    This function does not raise any exceptions.
    '''
    # Create a SYN-ACK (synchronization-acknowledgment) packet
    # The sequence number is 0, the acknowledgment number is 1, the flags are DRTP_SYN and DRTP_ACK indicating a SYN-ACK packet,
    # the window size is defined by WINDOW_SIZE, and there is no payload data
    syn_ack_packet = create_packet(0, 1, DRTP_SYN | DRTP_ACK, WINDOW_SIZE, b'')

    # Send the SYN-ACK packet to the client
    send_packet(s, addr, syn_ack_packet)


def send_fin(s, addr):
    '''
    Description:
    Sends a FIN packet to the specified address using the specified socket.

    Input Parameters:
    - 's': a socket object representing the UDP socket to use for sending the packet.
    - 'addr': a tuple representing the IP address and port number of the destination for the packet.

    Output Parameters:
    None.

    Returns:
    None.

    Exceptions:
    This function does not raise any exceptions.
    '''
    # Create a FIN (finish) packet
    # The sequence number is 0, the acknowledgment number is 0, the flag is DRTP_FIN indicating a FIN packet,
    # the window size is 0 (irrelevant for a FIN packet), and there is no payload data
    fin_packet = create_packet(0, 0, DRTP_FIN, 0, b'')

    # Send the FIN packet to the server
    send_packet(s, addr, fin_packet)


def handle_syn_ack(s, addr):
    '''
    Description:
    Handles the SYN-ACK packet received during the connection establishment.

    Input Parameters:
    - 's': The socket object used to receive the SYN-ACK packet.
    - 'addr': The source address from which the SYN-ACK packet was received.

    Output Parameters:
    None

    Returns:
    None

    Exception Handling:
    None
    '''
    # Receive a packet from the server
    # 's' is the socket
    header = receive_packet(s)[0]

    # Parse the header to get the flags
    flags = parse_header(header)[2]

    # Parse the flags to check for SYN and ACK flags
    syn, ack, fin = parse_flags(flags)

    # If the packet is a SYN-ACK packet (both SYN and ACK flags are set)
    if syn and ack:
        print("Received SYN-ACK")
        
        # Create an ACK (acknowledgment) packet in response
        # The sequence number is 1, the acknowledgment number is 1, the flag is DRTP_ACK indicating an ACK packet,
        # the window size is 0 (irrelevant for an ACK packet), and there is no payload data
        ack_packet = create_packet(1, 1, DRTP_ACK, 0, b'')
        
        # Send the ACK packet to the server
        send_packet(s, addr, ack_packet)


def stop_and_wait(s, addr, file):
    '''
    Description:
    Implements the Stop-and-Wait reliability mechanism for sending packets.

    Input Parameters:
    - 's': The socket object used to send packets.
    - 'addr': The destination address to send packets.
    - 'file': The file object to read the data from.

    Output Parameters:
    None

    Returns:
    None

    Exception Handling:
    The function catches the `TimeoutError` exception and
    resends the packet if a timeout occurs during receiving.
    '''
    # Sets the initial sequence number
    client_seq = 1

    # Reads a block of data from the file
    image_data = file.read(DRTP_DATA_SIZE)

    # Creates a packet with the data
    packet = create_packet(client_seq, 1, 0, 0, image_data)

    # Records the start time
    start_time = time.time()

    # While there is data to be sent
    while image_data:
        # Sends the packet to the server
        send_packet(s, addr, packet)
        
        # Sets a timeout on the socket
        s.settimeout(0.5)  # 500ms timeout
        
        try:
            # Receives a packet from the server
            header = receive_packet(s)[0]
            
            # Parses the header to get the acknowledgment number
            ack_num = parse_header(header)[1]

            # If the acknowledgment number is not the expected value
            if ack_num != client_seq + 1:
                continue  # Resend the packet
                    
        except TimeoutError:
            # If a timeout occurs, resend the packet
            print("Resending packet!")
            continue

        # Reads the next block of data from the file
        image_data = file.read(DRTP_DATA_SIZE)
        
        # Increments the sequence number
        client_seq += 1
        
        # Creates a new packet with the next block of data
        packet = create_packet(client_seq, 1, 0, 0, image_data)
            
    # Calculates and prints the elapsed time, file size, and throughput
    elapsed_time = time.time() - start_time
    throughput = os.path.getsize(args.filename) / elapsed_time
    print('-' * 50)
    print(f'TIME: {elapsed_time:.2f} second(s)')
    print(f'FILE SIZE: {os.path.getsize(args.filename/1000):.2f} kB')
    print(f'THROUGHPUT: {throughput/1000:.2f} kB per second')


def go_back_n(s, addr, file, testcase=None):
    '''
    Description:
    Implements the Go-Back-N reliability mechanism for sending packets.

    Input Parameters:
    - 's': The socket object used to send packets.
    - 'addr': The destination address to send packets.
    - 'file': The file object to read the data from.
    - 'testcase': An optional argument specifying the type of testcase to execute.

    Output Parameters:
    None

    Returns:
    None

    Exception Handling:
    The function catches the `TimeoutError` exception and
    resends the packet if a timeout occurs during receiving.
    '''
    # Initializes sequence number, skipped flag, and window size
    client_seq = 1
    skipped = False
    window_size = 5

    # Initializes a deque to serve as the sliding window
    window = deque()

    # Reads a block of data from the file
    image_data = file.read(DRTP_DATA_SIZE)

    # Starts the timer for throughput measurement
    start_time = time.time()

    # As long as there is data to be sent or unacknowledged packets in the window
    while image_data or window:
        
        # Fill the window with outgoing packets
        while image_data and len(window) < window_size:
            data_packet = create_packet(client_seq, 1, 0, 0, image_data)
            window.append(data_packet)
            client_seq += 1
            image_data = file.read(DRTP_DATA_SIZE)

        # Sends all packets in the window
        for packet in window:
            if testcase == "skip_seq" and not skipped:
                if parse_header(packet[:DRTP_HEADER_SIZE])[0] == 3:
                    # If specified, skip the packet with sequence number 3
                    skipped = True
                    print("Skipping packet with seq=3")
                    continue

            send_packet(s, addr, packet)

        # Sets a timeout on the socket
        s.settimeout(0.5)  # 500ms timeout

        # Receives ACK packets
        try:
            for _ in range(len(window)):
                header = receive_packet(s)[0]
                ack_number = parse_header(header)[1]
                
                # If the ACK number matches the expected value, remove the packet from the window
                if ack_number == (client_seq + 1) - len(window):
                    window.popleft()
        except TimeoutError:
            # If a timeout occurs, resend the entire window of packets
            print("Resending packet!")
            continue

    # Calculates the elapsed time, file size, and throughput
    elapsed_time = time.time() - start_time
    throughput = os.path.getsize(args.filename) / elapsed_time
    print('-' * 50)
    print(f'TIME: {elapsed_time:.2f} second(s)')
    print(f'FILE SIZE: {os.path.getsize(args.filename)/1000:.2f} kB')
    print(f'THROUGHPUT: {throughput/1000:.2f} kB per second')


def selective_repeat(s, addr, file, testcase=None):
    '''
    Description:
    Implements the Selective Repeat reliability mechanism for sending packets.

    Input Parameters:
    - 's': The socket object used to send packets.
    - 'addr': The destination address to send packets.
    - 'file': The file object to read the data from.
    - 'testcase': An optional argument specifying the type of testcase to execute.

    Output Parameters:
    None

    Returns:
    None

    Exception Handling:
    The function catches the `TimeoutError` exception and 
    continues the loop if a timeout occurs during receiving.
    '''
    # Initializes window start and end sequence numbers, skipped flag, and window size
    window_start_seq = 1
    window_end_seq = window_start_seq
    skipped = False
    window_size = 5

    # Initializes two deques: 'window' for outgoing packets, 'received' for tracking packet acknowledgement
    window = deque()
    received = deque()

    # Starts the timer for throughput measurement
    start_time = time.time()

    # Reads a block of data from the file
    image_data = file.read(DRTP_DATA_SIZE)

    # As long as there is data to be sent or unacknowledged packets in the window
    while image_data or window:
        
        # Fills the window with outgoing packets
        while image_data and len(window) < window_size:
            data_packet = create_packet(window_end_seq, 1, 0, 0, image_data)
            window.append(data_packet)
            received.append(False)
            window_end_seq += 1
            image_data = file.read(DRTP_DATA_SIZE)

        # Sends all unacknowledged packets in the window
        for confirmed, packet in zip(received, window):
            if testcase == "skip_seq" and not skipped:
                if parse_header(packet[:DRTP_HEADER_SIZE])[0] == 3:
                    skipped = True
                    print("Skipping packet with seq=3")
                    continue

            if confirmed:
                continue  # Skips sending acknowledged packets
            send_packet(s, addr, packet)

        # Sets a timeout on the socket
        s.settimeout(0.5)  # 500ms timeout

        # Receives ACK packets
        try:
            while received.count(False):  # While there are unacknowledged packets
                header = receive_packet(s)[0]
                ack_number = parse_header(header)[1]

                # If the ACK number is within the window, mark the corresponding packet as acknowledged
                if ack_number > window_start_seq and ack_number <= window_end_seq + 1:
                    received[(ack_number - 1) - window_start_seq] = True
                    
        except TimeoutError:
            continue  # If a timeout occurs, skip to the next iteration

        # Removes acknowledged packets from the start of the window
        while received and received[0]:
            window.popleft()
            received.popleft()
            window_start_seq += 1

    # Calculates the elapsed time, file size, and throughput
    elapsed_time = time.time() - start_time
    throughput = os.path.getsize(args.filename) / elapsed_time
    print('-' * 50)
    print(f'TIME: {elapsed_time:.2f} second(s)')
    print(f'FILE SIZE: {os.path.getsize(args.filename)/1000:.2f} kB')
    print(f'THROUGHPUT: {throughput/1000:.2f} kB per second')


def create_packet(seq, ack, flags, win, data):
    '''
    Description:
    Creates a packet by combining header information and application data.

    Input Parameters:
    - 'seq': The sequence number of the packet.
    - 'ack': The acknowledgment number of the packet.
    - 'flags': The flags for control messages in the packet.
    - 'win': The receiver window size of the packet.
    - 'data': The application data payload of the packet.

    Output Parameters:
    None

    Returns:
    - 'packet': A bytes object representing the complete packet with header and data.

    Exception Handling:
    None
    '''
    # Flags (we only use 4 bits),  receiver window and application data 
    # Struct.pack returns a bytes object containing the header values
    # Packed according to the header_format !IIHH
    header = pack (HEADER_FORMAT, seq, ack, flags, win)
    # Once we create a header, we add the application data to create a packet of 1472 bytes
    packet = header + data
    # print (f'packet containing header + data of size {len(packet)}') #just to show the length of the packet
    return packet


def parse_header(header):
    '''
    Description:
    Parses the header of a packet and returns a tuple with the header values.

    Input Parameters:
    - 'header': The header of the packet.

    Output Parameters:
    None

    Returns:
    - 'header_from_msg': A tuple containing the sequence number, 
    acknowledgment number, flags, and window size parsed from the header.

    Exception Handling:
    None
    '''
    # Assuming HEADER_FORMAT is defined elsewhere
    header_from_msg = unpack(HEADER_FORMAT, header)  # Unpacks the header using the defined format
    return header_from_msg  # Returns the parsed header
    

def parse_flags(flags):
    '''
    Description:
    Parses the flags field of a packet and determines the presence of specific flags.

    Input Parameters:
    - 'flags': The flags field of the packet.

    Output Parameters:
    None

    Returns:
    - 'syn': A boolean indicating the presence of the SYN flag.
    - 'ack': A boolean indicating the presence of the ACK flag.
    - 'fin': A boolean indicating the presence of the FIN flag.

    Exception Handling:
    None
    '''
    # We only parse the first 3 fields because we're not using rst in our implementation
    syn = flags & (1 << 3)
    ack = flags & (1 << 2)
    fin = flags & (1 << 1)
    return syn, ack, fin


if __name__ == "__main__":
    
    # Command line argument parsing
    parser = argparse.ArgumentParser(description="positional arguments", epilog="end of help")

    # Server arguments
    parser.add_argument("-s", "--server", action="store_true", help="Runs simpleperf in server mode")

    # Common arguments
    parser.add_argument("-p", "--port", type=int, default=8088, help="Port for hosts to connect to. Default: 8088")
    parser.add_argument("-r", "--reliability", choices=["StopAndWait", "GoBackN", "SelectiveRepeat"], help="Reliability protocol to use.")
    parser.add_argument("-f", "--filename", type=str, help="What you want the transferred file to be named")
    parser.add_argument("-t", "--test", choices=["skip_ack", "skip_seq"], help="Run test cases, skip_ack is for server, skip_seq is for client")

    # Client specific arguments
    parser.add_argument("-c", "--client", action="store_true", help="Run simpleperf in client mode")
    parser.add_argument("-i", "--serverip", help="Select the IP of the server", default="127.0.0.1")

    args = parser.parse_args()

    # Error correction to make sure the program is ran as a server or a client
    if args.server == False and args.client == False:
        print("You need to run the program as either a server or a client")
        sys.exit()

    # Handles if user trys to run the program as both a server and a client
    if args.server == True and args.client == True:
        print("You can only choose one mode at a time")
        print("Run as EITHER a server or a client")
        sys.exit()

    # Error correction for using both tests at the same time
    if args.test == "skip_ack" and args.test == "skip_seq":
        print("Use only 1 test at a time!")
        sys.exit()


    # If the program is run in server mode
    if args.server :

        try: 
            # Creates a UDP socket
            serverSocket = socket(AF_INET, SOCK_DGRAM)
            # Binds the socket to the specified IP and port
            serverSocket.bind((args.serverip, args.port))
            
            # Opens the file for writing
            file = open(args.filename, "wb")
            packet, addr = serverSocket.recvfrom(DRTP_PACKET_SIZE)
            print("Connected")
            skipped = False
            
            # 'StopAndWait' and 'GoBackN' reliability protocols
            if args.reliability == "StopAndWait" or args.reliability == "GoBackN":
                server_ack = 0
                server_seq = 0

                while packet:
                    # Parsing the packet
                    packet_seq, packet_ack, flags, window = parse_header(packet[:DRTP_HEADER_SIZE])
                    syn, ack, fin = parse_flags(flags)
                    
                    # If the SYN flag is set
                    if syn:
                        print("SYN received!")
                        server_ack += 1
                        syn_ack_packet = create_packet(server_seq, server_ack, DRTP_SYN | DRTP_ACK, WINDOW_SIZE, b'')
                        send_packet(serverSocket, addr, syn_ack_packet)

                    # If the FIN flag is set
                    elif fin:
                        print("FIN received, sending last ACK!")
                        server_ack += 1
                        final_ack = create_packet(server_seq, server_ack, DRTP_ACK, WINDOW_SIZE, b'')
                        send_packet(serverSocket, addr, final_ack)
                        break
                    
                    # If the ACK flag is set
                    elif ack:
                        if server_seq == 0:
                            print("ACK received!")
                            server_seq = packet_ack
                    
                    # If none of the flags are set
                    else:
                        if packet_seq == server_ack:
                            if args.test == "skip_ack" and not skipped and server_ack == 5:
                                print("Skipping ACK")
                                skipped = True
                            else:
                                server_ack += 1
                                ack_packet = create_packet(server_seq, server_ack, DRTP_ACK, WINDOW_SIZE, b'')
                                send_packet(serverSocket, addr, ack_packet)
                                file.write(packet[DRTP_HEADER_SIZE:])
                    
                    # Receives the next packet
                    packet = serverSocket.recvfrom(DRTP_PACKET_SIZE)[0]


            # Selective Repeat protocol
            if args.reliability == "SelectiveRepeat":
                server_ack = 0
                server_seq = 0
                window_size = 5  # Size of the sliding window
                window_start = server_ack  # Start of the window
                window = deque([None] * window_size)  # Initialize window with None
                
                while packet:
                    # Parsing the packet
                    packet_seq, packet_ack, flags, _ = parse_header(packet[:DRTP_HEADER_SIZE])
                    syn, ack, fin = parse_flags(flags)
                    
                    if syn:
                        # SYN flag is set
                        print("SYN received!")
                        server_ack += 1
                        syn_ack_packet = create_packet(server_seq, server_ack, DRTP_SYN | DRTP_ACK, WINDOW_SIZE, b'')
                        send_packet(serverSocket, addr, syn_ack_packet)

                    elif fin:
                        # FIN flag is set
                        print("FIN received!")
                        server_ack += 1
                        final_ack = create_packet(server_seq, server_ack, DRTP_ACK, WINDOW_SIZE, b'')
                        send_packet(serverSocket, addr, final_ack)
                        break
                    
                    elif ack:
                        # ACK flag is set
                        if server_seq == 0:
                            server_seq = packet_ack
                    
                    else:
                        # If the packet sequence number is within the window
                        if packet_seq >= server_ack and packet_seq < server_ack + window_size:
                            window[packet_seq - server_ack] = packet  # Stores the packet in the window

                            if args.test == "skip_ack" and not skipped and server_ack == 5:
                                # Skip an acknowledgement for testing purposes
                                print("Skipping ACK")
                                skipped = True
                            else:
                                # Send an acknowledgement to the client
                                ack_packet = create_packet(server_seq, packet_seq + 1, DRTP_ACK, WINDOW_SIZE, b'')
                                send_packet(serverSocket, addr, ack_packet)
                                
                                # Writes packets to file in order
                                while window[0]:
                                    packet = window.popleft()  # Removes the packet from the window
                                    window.append(None)  # Adds None to the end of the window
                                    server_ack += 1
                                    file.write(packet[DRTP_HEADER_SIZE:])  # Writes the packet data to the file

                    # Receives the next packet
                    packet = serverSocket.recvfrom(DRTP_PACKET_SIZE)[0]

            # Closes the file and the socket after the transfer is complete
            file.close()
            serverSocket.close()
        except:
            print("ConnectionError")
            sys.exit()


    # If the program is run in client mode
    if args.client:
        try:
            # Creates a UDP socket
            clientSocket = socket(AF_INET, SOCK_DGRAM)
            
            # Opens the file for reading
            file = open(args.filename, "rb")
            server_address = (args.serverip, args.port)
            
            # Sends SYN to the server
            send_syn(clientSocket, server_address)

            # Receives SYN ACK from the server
            handle_syn_ack(clientSocket, server_address)

            # Sends file based on the reliability protocol
            if args.reliability == "StopAndWait":
                stop_and_wait(clientSocket, server_address, file)

            if args.reliability == "GoBackN":
                go_back_n(clientSocket, server_address, file, args.test)

            if args.reliability == "SelectiveRepeat":
                selective_repeat(clientSocket, server_address, file, args.test)

            # Sends end-of-file ACK to the server
            print("Sending FIN")
            send_fin(clientSocket, server_address)

            # Receives the final ACK from the server
            ack_received = False
            while not ack_received:
                clientSocket.settimeout(1)  # Sets timeout to 1 second
                try:
                    # Receives ACK
                    ack_packet = clientSocket.recvfrom(DRTP_PACKET_SIZE)[0]
                    packet_seq, server_ack, flags, window = parse_header(ack_packet[:DRTP_HEADER_SIZE])
                    syn, ack, fin = parse_flags(flags)

                    # If ACK flag is set, end the loop
                    if ack:
                        ack_received = True
                        
                except timeout:
                    # If a timeout occurs, send end-of-file ACK again
                    send_fin(clientSocket, addr)
                    continue
            
            print("Final ACK received, closing the connection!")
            file.close()
            clientSocket.close()

        except ConnectionError:
            print("ConnectionError")
            sys.exit()
