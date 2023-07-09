Application.py

------------------------------------------------------------------------------------------------------------------------------

Welcome to application.py! This is a UDP based data transport application with built in reliability!
With this applicaiton you can transfer files from one machine to another while knowing your data will transfer smoothly!

------------------------------------------------------------------------------------------------------------------------------

How it works!

This applicaion uses python sockets to transfer data from one computer to another.
With built in reliability, using either Stop-and-Wait, Go-Back-N or Selective-Repeat, you can transfer data safely.

------------------------------------------------------------------------------------------------------------------------------

How to use application.py

application.py is made using argparse, so all you have to do is open a terminal of your choice to get started with this application!

Once you are in the terminal, write:

python application.py --help (on windows)

python3 application.py --help (on mac and linux)

This will show you all the command line arguments available to you in application.py, with helping text for each argument.

Make sure to always use this program in EITHER the server mode (-s) OR client mode (-c), and not both!

------------------------------------------------------------------------------------------------------------------------------

Short explaination of each of the flags:

Server specific arguments:

    -s: Use this flag to run the program in server mode

    -b: Use to bind the server to an IP address of your choice.

common arguments:

    -p: Run on server side to select the port the server should be listening to
        Run on client side and select the port of the server, to make the client able to find the server

    -f: Run on server side to set the name of the transfered file
        Run on client side to select the file you want to transfer
        
    -r: Run on server side to select which reliability protocol you want to use
        Run on client side to select which reliability protocol you want to use
            THIS HAS TO BE THE SAME FOR BOTH CLIENT AND SERVER!!!
            
    -t: Run on server side with 'skip_ack' to use the skip_ack test case (skip_seq does not work on the server side)
        Run on client side with 'skip_seq' to use the skip_seq test case (skip_ack does not work on the client side)
    
client specific arguments:

    -c: Use this flag to run the program in client mode
    
    -I: Use this to select the IP address of the server to make the client able to find the server

------------------------------------------------------------------------------------------------------------------------------
