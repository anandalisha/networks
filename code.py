#Exp1 client

import socket              

s = socket.socket()         
host = '127.0.0.1'
port = 12345               

s.connect((host, port))
s.send('Hello server'.encode())
print("message from server:",s.recv(15).decode())

s.close() 


'''OUTPUT
message from server: Welcome client
'''

#Exp1 server

import socket               
s = socket.socket()         
port = 12345 
x = True               
s.bind(('127.0.0.1', port))        

s.listen(5)               
while x:
   k,a = s.accept()     
   print("Connected to",a) 
   print("Message from client:",k.recv(15).decode())
   k.send('Welcome client'.encode())
   x=False

'''OUTPUT
Connected to ('127.0.0.1', 37348)
Message from client: Hello server
'''


#Single chat client

import socket

HOST = "127.0.0.1"  
PORT = 65432  

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(str.encode((input("Enter a message: "))))
    data = s.recv(1024)

print(f"Received {data!r}")

'''Output

Enter a message: hello
Received b'hello'

'''


#Single chat server

import socket

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
            print(f"Received {data!r}")

'''Output

Connected by ('127.0.0.1', 44180)
Received b'hello'

'''

#UDP server

import socket

localIP     = "127.0.0.1"
localPort   = 20001
bufferSize  = 1024 

msgFromServer = "Hello UDP Client"
bytesToSend = str.encode(msgFromServer)

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((localIP, localPort))
print("UDP server up and listening")

while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    print(clientMsg)
    print(clientIP)
    UDPServerSocket.sendto(bytesToSend, address)

'''Output

UDP server up and listening
Message from Client:b'Hello UDP Server'
Client IP Address:('127.0.0.1', 33981)

'''

#UDP Client

import socket

msgFromClient       = "Hello UDP Server"
bytesToSend         = str.encode(msgFromClient)
serverAddressPort   = ("127.0.0.1", 20001)
bufferSize          = 1024
 
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPClientSocket.sendto(bytesToSend, serverAddressPort)
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
msg = "Message from Server {}".format(msgFromServer[0])

print(msg)

'''Ouptut

Message from Server b'Hello UDP Client'

'''


#Multichat server

import socket
import threading
port= 5055
add = ('127.0.0.1', port)
leave_msg = "l"
active = True
server = socket.socket()
server.bind(add)
client_list = []
def serverside():
	server.listen(5)
	print(f"Server is listening...")
	while active:
		conn, addr = server.accept()
		client_list.append(conn)
		name=conn.recv(1024).decode()
		thread = threading.Thread(target=handle_client, args=(conn, name))
		thread.start()
		print(f"Number of active connections: {threading.active_count() - 1}")
def sendToAllClients(msg,conn):
	for client in client_list:
		if conn!=client:
			client.send(msg.encode())
def handle_client(conn, name):
	try:
		msg=f"{name} has joined the chat!"
		print(msg)
		sendToAllClients(msg,conn)
		while True:
			msg = conn.recv(1024).decode()
			if msg == leave_msg:
				break
			msg = (f"{name}:{msg}")
			print(msg)
			sendToAllClients(msg,conn)
		msg=f"{name} has left the chat!"
		print(msg)
		sendToAllClients(msg,conn)
		client_list.remove(conn)
		conn.close()
	except:
		return
serverside()

'''
Output:

$ python3 mulser.py
Server is listening...

amrutha has joined the chat!
amjith has joined the chat!
anand has joined the chat!

'''

#multichat client

import socket
import select
import sys
port = 5055
add = ('127.0.0.1', port)
leave_msg = "l"
active = True
client = socket.socket()
client.connect(add)
client.send(input("Enter name:").encode())
print("Sucessfully joined the chat!\nTo leave the chat enter 'l'\n")
def send(msg):
	msg = msg.encode()
	client.send(msg)
def receive():
	msg = client.recv(1024).decode()
	print(msg)
while active:
	rlist, wlist, errlist = select.select([client, sys.stdin], [], [])
	for s in rlist:
		if s == client:
			receive()
		else:
			msg = input()
			if msg == leave_msg:
				active = False
			send(msg)
send(msg)

'''
Ouput :

terminal 1: 
$ python3 mulcli.py
Enter name:amrutha 
Sucessfully joined the chat!
To leave the chat enter 'l'

amjith has joined the chat!
anand has joined the chat!


terminal 2 :
$ python3 mulcli.py
Enter name:amjith
Sucessfully joined the chat!
To leave the chat enter 'l'

anand has joined the chat!


terminal 3:
$ python3 mulcli.py
Enter name:anand
Sucessfully joined the chat!
To leave the chat enter 'l'


'''

#CRC Server

import socket


def xor(a, b):

	# initialize result
	result = []

	# Traverse all bits, if bits are
	# same, then XOR is 0, else 1
	for i in range(1, len(b)):
		if a[i] == b[i]:
			result.append('0')
		else:
			result.append('1')

	return ''.join(result)


# Performs Modulo-2 division
def mod2div(divident, divisor):

	# Number of bits to be XORed at a time.
	pick = len(divisor)

	# Slicing the divident to appropriate
	# length for particular step
	tmp = divident[0: pick]

	while pick < len(divident):

		if tmp[0] == '1':

			# replace the divident by the result
			# of XOR and pull 1 bit down
			tmp = xor(divisor, tmp) + divident[pick]

		else: # If leftmost bit is '0'
			# If the leftmost bit of the dividend (or the
			# part used in each step) is 0, the step cannot
			# use the regular divisor; we need to use an
			# all-0s divisor.
			tmp = xor('0'*pick, tmp) + divident[pick]

		# increment pick to move further
		pick += 1

	# For the last n bits, we have to carry it out
	# normally as increased value of pick will cause
	# Index Out of Bounds.
	if tmp[0] == '1':
		tmp = xor(divisor, tmp)
	else:
		tmp = xor('0'*pick, tmp)

	checkword = tmp
	return checkword

# Function used at the receiver side to decode
# data received by sender


def decodeData(data, key):

	l_key = len(key)

	# Appends n-1 zeroes at end of data
	appended_data = data.decode() + '0'*(l_key-1)
	remainder = mod2div(appended_data, key)

	return remainder


# Creating Socket
s = socket.socket()
print("Socket successfully created")

# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 12345

s.bind(('', port))
print("socket binded to %s" % (port))
# put the socket into listening mode
s.listen(5)
print("socket is listening")


while True:
	# Establish connection with client.
	c, addr = s.accept()
	print('\nGot connection from', addr)

	# Get data from client
	data = c.recv(1024)

	print("\nReceived encoded data in binary format :", data.decode())

	if not data:
		break

	key = "1001"

	ans = decodeData(data, key)
	print("Remainder after decoding is->"+ans)

	# If remainder is all zeros then no error occurred
	temp = "0" * (len(key) - 1)
	if ans == temp:
		c.sendto(("\nTHANK you Data ->"+data.decode() +
				" Received No error FOUND" + "\n").encode(), ('127.0.0.1', 12345))
	else:
		c.sendto(("\nError in data\n").encode(), ('127.0.0.1', 12345))

	c.close()


'''
$ python3 crc_server.py
Socket successfully created
socket binded to 12345
socket is listening

Got connection from ('127.0.0.1', 55586)

Received encoded data in binary format : 11001011100001111001011101001101000000
Remainder after decoding is->000

'''
#CRC client 
# Import socket module
import socket           
 
def xor(a, b):
 
    # initialize result
    result = []
 
    # Traverse all bits, if bits are
    # same, then XOR is 0, else 1
    for i in range(1, len(b)):
        if a[i] == b[i]:
            result.append('0')
        else:
            result.append('1')
 
    return ''.join(result)
 
 
# Performs Modulo-2 division
def mod2div(divident, divisor):
 
    # Number of bits to be XORed at a time.
    pick = len(divisor)
 
    # Slicing the divident to appropriate
    # length for particular step
    tmp = divident[0 : pick]
 
    while pick < len(divident):
 
        if tmp[0] == '1':
 
            # replace the divident by the result
            # of XOR and pull 1 bit down
            tmp = xor(divisor, tmp) + divident[pick]
 
        else: # If leftmost bit is '0'
 
            # If the leftmost bit of the dividend (or the
            # part used in each step) is 0, the step cannot
            # use the regular divisor; we need to use an
            # all-0s divisor.
            tmp = xor('0'*pick, tmp) + divident[pick]
 
        # increment pick to move further
        pick += 1
 
    # For the last n bits, we have to carry it out
    # normally as increased value of pick will cause
    # Index Out of Bounds.
    if tmp[0] == '1':
        tmp = xor(divisor, tmp)
    else:
        tmp = xor('0'*pick, tmp)
 
    checkword = tmp
    return checkword
 

def encodeData(data, key):
 
    l_key = len(key)
 
    # Appends n-1 zeroes at end of data
    appended_data = data + '0'*(l_key-1)
    remainder = mod2div(appended_data, key)
 
    # Append remainder in the original data
    codeword = data + remainder
    return codeword   
     
# Create a socket object
s = socket.socket()       
 
# Define the port on which you want to connect
port = 12345           
 
# connect to the server on local computer
s.connect(('127.0.0.1', port))
 
# Send data to server 'Hello world'
 
## s.sendall('Hello World')
 
input_string = input("Enter data you want to send->")
#s.sendall(input_string)
data =(''.join(format(ord(x), 'b') for x in input_string))
print("\nEntered data in binary format :",data)
key = "1001"
 
ans = encodeData(data,key)
print("\nEncoded data to be sent to server in binary format :",ans)
s.sendto(ans.encode(),('127.0.0.1', 12345))
 
 
# receive data from the server
print("\nReceived feedback from server :",s.recv(1024).decode())
 
# close the connection
s.close()


'''
$ python3 crc.py
Enter data you want to send->earth  

Entered data in binary format : 11001011100001111001011101001101000

Encoded data to be sent to server in binary format : 11001011100001111001011101001101000000

Received feedback from server : 
THANK you Data ->11001011100001111001011101001101000000 Received No error FOUND



'''

#Hamming code server

import socket
s = socket.socket()

PORT = 5000

s.bind(("", PORT))
s.listen(1)

 
def detectError(arr, nr):
	n = len(arr)
	res = 0
	for i in range(nr):
		val = 0
		for j in range(1, n + 1):
			if(j & (2**i) == (2**i)):
				val = val ^ int(arr[-1 * j])
		res = res + val*(10**i)
	return int(str(res), 2)

while True:
	c, addr = s.accept()
	print('Got connection from', addr)

	data = c.recv(1024).decode()

	if not data:
		break
	print(f"data: {data}")

	data = data.split(";")
	correction = detectError(data[0], int(data[1]))

	print("Received encoded data in binary format :", data[0])
	print(f"Redundant bits: {data[1]}")
	print(f"Correction: {correction}")

	if correction == 0:
		c.sendto("There is no error in the received message.".encode(), ('127.0.0.1', 12345))
	else:
		c.sendto(f"The position of error is {len(data[0])-correction+1} from the left".encode(), ('127.0.0.1', 12345))
	c.close()


'''
$ python3 server.py
Got connection from ('127.0.0.1', 53854)
data: 11001001100101110000111101001101000100000110101011110011100000110001111011111110110111010011101111011010110101;7
Received encoded data in binary format : 11001001100101110000111101001101000100000110101011110011100000110001111011111110110111010011101111011010110101
Redundant bits: 7
Correction: 0


'''

#Hamming code client

import socket
s = socket.socket()	
PORT = 5000		

s.connect(("127.0.0.1", PORT))

def calculate_redundant_bit(length):
	for i in range(length):
		if 2**i >= length + i + 1:
			return i

def position_of_redundant_bit(binary_string, no_of_redundant_bits):
	j = 0
	k = 1
	size_of_binary_string = len(binary_string)
	res = ''
	for i in range(1, size_of_binary_string + no_of_redundant_bits + 1):
		if i == 2**j:
			res += "0"
			j += 1
		else:
			res += binary_string[-1 * k]
			k += 1
	return res[::-1]

def calculate_parity_bit(binary_string, no_of_redundant_bits):
	n = len(binary_string)
	for i in range(no_of_redundant_bits):
		val = 0
		for j in range(1, n + 1):
			if j & (2**i) == (2**i):
				val = val ^ int(binary_string[-1 * j])
		binary_string = binary_string[:n-(2**i)] + str(val) + binary_string[n-(2**i)+1:]
	return binary_string

def main():
	input_string = input("Enter data you want to send: ")
	binary_input_string = ''.join(format(ord(x), 'b') for x in input_string)
	no_of_redundant_bits = calculate_redundant_bit(len(binary_input_string))

	arr = position_of_redundant_bit(binary_input_string, no_of_redundant_bits)
	print(arr)
	arr = calculate_parity_bit(arr, no_of_redundant_bits)
	print(arr)
	print("Data transferred is " + arr)

	s.sendto(f"{arr};{no_of_redundant_bits}".encode(),('127.0.0.1', 5000))
	
	message = s.recv(2048)

	print(message.decode())
	s.close()

main()


'''
$ python3 client.py
Enter data you want to send: death is coming
11001001100101110000111101001101000100000110100011110011100000110001111011111100110111010011100111011000110100
11001001100101110000111101001101000100000110101011110011100000110001111011111110110111010011101111011010110101
Data transferred is 11001001100101110000111101001101000100000110101011110011100000110001111011111110110111010011101111011010110101
There is no error in the received message.

'''



#Substitution cipher client


import itertools 
import sys

import socket			

s = socket.socket()		

port = 12345			
connecting = True
s.connect(('127.0.0.1', port))

	

def shift(a, b, reverse=False):
	x = (ord(a) - ord('a') + ord(b) - ord('a')) % 26 
	if reverse:
		x = (ord(a) - ord(b) + 26) %26
	x +=ord('a')
	return chr(x)

def encrypt(st, key): 
	output = ""
	for (a, b) in zip(st, itertools.cycle(key)): 
		upperFlag = False
		if a.isupper():
			a = a.lower() 
			upperFlag = True
		new_char = shift(a, b) 
		if upperFlag:
			new_char = new_char.upper() 
		output += new_char
	return output

while(connecting):
	st = input("Input the string t o encrypt: ") 
	key = input("Enter the key: ").lower()
	if (not st.isalpha() or not key.isalpha()):  
		print("Failure")
		sys.exit(1)
	ciphertext = encrypt(st, key) 
	print("Ciphertext: {}".format(ciphertext))
	s.send(ciphertext.encode())
	s.send(key.encode())
s.close()


'''
Output

$ python3 subcipher_client.py
Input the string t o encrypt: helloworld
Enter the key: abcd
Ciphertext: hfnooxqule

'''



#Substitution cipher server


import itertools 
import sys
import socket			

s = socket.socket()		
print ("Socket successfully created")


port = 12345			

s.bind(('', port))		
print ("socket binded to %s" %(port))

s.listen(5)	
print ("socket is listening")		


c, addr = s.accept()
print ('Got connection from', addr )


def shift(a, b, reverse=False):
	x = (ord(a) - ord('a') + ord(b) - ord('a')) % 26 
	if reverse:
		x = (ord(a) - ord(b) + 26) %26
	x +=ord('a')
	return chr(x)



def decrypt(ciphertext, key): 
	output = ""
	for (a, b) in zip(ciphertext, itertools.cycle(key)): 
		upperFlag = False
		if a.isupper():
			a = a.lower() 
			upperFlag = True
		new_char = shift(a, b, reverse=True) 
		if upperFlag:
			new_char = new_char.upper() 
		output += new_char
	return output

while True:
	ciphertext = c.recv(1024).decode()
	print("Ciphertext: {}".format(ciphertext))
	key= c.recv(1024).decode()
	plain = decrypt(ciphertext, key)
	print("Plaintext: {}".format(plain))
c.close()


'''
Output

$ python3 subcipherserver.py
Socket successfully created
socket binded to 12345
socket is listening
Got connection from ('127.0.0.1', 33934)
Ciphertext: hfnooxquleabcd

'''


#Transposition cipher client


import socket
import math

HOST='127.0.0.1'
PORT=12347

key = "HACK"
def encryptMessage(msg):
    cipher = ""
  
    
    k_indx = 0
  
    msg_len = float(len(msg))
    msg_lst = list(msg)
    key_lst = sorted(list(key))
  
   
    col = len(key)
 
    row = int(math.ceil(msg_len / col))
  
    
    fill_null = int((row * col) - msg_len)
    msg_lst.extend(' ' * fill_null)
  
   
    matrix = [msg_lst[i: i + col] 
              for i in range(0, len(msg_lst), col)]
  
    
    for _ in range(col):
        curr_idx = key.index(key_lst[k_indx])
        cipher += ''.join([row[curr_idx] 
                          for row in matrix])
        k_indx += 1
  
    return cipher
		
def main():
	sockett=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sockett.connect((HOST,PORT))
	
	while True:
		msg=input("Enter the plaintext : ")
		msg1=msg
		
		 
		
		
		postencoding=encryptMessage(msg)
		print("Ciphertext generated is : ",postencoding)
		msg=postencoding.encode("utf-8")
		sockett.send(msg)
		print("Message Sent!")
		
		
if __name__ == '__main__':
	main()


'''
Output

$ python3 transposclient.py
Enter the plaintext : helloworld
Ciphertext generated is :  ewdlo hollr 
Message Sent!

'''


#Transposition cipher server


import socket
import math
  
key = "HACK"
IP = '127.0.0.1'
PORT = 12347

def decryptMessage(cipher):
    msg = ""
  
    # track key indices
    k_indx = 0
  
    # track msg indices
    msg_indx = 0
    msg_len = float(len(cipher))
    msg_lst = list(cipher)
  
    
    col = len(key)
      
    
    row = int(math.ceil(msg_len / col))
  
    
    key_lst = sorted(list(key))
  
    
    dec_cipher = []
    for _ in range(row):
        dec_cipher += [[None] * col]
  
    
    for _ in range(col):
        curr_idx = key.index(key_lst[k_indx])
  
        for j in range(row):
            dec_cipher[j][curr_idx] = msg_lst[msg_indx]
            msg_indx += 1
        k_indx += 1
  
     
    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        raise TypeError("This program cannot",
                        "handle repeating words.")
  
    null_count = msg.count(' ')
  
    if null_count > 0:
        return msg[: -null_count]
  
    return msg
def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((IP, PORT))
	server.listen(10)
	while True:
		client, address = server.accept()
		print(f"Connected to {address[0]}  :{address[1]}")
		ds=client.recv(1024).decode("utf-8")
		print("Data received is {}".format(ds))

		 
		
		postdecoding=decryptMessage(ds)
		print("Plaintext after decoding is : ",postdecoding)

if __name__ == '__main__':
	main()


'''
Ouptut

$ python3 transposserver.py
Connected to 127.0.0.1  :47668
Data received is ewdlo hollr 
Plaintext after decoding is :  helloworld

'''


#LZW Compression


def compress(uncompressed):
	dict_size = 256
	dictionary = dict((chr(i), i) for i in range(dict_size))
	w = ""
	result = []
	for c in uncompressed:
		wc = w + c
		if wc in dictionary:
			w = wc
		else:
			result.append(dictionary[w])
			dictionary[wc] = dict_size
			dict_size += 1
			w = c
	if w:
		result.append(dictionary[w])
	return result
def decompress(compressed):
	from io import StringIO
	dict_size = 256
	dictionary = dict((i, chr(i)) for i in range(dict_size))
	result = StringIO()
	w = chr(compressed.pop(0))
	result.write(w)
	for k in compressed:
		if k in dictionary:
			entry = dictionary[k]
		elif k == dict_size:
			entry = w + w[0]
		else:
			raise ValueError('Bad compressed k: %s' % k)
		result.write(entry)
		dictionary[dict_size] = w + entry[0]
		dict_size += 1
		w = entry
	return result.getvalue()
str=input("Enter the string:")
compressed = compress(str)
print ("Encoded String is:",compressed)
decompressed = decompress(compressed)
print ("Decoded string is:",decompressed)


'''
Output

$ python3 lzw.py
Enter the string:helloworld
Encoded String is: [104, 101, 108, 108, 111, 119, 111, 114, 108, 100]
Decoded string is: helloworld

'''
