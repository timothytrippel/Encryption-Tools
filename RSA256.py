#! /usr/bin/env python2.7
import sys, os, copy, io
from PrimeGenerator import*
from BitVector import*

#Author: Timothy Trippel
#Python Version: 2.7
#OS Dev-Envrionment: Windows 8.1
#Date: 03/4/2014

#Code Below is only used to generate keys ONCE --> after keys are determined they are hard coded
#-----------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------
#Class below generates keys for a 256-bit RSA algorithm
#-----------------------------------------------------------------------------------------------------
class GenerateKeys():
	def __init__(self, modSize):
		self.e = 65537
		self.d = None
		self.p = None
		self.q = None
		self.n = None
		self.e_bv = None
		self.d_bv = None
		self.p_bv = None
		self.q_bv = None
		self.n_bv = None		
		self.totient_n = None
		self.public_key = None
		self.private_key = None
		#Code for the PrimeGenerator was written by Purdue Professor Dr. Avinash Kak
		self.generator = PrimeGenerator(bits = (modSize/2), debug = 0)

	#Function below generates primes numbers of a given size
	def GenPrime(self):
		return self.generator.findPrime()

	#Binary implementation of Euclid's Algorithm
	#Algorithm written in the "bgcd()" method below was written by Purdue Professor Dr. Avinash Kak
	def bgcd(self, a, b):
		if a == b: return a
		if a == 0: return b
		if b == 0: return a
		if (~a & 1):
			if (b &1):
				return self.bgcd(a >> 1, b)
			else:
				return self.bgcd(a >> 1, b >> 1) << 1
		if (~b & 1):
			return self.bgcd(a, b >> 1)
		if (a > b):
			return self.bgcd( (a-b) >> 1, b)
		return self.bgcd( (b-a) >> 1, a )

	#Method below generates two prime numbers (p and q) such that they meet certain criteria to be 
	#used in a 256-bit implementation of the RSA Encryption Algorithm
	def GenPQ(self):
		while True:
			#Generate Primes for P and Q
			self.p_bv = BitVector(intVal = self.GenPrime(), size = 128)
			while not (self.p_bv[0]&self.p_bv[1]):
				self.p_bv = BitVector(intVal = self.GenPrime(), size = 128)
			self.q_bv = BitVector(intVal = self.GenPrime(), size = 128)
			while not (self.q_bv[0]&self.q_bv[1]):
				self.q_bv = BitVector(intVal = self.GenPrime(), size = 128)
	 		#Check if (p-1) and (q-1) are co-prime to e and if p != q
	 		if self.p_bv != self.q_bv:
		 		if (self.bgcd((int(self.p_bv)-1), self.e) == 1) and (self.bgcd((int(self.p_bv)-1), self.e) == 1):
		 			break
	 	self.p = int(self.p_bv)
	 	self.q = int(self.q_bv)

	#Method below generates the "d" value which is a component of the RSA encryption algorithm public key
	def GenD(self):
		totient_n_mod = BitVector(intVal = self.totient_n)
		self.e_bv = BitVector(intVal = self.e)
		self.d_bv = self.e_bv.multiplicative_inverse(totient_n_mod)
		self.d = int(self.d_bv)

	#Method below generates both public and private keys to be used by a 256-bit implementation 
	#of the RSA encryption algorithm
	def GenKeys(self):
		self.GenPQ()	         #Generate P and Q Values
		self.n = self.p * self.q #Set n
		self.n_bv = BitVector(intVal = self.n)
		self.totient_n = (self.p - 1) * (self.q - 1) #Set totient of n
		self.GenD() #Generate d value
		self.public_key = [copy.deepcopy(self.e), copy.deepcopy(self.n)]  #Set Public-Key
		self.private_key = [copy.deepcopy(self.d), copy.deepcopy(self.n)] #Set Private-Key

	#Method below prints generated key-values for RSA encryption algorithm to output file
	def PrintKeys(self):
		keyFile = open("keys.txt", "w")
		keyFile.write("Public-Key: %s\n" % self.public_key)
		keyFile.write("Private-Key: %s\n" % self.private_key)
		keyFile.write("P-Value = %ld\n" % self.p)
		keyFile.write("Q-Value = %ld\n" % self.q)
		keyFile.close()

#-----------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------

#Class Below Implements RSA Encryption/Decryption ALgorithm using set of Keys
#-----------------------------------------------------------------------------------------------------
class RSA():
	def __init__(self, public_key, private_key, p_val, q_val, inputFileName, outputFileName, modSize):
		self.e = public_key[0]
		self.d = private_key[0]
		self.n = public_key[1]
		self.p = p_val
		self.q = q_val
		self.p_bv = BitVector(intVal = self.p)
		self.q_bv = BitVector(intVal = self.q)
		self.modSize = modSize
		self.blockSize = self.modSize / 2
		self.inputFileName = inputFileName
		self.outputFileName = outputFileName
		self.inputFile_bv = None
		self.outputFile = None

	def OpenFiles(self):
		self.inputFile_bv = BitVector(filename = self.inputFileName)
		self.outputFile = open(self.outputFileName, "wb")
		return

	def CloseFiles(self):
		self.inputFile_bv.close_file_object()
		self.outputFile.close()
		return

	def ModExpo(self, a, b, mod):
		result = 1
		while(b > 0):
			if (b&1):
				result = (result * a) % mod
			b = b >> 1
			a = (a * a) % mod
		return result

	def CRT(self, nextBitBlock_bv):
		#Implementation of Chinese Remainder Theorem (CRT) to speed-up modular exponentiation
		q_MI = self.q_bv.multiplicative_inverse(self.p_bv)
		p_MI = self.p_bv.multiplicative_inverse(self.q_bv)
		Xp = self.q * int(q_MI)
		Xq = self.p * int(p_MI)
		#Using Fermat's Little Theorem --> Calculate Vp and Vq
		v_p = self.d % (self.p-1)
		v_q = self.d % (self.q-1)
		#Calculate Vp and Vq for CRT
		Vp = self.ModExpo(int(nextBitBlock_bv), v_p, self.p)
		Vq = self.ModExpo(int(nextBitBlock_bv), v_q, self.q)
		#Recover Plain-Text Bit Block
		plain_text = ((Vp*Xp) + (Vq*Xq)) % self.n
		plain_text_bv = BitVector(intVal = plain_text, size = 256)
		return plain_text_bv

	def encrypt_RSA(self):
		self.OpenFiles() #Open I/O files
		#scan in bits from input file and perform encryption algorithm
		while(self.inputFile_bv.more_to_read):
			nextBitBlock_bv = self.inputFile_bv.read_bits_from_file(self.blockSize) #Scan in bit block
			if (nextBitBlock_bv.length() != self.blockSize):
				#Append newline characters to end of bit block
				num_NL_chars = (self.blockSize - nextBitBlock_bv.length()) / 8
				inputBitBlockText = nextBitBlock_bv.get_hex_string_from_bitvector()
				inputBitBlockText = inputBitBlockText + "0a"*num_NL_chars
				nextBitBlock_bv = BitVector(hexstring = inputBitBlockText)
			nextBitBlock_bv.pad_from_left(self.blockSize) #Pad bit block with zeros
			cipher_text = self.ModExpo(int(nextBitBlock_bv), self.e, self.n) #generate cipher-text "integer" using modular exponentiation
			outputBitBlock_bv = BitVector(intVal = cipher_text, size = self.modSize) #generate 256-bit bit-vector of cipher-text "integer"
			outputBitBlock_bv.write_to_file(self.outputFile) #Write cipher text to output file
		self.CloseFiles() #Close I/O Files
		return

	def decrypt_RSA(self):
		fileSize = os.path.getsize(self.inputFileName) #determine size of input file to be decrypted
		numBitBlocks = fileSize / (self.modSize / 8) #determine size of decryption bit blocks
		bitBlockInd = 1 #bit block index counter to know when to check for new line characters to be stripped from decrypted text
		self.OpenFiles() #Open I/O files
		#scan in bits from input file and perform decryption algorithm
		while(self.inputFile_bv.more_to_read):
			nextBitBlock_bv = self.inputFile_bv.read_bits_from_file(self.modSize)	#Scan in bit block
			nextBitBlock_bv = self.CRT(nextBitBlock_bv) #Perform modular exponentiation using CRT to speed up process
			[zeros_pad, nextBitBlock_bv] = nextBitBlock_bv.divide_into_two() #remove padded zeros
			if (bitBlockInd == numBitBlocks):
				#Strip appended new line characters
				outputTextHex = nextBitBlock_bv.get_hex_string_from_bitvector()
				outputTextHex = outputTextHex.strip("0a")
				nextBitBlock_bv = BitVector(hexstring = outputTextHex)
			nextBitBlock_bv.write_to_file(self.outputFile) #write bit block to output file
			bitBlockInd = bitBlockInd + 1 #increment bit block index counter
		self.CloseFiles() #Close I/O Files
		return

#-----------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------
#Gather Input Data from Command Arguments
if(len(sys.argv) != 4):
	print("Usage: RSA256 -<mode (e/d)> <input text file> <output text file>")
modeFlag = sys.argv[1]
inputFileName = sys.argv[2]
outputFileName = sys.argv[3]

#Set Script Mode
if (modeFlag == '-e'):
	modeChar = 'E'
else:
	modeChar = 'D'

# #------------------------------------------------------------------------------------------------------
# #Generate RSA Keys --> code below should only be run once to generate keys --> keys are then hard-coded
# keys = GenerateKeys(256) #instantiate key generator object
# keys.GenKeys() 		  #generate keys for 256-bit implementation of RSA Algorithm
# keys.PrintKeys()	  #print generated RSA public and private key information to output file
# #------------------------------------------------------------------------------------------------------

#Define Public and Private Keys
public_key = (65537, 102117154577038987669919790021006546472692798528138848131501593198770211254977L)
private_key = (44851645551368955858196761459247042742237993466727827433916173895427998460353L, 102117154577038987669919790021006546472692798528138848131501593198770211254977L)
p_val = 332218283139502990721109112903914634009
q_val = 307379695096908922730656447003530072553

#Perform Encryption/Decryption
RSA_Crypto = RSA(public_key, private_key, p_val, q_val, inputFileName, outputFileName, 256) #Instantiate RSA Object
if (modeChar == "E"):
	RSA_Crypto.encrypt_RSA()
else:
	RSA_Crypto.decrypt_RSA()

sys.exit(0)


#-----------------------------------------------------------------------------------------------------
#Sample Output
#-----------------------------------------------------------------------------------------------------
#Encryption Input File --> message.txt (new lines added to make more readable)
#-----------------------------------------------------------------------------------------------------
# Shakespeare has had neither equal nor second.
# But among the writers who have approached nearest
# to the manner of the great master we have no
# hesitation in placing Jane Austen, a woman of whom
# England is justly proud.

#-----------------------------------------------------------------------------------------------------
#Encryption Output File --> output.txt
#-----------------------------------------------------------------------------------------------------
# 7f5c 5d99 685f 3854 095b 1ca7 809a a5ed
# dfd3 a916 2fbe 62d7 2bf1 117a 1a59 1491
# de0f 9627 2766 c45f a838 a34a b9a7 e01f
# fcc0 836c e3c9 5fa5 a37c d4ad be1d 9173
# dcb1 8a32 714a e7b6 1790 317a 9298 5b1a
# 3a5c c7ca f0c5 99ac 3a6c c86c ecbd b6c5
# 87fe 0bac 0fa0 cd52 6c8c eb6e 9f35 7a60
# aee9 380d 7393 3940 fdcf b7ff 585d 24ba
# cd16 cc3d 61f4 22c6 8d30 44d8 658c a959
# 5c15 46fd 8ae3 d441 4ba4 7430 c6e8 9557
# cd4d cfc9 1682 1701 9f37 39bf 6cf5 e02a
# e270 c61d d9cf feb0 5cd8 eebf 12d9 33e8
# 0dfc 7560 b19b e72f c96f 69a6 a8fa 8f0b
# fd37 0963 b1a1 33ad c44a 0b02 869e 38d3
# 3377 cfd6 893f 2adf 4e36 9d57 7d89 8542
# b499 efdb 3bad a321 c462 5299 40e7 af69
# 2fae 4de0 b38c 617e c0bf 3d81 c468 a2e1
# 0a3d d475 234e 6738 b094 3b53 5ac7 0180
# 4e3a dc7f 6bf1 7a2f 54cd f7ef fc56 62be
# 87c0 8adf 0048 d933 10a8 9b37 a942 5db3
# 8eb7 239c edc6 adb5 0c34 64a2 f33e dc25
# c742 7205 991a 106c 716d 17f0 5221 8b0e
# 0e1e ca10 241a 6f9a 3eb6 446f 5b16 8554
# 0f3d b8f6 588a 362f a69b ef61 3ae8 26ad
# 2b2c 090b 1635 1c52 3b0b 77f3 d262 89b8
# bf76 6331 b46f 14ec ee28 7b78 e7bb 462a
# bacd 752c 8948 8e98 f590 b802 dd80 0760
# 4144 62d9 9360 f15e 5569 3a0b c28e c7d3

#-----------------------------------------------------------------------------------------------------
#Decryption Input File --> See Above Encryption Output File
#-----------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------
#Decryption Output File --> Decrypted.txt (HEX Format)
#-----------------------------------------------------------------------------------------------------
# 5368 616b 6573 7065 6172 6520 6861 7320
# 6861 6420 6e65 6974 6865 7220 6571 7561
# 6c20 6e6f 7220 7365 636f 6e64 2e20 4275
# 7420 616d 6f6e 6720 7468 6520 7772 6974
# 6572 7320 7768 6f20 6861 7665 2061 7070
# 726f 6163 6865 6420 6e65 6172 6573 7420
# 746f 2074 6865 206d 616e 6e65 7220 6f66
# 2074 6865 2067 7265 6174 206d 6173 7465
# 7220 7765 2068 6176 6520 6e6f 2068 6573
# 6974 6174 696f 6e20 696e 2070 6c61 6369
# 6e67 204a 616e 6520 4175 7374 656e 2c20
# 6120 776f 6d61 6e20 6f66 2077 686f 6d20
# 456e 676c 616e 6420 6973 206a 7573 746c
# 7920 7072 6f75 642e 

#-----------------------------------------------------------------------------------------------------
#Decryption Output File --> Decrypted.txt (ASCII Format) (new lines added to make more readable)
#-----------------------------------------------------------------------------------------------------
# Shakespeare has had neither equal nor second.
# But among the writers who have approached nearest
# to the manner of the great master we have no
# hesitation in placing Jane Austen, a woman of whom
# England is justly proud.

#-----------------------------------------------------------------------------------------------------
#Key Values
#-----------------------------------------------------------------------------------------------------
# p = 332218283139502990721109112903914634009
# q = 307379695096908922730656447003530072553
# d = 44851645551368955858196761459247042742237993466727827433916173895427998460353