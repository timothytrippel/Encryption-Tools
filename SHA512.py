#! /usr/bin/env python2.7
import sys, os, hashlib
from BitVector import*

#Homework Number: 7
#Name: Timothy Trippel
#ECN Login: ttrippel
#PUID: 0024770155
#Compiler Version: Python 2.7
#OS: Windows 8.1
#Due Date: 03/13/2014

#Function to pad message with appropriate bits for SHA-512
def PadMessage(inputFileName, inputMessage):
	fileSize = os.path.getsize(inputFileName) * 8 #Return size of message file in bits
	message_bv = inputMessage.read_bits_from_file(fileSize)
	message_bv1 = message_bv + BitVector(bitstring="1")
	message_bv1_length = message_bv1.length()
	num_zeros = (896 - message_bv1_length) % 1024
	zero_string = '0' * num_zeros
	padded_message = message_bv1 + BitVector(bitstring=zero_string) + BitVector(intVal=fileSize, size=128)
	return padded_message, message_bv.get_text_from_bitvector()

#Gather Command Line Input
if len(sys.argv) != 2:
	sys.stderr.write("Usage: ./hw07.py <input file to be hashed>\n")
	sys.exit(1)

#I/O file names
inputFileName = sys.argv[1]
outputFileName = "output.txt"

#Open output file for writing and input file as a BitVector Object Instance
outputTextFile = open(outputFileName, "wb") #open output file for writing bit stream
inputFile_bv = BitVector(filename = inputFileName) #create BV instance of input file

#Declare Hard-Coded I.V. Values as BitVectors
hb0 = BitVector(hexstring="6a09e667f3bcc908")
hb1 = BitVector(hexstring="bb67ae8584caa73b")
hb2 = BitVector(hexstring="3c6ef372fe94f82b")
hb3 = BitVector(hexstring="a54ff53a5f1d36f1")
hb4 = BitVector(hexstring="510e527fade682d1")
hb5 = BitVector(hexstring="9b05688c2b3e6c1f")
hb6 = BitVector(hexstring="1f83d9abfb41bd6b")
hb7 = BitVector(hexstring="5be0cd19137e2179")

#Declare Hard-Coded Round Constants
k = {}
k[0] = BitVector(hexstring="428a2f98d728ae22")
k[1] = BitVector(hexstring="7137449123ef65cd")
k[2] = BitVector(hexstring="b5c0fbcfec4d3b2f")
k[3] = BitVector(hexstring="e9b5dba58189dbbc")
k[4] = BitVector(hexstring="3956c25bf348b538")
k[5] = BitVector(hexstring="59f111f1b605d019")
k[6] = BitVector(hexstring="923f82a4af194f9b")
k[7] = BitVector(hexstring="ab1c5ed5da6d8118")
k[8] = BitVector(hexstring="d807aa98a3030242")
k[9] = BitVector(hexstring="12835b0145706fbe")
k[10] = BitVector(hexstring="243185be4ee4b28c")
k[11] = BitVector(hexstring="550c7dc3d5ffb4e2")
k[12] = BitVector(hexstring="72be5d74f27b896f")
k[13] = BitVector(hexstring="80deb1fe3b1696b1")
k[14] = BitVector(hexstring="9bdc06a725c71235")
k[15] = BitVector(hexstring="c19bf174cf692694")
k[16] = BitVector(hexstring="e49b69c19ef14ad2")
k[17] = BitVector(hexstring="efbe4786384f25e3")
k[18] = BitVector(hexstring="0fc19dc68b8cd5b5")
k[19] = BitVector(hexstring="240ca1cc77ac9c65")
k[20] = BitVector(hexstring="2de92c6f592b0275")
k[21] = BitVector(hexstring="4a7484aa6ea6e483")
k[22] = BitVector(hexstring="5cb0a9dcbd41fbd4")
k[23] = BitVector(hexstring="76f988da831153b5")
k[24] = BitVector(hexstring="983e5152ee66dfab")
k[25] = BitVector(hexstring="a831c66d2db43210")
k[26] = BitVector(hexstring="b00327c898fb213f")
k[27] = BitVector(hexstring="bf597fc7beef0ee4")
k[28] = BitVector(hexstring="c6e00bf33da88fc2")
k[29] = BitVector(hexstring="d5a79147930aa725")
k[30] = BitVector(hexstring="06ca6351e003826f")
k[31] = BitVector(hexstring="142929670a0e6e70")
k[32] = BitVector(hexstring="27b70a8546d22ffc")
k[33] = BitVector(hexstring="2e1b21385c26c926")
k[34] = BitVector(hexstring="4d2c6dfc5ac42aed")
k[35] = BitVector(hexstring="53380d139d95b3df")
k[36] = BitVector(hexstring="650a73548baf63de")
k[37] = BitVector(hexstring="766a0abb3c77b2a8")
k[38] = BitVector(hexstring="81c2c92e47edaee6")
k[39] = BitVector(hexstring="92722c851482353b")
k[40] = BitVector(hexstring="a2bfe8a14cf10364")
k[41] = BitVector(hexstring="a81a664bbc423001")
k[42] = BitVector(hexstring="c24b8b70d0f89791")
k[43] = BitVector(hexstring="c76c51a30654be30")
k[44] = BitVector(hexstring="d192e819d6ef5218")
k[45] = BitVector(hexstring="d69906245565a910")
k[46] = BitVector(hexstring="f40e35855771202a")
k[47] = BitVector(hexstring="106aa07032bbd1b8")
k[48] = BitVector(hexstring="19a4c116b8d2d0c8")
k[49] = BitVector(hexstring="1e376c085141ab53")
k[50] = BitVector(hexstring="2748774cdf8eeb99")
k[51] = BitVector(hexstring="34b0bcb5e19b48a8")
k[52] = BitVector(hexstring="391c0cb3c5c95a63")
k[53] = BitVector(hexstring="4ed8aa4ae3418acb")
k[54] = BitVector(hexstring="5b9cca4f7763e373")
k[55] = BitVector(hexstring="682e6ff3d6b2b8a3")
k[56] = BitVector(hexstring="748f82ee5defb2fc")
k[57] = BitVector(hexstring="78a5636f43172f60")
k[58] = BitVector(hexstring="84c87814a1f0ab72")
k[59] = BitVector(hexstring="8cc702081a6439ec")
k[60] = BitVector(hexstring="90befffa23631e28")
k[61] = BitVector(hexstring="a4506cebde82bde9")
k[62] = BitVector(hexstring="bef9a3f7b2c67915")
k[63] = BitVector(hexstring="c67178f2e372532b")
k[64] = BitVector(hexstring="ca273eceea26619c")
k[65] = BitVector(hexstring="d186b8c721c0c207")
k[66] = BitVector(hexstring="eada7dd6cde0eb1e")
k[67] = BitVector(hexstring="f57d4f7fee6ed178")
k[68] = BitVector(hexstring="06f067aa72176fba")
k[69] = BitVector(hexstring="0a637dc5a2c898a6")
k[70] = BitVector(hexstring="113f9804bef90dae")
k[71] = BitVector(hexstring="1b710b35131c471b")
k[72] = BitVector(hexstring="28db77f523047d84")
k[73] = BitVector(hexstring="32caab7b40c72493")
k[74] = BitVector(hexstring="3c9ebe0a15c9bebc")
k[75] = BitVector(hexstring="431d67c49c100d4c")
k[76] = BitVector(hexstring="4cc5d4becb3e42b6")
k[77] = BitVector(hexstring="597f299cfc657e2a")
k[78] = BitVector(hexstring="5fcb6fab3ad6faec")
k[79] = BitVector(hexstring="6c44198c4a475817")

#Perform Message Padding
message_bv, inputString = PadMessage(inputFileName, inputFile_bv)

#Perform 80-Round Processing
words = [None] * 80
for n in range(0, message_bv.length(), 1024):
	#Create Word Schedule
	block_bv = message_bv[n:n+1024]
	words[0:16] = [block_bv[ind:ind+64] for ind in range(0,1024, 64)]
	for ind in range(16, 80):
		sigma_0 = (words[ind - 15].deep_copy() >> 1) ^ (words[ind - 15].deep_copy() >> 8) ^ ((words[ind - 15].deep_copy()).shift_right(7))
		sigma_1 = (words[ind - 2].deep_copy() >> 19) ^ (words[ind - 2].deep_copy() >> 61) ^ ((words[ind - 2].deep_copy()).shift_right(6))
		words[ind] = BitVector(intVal=((int(words[ind-16]) + int(sigma_0) + int(words[ind-7]) + int(sigma_1)) % (2**64)), size=64)
	#Perform Round Functions
	a, b, c, d, e, f, g, h = hb0.deep_copy(), hb1.deep_copy(), hb2.deep_copy(), hb3.deep_copy(), hb4.deep_copy(), hb5.deep_copy(), hb6.deep_copy(), hb7.deep_copy()
	for ind in range(80):
		#Round Calculations
		sigma_a = (a.deep_copy() >> 28) ^ (a.deep_copy() >> 34) ^ (a.deep_copy() >> 39)
		sigma_e = (e.deep_copy() >> 14) ^ (e.deep_copy() >> 18) ^ (e.deep_copy() >> 41)
		ch = (e & f) ^ (~e & g)
		maj = (a & b) ^ (a & c) ^ (b & c)
		T_1 = (int(h) + int(ch) + int(sigma_e) + int(words[ind]) + int(k[ind])) % (2**64)
		T_2 = (int(sigma_a) + int(maj)) % (2**64)
		h = g
		g = f
		f = e
		e = BitVector(intVal=((int(d) + T_1) % (2**64)), size=64)
		d = c
		c = b
		b = a
		a = BitVector(intVal=((T_1 + T_2) % (2**64)), size=64)
	#Update Hash Buffer
	hb0 = BitVector(intVal=(int(hb0) + int(a))%(2**64), size=64)
	hb1 = BitVector(intVal=(int(hb1) + int(b))%(2**64), size=64)
	hb2 = BitVector(intVal=(int(hb2) + int(c))%(2**64), size=64)
	hb3 = BitVector(intVal=(int(hb3) + int(d))%(2**64), size=64)
	hb4 = BitVector(intVal=(int(hb4) + int(e))%(2**64), size=64)
	hb5 = BitVector(intVal=(int(hb5) + int(f))%(2**64), size=64)
	hb6 = BitVector(intVal=(int(hb6) + int(g))%(2**64), size=64)
	hb7 = BitVector(intVal=(int(hb7) + int(h))%(2**64), size=64)

#Output Hash Value
message_hash_code = hb0 + hb1 + hb2 + hb3 + hb4 + hb5 + hb6 + hb7
outputTextFile.write("%s" % (message_hash_code.get_hex_string_from_bitvector()))

#Check if Hash Value is Correct
sha_512 = hashlib.sha512(inputString)
hex_dig = sha_512.hexdigest()
if (message_hash_code.get_hex_string_from_bitvector() == hex_dig): print "SUCCESS"

#Close Files
inputFile_bv.close_file_object()
outputTextFile.close()
sys.exit(0)

#----------------------------------------------------------------------------
#Sample Output:
#----------------------------------------------------------------------------
#Input Message (new line characters added to increase readability):
#----------------------------------------------------------------------------
# We the people of the United States, 
# in order to form a more perfect union, 
# establish justice, insure domestic tranquility, 
# provide for the common defense, 
# promote the general welfare, and secure the 
# blessings of liberty to ourselves and our posterity, 
# do ordain and establish this Constitution 
# for the United States of America.

#----------------------------------------------------------------------------
#Output Hash Code:
#----------------------------------------------------------------------------
#ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f