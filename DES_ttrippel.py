#!/usr/bin/env python2.7
import sys, os, copy
from BitVector import*

#Homework Number: 2 - Problem 1
#Name: Timothy Trippel
#ECN Login: ttrippel
#PUID: 0024770155
#Compiler Version: Python 2.7
#OS: Windows 8.1
#Due Date: 01/30/2014

#--------------------------------------------------------------------------------
#Function Definitions Below
#Function to Generate Round Keys
def GenerateRoundKeys(Encryption_Key, KeyPermutation1_List, KeyPermutation2_List, ShiftInfoDict):
	#Generate 56-Bit BV from Encryption Key
	encryptionKeyBV = BitVector(textstring = Encryption_Key) #Declare BitVector from bit string

	#Perform Permutation 1
	textBV = encryptionKeyBV.deep_copy()
	for ind in range(0,56):
		textBV[ind] = encryptionKeyBV[KeyPermutation1_List[ind]]

	encryptionKeyBV = encryptionKeyBV.permute(KeyPermutation1_List)

	#Split Key into two 28-Bit Halves
	[key1_L, key1_R] = encryptionKeyBV.divide_into_two() #Split key into two 28-bit halves

	#Perform Round 1 Shift for Encryption 
	round1_shift = ShiftInfoDict[1] #obtain number of bits to shift key in round 1
	key1_L = key1_L << round1_shift #circularly shift left, left half of key
	key1_R = key1_R << round1_shift #circularly shift left, right half of key

	#Perform Contraction Permutation for round 1 key
	round1_key = key1_L + key1_R #join together both left and right halves of round 1 key
	round1_key = round1_key.permute(KeyPermutation2_List) #perform 56 to 48 bit contracting permutation

	#Add 1st Round Key to List
	roundNum = 1
	keyList = [round1_key]
	key_L = key1_L
	key_R = key1_R

	#Add Remaining Round Keys to List
	for roundNum in range(1,16):
		round_shift = ShiftInfoDict[roundNum+1] #obtain number of bits to shift ket by in present round
		key_L = key_L.deep_copy() << round_shift #circularly shift left, left half of key
		key_R = key_R.deep_copy() << round_shift #circularly shift left, right half of key
		round_key = key_L.deep_copy() + key_R.deep_copy() #join together both left and right halves of round 1 key
		round_key = round_key.permute(KeyPermutation2_List)#perform 56 to 48 bit contracting permutation
		keyList.append(round_key.deep_copy())

	return keyList

#Function to Encrypt a Single 64-Bit Block
def Encrypt_64Bit_Block(lBV, rBV, round_key, SBoxes_Dict_List, PBox_List):
	#Perform Expansion Permutation	
	sliceList = []; #empty list to hold 4-bit slices of right half of bit block
	bv_index = 0

	#Copy Right Side Bit Block
	rbv_copy = rBV.deep_copy()

	#Break 32-bit right half into 4-bit blocks
	for bv_index in range(0,29,4):
		sliceList.append(rBV[bv_index:(bv_index + 4)])

	#Expand 4-bit BV to a 6-bit BV
	#Create List of 8, 6-Bit, Bit Vectors
	newBV = BitVector(size = 6)
	newBV_List = []
	for ind in range(0, 8):
		newBV_List.append(newBV.deep_copy())
	#Update 6-Bit Long Bit Vectors with correct values
	for bv_index in range(0, 8):
		for ind in range(0, 6):
			if (ind == 0):
				newBV_List[bv_index][ind] = sliceList[bv_index - 1][3]
			elif (ind == 5):
				if ((bv_index + 1) < 8):
					newBV_List[bv_index][ind] = sliceList[bv_index + 1][0]
				else:
					newBV_List[bv_index][ind] = sliceList[0][0]
			else:
				newBV_List[bv_index][ind] = sliceList[bv_index][ind-1]

	#Concatenate all 6-bit BVs into one 48-bit block
	expandedBitBlock_bv = newBV_List[0]
	for bv_index in range(1,8):
		expandedBitBlock_bv = expandedBitBlock_bv + newBV_List[bv_index]

	#Perform Round-Key XOR-ing
	expandedBitBlock_bv = expandedBitBlock_bv ^ round_key;

	#Perform Substitution with S-Boxes
	#Split expanded 48-bit block back to 6-bit blocks
	SBox_SliceList = []
	for bv_index in range(0,43,6):
		SBox_SliceList.append(expandedBitBlock_bv[bv_index:(bv_index + 6)])
	#Perform S-Box Substitution
	subNumberList = []
	for bv_index in range(0,8):
		rowBitString = str(SBox_SliceList[bv_index][0]) #splice off 1st bit of 6-bit block
		rowBitString = rowBitString + str(SBox_SliceList[bv_index][5]) #splice off 1st bit of 6-bit block
		rowBV = BitVector(bitstring = rowBitString)
		columnBV = SBox_SliceList[bv_index][1:5] #splice off center 4 bits of 6-bit block
		rowIndex = int(rowBV) #retrieve row index number
		colIndex = int(columnBV) #retrieve column index number
		subNumberList.append(copy.deepcopy('{0:04b}'.format(SBoxes_Dict_List[bv_index][rowIndex][colIndex])))
		subNumberBitString = ''.join(subNumberList)
	subNumber_BV = BitVector(bitstring = subNumberBitString)

	#Perform Permutation with P-Box
	subNumber_BV = subNumber_BV.permute(PBox_List)

	#Perform XOR-ing with Left 32-Bit Half
	newR_bv = subNumber_BV ^ lBV
	newL_bv = rbv_copy

	#Return New Left and Right Bit Vectors
	return newL_bv, newR_bv

#Function to Encrypt a File using DES Algorithm
def EncryptFile(inputFileName, outputFileName, roundKeyList, KeyPermutation1_List, KeyPermutation2_List, SBoxes_Dict_List, PBox_List, ShiftInfoDict, modeChar):
	#open output file for writing and create BV instance of input file
	outputTextFile = open(outputFileName, "wb")
	inputFile_bv = BitVector(filename = inputFileName)
	nullByte_bv = BitVector(size = 8)
	nullChar = chr(int('00000000',2))
	#If decrypting --> retrieve size of output file (to aid with stripping of null bytes at end)
	if (modeChar == 'D'):
		fileSize = os.path.getsize(inputFileName)
	byteCount = 0

	#Scan in 64-Bit blocks of file at a time
	while (inputFile_bv.more_to_read):
		bitBlock_bv = inputFile_bv.read_bits_from_file(64)
		if bitBlock_bv.length() > 0:
			#Pad bit block with trailing zeros if necessary
			if (bitBlock_bv.length() != 64):
				bitBlock_bv.pad_from_right(64-bitBlock_bv.length())
				# bytesShort = (64 - bitBlock_bv.length())/8
				# bytesShort_bv = BitVector(int = bytesShort)
				# for ind in range(0, bytesShort):
				# 	bitBlock_bv = bitBlock_bv + bytesShort_bv

			#Split Bit Vector into 2-32Bit halves
			[lBV, rBV] = bitBlock_bv.divide_into_two()

			#Perform 1st Round of Encryption
			[lBV, rBV] = Encrypt_64Bit_Block(lBV, rBV, roundKeyList[0], SBoxes_Dict_List, PBox_List)

			#Perform Remaining 15 Rounds of Encryption
			for roundNum in range(1,16):
				#Retrieve Round Key
				round_key = roundKeyList[roundNum]
				#Call 64-bit Block Encryption Function
				[lBV, rBV] = Encrypt_64Bit_Block(lBV, rBV, round_key, SBoxes_Dict_List, PBox_List)

			#Concatenate Left and Right Halves of 64-Bit Block
			encryptedBitBlock_bv = rBV + lBV
			
			#Check for Padded NULL bytes if in "Decrypt" Mode
			ind = 0
			outputText = encryptedBitBlock_bv.getTextFromBitVector()
			if (modeChar == 'D'):
				byteCount = byteCount + 8
				if (byteCount > (fileSize - 8)):
					outputText = outputText.strip(nullChar) 

			#Write Output To Output File
			#print outputText
			outputTextFile.write(outputText)

	#Close Files
	outputTextFile.close()
	inputFile_bv.close_file_object()
	return

#--------------------------------------------------------------------------------
#Prompt User for Information
#Prompt User for Desired Mode: Encryption/Decryption
modeChar = raw_input("Enter Mode - Encryption or Decryption (E/D): ")
while ((modeChar != 'E') and (modeChar != 'D')):
	print("Mode not recognized. Try entering mode again.")
	modeChar = raw_input("Enter Mode - Encryption or Decryption (E/D): ")
#Prompt User for Encryption Key
DES_key = raw_input("Enter Encryption Key (at LEAST 8 Characters Long): ")
while (len(DES_key) < 8):
	print("Encryption key must be at least 8 characters long. Try again or enter '-1' to exit script.")
	DES_key = raw_input("Enter Encryption Key (at LEAST 8-Characters Long): ")
	if(DES_key == '-1'):
		sys.exit(1)

#Prompt User for Name of File to Be Encrypted
inputFileName = raw_input("Enter Name of Input File: ")
try:
	inputTextFile = open(inputFileName, 'r')
except IOError:
	print("Error: Input file does not exist.")
	sys.exit(1)
inputTextFile.close() #close opened file after checking for its existence
#Prompt User for Name of Output File to Store Encrypted File
outputFileName = raw_input("Enter Name of Output File: ")

#--------------------------------------------------------------------------------
#Data structures needed to perform DES algorithm
ShiftInfoDict = {1:1, 2:1, 3:2, 4:2, 5:2, 6:2, 7:2, 8:2, 9:1, 10:2, 11:2, 12:2, 13:2, 14:2, 15:2, 16:1} #Round key shift information

#Key Permutation Lists
KeyPermutation1_List = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
KeyPermutation2_List = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
#Correct offset of Permutation Lists 1 and 2 to be List Indices
for ind in range(0,len(KeyPermutation1_List)):
	KeyPermutation1_List[ind] = KeyPermutation1_List[ind] - 1
for ind in range(0,len(KeyPermutation2_List)):
	KeyPermutation2_List[ind] = KeyPermutation2_List[ind] - 1

#S-Boxes
SBoxes_Dict_List = [
{0:[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
1:[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
2:[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
3:[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]},

{0:[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
1:[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
2:[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
3:[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]},

{0:[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
1:[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
2:[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
3:[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]},

{0:[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
1:[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
2:[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
3:[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]},

{0:[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
1:[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
2:[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
3:[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]},

{0:[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
1:[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
2:[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
3:[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]},

{0:[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
1:[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
2:[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
3:[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]},

{0:[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
1:[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
2:[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
3:[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]}]

#P-Box
PBox_List = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
for ind in range(0,len(PBox_List)):
	PBox_List[ind] = PBox_List[ind] - 1

#--------------------------------------------------------------------------------
#Generate Ecryption Round Keys for Round 1
roundKeyList = GenerateRoundKeys(DES_key, KeyPermutation1_List, KeyPermutation2_List, ShiftInfoDict) #Generate encryption key BVs

#Encrypt/Decrypt File
if (modeChar == 'E'):
	#Call Encryption Function
	print "Encrypting File..."
	EncryptFile(inputFileName, outputFileName, roundKeyList, KeyPermutation1_List, KeyPermutation2_List, SBoxes_Dict_List, PBox_List, ShiftInfoDict, modeChar)
	print "File Successfully Encrypted."
elif (modeChar == 'D'):
	print "Decrypting File..."
	reverseRoundKeyList = []
	for ind in range(15,-1,-1):
		reverseRoundKeyList.append(roundKeyList[ind])
	#Call Decryption Function	
	EncryptFile(inputFileName, outputFileName, reverseRoundKeyList, KeyPermutation1_List, KeyPermutation2_List, SBoxes_Dict_List, PBox_List, ShiftInfoDict, modeChar)
	print "File Successfully Decrypted."
#Exit Script Successfully
sys.exit(0)


#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
#Script Output
#Encrypted Hex Output:
# 4a36 98c0 dae7 8511 7c88 7a33 f3fc 1c79
# 928c 77cd 0375 7223 0fb2 1cce 067d e488
# f7ab f9ff 6ecc 0bab 68f9 23b1 6142 c232
# a9cc 83fe ec2b acf6 bdfa 0f63 1184 f170
# bdd3 2a01 990d fb56 a9fe 97cc b03f 60ab
# dfe1 326b 94d8 8112 9abe fff6 d588 0b17
# 6c9a 0563 721f bc0b 1e50 8cfe 995b 3845
# 16d6 0395 d097 5cfb 6945 7cf7 185e 8ad1
# 1e51 75d9 6ecc 2277 c3b5 cdb8 4b71 f491
# e7e6 591d 1565 ce36 68f9 23b1 6142 c232
# 5fd9 e559 cbb1 d180 d9e3 ff95 0251 84be
# 2f03 98c7 6337 d3d0 5302 2429 b3dc 5712
# 6217 0aef fd8b 1085 31d5 3618 68f8 a0ed
# c1d1 7992 bcff fca8 da91 7b76 9607 03ff
# 1138 a117 4f07 316b 1233 9cdd 41f3 5830
# 7e8e 1e00 618d 0483 dcf8 886b f196 ce60
# 4a4e c661 5678 dec9 e857 e09f 02cc 9c05
# c4dd 6a94 a3c7 d7f3 87f2 d317 ea49 cf93
# 38a0 d1b0 5942 d3a9 50d1 ce80 e48d 59b1
# d405 6a76 852f 3483 8aec 6d7a 749b 20f5
# e0d1 1183 524a 3d22 73ef 97b4 1e71 370a
# e074 f4c8 43cc 672d 5cb3 23fe b6d7 73be
# 9c56 97a2 3b68 42a0 8397 c8ed a2c8 6b55
# 09de b782 a246 53fe 2a9c 93b4 1f10 c10e
# 7bc6 c481 ee2f 210a 36ca 79ee 95ca a769
# b775 e3d5 4a59 0ab6 abd7 6992 087d d5f3
# 1524 8740 4d12 873f 8fdb 58fc 0689 c1ad
# 1285 c5bb 5003 fa4f 229d 76c7 45fd e302
# a684 83e9 402b 703f f58a 0891 e982 743d
# bfb2 ad9c 869c 526b 291b 23d2 8527 2e9a
# 31e3 6b8a f905 49aa 833b 7630 5710 7231
# a07c ef47 560f 7f75 83dd a82a fd9a 0160
# e89e 1491 57a8 5a39 7c7c 858c a55a 4cb0
# c18e a0de 6286 1138 b876 d5ca 339a 6634
# ccb1 c903 d0b2 32a5 5b43 8bd5 7a3d b07f
# c589 a3ea f111 0c08 f1ba ea4f 985e b6c3
# c744 b679 0cd5 f346 774f 1e19 9b39 2509
# 5027 82fd 012c d1d8 ac06 9c75 8b93 453c
# ea6c 03ef a946 bff3 8a71 3ce7 bee1 361a
# ee8c 7fd4 6731 eec0 8c23 ed74 d7b8 1c9a
# 509e c36b f400 4587 3a38 7df5 7e04 02fe
# 4996 2eac 7bd0 49a7 8e98 936b 45b7 1636
# c738 d8c3 f572 d7d4 e5dd 821a a2b3 6346
# ab15 a5e8 2696 235f a84a 1e49 cdaa 7a50
# 6b2b 4c17 49e9 e1d0 b932 b8f5 5f13 a69a
# c718 e077 abb7 458b d2f7 0290 3930 65a8
# 5cb3 23fe b6d7 73be 5193 ee33 bfc1 e5e9
# dfda 524f 5e4d 2932 e291 746c 2e65 0b3e
# 1a4e 5708 08ab 52ff c798 c4f7 5f76 a08b
# 33b8 47bc 049d 8d0b d2b9 64f3 4070 caf5
# 5415 9e87 cab4 1f51 1242 c0a0 726c 7c60
# 860a 0c27 ee0a f52b 9393 955b 386a 0f00
# 6e35 7606 f310 09b2 7296 06df dfac 5425
# 9b24 159c 8ea0 1f61 487e 2bec 6d22 35df
# 9725 ec95 e747 ee79 1985 96ae 6b81 00c7
# 68f9 23b1 6142 c232 86b4 9081 1cc7 5c2c
# d764 6d00 a960 3b81 a97e 1b40 e376 6f95
# 5f8c e1fb 7a6e b4d8 8447 11f4 87e3 6357
# 
#Decrypted ASCII Output:
# A technology that constantly changes website code to defeat hackers has been unveiled by an US startup. 
# Shape Security says its product transforms a website code into a moving target to prevent cybercriminals 
# from carrying out scripted attacks. Shape describes its product as being a barrier against automated software tools known as bots 
# that recognise and exploit vulnerabilties in the website code. Many products try to prevent such breaches by 
# identifying bots by their signatures and the internet and email addresses they send data to. Hackers have tried to counter 
# detection by using a technique called real time polymorphism by making their bots rewrite their own code every time they 
# infect a new machine to make them harder to recognise. Shape says its product reverses this advantage. 
# The website looks and feels exactly the same to legitimate users, but the underlying site code is different on every page view.