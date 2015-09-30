#!/usr/bin/env python
import os, sys, re, copy
from BitVector import*

#Homework Number: 4
#Name: Timothy Trippel
#ECN Login: ttrippel
#PUID: 0024770155
#Compiler Version: Python 2.7
#OS: Windows 8.1
#Due Date: 02/18/2014

#--------------------------------------------------------------------------------------
#Program Specific Variables
#--------------------------------------------------------------------------------------
#Encryption Input Files
encryptionFileName = "plaintext.txt"
encryptOutputFileName = "encryptedtext.txt"
#Decryption Input Files
decryptionOutputFileName = "decryptedtext.txt"

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Function Definitions Below Generates a Key Schedule based on input Key Size
#--------------------------------------------------------------------------------------
#Function to Generate Key Schedule is Below
def GenerateKeySchedule(key, key_length, SBox):
	inputKeyBV = BitVector(textstring = key) #Create Bit Vector From Input Key String
	roundConstantWord = BitVector(bitstring = '00000001000000000000000000000000') #Initialize Round Constant Word
	keyRoundList = [] #Declare list to store key schedule

	#Define First Round Keys Words
	first_ind = 0
	last_ind = 32
	for word_num in range(0,8):
		keyRoundList.append(copy.deepcopy(inputKeyBV[first_ind:last_ind]))
		first_ind = last_ind
		last_ind = first_ind + 32
	word_num = word_num + 1 #increment word number counter

	for count in range(7):
		#Define Remaining Round Key Words (64 total keys for 256 bit input key --> only first 60 are used)
		#Generate G-Vector
		g_word = keyRoundList[word_num-1].deep_copy()
		g_word = g_word << 8 #Circular Left Shifted (by 8 bits/1 byte) Copy of Previous Word
		new_g_word = BitVector(size = 32)
		for word_ind in range(0,32,8):
			sub_row_ind = int(g_word[word_ind:(word_ind+4)]) #obtain row index for Sbox from upper nibble of byte
			sub_col_ind = int(g_word[(word_ind+4):(word_ind+8)]) #obtain column index for Sbox from lower nibble of byte
			subG_bv = SBox[sub_row_ind][sub_col_ind].deep_copy()
			new_g_word[word_ind:(word_ind+8)] = copy.deepcopy(subG_bv)
		new_g_word = new_g_word ^ roundConstantWord #XOR new G-word with round constant word
		#Generate Next 8 Round Keys of Key Schedule
		newVal = copy.deepcopy(keyRoundList[word_num-8])^copy.deepcopy(new_g_word)
		keyRoundList.append(newVal)
		word_num = word_num + 1
		for word_num in range(word_num,(word_num + 7)):
			#Perform SubByte on Every Word
			if ((word_num % 4) == 0): 
				for word_ind in range(0,32,8):
					old_word = copy.deepcopy(keyRoundList[word_num-1])
					sub_row_ind = int(old_word[word_ind:(word_ind+4)]) #obtain row index for Sbox from upper nibble of byte
					sub_col_ind = int(old_word[(word_ind+4):(word_ind+8)]) #obtain column index for Sbox from lower nibble of byte
					subG_bv = SBox[sub_row_ind][sub_col_ind].deep_copy()
					new_word[word_ind:(word_ind+8)] = copy.deepcopy(subG_bv)
			else:
				new_word = copy.deepcopy(keyRoundList[word_num-1])
			newVal = copy.deepcopy(keyRoundList[word_num-8])^new_word
			keyRoundList.append(newVal)
		word_num = word_num + 1
  		roundConstantWord = roundConstantWord << 1 #multiply round constant by 2 (by shifting left 1-bit) before next round
  	return keyRoundList

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#SubByte Functions Defined Below
#--------------------------------------------------------------------------------------
#Function Below Generates the appropriate SBox
def GenerateSubTable(modeChar):
	#Table Generation Variables
	modulus_poly = BitVector(bitstring = '100011011') #irreducible polynomial used in AES --> (x^8 + x^4 + x^3 + x + 1)
	byte_c = BitVector(bitstring = '01100011') #Encryption Mangle-Byte
	byte_d = BitVector(bitstring = '00000101') #Decryption Mangle-Byte
	scrambledBV = BitVector(size = 8)
	#Initialize 16x16 Sub-Table with all 0 Bit-Vectors
	zeroBV = BitVector(size = 8)
	LookUpTable = [[zeroBV.deep_copy() for x in range(16)] for y in range(16)] 
	#Set Each Table Entry to Multiplicative Inverse (in GF(2^8)) of Bit-Vector Concatenation of Row and Column 4-bit Bit-Vectors
	for x in range(16):
		for y in range(16):
			rowBV = BitVector(intVal=x, size=4) #Creat Bit Vector for Row Value
			colBV = BitVector(intVal=y, size=4) #Creat Bit Vector for Column Value
			tableBV_entry = rowBV + colBV
			#Perform MI & Bit-Mangling on Table Entries
			#If Mode is Encryption...
			if modeChar == 'E':
				#Only find MI of all bit-vectors except 0
				if (x != 0) or (y != 0):
					tableBV_entry = tableBV_entry.gf_MI(modulus_poly, 8) #Determine MI of table entry Bit-Vector
				for bit_ind in range(0, 8):
					newBit = tableBV_entry[bit_ind]^tableBV_entry[(bit_ind+1)%8]^tableBV_entry[(bit_ind+2)%8]^tableBV_entry[(bit_ind+3)%8]^tableBV_entry[(bit_ind+4)%8]^byte_c[bit_ind]
					scrambledBV[bit_ind] = newBit
			#If Mode is Decryption...
			else:
				for bit_ind in range(0, 8):
					newBit = tableBV_entry[(bit_ind+6)%8]^tableBV_entry[(bit_ind+3)%8]^tableBV_entry[(bit_ind+1)%8]^byte_d[bit_ind]
					scrambledBV[bit_ind] = newBit
				#Only find MI of all bit-vectors except 0
				if int(scrambledBV) != 0:
					scrambledBV = scrambledBV.gf_MI(modulus_poly, 8) #Determine MI of table entry Bit-Vector
			LookUpTable[x][y] = copy.deepcopy(scrambledBV)
	return LookUpTable

#Function Below Performs SubByte Processing Step (Encryption)
def SubByte(stateArray, SBox):
	for byte_ind in range(len(stateArray)):
		#Obtain Correct SBox Table Coordinate
		[row_nibble, col_nibble] = stateArray[byte_ind].divide_into_two()
		row_ind = int(row_nibble)
		col_ind = int(col_nibble)
		#Peform Byte Substitution
		stateArray[byte_ind] = copy.deepcopy(SBox[row_ind][col_ind])
	return stateArray

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Shift Rows Functions Defined Below
#--------------------------------------------------------------------------------------
#Function Below Performs ShiftRows Processing Step (Encryption)
def ShiftRows(stateArray):
	stateArray[1], stateArray[5], stateArray[9], stateArray[13] = stateArray[5], stateArray[9], stateArray[13], stateArray[1]   #Circularly Shift Row 2, 1-Byte to the Left
	stateArray[2], stateArray[6], stateArray[10], stateArray[14] = stateArray[10], stateArray[14], stateArray[2], stateArray[6] #Circularly Shift Row 3, 2-Bytes to the Left
	stateArray[3], stateArray[7], stateArray[11], stateArray[15] = stateArray[15], stateArray[3], stateArray[7], stateArray[11] #Circularly Shift Row 4, 3-Bytes to the Left
	return stateArray

#Function Below Performs InvShiftRows Processing Step (Decryption)
def InvShiftRows(stateArray):
	stateArray[1], stateArray[5], stateArray[9], stateArray[13] = stateArray[13], stateArray[1], stateArray[5], stateArray[9]   #Circularly Shift Row 2, 1-Byte to the Right
	stateArray[2], stateArray[6], stateArray[10], stateArray[14] = stateArray[10], stateArray[14], stateArray[2], stateArray[6] #Circularly Shift Row 3, 2-Bytes to the Right
	stateArray[3], stateArray[7], stateArray[11], stateArray[15] = stateArray[7], stateArray[11], stateArray[15], stateArray[3] #Circularly Shift Row 4, 3-Bytes to the Right
	return stateArray

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Mix Columns Functions Defined Below
#--------------------------------------------------------------------------------------
#Function Below Performs MixColumns Processing Step (Encryption)
def MixColumns(stateArray):
	modulus = BitVector(bitstring = '100011011') #irreducible polynomial used in AES --> (x^8 + x^4 + x^3 + x + 1)
	int_2_bv = BitVector(bitstring = '00000010') #Bit Vector representation of integer 2
	int_3_bv = BitVector(bitstring = '00000011') #Bit Vector representation of integer 3

	#Create Column Lists and New State Array Matrix (List of Lists)
	stateArrayMatrix = []
	columnList = []
	for ind in range(0,16):
		if ((ind % 4) == 0) and (ind != 0):
			stateArrayMatrix.append(copy.deepcopy(columnList))
			del columnList
			columnList = []
		columnList.append(stateArray.pop(0))
	stateArrayMatrix.append(copy.deepcopy(columnList))

	#Perform Column Mixing on Columns
	stateArray = []
	for columnList in stateArrayMatrix:
		for ind in range(0,4):
			newByte = columnList[ind].gf_multiply_modular(int_2_bv, modulus, 8) ^ columnList[(ind+1)%4].gf_multiply_modular(int_3_bv, modulus, 8) ^ columnList[(ind+2)%4] ^ columnList[(ind+3)%4]
			stateArray.append(copy.deepcopy(newByte))

	#Delete State Array Matrix (list of lists) and return new stateArray
	del stateArrayMatrix
	return stateArray

#Function Below Performs InvMixColumns Processing Step (Decryption)
def InvMixColumns(stateArray):
	modulus = BitVector(bitstring = '100011011') #irreducible polynomial used in AES --> (x^8 + x^4 + x^3 + x + 1)
	int_E_bv = BitVector(bitstring = '00001110') #Bit Vector representation of integer 0x0E
	int_B_bv = BitVector(bitstring = '00001011') #Bit Vector representation of integer 0x0B
	int_D_bv = BitVector(bitstring = '00001101') #Bit Vector representation of integer 0x0D
	int_9_bv = BitVector(bitstring = '00001001') #Bit Vector representation of integer 0x09

	#Create Column Lists and New State Array Matrix (List of Lists)
	stateArrayMatrix = []
	columnList = []
	for ind in range(0,16):
		if ((ind % 4) == 0) and (ind != 0):
			stateArrayMatrix.append(copy.deepcopy(columnList))
			del columnList
			columnList = []
		columnList.append(stateArray.pop(0))
	stateArrayMatrix.append(copy.deepcopy(columnList))

	#Perform Column Mixxing on Columns
	stateArray = []
	for columnList in stateArrayMatrix:
		for ind in range(0,4):
			newByte = columnList[ind].gf_multiply_modular(int_E_bv, modulus, 8) ^ columnList[(ind+1)%4].gf_multiply_modular(int_B_bv, modulus, 8) ^ columnList[(ind+2)%4].gf_multiply_modular(int_D_bv, modulus, 8) ^ columnList[(ind+3)%4].gf_multiply_modular(int_9_bv, modulus, 8)
			stateArray.append(copy.deepcopy(newByte))

	#Delete State Array Matrix (list of lists) and return new stateArray
	del stateArrayMatrix
	return stateArray

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Add Round Key Function Defined Below
#--------------------------------------------------------------------------------------
#Function Below Adds Round Key to Bit Block
def AddRoundKey(stateArray, roundKey1, roundKey2, roundKey3, roundKey4):
	#Declare Index Counter Variables
	first_ind1, last_ind1 = 0, 8
	first_ind2, last_ind2 = 0, 8
	first_ind3, last_ind3 = 0, 8
	first_ind4, last_ind4 = 0, 8
	#Add Round Key to State Array
	for index in range(0,16):
		#Add Round Key to Word #1
		if index < 4:
			stateArray[index] = stateArray[index] ^ roundKey1[first_ind1:last_ind1]
			first_ind1 = last_ind1 
			last_ind1 = last_ind1 + 8
		#Add Round Key to Word #2
		elif index < 8:
			stateArray[index] = stateArray[index] ^ roundKey2[first_ind2:last_ind2]
			first_ind2 = last_ind2 
			last_ind2 = last_ind2 + 8			
		#Add Round Key to Word #3
		elif index < 12:
			stateArray[index] = stateArray[index] ^ roundKey3[first_ind3:last_ind3]
			first_ind3 = last_ind3 
			last_ind3 = last_ind3 + 8			
		#Add Round Key to Word #4
		else:
			stateArray[index] = stateArray[index] ^ roundKey4[first_ind4:last_ind4]
			first_ind4 = last_ind4 
			last_ind4 = last_ind4 + 8
	#Return State Array
	return stateArray

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Encryption/Decryption Functions Defined Below
#--------------------------------------------------------------------------------------
#Function Below Performs Encryption on an Input File
def Encrypt_AES(inputFile_bv, outputTextFile, keySchedule, SBox):
	#Scan in file 128-bits at a time and perform processing on each block
	while (inputFile_bv.more_to_read):
		bitBlock_bv = inputFile_bv.read_bits_from_file(128)
		if bitBlock_bv.length() > 0:
			#Pad bit block with trailing zeros if necessary
			if (bitBlock_bv.length() != 128):
				bitBlock_bv.pad_from_right(128-bitBlock_bv.length())
			
			#Initialize State Array and Begin AES Encryption Process
			#Generate State Array
			stateArray = GenerateStateArray(bitBlock_bv)

			#Add Round Key to Initialize Encryption Sequence
			stateArray = AddRoundKey(stateArray, keySchedule[0], keySchedule[1], keySchedule[2], keySchedule[3])

			#Begin Rounds of AES Encryption
			roundCounter = 1 #Round counter to keep track of current processing round
			ind = 0 #key schedule array index
			for ind in range(4, 60, 4):
				#Perform SubByte on StateArray
				stateArray = SubByte(stateArray, SBox)	

				#Perform ShiftRows on StateArray
				stateArray = ShiftRows(stateArray)
				
				if (roundCounter != 14):
					#Perform MixColumns on StateArray
					stateArray = MixColumns(stateArray)

				#Add Round Key to State Array
				stateArray = AddRoundKey(stateArray, keySchedule[ind], keySchedule[ind+1], keySchedule[ind+2], keySchedule[ind+3])

				#Update Round Counter
				roundCounter = roundCounter + 1

			#Combine words in state array to output to file
			newBitBlock = stateArray[0]
			for index in range(1,16):
				newBitBlock = newBitBlock + stateArray[index]

		#Write current bit-block to outputfile
		outputTextFile.write(newBitBlock.get_text_from_bitvector())
	return

#Function Below Performs Decryption on an Input File
def Decrypt_AES(inputFile_bv, outputTextFile, keySchedule, SBox, numBlocks):
	#Define NULL Byte BV and String for Padding Purposes
	nullByte_bv = BitVector(size = 8)
	nullChar = chr(int('00000000',2))
	block_counter = 0
	
	#Scan in file 128-bits at a time and perform processing on each block
	while (inputFile_bv.more_to_read):
		bitBlock_bv = inputFile_bv.read_bits_from_file(128)
		block_counter = block_counter + 1
		if bitBlock_bv.length() > 0:

			#Initialize State Array and Begin AES Encryption Process
			#Generate State Array
			stateArray = GenerateStateArray(bitBlock_bv)
		
			#Add Round Key to Initialize Encryption Sequence
			stateArray = AddRoundKey(stateArray, keySchedule[56], keySchedule[57], keySchedule[58], keySchedule[59])
			
			#Begin Rounds of AES Encryption
			roundCounter = 1 #Round counter to keep track of current processing round
			ind = 0 #key schedule array index
			for ind in range(52,-1,-4):
				#Perform ShiftRows on StateArray
				stateArray = InvShiftRows(stateArray)

				#Perform SubByte on StateArray
				stateArray = SubByte(stateArray, SBox)

				#Add Round Key to State Array
				stateArray = AddRoundKey(stateArray, keySchedule[ind], keySchedule[ind+1], keySchedule[ind+2], keySchedule[ind+3])
				
				if (roundCounter != 14):
					#Perform MixColumns on StateArray
					stateArray = InvMixColumns(stateArray)

				#Update Round Counter
				roundCounter = roundCounter + 1

			#Combine words in state array to output to file
			newBitBlock = stateArray[0]
			for index in range(1,16):
				newBitBlock = newBitBlock + stateArray[index]

			#Check for Padded NULL bytes if in "Decrypt" Mode
			if (block_counter == numBlocks):
				outputText = newBitBlock.get_text_from_bitvector()
				outputText = outputText.strip(nullChar)
			else:
				outputText = newBitBlock.get_text_from_bitvector() 
		#Write current bit-block to outputfile
		outputTextFile.write(outputText)
	return

#Function Below Generates a 4x4 State Array of Bytes from a 128-Bit Bit-Vector Object
def GenerateStateArray(bitBlock_bv):
	stateArray = [] #Create Empty List for State Array
	first_ind = 0
	last_ind = 8	
	for list_ind in range(16):
		stateArray.append(bitBlock_bv[first_ind:last_ind].deep_copy())
		first_ind = last_ind  	#Increment first_ind bit-vector slice index
		last_ind = last_ind + 8 #Increment last_ind bit-vector slice index	
	return stateArray

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Prompt User for Information
#Prompt User for Desired Mode: Encryption/Decryption
modeChar = raw_input("Enter Mode - Encryption or Decryption (E/D): ")
while ((modeChar != 'E') and (modeChar != 'D')):
	print("Mode not recognized. Try entering mode again.")
	modeChar = raw_input("Enter Mode - Encryption or Decryption (E/D): ")
#Prompt User for Encryption Key
AES_key = raw_input("Enter Encryption Key (at LEAST 32 Characters Long): ")
while (len(AES_key) < 32):
	print("Encryption key must be at least 32 characters long. Try again or enter '-1' to exit script.")
	AES_key = raw_input("Enter Encryption Key (at LEAST 32-Characters Long): ")
	if(AES_key == '-1'):
		sys.exit(1)

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Open Input Files to Read Data From
if modeChar == 'E':
	inputFileName = encryptionFileName
	outputFileName = encryptOutputFileName
	try:
		inputTextFile = open(inputFileName, 'r')
	except IOError:
		print("Error: intput file %s does not exist." % (inputFileName))
		sys.exit(1)
else:
	inputFileName = encryptOutputFileName
	outputFileName = decryptionOutputFileName
	try:
		inputTextFile = open(inputFileName, 'r')
	except IOError:
		print("Error: intput file %s does not exist." % (inputFileName))
		sys.exit(1)	
inputTextFile.close() #close opened file after checking for its existence

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Open output file for writing and input file as a BitVector Object Instance
outputTextFile = open(outputFileName, "wb") #open output file for writing bit stream
inputFile_bv = BitVector(filename = inputFileName) #create BV instance of input file

#Generate S-Box --> For Key Schedule Generation always use "Encryption Mode" SBox
SBox = GenerateSubTable('E')

#Generate Key Schedule
keySchedule = GenerateKeySchedule(AES_key, 256, SBox)
keySchedule.pop(); keySchedule.pop(); keySchedule.pop(); keySchedule.pop() #Remove Last 4 elements of key schedule

#Regenerate S-Box for Correct Script Mode (Encryption/Decryption)
del SBox
SBox = GenerateSubTable(modeChar)

# Perform Encryption/Decryption
if modeChar == 'E':
	print("Encrypting file %s ..." % (inputFileName))
	newBitBlock = Encrypt_AES(inputFile_bv, outputTextFile, keySchedule, SBox)
	print("Encryption complete.")
else:
	print("Decrypting file %s ..." % (inputFileName))
	#In decryption mode --> retrieve size of output file (to aid with stripping of null bytes at end)
	fileSize = os.path.getsize(inputFileName)
	numBlocks = (fileSize*8)/128 #calculate number of 128-bit blocks to be decrypted
	Decrypt_AES(inputFile_bv, outputTextFile, keySchedule, SBox, numBlocks)
	print("Decryption complete.")

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
#Close All Opened Files and Exit Script
inputFile_bv.close_file_object()
outputTextFile.close()
sys.exit(0)

#--------------------------------------------------------------------------------------
# Sample Output Below:
#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
# Encryption Output:
#--------------------------------------------------------------------------------------
# =>ttrippel_AES.py
# Enter Mode - Encryption or Decryption (E/D): E
# Enter Encryption Key (at LEAST 32 Characters Long): anunexaminedlifeisnotworthliving
# Encrypting file plaintext.txt ...
# Encryption complete.
# 
#--------------------------------------------------------------------------------------
# Input File Read From --> plaintext.txt (New lines added to make readable)
#--------------------------------------------------------------------------------------
# This is an unusual paragraph. I'm curious how quickly you can find out what is so unusual about it? 
# It looks so plain you would think nothing was wrong with it! In fact, nothing is wrong with it! It is 
# unusual though. Study it, and think about it, but you still may not find anything odd. But if you work 
# at it a bit, you might find out! Try to do so without any coaching! You most probably won't, at first, 
# find anything particularly odd or unusual or in any way dissimilar to any ordinary composition. That 
# is not at all surprising, for it is no strain to acomplish in so short a paragraph a stunt similar to 
# that which an author did throughout all of his book, without spoiling a good writing job, 
# and it was no small book at that.
# 
#--------------------------------------------------------------------------------------
# Output File Created -->  encryptedtext.txt
#--------------------------------------------------------------------------------------
# 26b1 2bd2 b04f 8755 95a3 ec3d 58eb 7666
# ebe6 caf9 f4e6 3141 8d79 4a80 59df 72c2
# 4358 dd05 2952 59c7 a234 c5a8 1e55 e781
# 426b 89e4 39e3 8d60 c6f5 a19e ad3c 619b
# fa5b bc15 d204 8480 0b05 a6df 649f 531b
# 2534 d84b 29aa 6bbe b81c 95d6 4023 ca94
# 78d0 63dc 9326 28bc bb9d 42ef 00d5 a7a3
# b552 ec63 27bb d0c6 ad5c ad58 a4d1 c9f0
# 4f83 72d9 4180 7b44 49c7 493b 1dfe 0ef4
# 33fd 5f1c f804 b9a6 f6ea 92de f27b 9b1c
# 13cc 5d67 8e45 2821 ad1f 0ed6 271e cb89
# 76a3 f72b 1d0f 9025 b1d2 258a d47a 7eeb
# 87a7 9bb8 f314 5c22 8a30 a433 82f9 8040
# 8604 ebb6 46fb d502 0abd 2f33 bba6 1ad3
# fa8f 9eb1 47d9 4ad6 6473 93c7 16cf 48ba
# b32e 32b4 70dc dae8 1641 aa62 425c f458
# 71a9 1edc 4c56 b66d ed67 bfff 9c5f e26d
# 1458 d5bd 1027 2cf6 63a4 d709 9f17 d541
# 39bb 0fda f8ba 46e1 a5d9 bbf7 cff5 5259
# 8f65 9a82 ed7f 5db0 3876 608c fc1c 2708
# 4346 043e 3a30 0461 c3ce 1a23 1ed3 2561
# 4ac2 b6ec 8e7f 1ed8 52f1 7b94 6366 30f2
# 67ea 1910 8a90 67ab 4785 2235 128c eb32
# 546f b836 0877 4396 2d80 f2da 87cd 4d3d
# f9f6 abcd b1b4 9fae cee0 0495 61af 9eb5
# 165f edfa 3373 c7d0 4537 041a 57e4 944a
# 29f9 f1d2 c9bb b3c3 b76e 5512 5195 c1dd
# 3a94 3e33 9b67 e829 a5ab e858 dcd3 9159
# df1a f84f 7e2a 1af7 aff8 1e1c 4440 5294
# dd50 98d2 430b dcc4 1f4e a647 0843 6b26
# 4183 af9d 3194 12b2 5fe3 ba7b 49ea 7636
# eef5 3d7b 8cc2 29ab 8818 94c8 1349 44c3
# 1c29 bf3f 95c7 5136 f9ef 4b75 8d71 577f
# 7118 d07e e6da a000 a986 215d 4583 5b51
# 5fd8 4402 4d66 f2de aed1 01e6 cd08 f01e
# 7f31 dff8 d52c 0102 a7ac b3d1 6336 1172
# d1bd 2480 2e50 7e5e 4b86 f60a 6cbd e3d1
# ba71 f0af eb6f a41f 2942 0fe9 b5f6 34dc
# 76a9 d86e f222 59b8 0491 603e 7eb4 d627
# 2542 a07b df2b e561 9104 9eb2 5735 1652
# 5742 7c82 cae0 75d9 3581 d542 6f48 5daf
# 82ab 34a3 1c83 7ab3 fbd1 d3e1 05cc a445
# a925 9157 d111 95c9 c60b 7957 0c97 ebff
# 353d 2980 a4e1 16b7 cb3b ed58 801e 3e20
# 202c 455c 54c9 012a d4fb 6e8c 4852 ea74
# 0569 d798 eaac 2b66 d085 e14d c951 f29d

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------
# Decryption Output:
#--------------------------------------------------------------------------------------
# =>ttrippel_AES.py
# Enter Mode - Encryption or Decryption (E/D): D
# Enter Encryption Key (at LEAST 32 Characters Long): anunexaminedlifeisnotworthliving
# Decrypting file encryptedtext.txt ...
# Decryption complete.
# 
#--------------------------------------------------------------------------------------
# Input File Read From --> encryptedtext.txt
#--------------------------------------------------------------------------------------
# See above output file from Encryption mode.
# 
#-------------------------------------------------------------------------------------- 
# Output File Created -->  decryptedtext.txt  (New lines added to make readable)
#--------------------------------------------------------------------------------------
# This is an unusual paragraph. I'm curious how quickly you can find out what is so unusual about it? 
# It looks so plain you would think nothing was wrong with it! In fact, nothing is wrong with it! It is 
# unusual though. Study it, and think about it, but you still may not find anything odd. But if you work 
# at it a bit, you might find out! Try to do so without any coaching! You most probably won't, at first, 
# find anything particularly odd or unusual or in any way dissimilar to any ordinary composition. That 
# is not at all surprising, for it is no strain to acomplish in so short a paragraph a stunt similar to 
# that which an author did throughout all of his book, without spoiling a good writing job, 
# and it was no small book at that.                                                                      