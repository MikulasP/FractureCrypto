///
///     Code by:    Peter Mikulas
///                 2023
///

#include <iostream>
#include <fstream>
#include <cstring>
#include <random>

#include "aes_config.h"
#include "aes.h"

/*
 * ************************************
 * ************************************
 *				AES_KEYSET
 * ************************************
 * ************************************
*/

// 	#
//	#	Public functions
//	#

AES_KEYSET::AES_KEYSET(const uint8_t* key) {
	CalculateKeys(key);
}

//
void AES_KEYSET::ChangeSecretKey(const uint8_t* key) {
	CalculateKeys(key);
}

//
void AES_KEYSET::EraseSecretkey() {
	CalculateKeys(nullptr);
}

//
void AES_KEYSET::ChangeIV(const uint8_t* iv) {
	if (iv)		//Only copy if *iv is not nullptr
		memcpy(this->iv, iv, 16);
}

//
void AES_KEYSET::GetIV(uint8_t* dst) const {
	if (dst)	//Only copy if *dst is not nullptr
		memcpy(dst, this->iv, 16);
}

//
void AES_KEYSET::ClearIV() {
	for (uint8_t i = 0; i < 16; i++)
		this->iv[i] = rand() % 256;
}

//
void AES_KEYSET::AddRoundKey(uint8_t* block, uint8_t keyNum) {
	if (!block)		//Return if *block is a nullptr
		return;
	
	if(keyNum > 10)		//Return if key number is too big
		return;

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			block[j * 4 + i] = block[j * 4 + i] ^ keyset[keyNum][i * 4 + j];
}

//
void AES_KEYSET::XORIV(uint8_t* block) {
	if(!block)		//Return if *block is a nullptr
		return;

	for (uint8_t i = 0; i < 16; i++)
		block[i] = block[i] ^ this->iv[i];
}

//
void AES_KEYSET::XORIV(uint8_t* block, uint8_t* iv) {
	if (!block)		//Return if *block is a nullptr
		return;

	if (!iv) {		//If *iv is nullptr add the stored IV to the block
		XORIV(block);
		return;
	}

	for (uint8_t i = 0; i < 16; i++)
		block[i] = block[i] ^ this->iv[i];
}

//
void AES_KEYSET::SetIVMode(bool mode) {
	this->IVmode = mode;
}

//
bool AES_KEYSET::GetIVMode() const {
	return this->IVmode;
}

// 	#
//	#	Private functions
//	#

//
void AES_KEYSET::ExpandKey(uint8_t keyNum) {
	if (keyNum < 1 || keyNum > 10)
		return;
	uint8_t prevKeyNum = keyNum - 1;
	keyset[keyNum][0] = SubByteSingle(keyset[prevKeyNum][7]) ^ keyset[prevKeyNum][0] ^ rcon_table[keyNum - 1];
	keyset[keyNum][4] = SubByteSingle(keyset[prevKeyNum][11]) ^ keyset[prevKeyNum][4];
	keyset[keyNum][8] = SubByteSingle(keyset[prevKeyNum][15]) ^ keyset[prevKeyNum][8];
	keyset[keyNum][12] = SubByteSingle(keyset[prevKeyNum][3]) ^ keyset[prevKeyNum][12];
	for (uint8_t i = 1; i < 4; i++) {
		keyset[keyNum][i] = keyset[keyNum][i - 1] ^ keyset[prevKeyNum][i];
		keyset[keyNum][i + 4] = keyset[keyNum][i + 3] ^ keyset[prevKeyNum][i + 4];
		keyset[keyNum][i + 8] = keyset[keyNum][i + 7] ^ keyset[prevKeyNum][i + 8];
		keyset[keyNum][i + 12] = keyset[keyNum][i + 11] ^ keyset[prevKeyNum][i + 12];
	}
}

//
void AES_KEYSET::CalculateKeys(const uint8_t* key) {
	char keyArr[16] = { 0 };

	uint8_t i;
	for (i = 0; i < 16 && key[i] != '\0'; i++)
		keyArr[i] = key[i];

	for (; i < 16; i++)
		keyArr[i] = 0;

	//Arrange characters like it's a 4x4 matrix
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			keyset[0][j * 4 + i] = keyArr[i * 4 + j];

	for (uint8_t i = 1; i < 11; i++)
		ExpandKey(i);
}

//
uint8_t AES_KEYSET::SubByteSingle(uint8_t byte) {
	return sBox[byte >> 4][byte & 0x0F];
}


/*
 * ************************************
 * ************************************
 *				AES_BASE
 * ************************************
 * ************************************
*/

// 	#
//	#	Public functions
//	#

//
size_t AES_BASE::GetBufferLimit() const {
	return this->bufferLimit;
}

//
bool AES_BASE::SetBufferLimit(const size_t limit) {
	if (limit & 0x0F)
		return false;
	this->bufferLimit = limit;
	return true;
}

//
uint8_t* AES_BASE::EncryptBuffer(const uint8_t* src, size_t length, size_t* streamLength) {
	
	//Generate new IV for this encrypt
	this->keyset->ClearIV();
	
	uint8_t* encrypted = Encrypt(src, length, streamLength, true);

	if (this->keyset->GetIVMode()) {
		uint8_t* temp = new uint8_t[*streamLength + 16];
		this->keyset->GetIV(temp);
		memcpy(temp + 16, encrypted, *streamLength);
		*streamLength += 16;
		delete[] encrypted;
		encrypted = temp;
	}

	return encrypted;
	
}

//
void AES_BASE::EncryptFile(const char* inputFileName, const char* outputFileName) {

	std::fstream inputFile;
	std::fstream outputFile;

	uint8_t* rawData = nullptr;
	uint8_t* encryptedData = nullptr;

	//Generate new IV for this encrypt
	this->keyset->ClearIV();
	
	try {
		if (!inputFileName || !outputFileName)
			throw("filename was nullptr!\n");

		//Open input file
		inputFile.open(inputFileName, std::ios::in | std::ios::binary);

		//
		size_t streamLen =  GetFileSizeBytes(inputFile);

		if (!streamLen)
			throw("File stream was 0!\n");	//Empty input file

		//Create output file
		outputFile.open(outputFileName, std::ios::out | std::ios::binary);

		if (!outputFile)
			throw("Cannot create output file!");

		if (this->keyset->GetIVMode()) {
			uint8_t iv[16] = { 0 };
			this->keyset->GetIV(iv);
			outputFile.write((char*)iv, 16);
		}

		//The maximum ammount of data (bytes) to work on at once
		size_t dataChunkSize = (streamLen > this->bufferLimit ? this->bufferLimit : streamLen);

		size_t encryptedChunkSize = 0;

		//Encrypting without padding
		//TODO Redesign loop without constant reallocation
		while (streamLen > dataChunkSize) {

			//Store data from file
			rawData = new uint8_t[dataChunkSize * sizeof(uint8_t)];

			//Check memory allocation
			if (!rawData)
				throw("Memory allocation failed!");

			//Read data from file into buffer
			inputFile.read((char*)rawData, dataChunkSize);

			encryptedData = Encrypt(rawData, dataChunkSize, &encryptedChunkSize, false);

			//Check memory allocation
			if (!encryptedData)
				throw("Failed to encrypt data!");

			delete[] rawData;

			outputFile.write((char*)encryptedData, dataChunkSize);
			outputFile.flush();

			encryptedChunkSize = 0;
			streamLen -= dataChunkSize;

			delete[] encryptedData;
		}

		//Last round with padding
		rawData = new uint8_t[streamLen * sizeof(uint8_t)];

		//Check memory allocation
		if (!rawData)
				throw("Memory allocation failed!");

		//Read data from file into buffer
		inputFile.read((char*)rawData, streamLen);

		encryptedData = Encrypt(rawData, streamLen, &encryptedChunkSize, true);

		//Check memory allocation
		if (!encryptedData)
				throw("Failed to encrypt data!");

		//Write data to file
		outputFile.write((char*)encryptedData, encryptedChunkSize);
		outputFile.flush();
	}
	catch (const char* e) {
		std::cerr << "[ERROR] " << GetModeStr() << " Encrypt File: " << e << "\n";
	}
	catch (...) {
		std::cerr << "[ERROR] " << GetModeStr() << " Encrypt File: Unknown exception occured!\n";
	}

	//Clean up after finishing
	if (outputFile.is_open())
		outputFile.close();
	if(inputFile.is_open())
		inputFile.close();
	if (rawData)
		delete[] rawData;
	if (encryptedData)	
		delete[] encryptedData;
}

//
uint8_t* AES_BASE::DecryptBuffer(const uint8_t* src, size_t length, size_t* streamLength) {

	if (this->keyset->GetIVMode()) {
		this->keyset->ChangeIV(src);
		src += 16;
		length -= 16;
	}

	return Decrypt(src, length, streamLength, true);

}

//
void AES_BASE::DecryptFile(const char* inputFileName, const char* outputFileName) {
	
	std::fstream inputFile;
	std::fstream outputFile;

	uint8_t* rawData = nullptr;
	uint8_t* decryptedData = nullptr;

	try {	
	
		if (!inputFileName || !outputFileName)
			throw("filename was nullptr!\n");

		
		inputFile.open(inputFileName, std::ios::in | std::ios::binary);

		//
		size_t streamLen =  GetFileSizeBytes(inputFile);

		if (!streamLen)
			throw("File stream was 0!\n");	//Empty input file

		if ((streamLen & 0x0F) != 0x00)
			throw("Bad file stream size!");	//Bad file size

		if (this->keyset->GetIVMode()) {
			uint8_t iv[16] = { 0 };
			inputFile.read((char*)iv, 16);
			this->keyset->ChangeIV(iv);
			streamLen -= 16;
		}

		//Create output file
		outputFile.open(outputFileName, std::ios::out | std::ios::binary);

		//The maximum ammount of data (bytes) to work on at once
		size_t dataChunkSize = (streamLen > this->bufferLimit ? this->bufferLimit : streamLen);

		size_t decryptedChunkSize = 0;

		//Encrypting without padding
		while (streamLen > dataChunkSize) {

			//Store data from file
			rawData = new uint8_t[dataChunkSize * sizeof(uint8_t)];

			//Check memory allocation
			if (!rawData)
				throw("Memory allocation failed!");

			//Read data from file into buffer
			inputFile.read((char*)rawData, dataChunkSize);

			decryptedData = Decrypt(rawData, dataChunkSize, &decryptedChunkSize, false);

			//Check memory allocation
			if (!decryptedData)
				throw("Failed to decrypt data!");

			outputFile.write((char*)decryptedData, dataChunkSize);
			outputFile.flush();

			decryptedChunkSize = 0;
			streamLen -= dataChunkSize;

			delete[] rawData;
			delete[] decryptedData;
		}

		//Last round with padding
		rawData = new uint8_t[streamLen * sizeof(uint8_t)];

		//Check memory allocation
		if (!rawData)
			throw("Memory allocation failed!");

		//Read data from file into buffer
		inputFile.read((char*)rawData, streamLen);

		decryptedData = Decrypt(rawData, streamLen, &decryptedChunkSize, true);

		//Check memory allocation
			if (!decryptedData)
				throw("Failed to decrypt data!");

		outputFile.write((char*)decryptedData, decryptedChunkSize);
		outputFile.flush();

	} catch (const char* e) {
		std::cerr << "[ERROR] " << GetModeStr() << " Decrypt File: " << e << "\n";
	}
	catch (...) {
		std::cerr << "[ERROR] " << GetModeStr() << " Decrypt File: Unknown exception occured!\n";
	}

	//Clean up after finishing
	if (outputFile.is_open())
		outputFile.close();
	if(inputFile.is_open())
		inputFile.close();
	if (rawData)
		delete[] rawData;
	if (decryptedData)	
		delete[] decryptedData;
}

//
size_t AES_BASE::GetFileSizeBytes(FILE* file) {
	if (!file)
		return 0;
	size_t filePointerPos = (size_t)ftell(file);
	fseek(file, 0, SEEK_END);
	size_t fileSize = ftell(file);
	fseek(file, filePointerPos, SEEK_SET);
	return fileSize;
}

//
size_t AES_BASE::GetFileSizeBytes(std::fstream& fs) {
	std::streampos originalPos = fs.tellg();
	fs.seekg(0, std::ios::beg);
	std::streampos startPos = fs.tellg();
	fs.seekg(0, std::ios::end);
	std::streampos endPos = fs.tellg();
	fs.seekg(originalPos, std::ios::beg);
	return endPos - startPos;
}

//
void AES_BASE::SetIV(const uint8_t* iv) {
	// No check needed here, because ChangeIV() checks for nullptr
	this->keyset->ChangeIV(iv);
}

//
void AES_BASE::GetIV(uint8_t* dst) const {
	// No check needed here, because GetIV() checks for nullptr
	this->keyset->GetIV(dst);
}

//
const inline AES_MODE AES_BASE::GetMode() const {
	return this->aesMode;
}

//
const inline char* AES_BASE::GetModeStr() const {
	switch (this->aesMode)
	{
	case AES_BASE_M:
		return "AES BASE";

	case AES_ECB_M:
		return "AES ECB";

	case AES_CBC_M:
		return "AES CBC";
	
	case AES_CFB_M:
		return "AES CFB";

	case AES_OFB_M:
		return "AES OFB";
	
	default:
		return "AES UNKNOWN";
	}
}

// 	#
//	#	Private functions
//	#

//
inline void AES_BASE::EncryptBlock(uint8_t* block) {
	if (!block)
		return;
	keyset->AddRoundKey(block, 0);
	for (uint8_t i = 1; i < 10; i++)
	{
		SubBytes(block);
		ShiftRowsLeft(block);
		MixColumns(block);
		keyset->AddRoundKey(block, i);
	}
	SubBytes(block);
	ShiftRowsLeft(block);
	keyset->AddRoundKey(block, 10);
}

//
uint8_t* AES_BASE::Encrypt(const uint8_t* src, size_t length, size_t* streamLength, bool attachPadding) {
	if (!src) {
		std::cerr << "[ERROR] AES Encrypt: Pointer to source was nullptr!\n";
		return nullptr;
	}

	if (!length) {
		std::cerr << "[ERROR] AES Encrypt: Source length was 0!\n";
		return nullptr;
	}

	if(!streamLength) {
		std::cerr << "[ERROR] AES Encrypt: streamLength variable was nullptr!\n";
		return nullptr;
	}

	*streamLength = length + (attachPadding ? ((length & 0x0F) == 0 ? 16 : 16 - (length & 0x0F)) : 0);

	size_t allocLength = *streamLength;

	uint8_t* dstStream = new uint8_t[allocLength];
	
	if (!dstStream)	{
		std::cout << "[ERROR] AES Encrypt: Memory allocation failed!\n"; //Mem. allocation falied
		delete[] dstStream;
		return nullptr;
	}

	std::memcpy(dstStream, src, length);

	//Padding block with #PKCS7 standard
	if (this->GetMode() < AES_CFB_M && attachPadding)
		for (size_t i = (*streamLength) - 1; i >= length; i--)
			dstStream[i] = ((length & 0x0F) == 0 ? 16 : 16 - (length & 0x0F));

	EncryptStream(dstStream, *streamLength);

	return dstStream;
}

//
inline void AES_BASE::DecryptBlock(uint8_t* block) {
	if (!block)
		return;
	keyset->AddRoundKey(block, 10);
	for (uint8_t i = 9; i > 0; i--) {
		ShiftRowsRight(block);
		SubBytesInv(block);
		keyset->AddRoundKey(block, i);
		MixColumnsInv(block);
	}
	ShiftRowsRight(block);
	SubBytesInv(block);
	keyset->AddRoundKey(block, 0);
}

//
uint8_t* AES_BASE::Decrypt(const uint8_t* src, size_t length, size_t* streamLength, bool removePadding) {
	if (!src) {
		std::cerr << "[ERROR] AES Decrypt: Pointer to source was nullptr!\0";		//Define error	->	__null src or length
		return nullptr;
	}

	if (!length) {
		std::cerr << "[ERROR] AES Decrypt: Source length was 0!\n";
		return nullptr;
	}

	if ((length & 0x0F) != 0) {
		std::cerr << "[ERROR] AES Decrypt: Bad file stream size!\n";	//Bad file size
		return nullptr;
	}

	if(!streamLength) {
		std::cerr << "[ERROR] AES Decrypt: streamLength variable was nullptr!\n";
		return nullptr;
	}

	uint8_t* dstStream = new uint8_t[length];

	//Check memory allocation
	if (!dstStream)	{
		std::cerr << "[ERROR] AES Decrypt: Memory allocation failed!\n";		//Define error	->	Mem. allocation falied
		return nullptr;
	}

	std::memcpy(dstStream, src, length);

	DecryptStream(dstStream, length);

	if (this->GetMode() < AES_CFB_M && removePadding)
		*streamLength = length - dstStream[length - 1];

	return dstStream;
}

//
inline void AES_BASE::SubBytes(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		block[i] = sBox[block[i] >> 4][block[i] & 0x0F];
}

//
inline void AES_BASE::SubBytesInv(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		block[i] = sBoxInv[block[i] >> 4][block[i] & 0x0F];
}

//
inline void AES_BASE::ShiftRowsLeft(uint8_t* block) {
	procArray[0] = block[0];
	procArray[1] = block[5];
	procArray[2] = block[10];
	procArray[3] = block[15];
	procArray[4] = block[4];
	procArray[5] = block[9];
	procArray[6] = block[14];
	procArray[7] = block[3];
	procArray[8] = block[8];
	procArray[9] = block[13];
	procArray[10] = block[2];
	procArray[11] = block[7];
	procArray[12] = block[12];
	procArray[13] = block[1];
	procArray[14] = block[6];
	procArray[15] = block[11];
	std::memcpy(block, procArray, 16);
}

//
inline void AES_BASE::ShiftRowsRight(uint8_t* block) {
	procArray[0] = block[0];
	procArray[1] = block[13];
	procArray[2] = block[10];
	procArray[3] = block[7];
	procArray[4] = block[4];
	procArray[5] = block[1];
	procArray[6] = block[14];
	procArray[7] = block[11];
	procArray[8] = block[8];
	procArray[9] = block[5];
	procArray[10] = block[2];
	procArray[11] = block[15];
	procArray[12] = block[12];
	procArray[13] = block[9];
	procArray[14] = block[6];
	procArray[15] = block[3];
	std::memcpy(block, procArray, 16);
}

//
inline void AES_BASE::MixColumns(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrix[mult][0], block[i * 4]) ^ GFMult(constMatrix[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrix[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrix[mult][3], block[i * 4 + 3]);
	std::memcpy(block, procArray, 16);
}

//
inline void AES_BASE::MixColumnsInv(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrixInv[mult][0], block[i * 4]) ^ GFMult(constMatrixInv[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrixInv[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrixInv[mult][3], block[i * 4 + 3]);
	std::memcpy(block, procArray, 16);
}

//
inline uint8_t AES_BASE::GFMult(uint8_t multiplier, uint8_t multiplicant) {
	switch (multiplier)
	{
	case 1:
		return multiplicant;
	case 2:
		return mul_2[multiplicant];
	case 3:
		return mul_3[multiplicant];
	case 9:
		return mul_9[multiplicant];
	case 11:
		return mul_11[multiplicant];
	case 13:
		return mul_13[multiplicant];
	case 14:
		return mul_14[multiplicant];
	default:
		return 0;
	}
	return (uint8_t)(multiplicant >= GF_MULT_OVERFLOW ? (multiplicant - GF_MULT_OVERFLOW) ^ 0x1B : multiplicant);
}

//
inline void AES_BASE::BlockXOR(uint8_t* block_a, const uint8_t* block_b, const size_t length) {
	if (!block_a || !block_b || !length)
		return;
	
	for (size_t i = 0; i < length; i++)
		block_a[i] = block_a[i] ^ block_b[i];
}

/*
 * ************************************
 * ************************************
 *				AES_ECB
 * ************************************
 * ************************************
*/

// 
//	Public functions
//

//
AES_ECB::AES_ECB(const uint8_t* key) {
	this->keyset = new AES_KEYSET(key);
	
	//Never embed or read IV from file, because ECB uses no IV
	keyset->SetIVMode(false);
}

//
void AES_ECB::EncryptStream(uint8_t* stream, size_t length) {
	
	if (!stream) {
		std::cout << "AES ECB - EncryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cout << "AES ECB - EncryptStream: length was 0.";
		return;
	}

	if (length & 16) {
		std::cout << "AES ECB - EncryptStream: wrong stream length. Must be a multiple of 16.";
		return;
	}

	//Calculate block count
	size_t blcks = length / 16;

	//Encrypt blocks
	for (size_t i = 0; i < blcks; i++)
		EncryptBlock(stream + i * 16);
}

//
void AES_ECB::DecryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cout << "AES ECB - DecryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cout << "AES ECB - DecryptStream: length was 0.";
		return;
	}

	if (length & 16) {
		std::cout << "AES ECB - DecryptStream: wrong stream length. Must be a multiple of 16.";
		return;
	}

	//Calculate block count
	size_t blcks = length / 16;

	//Decrypt blocks
	for (size_t i = 0; i < blcks; i++)
		DecryptBlock(stream + i * 16);
}

//
AES_ECB::~AES_ECB() {
	delete keyset;
}

// 
//	Private functions
//



/*
 * ************************************
 * ************************************
 *				AES_CBC
 * ************************************
 * ************************************
*/

// 	#
//	#	Public functions
//	#

//
AES_CBC::AES_CBC(const uint8_t* key, const uint8_t* iv) {
	this->keyset = new AES_KEYSET(key);
	keyset->ChangeIV(iv);
}

//
void AES_CBC::EncryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "[ERROR] AES CBC Encrypt Stream: EncryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "[ERROR] AES CBC Encrypt stream: EncryptStream: length was 0.";
		return;
	}

	if (length & 0x0F) {
		std::cerr << "[ERROR] AES CBC EncryptStream: wrong stream length. Must be a multiple of 16.";
		return;
	}

	//Calculate block count
	size_t blcks = length / 16;

	//Encrypt first block with the keyset IV
	this->keyset->XORIV(stream);
	EncryptBlock(stream);

	//Encrypt remaining blocks with the previous block as IV
	for (size_t i = 1; i < blcks; i++) {
		this->keyset->XORIV(stream + i * 16, stream + (i - 1) * 16);
		EncryptBlock(stream + i * 16);
	}
}

//
void AES_CBC::DecryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "[ERROR] AES CBC Decrypt Stream: DecryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "[ERROR] AES CBC Decrypt Stream: DecryptStream: length was 0.";
		return;
	}

	if (length & 0x0F) {
		std::cerr << "[ERROR] AES CBC Decrypt Stream: DecryptStream: wrong stream length. Must be a multiple of 16.";
		return;
	}

	//Calculate block count
	size_t blcks = length / 16;

	//Array to store the original previous block 
	uint8_t prevBlock[16] = { 0 };
	this->keyset->GetIV(prevBlock);

	//Encrypt remaining blocks with the previous block as IV
	size_t i = 0;
	for (; i < blcks; i++) {
		//Save current block's original state to the processing array
		memcpy(this->procArray, stream + i * 16, 16);

		DecryptBlock(stream + i * 16);
		this->keyset->XORIV(stream + i * 16, prevBlock);

		//Copy the current block's original form to the previous block array for the next round
		memcpy(prevBlock, this->procArray, 16);
	}
}

//
AES_CBC::~AES_CBC() {
	delete keyset;
}

// 	#
//	#	Private functions
//	#


/*
 * ************************************
 * ************************************
 *				AES_CFB
 * ************************************
 * ************************************
*/

// 	#
//	#	Public functions
//	#

//
AES_CFB::AES_CFB(const uint8_t* key, const uint8_t* iv) {
	this->keyset = new AES_KEYSET(key);
	keyset->ChangeIV(iv);
}

//
void AES_CFB::EncryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "AES CFB - EncryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "AES CFB - EncryptStream: length was 0.";
		return;
	}

	size_t blcks = length / 16;

	uint8_t lastBlock[16] = { 0 };
	this->keyset->GetIV(lastBlock);

	size_t i = 0;
	for (; i < blcks; i++) {
		EncryptBlock(lastBlock);
		BlockXOR(lastBlock, stream + i * 16);
		memcpy(stream + i * 16, lastBlock, 16);
	}

	//Check if there is remaining data that is less than a block
	if (length & 0x0F) {
		EncryptBlock(lastBlock);
		BlockXOR(lastBlock, stream + i * 16, length & 0x0F);
		memcpy(stream + i * 16, lastBlock, length & 0x0F);
	}
}

//
void AES_CFB::DecryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "AES CFB - DecryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "AES CFB - DecryptStream: length was 0.";
		return;
	}

	size_t blcks = length / 16;

	uint8_t lastBlock[16] = { 0 };
	this->keyset->GetIV(lastBlock);

	/*
	 *
	 *	Note: 	In AES CFB mode the decription process also uses the
	 *			block encryption functions.
	 * 
	*/

	size_t i = 0;
	for (; i < blcks; i++) {
		EncryptBlock(lastBlock);
		memcpy(this->procArray, stream + i * 16, 16);
		BlockXOR(stream + i * 16, lastBlock);
		memcpy(lastBlock, this->procArray, 16);
	}

	//Check if there is remaining data that is less than a block
	if (length & 0x0F) {
		EncryptBlock(lastBlock);
		BlockXOR(stream + i * 16, lastBlock, length & 0x0F);
	}

}

//
AES_CFB::~AES_CFB() {
	delete keyset;
}

// 	#
//	#	Private functions
//	#


/*
 * ************************************
 * ************************************
 *				AES_CFB
 * ************************************
 * ************************************
*/

// 	#
//	#	Public functions
//	#

//
AES_OFB::AES_OFB(const uint8_t* key, const uint8_t* iv) {
	this->keyset = new AES_KEYSET(key);
	keyset->ChangeIV(iv);
}

//
void AES_OFB::EncryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "AES OFB - EncryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "AES OFB - EncryptStream: length was 0.";
		return;
	}

	size_t blcks = length / 16;

	uint8_t lastBlock[16] = { 0 };
	this->keyset->GetIV(lastBlock);

	size_t i = 0;
	for (; i < blcks; i++) {
		EncryptBlock(lastBlock);
		BlockXOR(stream + i * 16, lastBlock);
	}

	//Check if there is remaining data that is less than a block
	if (length & 0x0F) {
		EncryptBlock(lastBlock);
		BlockXOR(stream + i * 16, lastBlock, length & 0x0F);
	}

}

//
void AES_OFB::DecryptStream(uint8_t* stream, size_t length) {
	if (!stream) {
		std::cerr << "AES OFB - DecryptStream: stream was NULL.\n";
		return;
	}

	if (!length) {
		std::cerr << "AES OFB - DecryptStream: length was 0.";
		return;
	}

	size_t blcks = length / 16;

	uint8_t lastBlock[16] = { 0 };
	this->keyset->GetIV(lastBlock);

	size_t i = 0;
	for (; i < blcks; i++) {
		EncryptBlock(lastBlock);
		BlockXOR(stream + i * 16, lastBlock);
	}

	//Check if there is remaining data that is less than a block
	if (length & 0x0F) {
		EncryptBlock(lastBlock);
		BlockXOR(stream + i * 16, lastBlock, length & 0x0F);
	}
}

AES_OFB::~AES_OFB() {
	delete this->keyset;
}

// 	#
//	#	Private functions
//	#

