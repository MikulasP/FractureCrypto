///
///     Code by:    Peter Mikulas
///                 2023
///

#define AES_DEFAULT_BUFFSIZE    128000000  //Max buffer size on heap in bytes -!!- MUST BE MULTIPLE OF 16 -!!-
/*
*	Note: This size only restricts single buffers, NOT the whole program buffer size.
*/

class AES_KEYSET {
private:

	//All 11 stages of the key
	uint8_t keyset[11][16];

	//Initialization vector
	uint8_t iv[16];

	//Embed IV when encrypting and read IV from the input when decrypting
	bool IVmode = true;

public:

	/**
	 * 	@brief Default constructor
	 * 
	 * 	@param key Pointer to the key array
	*/
	AES_KEYSET(const uint8_t* key = nullptr);
	//*OK

	/**
	 * 	@brief Change AES secret key
	 * 
	 * 	@param key New secret key
	*/
	void ChangeSecretKey(const uint8_t* key);
	//*OK

	/**
	 * 	@brief Erase the secret key
	*/
	void EraseSecretkey(void);
	//*OK

	/**
	 * 	@brief Change initialization Vector. IV must be 16 bytes long!
	 * 
	 * 	@param iv Pointer to the array containing the IV
	*/
	void ChangeIV(const uint8_t* iv);
	//*OK

	/**
	 * 	@brief Get Initialization Vector
	 * 
	 * 	@param dst Pointer to a 16 bytes long array to store a copy of the IV
	*/
	void GetIV(uint8_t* dst) const;
	//*OK

	/**
	 * 	@brief Clear stored IV and auto generate new one.
	*/
	void ClearIV(void);
	//*OK

	/**
	 * 	@brief Add specified key to a given AES block
	 * 
	 * 	@param block AES block to add the key to
	 * 	@param keyNum Key's number
	*/
	void AddRoundKey(uint8_t* block, uint8_t keyNum);
	//*OK

	/**
	 * 	@brief Add stored IV to a given AES block
	 * 
	 * 	@param block AES block to add the IV to
	*/
	void XORIV(uint8_t* block);
	//*OK

	/**
	 * 	@brief Add a 16 bytes long IV to a given AES block
	 * 
	 * 	@param block  AES block to add the IV to
	 * 	@param iv  Pointer to an IV block
	*/
	void XORIV(uint8_t* block, uint8_t* iv);

	/**
	 * 	@brief Set what to do with the IV when encrypting
	 * 
	 * 	@param mode true: Save and read IV from the binary stream | false: always use the IV stored in the keyset
	*/
	void SetIVMode(bool mode);
	//*OK

	/**
	 * 	@brief Get IV mode
	 * 
	 * 	@returns Iv mode
	*/
	bool GetIVMode(void) const;
	//*OK

	/**
	 * 	@brief Destructor
	*/
	~AES_KEYSET() {}
	//*OK

private:

	//Calculate all required key stages
	void CalculateKeys(const uint8_t* key);
	//*OK

	//Calculate a single key stage
	void ExpandKey(uint8_t keyNum);
	//*OK

	/**
	*	@brief Substitute a single byte
	*
	*	@param byte  The byte to replace*
	*
	*	@returns Corresponding byte according to sBox
	*/
	uint8_t SubByteSingle(uint8_t byte);
	//*OK

};

/**
 * 	@brief Enum to identify AES modes
*/
enum AES_MODE {
	AES_BASE_M = 0,
	AES_ECB_M  = 1,
	AES_CBC_M  = 2,
	AES_CFB_M  = 3,
	AES_OFB_M =  4
};

class AES_BASE {
protected:

	//Max buffer size on heap in megabytes -!!- MUST BE MULTIPLE OF 16 bytes -!!-
	size_t bufferLimit = AES_DEFAULT_BUFFSIZE;    //Limits individual buffers to a maximum size

	AES_KEYSET* keyset = nullptr;	//Different key stages

	uint8_t procArray[16] = { 0 };		//Array to store a single block while it's being processed

	const AES_MODE aesMode = AES_BASE_M;	//AES mode identifier

public:

	/**
	 *	@brief Constructor
	 *
	 *	@param key Pointer to a max 16 bytes long array containing the secret key
	*/
	AES_BASE(const uint8_t* key = nullptr) {}
	//*OK

	/**
	 * 	@brief Destructor
	*/
	virtual ~AES_BASE() {}
	//*OK

	/**
	 * 	@brief	Get buffer size limit
	 * 
	 * 	@returns  Buffer limit size
	*/
	size_t GetBufferLimit(void) const;
	//*OK

	/**
	 * 	@brief Set buffer size limit (MUST BE MULTIPLE OF 16)
	 * 
	 * 	@param limit  New buffer size limit 
	 * 
	 * 	@returns  If set was successful
	*/
	bool SetBufferLimit(const size_t limit);
	//*OK

	/**
	* 	@brief Encrypt stream
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*
	*/
	virtual void EncryptStream(uint8_t* stream, size_t length) = 0;
	//*OK

	/**
	*	@brief Encrypt and pad a stream of bytes
	*
	*	@param src	Source stream
	*	@param length  Source length
	*	@param streamLength	Finished stream length
	*
	*	@returns Pointer to encrypted data
	*/
	uint8_t* EncryptBuffer(const uint8_t* src, size_t length, size_t* streamLength);
	//*OK

	/**
	*	@brief Encrypt file to binary file
	* 
	*	@param inputFileName  The source filename
	*	@param outputFileName  Encrypted (output) filename
	*/
	virtual void EncryptFile(const char* inputFileName, const char* outputFileName);
	//*OK

	/**
	* 	@brief Decrypt stream at original position
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*
	*/
	virtual void DecryptStream(uint8_t* stream, size_t length) = 0;
	//*OK

	/**
	*	@brief Decrypt a buffer of bytes
	*
	*	@param src	Source stream
	*	@param length  Source length
	*	@param streamLength	Finished stream length
	*
	*	@returns Pointer to decrypted data
	*/
	uint8_t* DecryptBuffer(const uint8_t* src, size_t length, size_t* streamLength);
	//TODO

	/**
	*	@brief Decrypt binary file to the original file
	* 
	*	@param inputFileName  The encrypted filename
	*	@param outputFileName  Decrypted (output) filename
	*/
	virtual void DecryptFile(const char* inputFileName, const char* outputFileName);
	//*OK

	/**
	*	@brief Get a file's size int bytes
	*
	*	@param filename  filename
	*
	*	@returns The input file's size in bytes
	*/
	//size_t GetFileSizeBytes(const char* filename);

	/**
	*	@brief Get a file's size int bytes
	*
	*	@param fs  File stream
	*
	*	@returns The input file's size in bytes
	*/
	size_t GetFileSizeBytes(std::fstream& fs);
	//*OK

	/**
	*	@brief Get a file's size int bytes
	*
	*	@param file	 Input file
	*
	*	@returns The input file's size in bytes
	*/
	size_t GetFileSizeBytes(FILE* file);
	//*OK

	/**
	 * 	@brief Set IV used for encryption and decryption
	 * 
	 * 	@param iv Pointer to array containing the IV. If nullptr random IV will be generated (Can be used to clear IV)
	*/
	virtual void SetIV(const uint8_t* iv);
	//*OK

	/**
	 * 	@brief Copy IV to a given (min. 16 bytes long) array
	 * 
	 * 	@param dst Pointer to the array to copy the IV into
	*/
	virtual void GetIV(uint8_t* dst) const;
	//*OK

	/**
	 * 	@brief Get AES mdoe
	 * 
	 * 	@returns AES mode
	*/
	const inline AES_MODE GetMode(void) const;
	//*OK

	/**
	 * 	@brief Get AES mode in c string
	 * 
	 * 	@returns AES mode in c string
	*/
	const inline char* GetModeStr(void) const;
	//*OK

protected:

	/**
	* 	@brief Encrypt a single 16 byte long block
	*
	* 	@param block  Array containing the data to be encrypted
	*
	*/
	inline void EncryptBlock(uint8_t* block);
	//*OK

	/**
	*	@brief Encrypt and pad a stream of bytes
	*
	*	@param src	Source stream
	*	@param length  Source length
	*	@param streamLength	Finished stream length
	*	@param attachPadding  Attach padding from the last block
	*
	*	@returns Pointer to encrypted data
	*/
	uint8_t* Encrypt(const uint8_t* src, size_t length, size_t* streamLength, bool attachPadding);
	//*OK

	/**
	* 	@brief Decrypt a single 16 byte long block*
	*
	* 	@param block  Array containing the data to be decrypted
	*
	*/
	inline void DecryptBlock(uint8_t* block);
	//*OK

	/**
	*	@brief Decrypt a stream of bytes
	*
	*	@param src	Source stream
	*	@param length  Source length
	*	@param streamLength	Finished stream length
	*	@param removePadding  Remove padding from the last block
	*
	*	@returns Pointer to decrypted data
	*/
	uint8_t* Decrypt(const uint8_t* src, size_t length, size_t* streamLength, bool removePadding);
	//*OK

	/**
	*	@brief Substitute bytes in block
	*
	*	@param block  The block of data to work on
	*/
	inline void SubBytes(uint8_t* block);
	//*OK

	/**
	*	@brief Inverse substitute bytes in block
	*
	*	@param block  The blockof data to work on
	*/
	inline void SubBytesInv(uint8_t* block);
	//*OK

	/**
	* 	@brief Shift rows left in block
	*
	* 	@param block  The block of data to work on
	*
	*/
	inline void ShiftRowsLeft(uint8_t* block);
	//*OK

	/**
	* 	@brief Shift rows right in block
	*
	* 	@param block  The block of data to work on
	*
	*/
	inline void ShiftRowsRight(uint8_t* block);
	//*OK

	/**
	* 	@brief Mix columns round
	*
	* 	@param block  The block of data to work on
	*
	*/
	inline void MixColumns(uint8_t* block);
	//*OK

	/**
	* 	@brief Inverse mix columns round
	*
	* 	@param block  The blockof data to work on
	*
	*/
	inline void MixColumnsInv(uint8_t* block);
	//*OK

	/**
		@brief Galois field GF(2^8) finite field multiplication

		@param multiplicant
		@param multiplier

		@returns Product of the multiplication
	*/
	inline uint8_t GFMult(uint8_t multiplier, uint8_t multiplicant);
	//*OK

	/**
	 * 	@brief XOR together 2 matrices and store the result in the 1st
	 * 
	 * 	@param block_a  Pointer to the 1st block where the result will be saved
	 * 	@param block_b  Pointer to the 2nd block
	 * 	@param length  The length of both blocks
	*/
	inline void BlockXOR(uint8_t* block_a, const uint8_t* block_b, const size_t length = 16);
	//*OK

};


class AES_ECB : public AES_BASE {
private:

	const AES_MODE aesMode = AES_ECB_M;		//AES mode identifier

public:

	/**
	 * 	@brief Constructor
	 * 
	 * 	@param key	Pointer to the key array
	*/
	AES_ECB(const uint8_t* key = nullptr);
	//*OK

	/**
	* 	@brief Encrypt stream
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*/
	void EncryptStream(uint8_t* stream, size_t length);
	//*OK

	/**
	* 	@brief Decrypt stream at original position
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*/
	void DecryptStream(uint8_t* stream, size_t length);
	//*OK

	/**
	 * 	@brief Destructor
	*/
	~AES_ECB();
	//*OK

};


class AES_CBC : public AES_BASE {
private:

	const AES_MODE aesMode = AES_CBC_M;		// AES mode identifier

public:

	/**
	 * 	@brief Constructor
	 * 
	 * 	@param key Pointer to the key array
	 * 	@param iv  Pointer to the IV array
	*/
	AES_CBC(const uint8_t* key = nullptr, const uint8_t* iv = nullptr);

	/**
	* 	@brief Encrypt stream
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*
	*/
	void EncryptStream(uint8_t* stream, size_t length);

	/**
	* 	@brief Decrypt stream at original position
	*
	*	@param stream  Source stream
	* 	@param length  Source length
	*/
	void DecryptStream(uint8_t* stream, size_t length);

	/**
	 * 	@brief Destructor
	*/
	~AES_CBC();

};

class AES_CFB : public AES_BASE {
private:

	const AES_MODE aesMode = AES_CFB_M;		// AES mode identifier

public:

	/**
	 * 	@brief Constructor
	 * 
	 * 	@param key Pointer to the key array
	 * 	@param iv  Pointer to the IV array
	*/
	AES_CFB(const uint8_t* key = nullptr, const uint8_t* iv = nullptr);

	/**
	* 	@brief Encrypt stream
	*
	*	@param stream					Source stream
	* 	@param length					Source length
	*
	*/
	void EncryptStream(uint8_t* stream, size_t length);

	/**
	* 	@brief Decrypt stream at original position
	*
	*	@param stream					Source stream
	* 	@param length					Source length
	*
	*/
	void DecryptStream(uint8_t* stream, size_t length);

	/**
	 * 	@brief Destructor
	*/
	~AES_CFB();

};


class AES_OFB : public AES_BASE {
private:

	const AES_MODE aesMode = AES_OFB_M;		// AES mode identifier

public:

	/**
	 * 	@brief Constructor
	 * 
	 * 	@param key Pointer to the key array
	 * 	@param iv  Pointer to the IV array
	*/
	AES_OFB(const uint8_t* key = nullptr, const uint8_t* iv = nullptr);

	/**
	* 	@brief Encrypt stream
	*
	*	@param stream					Source stream
	* 	@param length					Source length
	*
	*/
	void EncryptStream(uint8_t* stream, size_t length);

	/**
	* 	@brief Decrypt stream at original position
	*
	*	@param stream					Source stream
	* 	@param length					Source length
	*
	*/
	void DecryptStream(uint8_t* stream, size_t length);

	/**
	 * 	@brief Destructor
	*/
	~AES_OFB();

};
