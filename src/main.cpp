#include <iostream>
#include <cstring>
#include <fstream>
#include <chrono>
#include <ncurses.h>

#include "aes.h"
#include "consint.h"

//  AES operation
enum AES_OP { AES_ENCRYPT = 0, AES_DECRYPT = 1 };

//  AES method
enum AES_METHOD { AES_M_ECB, AES_M_CBC, AES_M_CFB, AES_M_OFB };

//  AES source type
enum AES_SRC { AES_S_FILE = 0, AES_S_TEXT = 1 };

/**
 * @brief AES runtime configuration
*/
struct RuntimeConfig {
    AES_OP mode = AES_ENCRYPT;
    AES_METHOD method = AES_M_CBC;
    AES_SRC sourceType = AES_S_FILE;
    char* source = nullptr;
    char* dst = nullptr;
    uint8_t* key = nullptr;
    uint8_t* iv = nullptr;
    bool writeToScreen = false;     //for JPorta
};

/**
 *  @brief  Check whether a cstring ends with a specific substring
 * 
 *  @param  str     string to search
 *  @param  suffix  substring to search for at the end of src
 * 
 *  @returns true: str ends with suffix | false: str ends with something else
*/
bool EndsWith(const char* str, const char* suffix) {
    if (str == nullptr || suffix == nullptr)
        return false;

    size_t strLength = std::strlen(str);
    size_t suffixLength = std::strlen(suffix);

    if (suffixLength > strLength)
        return false;

    const char* strSuffix = str + (strLength - suffixLength);
    return std::strcmp(strSuffix, suffix) == 0;
}

/**
 *  @brief Print help menu to console
*/
void PrintHelp(void) {
    std::cout << "Usage:" << std::endl;
    std::cout << " fracture.exe [OPTIONS]...  [-f] SOURCE_FILE  [OUTPUT_FILE]" << std::endl;
    std::cout << " fracture.exe [OPTIONS]...  -t  INPUT_TEXT  OUTPUT_FILE " << std::endl;
    std::cout << "\n1st form: Process file with optional parameters. Default is CBC encrypt, 0 as password with the original filename + \".bin\" extension." << std::endl;
    std::cout << "2nd form: Encrypt text from console. Default is CBC, 0 as password with actual date-time + \".bin\" extension." << std::endl;
    std::cout << "\nArguments:" << std::endl;
    std::cout << " -e\t\t\tEncrypt data" << std::endl;
    std::cout << " -d\t\t\tDecrypt data" << std::endl;
    std::cout << " -k\t\t\tSecret key for processing" << std::endl;
    //std::cout << " -i\t\t\tInitialization vector for CBC, CFB and OFB modes" << std::endl;
    std::cout << " -t\t\t\tEncrypt text from console" << std::endl;
    std::cout << " -f\t\t\tEncrypt file" << std::endl;
    std::cout << " -o\t\t\tOutput filename" << std::endl;
    std::cout << " -h, --help\t\tPrint help menu" << std::endl;
    std::cout << " --ecb\t\t\tSet AES mode to ECB" << std::endl;
    std::cout << " --cbc\t\t\tSet AES mode to CBC (default)" << std::endl;
    std::cout << " --cfb\t\t\tSet AES mode to CFB" << std::endl;
    std::cout << " --ofb\t\t\tSet AES mode to OFB" << std::endl;
}

/**
 *  @brief Execute AES operation
 * 
 *  @param confg AES runtime config
*/
void ExecAES(RuntimeConfig* config) {
    AES_BASE* aes = nullptr;
    
    try {

        std::cout << "Applying options..." << std::endl;

        if (!config->source)
            throw("No source was given!");

        if (!config->key) {
            std::cout << "[FRACTURE WARNING]: NO KEY SET! RESULT WILL BE INSECURE!\nDo you wish to continue? [Y/n] ";
            char answer = std::getchar();
            if (tolower(answer) != 'y')
                throw("No key set!");
        }

        switch (config->method)
        {
        case AES_M_ECB:
            aes = new AES_ECB(config->key);
            break;

        case AES_M_CBC:
            aes = new AES_CBC(config->key);
            break;

        case AES_M_CFB:
            aes = new AES_CFB(config->key);
            break;

        case AES_M_OFB:
            aes = new AES_OFB(config->key);
            break;
        
        default:
            //This should not be reached...
            throw("Unknown AES method was selected!");
        }

        //Decrypt
        if (config->mode) {
            
            //Test for source type
            if (config->sourceType != AES_S_FILE)
                throw("Cannot decrypt text from console!");
            
            //Test for source file type
            if(!EndsWith(config->source, ".bin") || strlen(config->source) <= 4)
                throw("Wrong source file type!");
            
            if (!config->dst) {
                config->dst = new char[strlen(config->source) - 3];   // -3 = -4 for '.bin' and +1 for '\0' char
                strncpy(config->dst, config->source, strlen(config->source) - 4);
                config->dst[strlen(config->source) - 4] = '\0';
            }

            aes->DecryptFile(config->source, config->dst);

            throw(0);   //Throw 0 for end of decrypt process

        }
        
        //Encrypt

        //Encrypt text
        if (config->sourceType == AES_S_TEXT) {

            //Generate output filename 
            if (!config->dst) {
                //Get current date and time
                std::time_t now = std::time(NULL);
                std::tm* ptm = std::localtime(&now);
                char currentTime[20];
                std::strftime(currentTime, 32, "%d-%m-%Y_%H-%M-%S", ptm);    //Time format is 19 characters long at every time point

                //Output filename
                config->dst = new char[strlen(currentTime) + 9]; // +9 = +4 for '.txt' (file type for decryption), +4 for '.bin' at the end and +1 for '\0' char
                sprintf(config->dst, "%s.txt.bin", currentTime);
            }

            size_t streamLength = 0;
            uint8_t* encrypted = aes->EncryptBuffer((uint8_t*)config->source, strlen(config->source), &streamLength);

            if (config->writeToScreen) {

                std::cout << "Encrypted data:\n";
                for (size_t i = 0; i < streamLength; i++)
                    std::cout << encrypted[i];
                std::cout << std::endl;
                delete[] encrypted;
                throw(0);
            }

            std::fstream outputFile;
            outputFile.open(config->dst, std::ios::out | std::ios::binary);

            if (!outputFile) {
                outputFile.close();
                throw("Cannot create output file!");
            }

            outputFile.write((char*)encrypted, streamLength);
            outputFile.flush();
            outputFile.close();

            delete[] encrypted;

            throw(0);   //Throw 0 for end of encrypt process
        }

        //Encrypt file 

        //Set destination name if empty
        if (!config->dst) {
            config->dst = new char[strlen(config->source) + 5];   // +5 = +4 for '.bin' at the end, +1 for '\0' character
            sprintf(config->dst, "%s.bin", config->source);
        }

        aes->EncryptFile(config->source, config->dst);

        throw(0);

    } catch (const char* e) {
        std::cerr << "[FRACTURE ERROR]: " << e << std::endl;
    } catch (int code) {
        std::cout << "Operation finished with exit code " << code << std::endl;
    } catch (...) {
        std::cerr << "[FRACTURE ERROR]: Unknown error!" << std::endl;
    }

    
    //Free up used memory before exiting
    if (aes)
        delete aes;
    
}

/**
 *  @brief Execute program with cli arguments
 * 
 *  @param argc Argument count
 *  @param argv Array of arguments
*/
void ArgCLI(int argc, char** argv) {

    if (argc == 2 && (EndsWith((const char*)argv[1], "-h") || EndsWith((const char*)argv[1], "--help") || EndsWith((const char*)argv[1], "-?"))) {
        PrintHelp();
        return;
    }

    std::cout << "Arguments given: " << argc << std::endl;

    RuntimeConfig config;

    int argCntr = 1;

    try {

        while (argCntr < argc) {

            //Check for arguments that too short
            if(strlen(argv[argCntr]) < 2)
                throw("Invalid arguments given!");
            
            if (argv[argCntr][0] == '-')
                switch (argv[argCntr][1])
                {
                case 'e':
                    config.mode = AES_ENCRYPT;
                    argCntr++;
                    break;

                case 'd':
                    config.mode = AES_DECRYPT;
                    argCntr++;
                    break;

                case 'k':
                    //Stop if no key was given
                    if (argc <= argCntr + 1)
                        throw("No key was given!");

                    //Ignore option if key is already set
                    if (config.key)
                        argCntr += 2;
                    
                    //If not set read and store the key
                    config.key = new uint8_t[strlen(argv[argCntr + 1]) + 1];
                    memcpy(config.key, argv[argCntr + 1], strlen(argv[argCntr + 1]));
                    argCntr += 2;
                    break;

                //Encrypt text from console
                /*
                * Note:    With the -t and -f options the same parameter will be set the same way.
                *          And since {config.sourceType} is set as AES_S_FILE by default it only needs to be
                *          changed if it is set to text. And with that they can be used with the same code
                *          except setting the source type to AES_S_TEXT when the -t option is used.
                *
                */
                case 't':
                    config.sourceType = AES_S_TEXT;
                //Encrypt file
                case 'f':
                    //Stop if no source was given
                    if (argc <= argCntr + 1)
                        throw("No source was given!");

                    //Ignore option if source already set
                    if (config.source)
                        argCntr += 2;
                    
                    //If not set read and store source
                    config.source = new char[strlen(argv[argCntr + 1]) + 1];
                    strcpy(config.source, argv[argCntr + 1]);
                    argCntr += 2;
                    break;

                //Output filename
                case 'o':
                    //Stop if no source was given
                    if (argc <= argCntr + 1)
                        throw("No destination was given!");

                    //Ignore option if source already set
                    if (config.dst)
                        argCntr += 2;
                    
                    //If not set read and store source
                    config.dst = new char[strlen(argv[argCntr + 1]) + 1];
                    strcpy(config.dst, argv[argCntr + 1]);
                    argCntr += 2;
                    break;

                case 's':
                    config.writeToScreen = true;
                    argCntr++;
                    break;
                
                case '-':

                    if(!strcmp(argv[argCntr], "--ecb"))
                        config.method = AES_M_ECB;
                    else if (!strcmp(argv[argCntr], "--cbc"))
                        config.method = AES_M_CBC;
                    else if (!strcmp(argv[argCntr], "--cfb"))
                        config.method = AES_M_CFB;
                    else if (!strcmp(argv[argCntr], "--ofb"))
                        config.method = AES_M_OFB;
                    else 
                        throw("Invalid arguments given!");

                    argCntr++;
                    break;

                default:
                    throw("Invalid arguments given!");
                }
            else {

                //Set source if not set
                if (!config.source) {
                    config.source = new char[strlen(argv[argCntr]) + 1];
                    strcpy(config.source, argv[argCntr]);
                    argCntr++;
                    continue;
                }

                //Set destination if not set
                if (!config.dst) {
                    config.dst = new char[strlen(argv[argCntr]) + 1];
                    strcpy(config.dst, argv[argCntr]);
                    argCntr++;
                    continue;
                }


                
            }
        }

    
        ExecAES(&config);
    } catch(const char* e) {
        std::cerr << "FractureCrypto [ERROR]: " << e << std::endl;
    } catch (...) {
        std::cerr << "FractureCrypto [ERROR]: Unknown error occured!" << std::endl;
    }


    if (config.source)
        delete[] config.source;

    if (config.dst)
        delete[] config.dst;

    if(config.key)
        delete[] config.key;

    if(config.iv)
        delete[] config.iv;
}

/**
 *  @brief Execute program with GUI
*/
int GUI() {

    RuntimeConfig config;
    config.key = new uint8_t[17];
    config.source = new char[257];  //File path length limit
    //config.source[0] = 0;

    // Initialize ncurses
    initscr();
    keypad(stdscr, TRUE); // Enable keypad for special keys
    noecho(); // Disable automatic echoing of keypresses
    curs_set(0); // Hide the cursor

    // Menu options
    const char* menuOptions[] = { "Encrypt", "Decrypt", "Set Secret Key", "Clear Secret Key", "Exit" };
    int numOptions = sizeof(menuOptions) / sizeof(menuOptions[0]);

    const char* methodOptions[] = { "AES ECB", "AES CBC", "AES CFB", "AES OFB"};
    int numMethods = sizeof(methodOptions) / sizeof(methodOptions[0]);

    bool runLoop = true;

    while(runLoop) {
        bool setup = true;

        while (setup)
        {
            switch (MenuScreen(menuOptions, numOptions))
            {

            case 0:
                config.method = (AES_METHOD)MenuScreen(methodOptions, numMethods);
                PasswordPrompt(config.source, 256, "Source file:", true);
                config.mode = AES_ENCRYPT;
                setup = false;
                break;

            case 1:
                
                config.mode = AES_DECRYPT;
                config.sourceType = AES_S_FILE;
                config.method = (AES_METHOD)MenuScreen(methodOptions, numMethods);
                PasswordPrompt(config.source, 256, "Source file:", true);
                setup = false;
                break;

            case 2:
                PasswordPrompt((char*)config.key, 16, "Secret key:", false);
                break;

            case 3:
                config.key[0] = 0;
                break;

            //Exit
            case 4:
                // Cleanup
                endwin();
                runLoop = false;
                setup = false;
                break;
            
            default:
                break;
            }
        }

        //Only execute AES functions when the program is running
        if (runLoop)
            ExecAES(&config);
    }
    

    std::cout << "Cleaning up..." << std::endl;
    if (config.source)
        delete[] config.source;

    if (config.dst)
        delete[] config.dst;

    if(config.key)
        delete[] config.key;

    if(config.iv)
        delete[] config.iv;

    return 0;

}

int main(int argc, char **argv) {

    if (argc > 1) {
        ArgCLI(argc, argv);
        return 0;
    }

    return GUI();

}