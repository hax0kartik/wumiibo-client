#include <string>
#include <cinttypes>
#include <functional>
#include "amiibo_structs.h"
#include "bswap.h"
class Communicator
{
    public:
        void SetDecryptedFile(const std::string filename) {
            m_decryptedfile = filename;
        };
        
        void SetEncryptedFile(const std::string filename) {
            m_encryptedfile = filename;
        };

        void SetIPAddr(const std::string addr){
            m_addr = addr;
        }
        
        const std::string &GetEncryptedFile() {
            return m_encryptedfile;
        };
        
        const std::string &GetDecryptedFile() {
            return m_decryptedfile;
        };

        uint64_t GetAmiiboID() {
            uint64_t val;
            memcpy(&val, &m_identityblock, 8);
            val = bswap_64(val);
            return val;
        }
        
        int ReadFiles();
        int ParseFiles();
        void FlushToFileIfRequired();
        int ConnectTo3DS();
        void IPCServer();

    protected:
        int ParseEncryptedFile();
        int ParseDecryptedFile();
    
    private:
        std::string m_decryptedfile;
        std::string m_encryptedfile;
        std::string m_addr;
        uint8_t m_decrypteddata[540];
        uint8_t m_encrypteddata[540];

        NFC_PlainData m_plaindata;
        NFC_IdentificationBlock m_identityblock;
        NFC_TagInfo m_taginfo;

        int m_sockfd;
        uint8_t m_tagstate = NFC_TagState_ScanningStopped;
        bool m_flush;
};