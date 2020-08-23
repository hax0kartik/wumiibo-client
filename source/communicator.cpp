#include "communicator.h"
#include <fstream>
#include <iostream>
#define SA struct sockaddr
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>

static int readFile(std::string filename, uint8_t *data)
{
   std::ifstream is(filename, std::ifstream::binary);
   if(is) 
   {
      is.seekg (0, is.end);
      int length = is.tellg();
      is.seekg (0, is.beg);
      if(length > 540)
         return -1; // decrypted file is not usually bigger than 540 bytes.
      is.read((char*)data, length);
      is.close();
      return 0;
   }
   return -1;
}

static int writeFile(std::string filename, uint8_t *data, int length)
{
   std::ofstream is(filename, std::ofstream::binary);
   if(is)
   {
      is.write((char*)data, length);
      is.close();
      return 0;
   }
   return -1;
}

int Communicator::ReadFiles()
{
   int r1 = readFile(m_decryptedfile, m_decrypteddata);
   int r2 = readFile(m_encryptedfile, m_encrypteddata);
   return r1 && r2;
}

int Communicator::ParseEncryptedFile()
{
   if(m_encrypteddata[0xC] != 0xF1 && m_encrypteddata[0xD] != 0x10) // signature fail
      return -1;
   memcpy((uint8_t*)&m_taginfo.id[0], (uint8_t*)&m_encrypteddata[0], 7);
   memcpy((uint8_t*)&m_identityblock, (uint8_t*)&m_encrypteddata[0x54], 8);
   return 0;
}

int Communicator::ParseDecryptedFile()
{
   if(m_decrypteddata[0x02] != 0xF && m_decrypteddata[0x3] != 0xE0)
      return -1;
   
   m_plaindata.pagex4_byte3 = m_decrypteddata[0x2B];
   m_plaindata.flag = m_decrypteddata[0x2C];
   m_plaindata.lastwritedate = Date(bswap_16(*(uint16_t*)&m_decrypteddata[0x32]));
   m_plaindata.writecounter = bswap_16((m_decrypteddata[0xB4] << 8) | m_decrypteddata[0xB5]);
   if(m_plaindata.flag << 27 >> 31)
   {
      memcpy(m_plaindata.settings.mii, &m_decrypteddata[0x4C], 0x60);
      memcpy(m_plaindata.settings.nickname, &m_decrypteddata[0x38], 2*10);
      m_plaindata.settings.flags = m_decrypteddata[0x2C] & 0xF;
      m_plaindata.settings.countrycodeid = m_decrypteddata[0x2D];
      m_plaindata.settings.setupdate = Date(bswap_16(*(uint16_t*)&m_decrypteddata[0x30]));
      if(m_plaindata.flag << 26 >> 31)
      {
         memcpy((uint8_t*)&m_plaindata.appDataConfig.appid, (uint8_t*)&m_decrypteddata[0xB6], 4);
         memcpy((uint8_t*)&m_plaindata.appDataConfig.titleid, (uint8_t*)&m_decrypteddata[0xAC], 8);
         m_plaindata.appDataConfig.titleid = bswap_64(m_plaindata.appDataConfig.titleid);
         m_plaindata.appDataConfig.counter = bswap_16(*((uint16_t*)&m_decrypteddata[0xB4]));
         m_plaindata.appDataConfig.unk = m_plaindata.flag >> 4;
         memcpy((uint8_t*)&m_plaindata.AppData[0], (uint8_t*)&m_decrypteddata[0xDC], 0xD8);
      }
   }
   return 0;
}

int Communicator::ParseFiles()
{
   int p1 = ParseEncryptedFile();
   int p2 = ParseDecryptedFile();
   return p1 && p2;
}

void Communicator::FlushToFileIfRequired()
{
   if(!m_flush) return;
   m_decrypteddata[0x2B] = m_plaindata.pagex4_byte3;
   m_decrypteddata[0x2C] = m_plaindata.flag;
   // memcpy(&m_decrypteddata[0x32], &m_plaindata.lastwritedate.getraw(), 2); //TODO fix this
   m_plaindata.writecounter = bswap_16(m_plaindata.writecounter += 1);
   memcpy(&m_decrypteddata[0xB4], &m_plaindata.writecounter, 2);
   if(m_plaindata.flag << 27 >> 31)
   {
      memcpy(&m_decrypteddata[0x4C], m_plaindata.settings.mii, 0x60);
      memcpy(&m_decrypteddata[0x38], m_plaindata.settings.nickname, 2*10);
      m_decrypteddata[0x2D] = m_plaindata.settings.countrycodeid;
      uint16_t date = bswap_16(m_plaindata.settings.setupdate.getraw());
      memcpy(&m_decrypteddata[0x30], &date, 2);
      if(m_plaindata.flag << 26 >> 31)
      {
         memcpy((uint8_t*)&m_decrypteddata[0xB6], (uint8_t*)&m_plaindata.appDataConfig.appid, 4);
         memcpy((uint8_t*)&m_decrypteddata[0xAC], (uint8_t*)&m_plaindata.appDataConfig.titleid, 8);
         //m_plaindata.appDataConfig.counter = bswap_16(*((uint16_t*)&m_decrypteddata[0xB4]));
         //m_plaindata.appDataConfig.unk = m_plaindata.flag >> 4;
         memcpy((uint8_t*)&m_decrypteddata[0xDC], (uint8_t*)&m_plaindata.AppData[0], 0xD8);
      }
   }
   writeFile(m_decryptedfile, m_decrypteddata, 532);
}

int Communicator::ConnectTo3DS()
{
   WSADATA wsaData;
   int winsock_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (winsock_res != 0)
   {
      printf("Failed WSAStartup()\n");
      return 1;
   }
   struct sockaddr_in servaddr, cli;
   // socket create and varification 
   m_sockfd = socket(AF_INET, SOCK_STREAM, 0); 
   if (m_sockfd == -1)
   {
      printf("Socket creation failed\n");
      return -1;
   }
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = inet_addr(m_addr.c_str()); 
   servaddr.sin_port = htons(8001); 
  
   if (connect(m_sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
      printf("Connect failed\n");
      return -1;
   }
   printf("Connect succeeded\n");
   return 0; 
}

void Communicator::IPCServer()
{
   uint8_t buff[256]; 
   for (;;) 
   { 
      int res = recv(m_sockfd, (char*)buff, 256, 0); 
      if(res == SOCKET_ERROR) break;
      uint32_t *cmdbuf = (uint32_t*)buff;
      uint16_t cmdid = cmdbuf[0] >> 16;
      printf("Cmdid recieved %08X\n", cmdbuf[0]);
      switch(cmdid)
      {
         case 1:
         case 2:
         case 3:
         case 4:
         {
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 5: // StartTagScanning
         {
            m_tagstate = NFC_TagState_Scanning;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 6: // StopTagScanning
         {
            m_tagstate = NFC_TagState_ScanningStopped;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 7: // LoadAmiiboData
         {
            m_tagstate = NFC_TagState_DataReady;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 8: // ResetTagState
         {
            m_tagstate = NFC_TagState_OutOfRange;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 9: // UpdateStoredAmiiboData
         {
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0xB: // GetTagInRangeEvent
         {

         }

         case 0xD: // GetTagState
         {
            if(cmdbuf[1] == 1)
            {
               printf("TagState changed by module\n");
               m_tagstate = cmdbuf[2];
            }
            cmdbuf[2] = m_tagstate;
            printf("TagState %d\n", m_tagstate);
            if(m_tagstate == NFC_TagState_Scanning) m_tagstate = NFC_TagState_InRange;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 2, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0xF: // CommunicationGetStatus
         {
            cmdbuf[2] = 2; // Hardcode to "communication established successfully"
            cmdbuf[0] = IPC_MakeHeader(cmdid, 2, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x11: // GetTagInfo
         {
            m_taginfo.id_offset_size = 7;
            m_taginfo.unk_x2 = 0;
            m_taginfo.unk_x3 = 2;
            memcpy(&cmdbuf[2], &m_taginfo, sizeof(NFC_TagInfo));
            cmdbuf[0] = IPC_MakeHeader(cmdid, 12, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x13: //OpenAppData
         {
            uint32_t appid = bswap_32(cmdbuf[1]);
            printf("Expected AppID %X: Our AppID %X\n", appid, m_plaindata.appDataConfig.appid);
            if(m_plaindata.flag << 26 >> 31)
            {
               if(appid == m_plaindata.appDataConfig.appid)
                  cmdbuf[1] = 0;
               else
               {
                  printf("0x13 AppID was incorrect\n");
                  cmdbuf[1] = 0xC8A17638; // AppId incorrect
               }				
            }
            else
            {
               cmdbuf[1] = 0xC8A17620; // Not Initialized
               printf("0x13 Not Initialized\n");
            }
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            break;
         }

         case 0x14: //InitializeAppData
         {
            uint32_t appid = cmdbuf[1];
            uint32_t size = cmdbuf[2];
            send(m_sockfd, (char*)cmdbuf, 256, 0);
            recv(m_sockfd, (char*)buff, 256, 0);
            uint64_t pid = 0;
            memcpy((uint8_t*)&pid, (uint8_t*)&buff[0], 8);
            printf("TitleID %llX\n", pid);
            pid = bswap_64(pid);
            printf("TitleID after swap %llX\n", pid);
            m_plaindata.appDataConfig.titleid = pid;
            m_plaindata.appDataConfig.appid = bswap_32(appid);
            m_plaindata.flag |= 0x20u;
            memcpy((uint8_t*)&m_plaindata.AppData[0], (uint8_t*)&cmdbuf[2], 0xD8);

            m_flush = true;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            break;
         }

         case 0x15: //GetAppdata
         {
            //uint32_t size = cmdbuf[2];
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 2);
            cmdbuf[1] = 0;
            cmdbuf[2] = IPC_Desc_StaticBuffer(0xd8, 0);
            memcpy((uint8_t*)&cmdbuf[3], (uint8_t*)&m_plaindata.AppData[0], 0xD8);
            break;
         }

         case 0x16: // WriteAppData
         {
            uint32_t size = cmdbuf[1];
            struct cmdbuf_struct
            {
               uint8_t uid[7];
               uint16_t unk;
               uint8_t uid_size;
               uint8_t unk2[0x15];
            };
            struct cmdbuf_struct cmdbuf_0x16;
            memcpy((uint8_t*)&cmdbuf_0x16, (uint8_t*)&cmdbuf[2], sizeof(struct cmdbuf_struct));
            send(m_sockfd, (char*)cmdbuf, 256, 0);
            recv(m_sockfd, (char*)buff, 256, 0);
            memcpy((uint8_t*)&m_plaindata.AppData[0], (uint8_t*)&buff[0], 0xD8);
      
            m_flush = true;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }


         case 0x17: // GetAmiiboSettings
         {
            if (!(m_plaindata.flag & 0x10)) 
            {
               memset(&m_plaindata.settings, 0, sizeof(m_plaindata.settings));
               printf("0x17 UNINITITIALIZED\n");
               cmdbuf[1] = 0xC8A17628; //uninitialised
            } 
            else 
               cmdbuf[1] = 0;

            cmdbuf[0] = IPC_MakeHeader(cmdid, 0x2B, 0);
            memcpy(&cmdbuf[2], &m_plaindata.settings, sizeof(m_plaindata.settings));
            break;
         }

         case 0x18: // GetAmiiboConfig
         {
            printf("Cmdid 0x18 recieved");
            NFC_AmiiboConfig config;
            config.lastwritedate.year = m_plaindata.lastwritedate.year;
            config.lastwritedate.month = m_plaindata.lastwritedate.month;
            config.lastwritedate.day = m_plaindata.lastwritedate.day;
            config.write_counter = m_plaindata.writecounter;
            config.characterID[0] = m_identityblock.id[0];
            config.characterID[1] = m_identityblock.id[1];
            config.characterID[2] = m_identityblock.char_variant;
            config.series = m_identityblock.series;
            config.amiiboID[0] = m_identityblock.model_no[0];
            config.amiiboID[1] = m_identityblock.model_no[1];
            config.type = m_identityblock.figure_type;
            config.pagex4_byte3 = m_plaindata.pagex4_byte3; //raw page 0x4 byte 0x3, dec byte
            config.appdata_size = 0xD8;
            memcpy((uint8_t*)&cmdbuf[2], (uint8_t*)&config, 0x40);
            cmdbuf[0] = IPC_MakeHeader(cmdid, 17, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x19: //GetAppDataInitStruct IDA decompilation shows that this function just returns a 0x3c empty struct
         // We will do the same
         {
            uint8_t data[0x3c];
            memset(data, 0, 0x3c);
            memcpy((uint8_t*)&cmdbuf[2], (uint8_t*)&data[0], 0x3c);
            cmdbuf[0] = IPC_MakeHeader(cmdid, 16 ,0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x1A: // Unknown1A
         {
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x1B: // GetAmiiboIdentificationBlock
         {
            memcpy((uint8_t*)&cmdbuf[2], (uint8_t*)&m_identityblock, 0x36);
            cmdbuf[0] = IPC_MakeHeader(cmdid, 15, 0);
            cmdbuf[1] = 0;
            break;
         }
         
         case 0x401: //Reset
         {
            m_plaindata.flag = 0;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x402: //GetAppDataConfig
         {
            m_plaindata.appDataConfig.unk2 = 2;
            m_plaindata.appDataConfig.tid_related = -1;
            if(m_plaindata.flag << 26 >> 31)
            {
               switch(m_plaindata.appDataConfig.titleid >> 28)
               {
                  case 0:
                  case 2:
                     m_plaindata.appDataConfig.tid_related = 0;
                     break;
                  case 1:
                     m_plaindata.appDataConfig.tid_related = 1;
               }
            }
            memcpy((uint8_t*)&cmdbuf[2], (uint8_t*)&m_plaindata.appDataConfig, sizeof(m_plaindata.appDataConfig));
            cmdbuf[0] = IPC_MakeHeader(cmdid, 16, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x404: //SetAmiiboSettings
         {
            memcpy((uint8_t*)&m_plaindata.settings, &cmdbuf[1], sizeof(NFC_AmiiboSettings));
            if(!(m_plaindata.flag << 27 >> 31) & 0xF)
            {
               printf("0x404 Doing first time initialization");
               time_t now = time(0);
               struct tm *aTime = localtime(&now);
               Date date(aTime->tm_mday, aTime->tm_mon + 1, aTime->tm_year + 1900);
               uint16_t raw = date.getraw();
               m_plaindata.settings.setupdate = Date(raw);
               m_plaindata.settings.countrycodeid = cmdbuf[43] >> 24; // Set countrycode
            }
            m_plaindata.flag = ((m_plaindata.flag & 0xF0) | (m_plaindata.settings.flags & 0xF) | 0x10);
            m_flush = true;
            cmdbuf[0] = IPC_MakeHeader(cmdid, 1, 0);
            cmdbuf[1] = 0;
            break;
         }

         case 0x407:
         {
            uint32_t isSet = (m_plaindata.flag << 26 >> 31) & 1;
            printf("IsSet %d\n", isSet);
            cmdbuf[0] = IPC_MakeHeader(cmdid, 2, 0);
            cmdbuf[1] = 0;
            cmdbuf[2] = isSet;
            break;
         }

         default:
            printf("Unimplemented command %08x\n", cmdbuf[0]);
      }
      send(m_sockfd, (char*)cmdbuf, 256, 0);
   }
   printf("Disconnected\n");
}