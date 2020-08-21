#include <nana/gui.hpp>                  // always include this
#include <nana/gui/widgets/button.hpp>
#include <nana/gui/widgets/label.hpp>
#include <nana/gui/widgets/textbox.hpp>
#include <nana/gui/filebox.hpp>
#include <nana/gui/msgbox.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <functional>
#include "communicator.h"
#include "AmiiboUtil.h"

void start(Communicator *comm, nana::form *fm, nana::textbox *box)
{
   AmiiboUtil util;
   auto error = [](nana::form *fm, std::string message) -> void {
      nana::msgbox m(*fm, "Error");
      m.icon(m.icon_error);
      m << message;
      auto response = m();
   };

   printf("Reading Files.\n");
   if(comm->ReadFiles() != 0)
   {
      error(fm, "An Error occured while reading files");
      return;
   }

   printf("Files parsed successfully.\n");
   if(comm->ParseFiles() != 0)
   {
      error(fm, "Files are invalid");
      return;
   }

   box->append("Figurine: " + util.GetNameForID(comm->GetAmiiboID()), false);

   printf("Connecting to 3DS.\n");
   if(comm->ConnectTo3DS() != 0)
   {
      error(fm, "Could not connect to 3DS, check IP Address and the internet connection.");
      return;
   }
   
   printf("Connected.\n");
   comm->IPCServer();
   comm->FlushToFileIfRequired();
}

int main()
{
   using namespace nana;
   Communicator comm;
   AmiiboUtil webutil;
   form fm {API::make_center(300, 200), appearance{true, true, false, false, true, false, false}};
   nana::filebox picker{nullptr, true};
   fm.caption("Wumiibo");     

   label enc_label{fm, rectangle{10, 10, 110, 30}}; // pos x:y:width:height
   label dec_label{fm, rectangle{10, 40, 110, 30}};
   label ip_addr{fm, rectangle{10, 70, 110, 30}};
   enc_label.caption("Enc amiibo file:");
   dec_label.caption("Dec amiibo file:");
   ip_addr  .caption("3DS IP Address:");
       
   textbox enc_loc {fm, rectangle{100, 4, 150, 25}, true};
   textbox dec_loc {fm, rectangle{100, 34, 150, 25}, true};
   textbox ip_loc  {fm, rectangle{100, 64, 150, 25}, true};
   textbox debug_loc {fm, rectangle{10, 160, 280, 30}, true};
   enc_loc.editable(false);
   dec_loc.editable(false);
   debug_loc.editable(false);

   button enc_button {fm, rectangle{260, 4, 30, 25}};
   enc_button.caption("...");
   button dec_button {fm, rectangle{260, 34, 30, 25}};
   dec_button.caption("...");
   button set_ip {fm, rectangle{260, 64, 30, 25}};
   set_ip.caption("set");
      
   button emulate {fm, rectangle {110, 120, 90, 30}};
   emulate.caption("Emulate");
       
   enc_button.events().click([&]() {
                     auto paths = picker.show();
                     if(!paths.empty()){
                           enc_loc.append(paths[0].filename(), true);
                           comm.SetEncryptedFile(paths[0].u8string());
                     }
                  });

   dec_button.events().click([&]() {
                     auto paths = picker.show();
                     if(!paths.empty()){
                           dec_loc.append(paths[0].filename(), true);
                           comm.SetDecryptedFile(paths[0].u8string());
                     }
                  });

   set_ip.events().click([&]() {
                     std::string ip;
                     if(ip_loc.getline(0, ip))
                        comm.SetIPAddr(ip);
       });

   emulate.events().click([&]() {
                     std::thread(start, &comm, &fm, &debug_loc).detach();
          });

   // fm_place.collocate();                      // and collocate all in place
   fm.show();
   exec();
 }