#include "communicator.h"
#include "AmiiboUtil.h"


int main(int argc, char **argv)
{
    Communicator comm;
    AmiiboUtil util;
    comm.SetEncryptedFile(argv[1]);
    comm.SetDecryptedFile(argv[2]);
    comm.SetIPAddr(argv[3]);

    if(comm.ReadFiles() != 0)
    {
        printf("An error occured while reading the files\n");
        return -1;
    }

    if(comm.ParseFiles() != 0)
    {
        printf("Files are invalid\n");
        return -2;
    }
    printf("Files parsed successfully.\n");
    printf("Figurine: %s\n", util.GetNameForID(comm.GetAmiiboID()).c_str());
    printf("Connecting to 3ds.\n");
    if(comm.ConnectTo3DS() != 0)
    {
        printf("Could not connect to 3ds\n");
        return -3;
    }
    printf("Connected.\n");
    comm.IPCServer();
    comm.FlushToFileIfRequired();
    return 0;
}