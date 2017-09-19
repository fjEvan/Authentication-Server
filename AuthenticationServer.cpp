// April 2017  Jiao Feng (Evan)  Authentication Server 

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>
#include <sstream>
using namespace std;
#include "sha256.h"

#include <cleansocks.h>
#include <cleanip.h>
#include <cleanbuf.h>
using namespace cleansocks;

static const int BUFFSIZE = 1024;

string getServerNonce();                       /* function prototypes */
string getHash(string s_Nonce, string c_Nonce, string password);
bool permissionCheck(string sPermission, string cPermission);
bool over_30_Seconds(int t1, int t2);

void verified(buffered_socket &conn);
void declined(buffered_socket &conn);
void sendError(buffered_socket &conn);
void sendTryAgain(buffered_socket &conn);

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        cerr<< "Usage: " <<argv[0]<<" <PortNO.> "<< " <File Name> "<<endl;
        exit(1);
    }

    ifstream database(argv[2]); // read file name from CMD line, open file
    if( !database.is_open() )  // fail to open, quit
    {
        cout << "ERROR opening file. Finish." << endl;
        return 0;
    }
    string line;
    string user[100][3];  // 3 columns,  userID:Password:Permission
    int colonPos1 = 0;
    int colonPos2 = 0;
    int infoLength = 0;
    int i = 0;

    while(getline(database, line) != false)  // store info from the file
    {
        colonPos1 = line.find(':', 0);
        infoLength = colonPos1;
        user[i][0] = line.substr(0, infoLength);  // store name
        colonPos2 = line.find(':', colonPos1+1);
        infoLength = colonPos2 - colonPos1 - 1;
        user[i][1] = line.substr(colonPos1+1, infoLength); // store password
        user[i][2] = line.substr(colonPos2+1);  // store permission

        i++;
    }

    i--;
    int preserveI = i;

    TCPsocket listener;
    IPport lport = atoi(argv[1]);
    IPendpoint lend(IPaddress::any(), lport);
    bind(listener, lend);
    listen(listener);

    char buff[BUFFSIZE];  // BUFFSIZE = 1024
    int lineLength;

    while(1)
    {
        i = preserveI;
        IPendpoint rmt;
        sock client = accept(listener, rmt);
        buffered_socket conn(client);

    /* Receive message from client, expecting the command N */
        try
        {
            lineLength = recvln(conn, buff, BUFFSIZE-1);
            buff[lineLength] = '\0';
            string cmd;
            istringstream getCMDLine1(buff);
            getCMDLine1 >> cmd;

            string serverNonce = getServerNonce();
            if(cmd == "N")
            {
                string sendSNonce = "+ " + serverNonce + "\r\n";
                send(conn, sendSNonce);
            }
            else
            {
                sendTryAgain(conn);
                continue;
            }

            int sendNonceTime = time(NULL);
    /* Receive message from client, expecting C userID perm cNonce hash */
            string userID, cPerm, clientNonce, clientHash;
            lineLength = recvln(conn, buff, BUFFSIZE-1);
            buff[lineLength] = '\0';
            istringstream getCMDLine2(buff);
            getCMDLine2 >> cmd >> userID >> cPerm >> clientNonce
                        >> clientHash; // store everything from client
            if(cmd != "C")
            {
                sendTryAgain(conn);
                continue;
            }
            if(cPerm.length() > 4)  // rwxa, can't be more than 4 char
            {
                sendError(conn);
                continue;
            }

            int j;
            for(j=0; j <cPerm.length(); j++)
            {
                int p = 0;
                switch (cPerm[j])
                {
                    case 'r' :
                    case 'w' :
                    case 'x' :
                    case 'a' :  break;
                    default:  sendError(conn);
                              j = cPerm.length() + 2;
                }
            }
            if(j == cPerm.length() + 2)    continue;

            while( userID != user[i][0] )
            {
                i--;
                if(i <0)
                {
                    declined(conn);
                    break;
                }
            }  // after looping, either quit or matched with a corresponding i
            if(i <0)  continue; // providing wrong name, skip this iteration

            string serverHash = getHash(serverNonce, clientNonce, user[i][1]);
            string sPerm = user[i][2]; // permission stored in database

            int momentBeforeCheck = time(NULL);
            if( over_30_Seconds(sendNonceTime, momentBeforeCheck) )
            {                              // if over 30 secs, decline
                declined(conn);
                continue;
            }

            if(permissionCheck(sPerm, cPerm) && (serverHash == clientHash))
                verified(conn);
            else
                declined(conn);
        } // end try
        catch(exception &e)
        {
            cout<<e.what()<<endl;
        }

        close(conn);
    }  // end while(1)

    return 0;
}  // end main

string getServerNonce()  // generate server Nonce
{
    srand(time(NULL));
    string sNonce;
    char randHex[5];  // max of rand() is 32767(7FFF) [5]= '\0'
    do                // generate >= 32-bit long Hex Nonce
    {
        sprintf(randHex, "%x", rand());
        sNonce += randHex;
    } while(sNonce.length() <32);

    return sNonce;
}

string getHash(string s_Nonce, string c_Nonce, string password)
{                                                   // calculate hash
    sha256 hasher;
    string sHash = hasher.process(s_Nonce + c_Nonce + password).getx();
    return sHash;
}

bool permissionCheck(string sPermission, string cPermission)
{                          // check permissions that the client requests
    bool permissionMatch = true;
    int findW = sPermission.find('w',0);
    if(findW >= 0)               // if w exists, replace w with wa
        sPermission = sPermission.replace(findW, 1, "wa");

    for(int k=0; k <cPermission.length(); k++)
    {
        if( sPermission.find(cPermission[k], 0) == -1 )
        {
            permissionMatch = false;
            break;
        }
    }
    return permissionMatch;
}

void verified(buffered_socket &conn)  // send yes to client
{
    string verified = "+\r\n";
    send(conn, verified);
}

void declined(buffered_socket &conn)  // send no to client
{
    string declined = "-\r\n";
    send(conn, declined);
}

void sendError(buffered_socket &conn)  // send error warning to client
{
    string errorMessage = "E Badly-formed check message\r\n";
    send(conn, errorMessage);
}

void sendTryAgain(buffered_socket &conn)  // send try again to client
{
    string tryAgain = "E ERROR. Please try again.\r\n";
    send(conn, tryAgain);
}

bool over_30_Seconds(int t1, int t2)  // test if it exceeds 30 secs
{
    return ( (t2 - t1) > 30);
}















