/*
Copyright 2015 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "ILibParsers.h"
#include "ILibAsyncSocket.h"
#include "ILibWebRTC.h"
#include "ILibWrapperWebRTC.h"
#include "../core/utils.h"

#if defined(_ICE_DEBUG_)
	#define _ILibDebugPrintf
	#define ILibDebugPrintf_V1(...) printf(__VA_ARGS__)
	#define ILibDebugPrintf_V2(...) printf(__VA_ARGS__)
	#define ILibDebugPrintf_V3(...) printf(__VA_ARGS__)
#elif defined(_ICE_DEBUG_TRANSACTION_)
	#define _ILibDebugPrintf
	#define ILibDebugPrintf_V1(...) ;
	#define ILibDebugPrintf_V2(...) ;
	#define ILibDebugPrintf_V3(...) printf(__VA_ARGS__)
#else
	#define ILibDebugPrintf_V1(...) ;
	#define ILibDebugPrintf_V2(...) ;
	#define ILibDebugPrintf_V3(...) ;
#endif

#if defined(WIN32) && !defined(snprintf) && _MSC_VER < 1900
#define snprintf(dst, len, frm, ...) _snprintf_s(dst, len, _TRUNCATE, frm, __VA_ARGS__)
#endif

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#define WEBRTC_CONNECTION_ID_SIZE 8
#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
#define INET_SOCKADDR_PORT(x) (x->sa_family==AF_INET6?(unsigned short)(((struct sockaddr_in6*)x)->sin6_port):(unsigned short)(((struct sockaddr_in*)x)->sin_port))

char g_SessionRandom[32];
unsigned int g_SessionRandomId;
unsigned int g_nextiv = 0;

typedef struct
{
	void (*PreSelect)(void* object,void* readset, void *writeset, void *errorset, int* blocktime);
	void (*PostSelect)(void* object,int slct, void *readset, void *writeset, void *errorset);
	void (*Destroy)(void* object);

	ILibWrapper_WebRTC_ConnectionFactory mFactory;
	void* mChain;
	void* ConnectionTable;

	struct util_cert selfcert;
	struct util_cert selftlscert;
	struct util_cert selftlsclientcert;
	SSL_CTX* ctx;
	char tlsServerCertThumbprint[32];
	char g_selfid[UTIL_HASHSIZE];

	ILibWebRTC_TURN_ConnectFlags mTurnSetting;
	struct sockaddr_in6 mTurnServer;
	char* mTurnServerUsername;
	int mTurnServerUsernameLen;
	char* mTurnServerPassword;
	int mTurnServerPasswordLen;
}ILibWrapper_WebRTC_ConnectionFactoryStruct;

typedef struct
{
	void *dtlsSession;
	void *User1, *User2, *User3;
	ILibWrapper_WebRTC_ConnectionFactoryStruct *mFactory;
	char** stunServerList;
	char* stunServerFlags;
	int stunServerListLength;
	int stunIndex;
	int isConnected;

	char id[WEBRTC_CONNECTION_ID_SIZE];
	char localUsername[9];
	char localPassword[33];

	char *remoteUsername;
	char* remotePassword;
	char *remoteOfferBlock;
	int remoteOfferBlockLen;

	char* offerBlock;
	int offerBlockLen;
	int isOfferInitiator;
	int isDtlsClient;

	void *dataChannels;	

	ILibWrapper_WebRTC_OnConnectionCandidate OnCandidates;
	ILibWrapper_WebRTC_Connection_OnConnect OnConnected;
	ILibWrapper_WebRTC_Connection_OnDataChannel OnDataChannel;
	ILibWrapper_WebRTC_Connection_OnSendOK OnSendOK;

	ILibWrapper_WebRTC_Connection_Debug_OnEvent OnDebugEvent;
}ILibWrapper_WebRTC_ConnectionStruct;

// Prototypes:
int ILibWrapper_WebRTC_PerformStun(ILibWrapper_WebRTC_ConnectionStruct *connection);



short ILibWrapper_ReadShort(char* buffer, int offset)
{
	return(ntohs(((short*)(buffer+offset))[0]));
}
int ILibWrapper_ReadInt(char* buffer, int offset)
{
	return(ntohl(((int*)(buffer+offset))[0]));
}
char* ILibWrapper_ReadString(char* buffer, int offset, int length)
{
	char* retVal;
	if((retVal = (char*)malloc(length+1)) == NULL) {ILIBCRITICALEXIT(254);}
	memcpy(retVal, buffer+offset, length);
	retVal[length] = 0;
	return(retVal);
}

unsigned short ILibWrapper_GetNextStreamId(ILibWrapper_WebRTC_ConnectionStruct *connection)
{
	unsigned short id = 0;
	void *node;
	int done = 0;

	ILibLinkedList_Lock(connection->dataChannels);

	while(done==0)
	{
		done = 1;
		while(++id % 2 == (connection->isDtlsClient ? 0 : 1));

		node = ILibLinkedList_GetNode_Head(connection->dataChannels);
		while(node!=NULL)
		{
			if(((ILibWrapper_WebRTC_DataChannel*)ILibLinkedList_GetDataFromNode(node))->streamId == id)
			{
				done = 0;
				break;
			}
			node = ILibLinkedList_GetNextNode(node);
		}
	}
	ILibLinkedList_UnLock(connection->dataChannels);

	return(id);
}

int ILibWrapper_SdpToBlock(char* sdp, int sdpLen, int *isActive, char **username, char **password, char **block)
{
	struct parser_result *pr;
	struct parser_result_field *f;

	int ptr;
	int blockLen;
	void* candidates = NULL;
	char* lines;
	char* dtlshash = NULL;
	int dtlsHashLen = 0;
	int candidatecount = 0;
	int BlockFlags = 0;
	*isActive = 0;
	*username = NULL;
	*password = NULL;


	ILibCreateStack(&candidates);

	lines = ILibString_Replace(sdp, sdpLen, "\n", 1, "\r", 1);
	pr = ILibParseString(lines, 0, sdpLen, "\r", 1);
	f = pr->FirstResult;
	while(f!=NULL)
	{
		if(f->datalength == 0) { f = f->NextResult; continue; }

		f->data[f->datalength] = 0;
		if(strcmp(f->data, "a=setup:passive")==0)
        {			
			BlockFlags |= ILibWebRTC_SDP_Flags_DTLS_SERVER;
			ILibDebugPrintf_V3("Detected PASSIVE\r\n");
        }
		else if(strcmp(f->data, "a=setup:active")==0 || strcmp(f->data, "a=setup:actpass")==0)
		{
			*isActive = 1;
			ILibDebugPrintf_V3("Detected ACTIVE\r\n");
		}

		if(f->datalength > 12 && strncmp(f->data, "a=ice-ufrag:", 12)==0) {*username = f->data + 12;} 
		if(f->datalength > 10 && strncmp(f->data, "a=ice-pwd:", 10)==0) {*password = f->data + 10;} 

		if(f->datalength > 22 && strncmp(f->data, "a=fingerprint:sha-256 ", 22)==0)
		{
			char* tmp = ILibString_Replace(f->data + 22, f->datalength - 22, ":", 1, "", 0);
			dtlsHashLen = util_hexToBuf(tmp, strlen(tmp), tmp);
			dtlshash = tmp;
		}

		if(f->datalength > 12 && strncmp(f->data, "a=candidate:", 12)==0)
        {
			struct parser_result* pr2 = ILibParseString(f->data, 0, f->datalength, " ", 1);

			if(pr2->FirstResult->NextResult->datalength == 1 && pr2->FirstResult->NextResult->data[0] == '1' && pr2->FirstResult->NextResult->NextResult->datalength == 3 && strncasecmp(pr2->FirstResult->NextResult->NextResult->data, "UDP", 3)==0)
			//if(pr2->FirstResult->NextResult->NextResult->datalength == 3 && strncasecmp(pr2->FirstResult->NextResult->NextResult->data, "UDP", 3)==0)
			{
				char* candidateData;
				struct parser_result *pr3;
				char *tmp = pr2->FirstResult->NextResult->NextResult->NextResult->NextResult->NextResult->data;
				unsigned short port;

				tmp[pr2->FirstResult->NextResult->NextResult->NextResult->NextResult->NextResult->datalength] = 0;
				port = atoi(tmp);
				
				pr3 = ILibParseString(pr2->FirstResult->NextResult->NextResult->NextResult->NextResult->data, 0, pr2->FirstResult->NextResult->NextResult->NextResult->NextResult->datalength, ".", 1);					
				{
					candidateData = pr3->FirstResult->data;
					pr3->FirstResult->data[pr3->FirstResult->datalength] = 0;
					candidateData[0] = (char)atoi(pr3->FirstResult->data);
					pr3->FirstResult->NextResult->data[pr3->FirstResult->NextResult->datalength] = 0;
					candidateData[1] = (char)atoi(pr3->FirstResult->NextResult->data);
					pr3->FirstResult->NextResult->NextResult->data[pr3->FirstResult->NextResult->NextResult->datalength] = 0;
					candidateData[2] = (char)atoi(pr3->FirstResult->NextResult->NextResult->data);
					pr3->FirstResult->NextResult->NextResult->NextResult->data[pr3->FirstResult->NextResult->NextResult->NextResult->datalength] = 0;
					candidateData[3] = (char)atoi(pr3->FirstResult->NextResult->NextResult->NextResult->data);
				}
				ILibDestructParserResults(pr3);

				((unsigned short*)candidateData)[2] = htons(port);
				candidateData[6] = 0;

				ILibPushStack(&candidates, candidateData);
				++candidatecount;
			}

			ILibDestructParserResults(pr2);
        }
		f = f->NextResult;
    }

	if (*username == NULL || *password == NULL || dtlshash == NULL || candidatecount == 0)
    {
		*block = NULL;
		return(0);
    }

	
	blockLen = 6 + strlen(*username)+1 + strlen(*password)+1  + dtlsHashLen + 1 + (candidatecount*6)+1;
	if((*block = (char*)malloc(blockLen))==NULL){ILIBCRITICALEXIT(254);}
	ptr = 0;

	((unsigned short*)*block+ptr)[0] = htons(1);
	ptr += 2;

	((unsigned int*)(*block+ptr))[0] = htonl(BlockFlags);
	ptr += 4;

	(*block)[ptr] = (char)strlen(*username);
	ptr += 1;
	memcpy(*block+ptr, *username, strlen(*username));
	ptr += strlen(*username);

	(*block)[ptr] = (char)strlen(*password);
	ptr += 1;
	memcpy(*block+ptr, *password, strlen(*password));
	ptr += strlen(*password);

	(*block)[ptr] = (char)dtlsHashLen;
	ptr += 1;
	memcpy(*block+ptr, dtlshash, dtlsHashLen);
	ptr += dtlsHashLen;

	(*block)[ptr] = (char)candidatecount;
	ptr += 1;
	while(ILibPeekStack(&candidates)!=NULL)
	{
		memcpy(*block+ptr, ILibPopStack(&candidates), 6);
		ptr += 6;
	}

	ILibDestructParserResults(pr);
	free(lines);
	if(dtlshash!=NULL) {free(dtlshash);}
	return(ptr);
}

int ILibWrapper_BlockToSDPEx(char* block, int blockLen, char** username, char** password, char **sdp, char* serverReflexiveCandidateAddress, unsigned short serverReflexiveCandidatePort)
{
	char* sdpTemplate1 = "v=0\r\no=MeshAgent %u 0 IN IP4 0.0.0.0\r\ns=SIP Call\r\nt=0 0\r\na=ice-ufrag:%s\r\na=ice-pwd:%s\r\na=fingerprint:sha-256 %s\r\nm=application 1 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=sctpmap:5000 webrtc-datachannel 16\r\na=setup:%s\r\n";
	char* sdpTemplateRelay = "a=candidate:%d %d UDP %d %s %d typ relay raddr %u.%u.%u.%u %d\r\n";
	char* sdpTemplateLocalCand = "a=candidate:%d %d UDP %d %u.%u.%u.%u %u typ host\r\n";
	char* sdpTemplateSrflxCand = "a=candidate:%d %d UDP %d %s %u typ srflx raddr %u.%u.%u.%u rport %u\r\n";

	int sdpLen;
	int c,x,i,ptr;
	char junk[4];
	struct sockaddr_in6 *relayEndPoint = NULL;
	char relayAddressString[128];
	unsigned short relayAddressPort = 0;
	
	// Decode the block

	//This value is commented out to prevent a compiler warning for unused variables, but I left it here to show how to fetch it
	//
    //short blockversion = ILibWrapper_ReadShort(block, 0);
	//

    int blockflags = ILibWrapper_ReadInt(block, 2);	
	int isActive = (blockflags & ILibWebRTC_SDP_Flags_DTLS_SERVER) == ILibWebRTC_SDP_Flags_DTLS_SERVER ? 0:1;

	int usernamelen = (int)block[6];
	int passwordlen = (int)block[7 + usernamelen];
	int dtlshashlen = (int)block[8 + usernamelen + passwordlen];
	int candidatecount = (int)block[9 + usernamelen + passwordlen + dtlshashlen];
	char dtlshash[128];
	int rlen = 10 + usernamelen + passwordlen + dtlshashlen + (candidatecount * 6);
	char* candidates = block + 10 + usernamelen + passwordlen + dtlshashlen;

    *username = ILibWrapper_ReadString(block, 7, usernamelen);            
    *password = ILibWrapper_ReadString(block, 8 + usernamelen, passwordlen);

	util_tohex2(block + 9 + usernamelen + passwordlen, dtlshashlen, dtlshash);

	if (rlen < blockLen)
    {
		relayEndPoint = (struct sockaddr_in6*)(block+rlen+1);
		ILibInet_ntop2((struct sockaddr*)relayEndPoint, relayAddressString, 128);
		switch(((struct sockaddr_in*)relayEndPoint)->sin_family)
		{
			case AF_INET:
				relayAddressPort = ntohs(((struct sockaddr_in*)relayEndPoint)->sin_port);
				break;
			case AF_INET6:
				relayAddressPort = ntohs(relayEndPoint->sin6_port);
				break;
		}
    }


	// Build the sdp
	sdpLen = 2 + strlen(sdpTemplate1) + usernamelen + passwordlen + 7 + (dtlshashlen*3) + 7 + (2 *   (candidatecount * (12 + 21 + strlen(sdpTemplateLocalCand)))  );
	if(serverReflexiveCandidateAddress!=NULL)
	{
		sdpLen += (2* (12 + 21 + strlen(sdpTemplateSrflxCand)));
	}
	if(relayEndPoint!=NULL)
	{
		sdpLen += (2* (12 + 21 + strlen(sdpTemplateRelay)));
	}

	if((*sdp = (char*)malloc(sdpLen))==NULL){ILIBCRITICALEXIT(254);}

	util_random(4, junk);

	x = snprintf(*sdp, sdpLen, sdpTemplate1, ((unsigned int*)junk)[0]%1000000, *username, *password, dtlshash, isActive==0?"passive":"actpass");

	for(c = 1; c <= 2; ++c)
	{
		for (i = 0; i < candidatecount; i++)
		{
			ptr = i*6;
			x += snprintf(*sdp+x, sdpLen-x, sdpTemplateLocalCand, i, c, 2128609535-i, (unsigned char)candidates[ptr], (unsigned char)candidates[ptr+1], (unsigned char)candidates[ptr+2], (unsigned char)candidates[ptr+3], ntohs(((unsigned short*)(candidates+ptr+4))[0]));
		}
		if(serverReflexiveCandidateAddress!=NULL)
		{
			x += snprintf(*sdp+x, sdpLen-x, sdpTemplateSrflxCand, i, c, 2128609535-i, serverReflexiveCandidateAddress, serverReflexiveCandidatePort, (unsigned char)candidates[0], (unsigned char)candidates[1], (unsigned char)candidates[2], (unsigned char)candidates[3], ntohs(((unsigned short*)(candidates+4))[0]));
			++i;
		}
		if(relayEndPoint!=NULL)
		{
			x += snprintf(*sdp+x, sdpLen-x, sdpTemplateRelay, i, c, 2128609535-i, relayAddressString, relayAddressPort,  (unsigned char)candidates[0], (unsigned char)candidates[1], (unsigned char)candidates[2], (unsigned char)candidates[3]);
		}
	}
	return(x);
}
int ILibWrapper_BlockToSDP(char* block, int blockLen, int isActive, char** username, char** password, char **sdp)
{
	return(ILibWrapper_BlockToSDPEx(block, blockLen, username, password, sdp, NULL, 0));
}
void ILibWrapper_WebRTC_InitializeCrypto(ILibWrapper_WebRTC_ConnectionFactoryStruct *factory)
{
	int l = 32;

	// Init SSL
	util_openssl_init();

	// Init Certs
	util_mkCert(NULL, &(factory->selfcert), 2048, 10000, "localhost", CERTIFICATE_ROOT, NULL);
	util_keyhash(factory->selfcert, factory->g_selfid);
	util_mkCert(&(factory->selfcert), &(factory->selftlscert), 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER, NULL);
	util_mkCert(&(factory->selfcert), &(factory->selftlsclientcert), 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL);

	// Init DTLS
	factory->ctx = SSL_CTX_new(DTLSv1_method());
	SSL_CTX_use_certificate(factory->ctx, factory->selftlscert.x509);
	SSL_CTX_use_PrivateKey(factory->ctx, factory->selftlscert.pkey);		
	X509_digest(factory->selftlscert.x509, EVP_get_digestbyname("sha256"), (unsigned char*)factory->tlsServerCertThumbprint, (unsigned int*)&l);
}
void ILibWrapper_WebRTC_UnInitializeCrypto(ILibWrapper_WebRTC_ConnectionFactoryStruct *factory)
{
	// UnInit DTLS
	SSL_CTX_free(factory->ctx);
	factory->ctx = NULL;

	// UnInit Certs
	util_freecert(&(factory->selftlsclientcert));
	util_freecert(&(factory->selftlscert));
	util_freecert(&(factory->selfcert));
	memset(&(factory->selftlsclientcert),0,sizeof(struct util_cert));
	memset(&(factory->selftlscert),0,sizeof(struct util_cert));
	memset(&(factory->selfcert),0,sizeof(struct util_cert));

	
	// UnInit SSL
	util_openssl_uninit();
}
void ILibWrapper_WebRTC_ConnectionFactory_OnDestroy(void *obj)
{
	ILibWrapper_WebRTC_ConnectionFactoryStruct *cfs = (ILibWrapper_WebRTC_ConnectionFactoryStruct*)obj;
	void *en = ILibHashTree_GetEnumerator(cfs->ConnectionTable);
	char *key;
	int keyLen;
	void *data;


	while(ILibHashTree_MoveNext(en)==0)
	{
		ILibHashTree_GetValue(en, &key, &keyLen, &data);
		ILibWrapper_WebRTC_Connection_DestroyConnection(data);
	}
	ILibHashTree_DestroyEnumerator(en);

	ILibDestroyHashTree(cfs->ConnectionTable);
	ILibWrapper_WebRTC_UnInitializeCrypto((ILibWrapper_WebRTC_ConnectionFactoryStruct*)obj);
}


void ILibWrapper_WebRTC_Connection_DestroyConnection(ILibWrapper_WebRTC_Connection connection)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*)connection;
	ILibWrapper_WebRTC_DataChannel *dc;

	if(obj==NULL) {return;}

	
	if(ILibIsChainBeingDestroyed(obj->mFactory->mChain)==0)
	{
		ILibDeleteEntry(obj->mFactory->ConnectionTable, obj->id, WEBRTC_CONNECTION_ID_SIZE);

		// Chain is not being destroyed, so we can disconnect DTLS		
		if(obj->dtlsSession!=NULL)
		{
			ILibSCTP_Close(obj->dtlsSession);
		}
		else
		{
			if(obj->offerBlock!=NULL && obj->offerBlockLen>0)
			{
				// Clear the ICE State for the local Offer
				ILibStun_ClearIceState(obj->mFactory->mFactory, ILibStun_CharToSlot(obj->offerBlock[7]));
			}
			if(obj->remoteOfferBlock!=NULL && obj->remoteOfferBlockLen>0)
			{
				// Clear the ICE State for the remote Offer
				ILibStun_ClearIceState(obj->mFactory->mFactory, ILibStun_CharToSlot(obj->remoteOfferBlock[7]));
			}
		}
	}

	ILibWebRTC_SetUserObject(obj->mFactory->mFactory, obj->localUsername, NULL);

	if(obj->stunServerList!=NULL && obj->stunServerListLength>0)
	{
		int i;
		for(i=0;i<obj->stunServerListLength;++i)
		{
			free(obj->stunServerList[i]);
		}
		free(obj->stunServerList);
		obj->stunServerList = NULL;
	}

	if(obj->offerBlock!=NULL)
	{
		free(obj->offerBlock);
		obj->offerBlock = NULL;
	}

	if(obj->remoteOfferBlock!=NULL)
	{
		free(obj->remoteOfferBlock);
		obj->remoteOfferBlock = NULL;
	}

	while(ILibLinkedList_GetCount(obj->dataChannels)>0)
	{
		dc = (ILibWrapper_WebRTC_DataChannel*)ILibLinkedList_GetDataFromNode(ILibLinkedList_GetNode_Head(obj->dataChannels));
		if(dc->OnClosed!=NULL) {dc->OnClosed(dc);}
		free(dc->channelName);
		free(dc);

		ILibLinkedList_Remove(ILibLinkedList_GetNode_Head(obj->dataChannels));
	}
	ILibLinkedList_Destroy(obj->dataChannels);

	if(obj->stunServerFlags!=NULL)
	{
		free(obj->stunServerFlags);
	}

	free(obj);
}

void ILibWrapper_WebRTC_Connection_Disconnect(ILibWrapper_WebRTC_Connection connection)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*)connection;

	if(obj->dtlsSession!=NULL)
	{
		// If DTLS was connected, this will call OnDisconnect later
		ILibSCTP_Close(obj->dtlsSession);
	}
	else
	{
		// No DTLS session, so just clean up the connection object

		if(obj->offerBlock!=NULL && obj->offerBlockLen>0)
		{
			// Clear the ICE State for the local Offer
			ILibStun_ClearIceState(obj->mFactory->mFactory, ILibStun_CharToSlot(obj->offerBlock[7]));
		}
		if(obj->remoteOfferBlock!=NULL && obj->remoteOfferBlockLen>0)
		{
			// Clear the ICE State for the remote Offer
			ILibStun_ClearIceState(obj->mFactory->mFactory, ILibStun_CharToSlot(obj->remoteOfferBlock[7]));
		}

		if(obj->OnConnected!=NULL) {obj->OnConnected(connection, 0);}
		ILibWrapper_WebRTC_Connection_DestroyConnection(connection);
	}
}

void ILibWrapper_WebRTC_OnStunResult(void* StunModule, ILibStun_Results Result, struct sockaddr_in* PublicIP, void *user)
{
	ILibWrapper_WebRTC_ConnectionStruct *connection = (ILibWrapper_WebRTC_ConnectionStruct*)user;
	connection->stunServerFlags[connection->stunIndex] = 1;

	switch(Result)
	{
		case ILibStun_Results_Unknown:
		case ILibStun_Results_ServerError_RFC5780_NOT_IMPLEMENTED:
			// The STUN Server we used is no good, so try with a different server
			connection->stunServerFlags[connection->stunIndex] = 2;
			if(ILibWrapper_WebRTC_PerformStun(connection)!=0 && connection->OnCandidates!=NULL)
			{
				// No more STUN servers to try, so give up
				connection->OnCandidates(connection, NULL);
			}
			break;
		case ILibStun_Results_Full_Cone_NAT:
		case ILibStun_Results_Port_Restricted_NAT:
		case ILibStun_Results_Restricted_NAT:
			if(connection->OnCandidates!=NULL)
			{
				connection->OnCandidates(connection, (struct sockaddr_in6*)PublicIP);
			}
			break;
		case ILibStun_Results_No_NAT:
			// Don't need to do anything if there was no NAT, as the local candidates will be good enough
			if(connection->OnCandidates!=NULL)
			{
				connection->OnCandidates(connection, NULL);
			}
			break;
		case ILibStun_Results_Symetric_NAT:
			// This won't work... 
			//ToDo: Add support for basic Port Prediction
			if(connection->OnCandidates!=NULL)
			{
				connection->OnCandidates(connection, NULL);
			}
			break;
	}
}

int ILibWrapper_WebRTC_Connection_IsConnected(ILibWrapper_WebRTC_Connection connection)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) connection;

	return(obj!=NULL?obj->isConnected:0);
}

void ILibWrapper_WebRTC_OnConnectSink(void *StunModule, void* module, int connected)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) ILibWebRTC_GetUserObjectFromDtlsSession(module);
	if(obj==NULL) {return;}

	obj->dtlsSession = module;
	obj->isConnected = connected;

	obj->isDtlsClient = ILibWebRTC_IsDtlsInitiator(module);

	if(obj->OnConnected!=NULL)
	{
		obj->OnConnected(obj, connected);
	}

	if(connected==0)
	{
		if(ILibIsChainBeingDestroyed(obj->mFactory->mChain)==0)
		{
			// Connection was closed, so let's clean up, but only if the chain is still running. It's possible that the previous callback caused the layer above
			// us to initiate a chain shutdown. In that case, skip this method call, becuase otherwise we may end up calling it twice, which will cause a crash.
			ILibWrapper_WebRTC_Connection_DestroyConnection(obj);
		}
	}
}
void ILibWrapper_WebRTC_OnDataSink(void* StunModule, void* module, unsigned short streamId, int pid, char* buffer, int bufferLen, void** user)
{
	ILibWrapper_WebRTC_DataChannel *dc = NULL;
	if(*user==NULL)
	{		
		ILibWrapper_WebRTC_ConnectionStruct *connection = (ILibWrapper_WebRTC_ConnectionStruct*)ILibWebRTC_GetUserObjectFromDtlsSession(module);
		void *node = ILibLinkedList_GetNode_Head(connection->dataChannels);

		while(node!=NULL)
		{
			dc = (ILibWrapper_WebRTC_DataChannel*)ILibLinkedList_GetDataFromNode(node);
			if(dc->streamId == streamId)
			{
				*user = dc;
				break;
			}
			node = ILibLinkedList_GetNextNode(node);
		}		
	}
	else
	{
		dc = (ILibWrapper_WebRTC_DataChannel*)*user;
	}

	if(dc!=NULL)
	{
		if(dc->OnRawData!=NULL)	{dc->OnRawData(dc, buffer, bufferLen, pid);}
		if(dc->OnStringData!=NULL && pid == 51) {dc->OnStringData(dc, buffer, bufferLen);}
		if(dc->OnBinaryData!=NULL && pid == 53) {dc->OnBinaryData(dc, buffer, bufferLen);}
	}
}
void ILibWrapper_WebRTC_OnSendOKSink(void* StunModule, void* module, void* user)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) ILibWebRTC_GetUserObjectFromDtlsSession(module);
	if(obj != NULL && obj->OnSendOK != NULL)
	{
		obj->OnSendOK(obj);
	}
}

int ILibWrapper_WebRTC_OnDataChannel(void *StunModule, void* WebRTCModule, unsigned short StreamId, char* ChannelName, int ChannelNameLength)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) ILibWebRTC_GetUserObjectFromDtlsSession(WebRTCModule);
	ILibWrapper_WebRTC_DataChannel* dataChannel = NULL;
	void *node;

	if(obj->OnDataChannel!=NULL)
	{
		ILibLinkedList_Lock(obj->dataChannels);		
		{
			node = ILibLinkedList_GetNode_Head(obj->dataChannels);
			while(node!=NULL)
			{
				dataChannel = (ILibWrapper_WebRTC_DataChannel*)ILibLinkedList_GetDataFromNode(node);
				if(dataChannel->streamId == StreamId)
				{
					break;
				}
				dataChannel = NULL;
				node = ILibLinkedList_GetNextNode(node);
			}
		
			if(dataChannel == NULL)
			{
				if((dataChannel = (ILibWrapper_WebRTC_DataChannel*)malloc(sizeof(ILibWrapper_WebRTC_DataChannel)))==NULL){ILIBCRITICALEXIT(254);}
				memset(dataChannel, 0, sizeof(ILibWrapper_WebRTC_DataChannel));

				dataChannel->parent = obj;
				dataChannel->streamId = StreamId;
				if((dataChannel->channelName = (char*)malloc(ChannelNameLength+1))==NULL){ILIBCRITICALEXIT(254);}
				ChannelName[ChannelNameLength] = 0;
				strcpy(dataChannel->channelName, ChannelName);
				ILibLinkedList_AddTail(obj->dataChannels, dataChannel);
			}
		}
		ILibLinkedList_UnLock(obj->dataChannels);
			
		obj->OnDataChannel(obj, dataChannel);
	}
	//
	// 0 = ACK DATA CHANNEL
	// 1 = DO NOT ACK DATA CHANNEL
	//
	return(dataChannel==NULL?1:0); 
}
void ILibWrapper_WebRTC_OnDataChannelAck(void *StunModule, void* WebRTCModule, unsigned short StreamId)
{
	ILibWrapper_WebRTC_ConnectionStruct *connection = (ILibWrapper_WebRTC_ConnectionStruct*)ILibWebRTC_GetUserObjectFromDtlsSession(WebRTCModule);
	ILibWrapper_WebRTC_DataChannel *dataChannel;
	void* node;

	if(connection!=NULL)
	{
		node = ILibLinkedList_GetNode_Head(connection->dataChannels);
		while(node!=NULL)
		{
			dataChannel = (ILibWrapper_WebRTC_DataChannel*)ILibLinkedList_GetDataFromNode(node);
			if(dataChannel!=NULL && dataChannel->streamId == StreamId)
			{
				if(dataChannel->OnAck != NULL) {dataChannel->OnAck(dataChannel);}
				break;
			}
			node = ILibLinkedList_GetNextNode(node);
		}
	}
}
void ILibWrapper_WebRTC_OnOfferUpdated(void* stunModule, char* iceOffer, int iceOfferLen)
{
}

ILibWrapper_WebRTC_ConnectionFactory ILibWrapper_WebRTC_ConnectionFactory_CreateConnectionFactory(void* chain, unsigned short localPort)
{
	ILibWrapper_WebRTC_ConnectionFactoryStruct *retVal = (ILibWrapper_WebRTC_ConnectionFactoryStruct*)malloc(sizeof(ILibWrapper_WebRTC_ConnectionFactoryStruct));
	if(retVal==NULL){ILIBCRITICALEXIT(254);}

	memset(retVal, 0, sizeof(ILibWrapper_WebRTC_ConnectionFactoryStruct));
	ILibAddToChain(chain, retVal);

	retVal->Destroy = &ILibWrapper_WebRTC_ConnectionFactory_OnDestroy;
	ILibWrapper_WebRTC_InitializeCrypto(retVal);

	retVal->mFactory = ILibStunClient_Start(chain, localPort, &ILibWrapper_WebRTC_OnStunResult);
	ILibStunClient_SetOptions(retVal->mFactory, retVal->ctx, retVal->tlsServerCertThumbprint);
	ILibSCTP_SetCallbacks(retVal->mFactory, &ILibWrapper_WebRTC_OnConnectSink, &ILibWrapper_WebRTC_OnDataSink, &ILibWrapper_WebRTC_OnSendOKSink);
	ILibWebRTC_SetCallbacks(retVal->mFactory, &ILibWrapper_WebRTC_OnDataChannel, &ILibWrapper_WebRTC_OnDataChannelAck, &ILibWrapper_WebRTC_OnOfferUpdated);
	
	retVal->ConnectionTable = ILibInitHashTree();
	retVal->mChain = chain;

	

	return(retVal); 
}

ILibWrapper_WebRTC_Connection ILibWrapper_WebRTC_ConnectionFactory_CreateConnection(ILibWrapper_WebRTC_ConnectionFactory factory, ILibWrapper_WebRTC_Connection_OnConnect OnConnectHandler, ILibWrapper_WebRTC_Connection_OnDataChannel OnDataChannelHandler, ILibWrapper_WebRTC_Connection_OnSendOK OnConnectionSendOK)
{
	ILibWrapper_WebRTC_ConnectionStruct *retVal = (ILibWrapper_WebRTC_ConnectionStruct*)malloc(sizeof(ILibWrapper_WebRTC_ConnectionStruct));
	if(retVal==NULL){ILIBCRITICALEXIT(254);}

	memset(retVal, 0, sizeof(ILibWrapper_WebRTC_ConnectionStruct));

	retVal->OnConnected = OnConnectHandler;
	retVal->OnDataChannel = OnDataChannelHandler;
	retVal->OnSendOK = OnConnectionSendOK;

	retVal->mFactory = (ILibWrapper_WebRTC_ConnectionFactoryStruct*)factory;
	util_random(WEBRTC_CONNECTION_ID_SIZE, retVal->id);

	ILibHashTree_Lock(retVal->mFactory->ConnectionTable);
	ILibAddEntry(retVal->mFactory->ConnectionTable, retVal->id, WEBRTC_CONNECTION_ID_SIZE, retVal);
	ILibHashTree_UnLock(retVal->mFactory->ConnectionTable);
	
	retVal->dataChannels = ILibLinkedList_Create();

	return(retVal);
}
void ILibWrapper_WebRTC_Connection_SetStunServers(ILibWrapper_WebRTC_Connection connection, char** serverList, int serverLength)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) connection;
	int i;

	if(serverLength<=0){return;}

	if((obj->stunServerFlags = (char*)malloc(serverLength))==NULL){ILIBCRITICALEXIT(254);}
	memset(obj->stunServerFlags, 0, serverLength);

	obj->stunServerList = (char**)malloc(serverLength * sizeof(char*));
	obj->stunServerListLength = serverLength;
	for(i=0;i<serverLength;++i)
	{
		obj->stunServerList[i] = (char*)malloc(strlen(serverList[i])+1);
		strcpy(obj->stunServerList[i], serverList[i]);
	}
}

int ILibWrapper_WebRTC_PerformStun(ILibWrapper_WebRTC_ConnectionStruct *connection)
{
	int i,delimiter;
	struct sockaddr_in6 stunServer;
	unsigned short port;
	char temp[255];
	char *host;

	if(connection->stunServerListLength > 0)
	{
		for(i=0;i<connection->stunServerListLength;++i)
		{
			if(connection->stunServerFlags[i] > 1) {continue;} // 0 = Unknown, 1 = Success, 2 = ERROR

			delimiter = ILibString_IndexOf(connection->stunServerList[i], strlen(connection->stunServerList[i]), ":", 1);
			if(delimiter>0) 
			{
				memcpy(temp,connection->stunServerList[i], delimiter);
				temp[delimiter] = 0;
				host = temp;
				port = atoi(connection->stunServerList[i] + delimiter + 1);
			}
			else
			{
				host = connection->stunServerList[i];
				port = 3478;
			}
			if(ILibResolve(host, "http", &stunServer)==0)
			{
				switch(stunServer.sin6_family)
				{
					case AF_INET:
						((struct sockaddr_in*)&stunServer)->sin_port = htons(port);
						break;
					case AF_INET6:
						stunServer.sin6_port = htons(port);
						break;
				}
				connection->stunIndex = i;
				ILibStunClient_PerformStun(connection->mFactory->mFactory, (struct sockaddr_in*)&stunServer, connection);
				break;
			}
			else
			{
				connection->stunServerFlags[i] = 2; // Could not resolve, so skip, and use another server
			}
		}
		return(i<connection->stunServerListLength?0:1);
	}
	else
	{
		return(1);
	}
}

char* ILibWrapper_WebRTC_Connection_SetOffer(ILibWrapper_WebRTC_Connection connection, char* offer, int offerLen, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) connection;
	char* sdp;
	int isActive;
	char *un,*up;

	if(obj->remoteOfferBlock!=NULL) {free(obj->remoteOfferBlock);}
	if(obj->offerBlock!=NULL) {free(obj->offerBlock);}
	
	obj->remoteOfferBlockLen = ILibWrapper_SdpToBlock(offer, offerLen, &isActive, &(obj->remoteUsername), &(obj->remotePassword), &(obj->remoteOfferBlock));

	offer[offerLen] = 0;
	ILibDebugPrintf_V3("Received offer: \r\n%s\r\n", offer);


	obj->offerBlockLen = ILibStun_SetIceOffer2(obj->mFactory->mFactory, obj->remoteOfferBlock, obj->remoteOfferBlockLen, obj->offerBlock!=NULL?obj->localUsername:NULL, obj->offerBlock!=NULL?8:0, obj->offerBlock!=NULL?obj->localPassword:NULL, obj->offerBlock!=NULL?32:0, &obj->offerBlock);	
	ILibWrapper_BlockToSDP(obj->offerBlock, obj->offerBlockLen, obj->isOfferInitiator, &un, &up, &sdp);

	ILibDebugPrintf_V3("Response: \r\n%s\r\n", sdp);

	ILibWebRTC_SetUserObject(obj->mFactory->mFactory, un, obj);
	memcpy(obj->localUsername, un, strlen(un));
	memcpy(obj->localPassword, up, strlen(up));

	free(un);
	free(up);

	if(onCandidates != NULL)
	{
		obj->OnCandidates = onCandidates;
		if(ILibWrapper_WebRTC_PerformStun(obj)!=0)
		{
			// No STUN Servers to try
			onCandidates(connection, NULL);
		}
	}

	return(sdp);
}

char* ILibWrapper_WebRTC_Connection_GenerateOffer(ILibWrapper_WebRTC_Connection connection, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) connection;

	char* offer;
	int offerLen = ILibStun_GenerateIceOffer(obj->mFactory->mFactory, &offer, obj->localUsername, obj->localPassword);
	char *sdp;
	char* username,*password;

	obj->isOfferInitiator = 1;
	ILibWrapper_BlockToSDP(offer, offerLen, obj->isOfferInitiator, &username, &password, &sdp);

	free(username);
	free(password);

	obj->offerBlock = offer;
	obj->offerBlockLen = offerLen;
	obj->OnCandidates = onCandidates;

	if(onCandidates != NULL)
	{
		if(ILibWrapper_WebRTC_PerformStun(obj)!=0)
		{
			// No STUN Servers to try
			onCandidates(connection, NULL);
		}
	}

	return(sdp);
}

char* ILibWrapper_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(ILibWrapper_WebRTC_Connection connection, struct sockaddr_in6* candidate)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*) connection;
	char *sdp;
	char *username;
	char *password;
	char address[255];
	
	if(candidate!=NULL)
	{
		ILibInet_ntop2((struct sockaddr*)candidate, address, 255);
		ILibWrapper_BlockToSDPEx(obj->offerBlock, obj->offerBlockLen, &username, &password, &sdp, address, ntohs(candidate->sin6_port));
	}
	else
	{
		ILibWrapper_BlockToSDPEx(obj->offerBlock, obj->offerBlockLen, &username, &password, &sdp, NULL, 0);
	}
	

	free(username);
	free(password);

	return(sdp);
}

enum ILibAsyncSocket_SendStatus ILibWrapper_WebRTC_DataChannel_SendEx(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen, int dataType)
{
	ILibWrapper_WebRTC_ConnectionStruct *connection = (ILibWrapper_WebRTC_ConnectionStruct*)dataChannel->parent;

	return((enum ILibAsyncSocket_SendStatus)ILibSCTP_SendEx(connection->dtlsSession, dataChannel->streamId, data, dataLen, dataType));
}
enum ILibAsyncSocket_SendStatus ILibWrapper_WebRTC_DataChannel_Send(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen)
{
	return(ILibWrapper_WebRTC_DataChannel_SendEx(dataChannel, data, dataLen, 53));
}
enum ILibAsyncSocket_SendStatus ILibWrapper_WebRTC_DataChannel_SendString(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen)
{
	return(ILibWrapper_WebRTC_DataChannel_SendEx(dataChannel, data, dataLen, 51));
}

ILibWrapper_WebRTC_DataChannel* ILibWrapper_WebRTC_DataChannel_Create(ILibWrapper_WebRTC_Connection connection, char* channelName, int channelNameLen, ILibWrapper_WebRTC_DataChannel_OnDataChannelAck OnAckHandler)
{
	return(ILibWrapper_WebRTC_DataChannel_CreateEx(connection, channelName, channelNameLen, ILibWrapper_GetNextStreamId((ILibWrapper_WebRTC_ConnectionStruct*)connection), OnAckHandler));
}
ILibWrapper_WebRTC_DataChannel* ILibWrapper_WebRTC_DataChannel_CreateEx(ILibWrapper_WebRTC_Connection connection, char* channelName, int channelNameLen, unsigned short streamId, ILibWrapper_WebRTC_DataChannel_OnDataChannelAck OnAckHandler)
{
	ILibWrapper_WebRTC_DataChannel *retVal = (ILibWrapper_WebRTC_DataChannel*)malloc(sizeof(ILibWrapper_WebRTC_DataChannel));
	if(retVal==NULL){ILIBCRITICALEXIT(254);}
	memset(retVal, 0, sizeof(ILibWrapper_WebRTC_DataChannel));

	retVal->parent = connection;
	if((retVal->channelName = (char*)malloc(channelNameLen+1))==NULL){ILIBCRITICALEXIT(254);}
	memcpy(retVal->channelName, channelName, channelNameLen);
	retVal->channelName[channelNameLen] = 0;

	retVal->streamId = streamId;
	retVal->OnAck = OnAckHandler;

	ILibLinkedList_Lock(((ILibWrapper_WebRTC_ConnectionStruct*)connection)->dataChannels);
	ILibLinkedList_AddTail(((ILibWrapper_WebRTC_ConnectionStruct*)connection)->dataChannels, retVal);
	ILibLinkedList_UnLock(((ILibWrapper_WebRTC_ConnectionStruct*)connection)->dataChannels);

	ILibStun_WebRTC_OpenChannel(((ILibWrapper_WebRTC_ConnectionStruct*)connection)->dtlsSession, streamId, channelName, channelNameLen);
	return(retVal);
}
void ILibWrapper_WebRTC_ConnectionFactory_SetTurnServer(ILibWrapper_WebRTC_ConnectionFactory factory, struct sockaddr_in6* turnServer, char* username, int usernameLength, char* password, int passwordLength, ILibWebRTC_TURN_ConnectFlags turnSetting)
{
	ILibWrapper_WebRTC_ConnectionFactoryStruct *cf = (ILibWrapper_WebRTC_ConnectionFactoryStruct*)factory;
	cf->mTurnSetting = turnSetting;

	if(turnServer != NULL) {memcpy(&(cf->mTurnServer), turnServer, INET_SOCKADDR_LENGTH(turnServer->sin6_family));}
	if(cf->mTurnServerUsername!=NULL) {free(cf->mTurnServerUsername);cf->mTurnServerUsername = NULL;}
	if(cf->mTurnServerPassword!=NULL) {free(cf->mTurnServerPassword);cf->mTurnServerPassword = NULL;}

	if(turnSetting == ILibWebRTC_TURN_DISABLED)
	{
		ILibWebRTC_SetTurnServer(cf->mFactory, NULL, NULL, 0, NULL, 0, ILibWebRTC_TURN_DISABLED);
	}
	else
	{
		if((cf->mTurnServerUsername = (char*)malloc(usernameLength))==NULL){ILIBCRITICALEXIT(254);}
		cf->mTurnServerUsernameLen = usernameLength;
		memcpy(cf->mTurnServerUsername, username, usernameLength);

		if((cf->mTurnServerPassword = (char*)malloc(passwordLength))==NULL){ILIBCRITICALEXIT(254);}
		cf->mTurnServerPasswordLen = passwordLength;
		memcpy(cf->mTurnServerPassword, password, passwordLength);
	

		ILibWebRTC_SetTurnServer(cf->mFactory, turnServer, username, usernameLength, password, passwordLength, turnSetting);
	}
}
void ILibWrapper_WebRTC_Connection_SetUserData(ILibWrapper_WebRTC_Connection connection, void *user1, void *user2, void *user3)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*)connection;
	obj->User1 = user1;
	obj->User2 = user2;
	obj->User3 = user3;
}
void ILibWrapper_WebRTC_Connection_GetUserData(ILibWrapper_WebRTC_Connection connection, void **user1, void **user2, void **user3)
{
	ILibWrapper_WebRTC_ConnectionStruct *obj = (ILibWrapper_WebRTC_ConnectionStruct*)connection;
	if(user1!=NULL) {*user1 = obj->User1;}
	if(user2!=NULL) {*user2 = obj->User2;}
	if(user3!=NULL) {*user3 = obj->User3;}
}
void ILibWrapper_WebRTC_DataChannel_OnDebug(void *dtlsSession, char* debugField, int debugValue)
{
	ILibWrapper_WebRTC_ConnectionStruct *cs = (ILibWrapper_WebRTC_ConnectionStruct*)ILibWebRTC_GetUserObjectFromDtlsSession(dtlsSession);
	if(cs!=NULL && cs->OnDebugEvent!=NULL) {cs->OnDebugEvent(cs, debugField, debugValue);}
}
#ifdef _WEBRTCDEBUG
int ILibWrapper_WebRTC_Connection_Debug_Set(ILibWrapper_WebRTC_Connection connection, char* debugFieldName, ILibWrapper_WebRTC_Connection_Debug_OnEvent eventHandler)
{
	ILibWrapper_WebRTC_ConnectionStruct *cs = (ILibWrapper_WebRTC_ConnectionStruct*)connection;
	cs->OnDebugEvent = eventHandler;
	return(ILibSCTP_Debug_SetDebugCallback(cs->dtlsSession, debugFieldName, &ILibWrapper_WebRTC_DataChannel_OnDebug));
}
void ILibWrapper_WebRTC_ConnectionFactory_SetSimulatedLossPercentage(ILibWrapper_WebRTC_ConnectionFactory factory, int lossPercentage)
{
	ILibSCTP_SetSimulatedInboundLossPercentage(((ILibWrapper_WebRTC_ConnectionFactoryStruct*)factory)->mFactory, lossPercentage);
}
#endif