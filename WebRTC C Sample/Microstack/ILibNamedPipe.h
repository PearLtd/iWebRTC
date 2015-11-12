/*   
Copyright 2006 - 2011 Intel Corporation

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


/*! \file ILibNamedPipe.h 
\brief MicroStack APIs for various functions and tasks related to named pipes
*/

#ifndef __ILibNamedPipe__
#define __ILibNamedPipe__

	#define ILibTransports_NamedPipe 0x60

	typedef void* ILibNamedPipe_Manager;
	typedef void* ILibNamedPipe_Module_Server;
	typedef void* ILibNamedPipe_Module_Client;

	typedef void(*ILibNamedPipe_OnClientConnectionHandler)(ILibNamedPipe_Manager sender, ILibNamedPipe_Module_Client clientPipeModule, void *user);
	typedef void(*ILibNamedPipe_OnReadHandler)(ILibNamedPipe_Module_Client pipeModule, char* buffer, int offset, int bytesRead, int *bytesConsumed, void *user);
	typedef void(*ILibNamedPipe_OnSendOKHandler)(ILibNamedPipe_Module_Client pipeModule, void* user);

	ILibNamedPipe_Manager ILibNamedPipe_CreateManager(void *chain);
	ILibNamedPipe_Module_Server ILibNamedPipe_Manager_CreateServerPipe(ILibNamedPipe_Manager manager, char* pipeName, int pipeNameLength, void *user, ILibNamedPipe_OnClientConnectionHandler onConnect, ILibNamedPipe_OnClientConnectionHandler onDisconnect);
	ILibNamedPipe_Module_Client ILibNamedPipe_Manager_CreateClientPipe(ILibNamedPipe_Manager manager, char* pipeName, int pipeNameLength, void *user, int readBufferSize, ILibNamedPipe_OnClientConnectionHandler onDisconnectCallback);

	void ILibNamedPipe_Module_StartIO(ILibNamedPipe_Module_Client module, int bufferSize, ILibNamedPipe_OnReadHandler ReaderCallback, ILibNamedPipe_OnSendOKHandler OnSendOK);

	int ILibNamedPipe_Write_BLOCKING(ILibNamedPipe_Module_Client module, char* buffer, int bufferSize);
	ILibTransport_DoneState ILibNamedPipe_Write(ILibNamedPipe_Module_Client module, char* buffer, int bufferLen, ILibTransport_MemoryOwnership ownership);
	void ILibNamedPipe_Module_Close(void* module);
#endif

/* \} */   // End of ILibNamedPipe Group

