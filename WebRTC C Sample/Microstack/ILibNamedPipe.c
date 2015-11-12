/*   
Copyright 2013 Intel Corporation

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

#ifdef MEMORY_CHECK
#include <assert.h>
#define MEMCHECK(x) x
#else
#define MEMCHECK(x)
#endif

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


#include "ILibParsers.h"
#include "ILibRemoteLogging.h"
#include "ILibNamedPipe.h"
#include <assert.h>

#define PIPE_BUFFER_SIZE 4096

#ifndef WIN32
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE -1
#include <sys/stat.h>
#include <fcntl.h>
#endif

typedef struct ILibNamedPipe_Manager_Struct
{
	ILibChain_PreSelect Pre;
	ILibChain_PostSelect Post;
	ILibChain_Destroy Destroy;

	void* chain;
	ILibLinkedList ActivePipes;
	ILibQueue WaitHandles_PendingAdd;
	ILibQueue WaitHandles_PendingDel;
#ifdef WIN32
	int abort;
	HANDLE updateEvent;
#endif
}ILibNamedPipe_Manager_Object;
typedef struct ILibNamedPipe_Module_Server_object
{
	ILibNamedPipe_Manager_Object *man;
	char* mPipeName1;
	char* mPipeName2;
	void* userObject;
	ILibNamedPipe_OnClientConnectionHandler userConnectionCallback;
	ILibNamedPipe_OnClientConnectionHandler userDisconnectionCallback;
}ILibNamedPipe_Module_Server_object;
typedef struct ILibNamedPipe_Module_struct
{
	ILibChain_PreSelect Pre;
	ILibChain_PostSelect Post;
	ILibChain_Destroy Destroy;
	void* Chain;
	ILibTransport_SendPtr Send;
	ILibTransport_ClosePtr Close;
	ILibTransport_PendingBytesToSendPtr PendingBytes;
	unsigned int IdentifierFlags;
	/*
	*
	* Do NOT modify struct definition above this comment block (ILibTransport)
	*
	*/


	char* mPipeName1;
	char* mPipeName2;

	int started;
	ILibNamedPipe_Module_Server_object *server;
#ifdef WIN32
	HANDLE pipe1;
	HANDLE pipe2;
	struct _OVERLAPPED *pipe1_OVERLAPPED;
	struct _OVERLAPPED *pipe2_OVERLAPPED;
#else
	int pipe1;
	int pipe2;
#endif

	int connected_pipe1;
	int connected_pipe2;


	char* readBuffer;
	unsigned long readBufferOffset;
	unsigned long readBufferTotalRead;
	unsigned long readBufferSize;

	ILibQueue WriteBuffer;
	unsigned long WriteStatus;

	void* userObject;
	ILibNamedPipe_Manager_Object *manager;

	ILibNamedPipe_OnClientConnectionHandler userConnectionCallback;
	ILibNamedPipe_OnClientConnectionHandler userDisconnectionCallback;
	ILibNamedPipe_OnReadHandler readerCallback;
	ILibNamedPipe_OnSendOKHandler onSendOkCallback;
}ILibNamedPipe_Module_Object;

#ifdef WIN32
typedef void(*ILibNamedPipe_WaitHandle_Handler)(HANDLE event, int signaled, void* user);
typedef struct ILibNamedPipe_WaitHandle
{
	HANDLE event;
	void *user;
	ILibNamedPipe_WaitHandle_Handler callback;
}ILibNamedPipe_WaitHandle;
#endif

typedef struct ILibNamedPipe_WriteData
{
	char* data;
	int dataLen;
	ILibTransport_MemoryOwnership ownership;
}ILibNamedPipe_WriteData;

void ILibNamedPipe_Module_StartServer(ILibNamedPipe_Module_Server server);

#ifdef WIN32
int ILibNamedPipe_Manager_WindowsWaitHandles_Remove_Comparer(void *source, void *matchWith)
{
	return(((ILibNamedPipe_WaitHandle*)source)->event == matchWith ? 0 : 1);
}
void ILibNamedPipe_Manager_WindowsWaitHandlesLoop(void *arg)
{
	ILibNamedPipe_Manager_Object *manager = (ILibNamedPipe_Manager_Object*)arg;
	HANDLE* hList = (HANDLE*)malloc(FD_SETSIZE * sizeof(HANDLE) * 2);
	ILibLinkedList active = ILibLinkedList_Create();

	void* node;
	ILibNamedPipe_WaitHandle* data;

	int i,x;

	memset(hList, 0, FD_SETSIZE * sizeof(HANDLE) * 2);
	
	while(manager->abort == 0)
	{
		hList[0] = manager->updateEvent;
		i = 1;

		//Pending Remove
		ILibQueue_Lock(manager->WaitHandles_PendingDel);
		while(ILibQueue_IsEmpty(manager->WaitHandles_PendingDel)==0)
		{
			node = ILibQueue_DeQueue(manager->WaitHandles_PendingDel);
			node = ILibLinkedList_GetNode_Search(active, ILibNamedPipe_Manager_WindowsWaitHandles_Remove_Comparer, node);
			if(node != NULL) {free(ILibLinkedList_GetDataFromNode(node)); ILibLinkedList_Remove(node);}
		}
		ILibQueue_UnLock(manager->WaitHandles_PendingDel);

		//Pending Add
		ILibQueue_Lock(manager->WaitHandles_PendingAdd);
		while(ILibQueue_IsEmpty(manager->WaitHandles_PendingAdd)==0)
		{
			ILibLinkedList_AddTail(active, ILibQueue_DeQueue(manager->WaitHandles_PendingAdd));
		}
		ILibQueue_UnLock(manager->WaitHandles_PendingAdd);

		//Prepare the rest of the WaitHandle Array, for the WaitForMultipleObject call
		node = ILibLinkedList_GetNode_Head(active);
		while(node != NULL && (data = (ILibNamedPipe_WaitHandle*)ILibLinkedList_GetDataFromNode(node)) != NULL)
		{
			hList[i] = data->event;
			hList[i+FD_SETSIZE] = (HANDLE)data;
			++i;
			node = ILibLinkedList_GetNextNode(node);
		}


		while((x = WaitForMultipleObjects(i, hList, FALSE, INFINITE) - WAIT_OBJECT_0)!=0)
		{
			data = 	(ILibNamedPipe_WaitHandle*)hList[x+FD_SETSIZE];
			if(data->callback != NULL) { data->callback(data->event, 1, data->user); }
		}
		ResetEvent(manager->updateEvent);
	}

	for(x=1;x<(1+ILibLinkedList_GetCount(active));++x)
	{
		free(hList[x+FD_SETSIZE]);
	}
	ILibLinkedList_Destroy(active);
	free(hList);
}

void ILibNamedPipe_WaitHandle_Remove(ILibNamedPipe_Manager_Object *manager, HANDLE event)
{
	ILibQueue_Lock(manager->WaitHandles_PendingDel);
	ILibQueue_EnQueue(manager->WaitHandles_PendingDel, event);
	ILibQueue_UnLock(manager->WaitHandles_PendingDel);
	SetEvent(manager->updateEvent);
}
void ILibNamedPipe_WaitHandle_Add(ILibNamedPipe_Manager_Object *manager, HANDLE event, void *user, ILibNamedPipe_WaitHandle_Handler callback)
{
	ILibNamedPipe_WaitHandle *waitHandle;
	if((waitHandle = (ILibNamedPipe_WaitHandle*)malloc(sizeof(ILibNamedPipe_WaitHandle))) == NULL) {ILIBCRITICALEXIT(254);}
	memset(waitHandle, 0, sizeof(ILibNamedPipe_WaitHandle));

	waitHandle->event = event;
	waitHandle->user = user;
	waitHandle->callback = callback;

	ILibQueue_Lock(manager->WaitHandles_PendingAdd);
	ILibQueue_EnQueue(manager->WaitHandles_PendingAdd, waitHandle);
	ILibQueue_UnLock(manager->WaitHandles_PendingAdd);
	SetEvent(manager->updateEvent);
}
void ILibNamedPipe_Manager_Start(void* chain, void* user)
{
	ILibSpawnNormalThread((voidfp)&ILibNamedPipe_Manager_WindowsWaitHandlesLoop, user);
}
#endif

void ILibNamedPipe_Destroy(void* object)
{
	struct ILibNamedPipe_Module_struct* j = (struct ILibNamedPipe_Module_struct*)object;
	struct ILibNamedPipe_Manager_Struct* manager = (struct ILibNamedPipe_Manager_Struct*)j->manager;

#ifdef WIN32
	if(j->pipe1!=NULL)
	{
		CloseHandle(j->pipe1);
		j->pipe1 = NULL;
	}
	if(j->pipe2!=NULL)
	{
		CloseHandle(j->pipe2);
		j->pipe2 = NULL;
	}

	if(j->pipe1_OVERLAPPED!=NULL)
	{
		ILibNamedPipe_WaitHandle_Remove(j->manager, j->pipe1_OVERLAPPED->hEvent);
		free(j->pipe1_OVERLAPPED);
		j->pipe1_OVERLAPPED = NULL;
	}
	if(j->pipe2_OVERLAPPED!=NULL)
	{
		ILibNamedPipe_WaitHandle_Remove(j->manager, j->pipe2_OVERLAPPED->hEvent);
		free(j->pipe2_OVERLAPPED);
		j->pipe2_OVERLAPPED = NULL;
	}
#endif

	if(j->readBuffer!=NULL)
	{
		free(j->readBuffer);
		j->readBuffer = NULL;
	}

	if (j->server == NULL)
	{
		free(j->mPipeName1);
		free(j->mPipeName2);
	}
	free(j);
}

#ifdef WIN32
void ILibNamedPipe_IO_WriteHandler(HANDLE event, int signaled, void* user)
#else
void ILibNamedPipe_IO_WriteHandler(void* event, int signaled, void* user)
#endif
{
	ILibNamedPipe_Module_Object *j = (ILibNamedPipe_Module_Object*)user;
	unsigned long bytesWritten;
	void *node;
	ILibNamedPipe_WriteData *data;

#ifdef WIN32
	BOOL result = GetOverlappedResult(j->server != NULL ? j->pipe2 : j->pipe1, j->server != NULL ? j->pipe2_OVERLAPPED : j->pipe1_OVERLAPPED, &bytesWritten, FALSE);
#else
	int result = 0;
#endif

	if (result == FALSE)
	{
		//if (GetLastError() == ERROR_IO_INCOMPLETE)
		//{
		//	__asm int 3;
		//}
		//
		// Broken Pipe
		//
		ILibNamedPipe_Manager_Object *manager = (ILibNamedPipe_Manager_Object*)j->manager;
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[WriteHandler]: Broken Pipe on Pipe: %s", j->server != NULL ? j->mPipeName2 : j->mPipeName1);

		if (j->userDisconnectionCallback != NULL)
		{
			j->userDisconnectionCallback(j->manager, j, j->userObject);
		}

		if ((node = ILibLinkedList_GetNode_Search(j->manager->ActivePipes, NULL, j)) != NULL)
		{
			ILibLinkedList_Remove(node);
			ILibNamedPipe_Destroy(j);
		}

		return;
	}

	ILibQueue_Lock(j->WriteBuffer);

	if (ILibQueue_IsEmpty(j->WriteBuffer) == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[WriteHandler]: Drained %u bytes from WriteBuffer on Pipe: %s", bytesWritten, j->server != NULL ? j->mPipeName2 : j->mPipeName1);

		while ((data = (ILibNamedPipe_WriteData*)ILibQueue_DeQueue(j->WriteBuffer)) != NULL)
		{
			if (data->ownership == ILibTransport_MemoryOwnership_CHAIN) { free(data->data); }
			free(data);
			if (ILibQueue_IsEmpty(j->WriteBuffer) == 0)
			{
				data = (ILibNamedPipe_WriteData*)ILibQueue_PeekQueue(j->WriteBuffer);
#ifdef WIN32
				j->WriteStatus = WriteFile(j->server != NULL ? j->pipe2 : j->pipe1, data->data, data->dataLen, &bytesWritten, j->server != NULL ? j->pipe2_OVERLAPPED : j->pipe1_OVERLAPPED);
				if (j->WriteStatus == TRUE)
				{
					if (GetOverlappedResult(j->server != NULL ? j->pipe2 : j->pipe1, j->server != NULL ? j->pipe2_OVERLAPPED : j->pipe1_OVERLAPPED, &bytesWritten, FALSE) == TRUE)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[WriteHandler]: Drained %u bytes from WriteBuffer on Pipe: %s", bytesWritten, j->server != NULL ? j->mPipeName2 : j->mPipeName1);
					}
					else
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe[WriteHandler]: UNKNOWN ERROR on Pipe: %s", j->server != NULL ? j->mPipeName2 : j->mPipeName1);
					}
					continue;
				}
				else if (j->WriteStatus == FALSE && GetLastError() == ERROR_IO_PENDING)
				{
					ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[WriteHandler]: Trying to drain %u bytes from write buffer on Pipe: %s", data->dataLen, j->server != NULL ? j->mPipeName2 : j->mPipeName1);
					break;
				}
				else
				{
					// Some kind of error happened (BROKEN PIPE), with no way to recover
					ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe[WriteHandler]: I/O Error on pipe: %s", j->server != NULL ? j->mPipeName2 : j->mPipeName1);
				}
#endif
			}
			else
			{
				break;
			}
		}
		if (ILibQueue_IsEmpty(j->WriteBuffer) != 0)
		{
			// No Pending Data
#ifdef WIN32
			ILibNamedPipe_WaitHandle_Remove(j->manager, j->server != NULL ? j->pipe2_OVERLAPPED->hEvent : j->pipe1_OVERLAPPED->hEvent); // Remove the handle, becuase it won't signal, and we don't want to cause a race condition with the next send
#endif
			ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[WriteHandler]: Signaling OnSendOK on Pipe: %s", j->server != NULL ? j->mPipeName2 : j->mPipeName1);
			ILibQueue_UnLock(j->WriteBuffer);
			if (j->onSendOkCallback != NULL)
			{
				j->onSendOkCallback(j, j->userObject);
			}
			return;
		}
	}
	ILibQueue_UnLock(j->WriteBuffer);
}
#ifdef WIN32
void ILibNamedPipe_IO_ReadHandler(HANDLE event, int signaled, void* user)
#else
void ILibNamedPipe_IO_ReadHandler(void* event, int signaled, void* user)
#endif
{
	ILibNamedPipe_Module_Object *j = (ILibNamedPipe_Module_Object*)user;
	unsigned long bytesRead;
	int result;
	void *node;
	int consumed;
	int err;
	
#ifdef WIN32
	do
	{
		result = GetOverlappedResult(j->server != NULL ? j->pipe1 : j->pipe2, j->server != NULL ? j->pipe1_OVERLAPPED : j->pipe2_OVERLAPPED, &bytesRead, FALSE);
		if (result == FALSE) { break; }
		j->readBufferTotalRead += bytesRead;
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[ReadHandler]: %u bytes read from Pipe: %s", bytesRead, j->server != NULL ? j->mPipeName1 : j->mPipeName2);

		if (j->readerCallback == NULL)
		{
			//
			// Since the user doesn't care about the data, we'll just empty the buffer
			//
			j->readBufferOffset = 0;
			j->readBufferTotalRead = 0;
			continue;
		}

		while (1)
		{
			consumed = 0;
			j->readerCallback(j, j->readBuffer, j->readBufferOffset, j->readBufferTotalRead - j->readBufferOffset, &consumed, j->userObject);
			if (consumed == 0)
			{
				//
				// None of the buffer was consumed
				//
				ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[ReadHandler]: No bytes consumed on Pipe: %s", j->server != NULL ? j->mPipeName1 : j->mPipeName2);

				//
				// We need to move the memory to the start of the buffer, or else we risk running past the end, if we keep reading like this
				//
				memmove(j->readBuffer, j->readBuffer + j->readBufferOffset, j->readBufferTotalRead - j->readBufferOffset);
				j->readBufferTotalRead -= j->readBufferOffset;
				j->readBufferOffset = 0;

				break; // Break out of inner while loop
			}
			else if (consumed == (j->readBufferTotalRead - j->readBufferOffset))
			{
				//
				// Entire Buffer was consumed
				//
				j->readBufferOffset = 0;
				j->readBufferTotalRead = 0;

				ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[ReadHandler]: ReadBuffer drained on Pipe: %s", j->server != NULL ? j->mPipeName1 : j->mPipeName2);
				break; // Break out of inner while loop
			}
			else
			{
				//
				// Only part of the buffer was consumed
				//
				j->readBufferOffset += consumed;
			}
		}
	} while ((result = ReadFile(j->server != NULL ? j->pipe1 : j->pipe2, j->readBuffer, j->readBufferSize, NULL, j->server != NULL ? j->pipe1_OVERLAPPED : j->pipe2_OVERLAPPED)) == TRUE);

	if ((err = GetLastError()) != ERROR_IO_PENDING)
	{
		//
		// Broken Pipe
		//
		ILibNamedPipe_Manager_Object *manager = (ILibNamedPipe_Manager_Object*)j->manager;
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe[ReadHandler]: BrokenPipe(%d) on Pipe: %s", err, j->server != NULL ? j->mPipeName1 : j->mPipeName2);

		if(j->userDisconnectionCallback!=NULL)
		{
			j->userDisconnectionCallback(j->manager, j, j->userObject);
		}

		if ((node = ILibLinkedList_GetNode_Search(j->manager->ActivePipes, NULL, j)) != NULL)
		{
			ILibLinkedList_Remove(node);
			ILibNamedPipe_Destroy(j);
		}
		
		return;
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[ReadHandler]: Pipe: %s [EMPTY]", j->server != NULL ? j->mPipeName1 : j->mPipeName2);
	}
#endif
}
void ILibNamedPipe_Module_StartIO(ILibNamedPipe_Module_Client module, int bufferSize, ILibNamedPipe_OnReadHandler ReaderCallback, ILibNamedPipe_OnSendOKHandler onSendOK)
{
	ILibNamedPipe_Module_Object *j = (ILibNamedPipe_Module_Object*)module;
	int retVal;

	if ((j->readBuffer = (char*)malloc(bufferSize)) == NULL) { ILIBCRITICALEXIT(254); }
	j->readBufferSize = bufferSize;
	j->readerCallback = ReaderCallback;
	j->onSendOkCallback = onSendOK;

#ifdef WIN32
	ResetEvent(j->pipe1_OVERLAPPED->hEvent);
	ResetEvent(j->pipe2_OVERLAPPED->hEvent);

	retVal = ReadFile(j->server != NULL ? j->pipe1 : j->pipe2, j->readBuffer, bufferSize, NULL, j->server != NULL ? j->pipe1_OVERLAPPED : j->pipe2_OVERLAPPED);
	ILibNamedPipe_WaitHandle_Add(j->manager, j->server != NULL ? j->pipe1_OVERLAPPED->hEvent : j->pipe2_OVERLAPPED->hEvent, j, &ILibNamedPipe_IO_ReadHandler);
#endif
}

#ifdef WIN32
void ILibNamedPipe_ConnectCallback(HANDLE event, int signaled, void *user)
{
	ILibNamedPipe_Module_Object* module = (ILibNamedPipe_Module_Object*)user;
	if(module->server != NULL)
	{
		if(module->pipe1_OVERLAPPED->hEvent == event && signaled != 0)
		{
			module->connected_pipe1 = 1;	
			ILibRemoteLogging_printf(ILibChainGetLogger(module->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "NamedPipe[ConnectCallback] Client Connection Established on pipe: %s", module->mPipeName1);
		}
		if(module->pipe2_OVERLAPPED->hEvent == event && signaled != 0)
		{
			module->connected_pipe2 = 1;
			ILibRemoteLogging_printf(ILibChainGetLogger(module->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "NamedPipe[ConnectCallback] Client Connection Established on pipe: %s", module->mPipeName2);
		}
		ILibNamedPipe_WaitHandle_Remove(module->manager, event);

		if(module->connected_pipe1 == module->connected_pipe2 == 1)
		{
			// Input/Output Pipes are connected
			if(module->userConnectionCallback != NULL)
			{
				module->userConnectionCallback(module->manager, module, module->userObject);
			}
		}
	}
}
#endif

void ILibNamedPipe_Module_Server_ClientDisconnected(ILibNamedPipe_Manager sender, ILibNamedPipe_Module_Client clientPipeModule, void *user)
{
	ILibNamedPipe_Module_Object* j = (ILibNamedPipe_Module_Object*)clientPipeModule;
	if (j->server != NULL) 
	{ 
		if (j->server->userDisconnectionCallback != NULL) { j->server->userDisconnectionCallback(j->manager, j, j->userObject); }
		ILibNamedPipe_Module_StartServer(j->server); 
	}
}

#ifndef WIN32
void ILibNamedPipe_Module_StartServerSink(void *object)
{
	ILibNamedPipe_Module_Object* obj = (ILibNamedPipe_Module_Object*)object;
	ILibLinkedList_AddTail(obj->manager->ActivePipes, obj);

	if (obj->server == NULL)
	{
		// Client: Check if we need to attach writer pipe
		if (obj->pipe1 == 0)
		{
			if ((obj->pipe1 = open(obj->mPipeName1, O_WRONLY | O_NONBLOCK)) < 0)
			{
				// Failed... Try again in one second
				ILibLifeTime_Add(ILibGetBaseTimer(obj->Chain), obj, 1, &ILibNamedPipe_Module_StartServerSink, NULL);
			}
		}
	}
}
#endif

void ILibNamedPipe_Module_StartServer(ILibNamedPipe_Module_Server server)
{
	ILibNamedPipe_Module_Server_object* smodule = (ILibNamedPipe_Module_Server_object*)server;
	struct ILibNamedPipe_Module_struct* retVal;

	if ((retVal = (struct ILibNamedPipe_Module_struct*)malloc(sizeof(struct ILibNamedPipe_Module_struct))) == NULL) { ILIBCRITICALEXIT(254); }
	memset(retVal, 0, sizeof(struct ILibNamedPipe_Module_struct));

#ifdef WIN32
	if ((retVal->pipe1_OVERLAPPED = (struct _OVERLAPPED*)malloc(sizeof(struct _OVERLAPPED))) == NULL) { ILIBCRITICALEXIT(254); }
	if ((retVal->pipe2_OVERLAPPED = (struct _OVERLAPPED*)malloc(sizeof(struct _OVERLAPPED))) == NULL) { ILIBCRITICALEXIT(254); }

	memset(retVal->pipe1_OVERLAPPED, 0, sizeof(struct _OVERLAPPED));
	memset(retVal->pipe2_OVERLAPPED, 0, sizeof(struct _OVERLAPPED));
	retVal->pipe1_OVERLAPPED->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	retVal->pipe2_OVERLAPPED->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
#endif

	retVal->Chain = smodule->man->chain;
	retVal->mPipeName1 = smodule->mPipeName1;
	retVal->mPipeName2 = smodule->mPipeName2;
	retVal->WriteBuffer = ILibQueue_Create();
	retVal->userObject = smodule->userObject;
	retVal->userConnectionCallback = smodule->userConnectionCallback;
	retVal->userDisconnectionCallback = &ILibNamedPipe_Module_Server_ClientDisconnected;
	retVal->server = smodule;

#ifdef WIN32
	retVal->pipe1 = CreateNamedPipeA(retVal->mPipeName1, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);
	retVal->pipe2 = CreateNamedPipeA(retVal->mPipeName2, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);
	if (retVal->pipe1 == INVALID_HANDLE_VALUE || retVal->pipe2 == INVALID_HANDLE_VALUE)
	{
		//
		// Error creating pipe
		//
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Error Creating ServerPipe[%s]", retVal->mPipeName1);
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Error Creating ServerPipe[%s]", retVal->mPipeName2);

		ILibNamedPipe_Destroy(retVal);
		retVal = NULL;
	}
#else
	if((retVal->pipe1 = open(retVal->mPipeName1, O_RDONLY | O_NONBLOCK)) > 0)
	{
		ILibLifeTime_AddEx(ILibGetBaseTimer(smodule->man->chain), retVal, 1, &ILibNamedPipe_Module_StartServerSink, NULL); // Context switch to Microstack Thread, to add ourselves to the Select
	}
	else
	{
		//
		// Error creating pipe
		//
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: open() error (%u) on ServerPipe[%s]", errno, retVal->mPipeName1);
		ILibNamedPipe_Destroy(retVal);
		retVal = NULL;
	}
#endif

	if (retVal != NULL)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Created ServerPipe[%s]", retVal->mPipeName1);
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Created ServerPipe[%s]", retVal->mPipeName2);

		retVal->manager = smodule->man;
#ifdef WIN32
		ILibLinkedList_Lock(smodule->man->ActivePipes);
		{
			ILibLinkedList_AddTail(smodule->man->ActivePipes, retVal);
		}
		ILibLinkedList_UnLock(smodule->man->ActivePipes);
		ILibNamedPipe_WaitHandle_Add(smodule->man, retVal->pipe1_OVERLAPPED->hEvent, retVal, &ILibNamedPipe_ConnectCallback);
		ILibNamedPipe_WaitHandle_Add(smodule->man, retVal->pipe2_OVERLAPPED->hEvent, retVal, &ILibNamedPipe_ConnectCallback);

		ConnectNamedPipe(retVal->pipe1, retVal->pipe1_OVERLAPPED);
		ConnectNamedPipe(retVal->pipe2, retVal->pipe2_OVERLAPPED);
#endif
	}
}
ILibTransport_DoneState ILibNamedPipe_Write(ILibNamedPipe_Module_Client module, char* buffer, int bufferLen, ILibTransport_MemoryOwnership ownership)
{
	ILibNamedPipe_Module_Object *j = (ILibNamedPipe_Module_Object*)module;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;
	ILibNamedPipe_WriteData *data;

	// Need to remove WaitHandle first, because otherwise there will be a race condition with MainLoop.

	ILibQueue_Lock(j->WriteBuffer);
#ifdef WIN32
	if (j->pipe1 == NULL || j->pipe2 == NULL)
#else
	if (j->pipe1 == 0 || j->pipe2 == 0)
#endif
	{
		ILibQueue_UnLock(j->WriteBuffer);
		return(ILibTransport_DoneState_ERROR);
	}

	if (ILibQueue_IsEmpty(j->WriteBuffer) == 0)
	{		
		ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe: %u bytes queued on Pipe: %s", bufferLen, j->server != NULL ? j->mPipeName2 : j->mPipeName1);

		data = (ILibNamedPipe_WriteData*)malloc(sizeof(ILibNamedPipe_WriteData));
		data->data = buffer;
		data->dataLen = bufferLen;
		data->ownership = ownership;
		ILibQueue_EnQueue(j->WriteBuffer, data);
		retVal = ILibTransport_DoneState_INCOMPLETE;
	}
	else
	{
#ifdef WIN32
		j->WriteStatus = WriteFile(j->server != NULL ? j->pipe2 : j->pipe1, buffer, bufferLen, NULL, j->server != NULL ? j->pipe2_OVERLAPPED : j->pipe1_OVERLAPPED);
		if (j->WriteStatus == TRUE)		
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[Write]: %u bytes written to Pipe: %s", bufferLen, j->server != NULL ? j->mPipeName2 : j->mPipeName1);
			ResetEvent((j->server != NULL ? j->pipe2_OVERLAPPED : j->pipe1_OVERLAPPED)->hEvent); // Need to reset event, becuase otherwise we'll unneccesarily unblock the WaitForMultipleObject
			if (ownership == ILibTransport_MemoryOwnership_CHAIN) { free(buffer); }
			retVal = ILibTransport_DoneState_COMPLETE;
		}
		else if (j->WriteStatus == FALSE && GetLastError() == ERROR_IO_PENDING)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibNamedPipe[Write]: %u bytes pending to be written on Pipe: %s", bufferLen, j->server != NULL ? j->mPipeName2 : j->mPipeName1);

			data = (ILibNamedPipe_WriteData*)malloc(sizeof(ILibNamedPipe_WriteData));
			data->data = buffer;
			data->dataLen = bufferLen;
			data->ownership = ownership;
			ILibQueue_EnQueue(j->WriteBuffer, data);
			retVal = ILibTransport_DoneState_INCOMPLETE;
			ILibNamedPipe_WaitHandle_Add(j->manager, j->server != NULL ? j->pipe2_OVERLAPPED->hEvent : j->pipe1_OVERLAPPED->hEvent, j, &ILibNamedPipe_IO_WriteHandler);
		}
#endif 
	}
	ILibQueue_UnLock(j->WriteBuffer);
	return(retVal);
}

int ILibNamedPipe_Write_BLOCKING(ILibNamedPipe_Module_Client module, char* buffer, int bufferSize)
{
	struct ILibNamedPipe_Module_struct* j = (struct ILibNamedPipe_Module_struct*)module;
	unsigned long bytesWritten = 0;

#ifdef WIN32
	if (j->server != NULL == 0)
	{
		//
		// Server Pipe... Write to Pipe #2
		//
		WriteFile(j->pipe2, buffer, bufferSize, &bytesWritten,NULL);
	}
	else
	{
		//
		// Client Pipe... Write to Pipe #1
		//
		WriteFile(j->pipe1, buffer, bufferSize, &bytesWritten,NULL);
	}
#endif
	return(bytesWritten);
}

void ILibNamedPipe_Manager_Destroy(void* obj)
{
}

#ifndef WIN32
void ILibNamedPipe_Manager_OnPreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	ILibNamedPipe_Manager_Object *man = (ILibNamedPipe_Manager_Object*)object;
	void *node;
	ILibNamedPipe_Module_Object *j;

	node = ILibLinkedList_GetNode_Head(man->ActivePipes);

	while (node != NULL && (j = ILibLinkedList_GetDataFromNode(node)) != NULL)
	{
		if (j->server != NULL)
		{
			FD_SET(j->pipe1, readset); FD_SET(j->pipe1, errorset);
			if (j->pipe2 != 0) { FD_SET(j->pipe2, writeset); FD_SET(j->pipe2, errorset); }
			else
			{
				FD_SET(j->pipe1, writeset); 
			}
		}
		else
		{
			FD_SET(j->pipe2, readset); FD_SET(j->pipe2, errorset);
			if (j->pipe1 != 0) { FD_SET(j->pipe1, writeset); FD_SET(j->pipe1, errorset); printf("FD_SET: %s\r\n", j->mPipeName1); }
		}
		node = ILibLinkedList_GetNextNode(node);
	}
}

void ILibNamedPipe_Manager_OnPostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	ILibNamedPipe_Manager_Object *man = (ILibNamedPipe_Manager_Object*)object;
	void *node;
	ILibNamedPipe_Module_Object *j;

	node = ILibLinkedList_GetNode_Head(man->ActivePipes);
	while (node != NULL && (j = ILibLinkedList_GetDataFromNode(node)) != NULL)
	{
		if (j->server != NULL)
		{
			// Server Pipe
			if (FD_ISSET(j->pipe1, writeset) != 0)
			{
				printf("WRITESET!\r\n");
			}
			else if (FD_ISSET(j->pipe1, readset) != 0)
			{
				printf("SET!\r\n");
				if (j->pipe2 == 0)
				{
					j->connected_pipe1 = 1;
					ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "NamedPipe[PostSelect]: ConnectedPipe: %s", j->mPipeName1);
					if ((j->pipe2 = open(j->mPipeName2, O_WRONLY | O_NONBLOCK)) != 0)
					{
						// Failed to Connect Pipe2, try again later
						j->pipe2 = 0;
						ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "NamedPipe[PostSelect]: Failed to Connect Pipe: %s", j->mPipeName2);
					}
					else
					{
						// We established connection on the other pipe, so now we can propagate a connection event up
						j->connected_pipe2 = 1;					
						ILibRemoteLogging_printf(ILibChainGetLogger(j->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "NamedPipe[PostSelect]: ConnectedPipe: %s", j->mPipeName2);
						if (j->userConnectionCallback != NULL) { j->userConnectionCallback(j->manager, j, j->userObject); }
					}
				}
				else
				{
					// Both Pipes are Connected, so this means there is data available to read
					ILibNamedPipe_IO_ReadHandler(NULL, 1, j);
				}
			}
			if (j->pipe2 != 0 && FD_ISSET(j->pipe2, writeset) != 0)
			{
				ILibNamedPipe_IO_WriteHandler(NULL, 1, j);
			}
		}
		else
		{
			// Client Pipe
			if (FD_ISSET(j->pipe2, readset) != 0)
			{
				if (j->pipe1 == 0)
				{
					// Write Pipe Isn't Connected yet, so try to connect it
					j->connected_pipe2 = 1;
					if ((j->pipe1 = open(j->mPipeName1, O_WRONLY | O_NONBLOCK)) != 0)
					{
						j->pipe1 = 0; // Failed to connect Write Pipe, try again later
					}
					else
					{
						j->connected_pipe1 = 1;
						if (j->userConnectionCallback != NULL) { j->userConnectionCallback(j->manager, j, j->userObject); }
					}
				}
				else
				{
					// Write Pipe Already Connected, so this just means data is available to read
					ILibNamedPipe_IO_ReadHandler(NULL, 1, j);
				}
			}
			else if (FD_ISSET(j->pipe2, errorset) != 0)
			{

			}
			if (j->pipe1 != 0 && FD_ISSET(j->pipe1, writeset) != 0)
			{
				ILibNamedPipe_IO_WriteHandler(NULL, 1, j);
			}
		}
		node = ILibLinkedList_GetNextNode(node);
	}
}
#endif

ILibNamedPipe_Manager ILibNamedPipe_CreateManager(void *chain)
{
	struct ILibNamedPipe_Manager_Struct* retVal = (struct ILibNamedPipe_Manager_Struct*)malloc(sizeof(struct ILibNamedPipe_Manager_Struct));
	memset(retVal,0,sizeof(struct ILibNamedPipe_Manager_Struct));

	retVal->Destroy = &ILibNamedPipe_Manager_Destroy;
	retVal->ActivePipes = ILibLinkedList_Create();
	retVal->WaitHandles_PendingAdd = ILibQueue_Create();
	retVal->WaitHandles_PendingDel = ILibQueue_Create();
	retVal->chain = chain;

#ifdef WIN32
	retVal->updateEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	ILibChain_OnStartEvent_AddHandler(chain, (ILibChain_StartEvent)&ILibNamedPipe_Manager_Start, retVal);
#else
	retVal->Pre = &ILibNamedPipe_Manager_OnPreSelect;
	retVal->Post = &ILibNamedPipe_Manager_OnPostSelect;
#endif

	ILibAddToChain(chain,retVal);
	return(retVal);
}

ILibNamedPipe_Module_Server ILibNamedPipe_Manager_CreateServerPipe(ILibNamedPipe_Manager manager, char* pipeName, int pipeNameLength, void *user, ILibNamedPipe_OnClientConnectionHandler onConnect, ILibNamedPipe_OnClientConnectionHandler onDisconnect)
{
	ILibNamedPipe_Manager_Object* man = (ILibNamedPipe_Manager_Object*)manager;
	ILibNamedPipe_Module_Server_object* smodule;
	
	if ((smodule = (ILibNamedPipe_Module_Server_object*)malloc(sizeof(ILibNamedPipe_Module_Server_object))) == NULL) { ILIBCRITICALEXIT(254); }

	memset(smodule, 0, sizeof(ILibNamedPipe_Module_Server_object));
	smodule->userObject = user;
	smodule->userConnectionCallback = onConnect;
	smodule->userDisconnectionCallback = onDisconnect;
	smodule->man = man;

#ifdef WIN32
	if ((smodule->mPipeName1 = (char*)malloc(pipeNameLength + 11)) == NULL) { ILIBCRITICALEXIT(254); }
	if ((smodule->mPipeName2 = (char*)malloc(pipeNameLength + 11)) == NULL) { ILIBCRITICALEXIT(254); }
	memcpy(smodule->mPipeName1, "\\\\.\\pipe\\", 9);
	memcpy(smodule->mPipeName2, "\\\\.\\pipe\\", 9);
	memcpy(smodule->mPipeName1 + 9, pipeName, pipeNameLength);
	memcpy(smodule->mPipeName2 + 9, pipeName, pipeNameLength);
	(smodule->mPipeName1)[9 + pipeNameLength] = '1';
	(smodule->mPipeName2)[9 + pipeNameLength] = '2';
	(smodule->mPipeName1)[10 + pipeNameLength] = 0;
	(smodule->mPipeName2)[10 + pipeNameLength] = 0;
	ILibNamedPipe_Module_StartServer(smodule);
#else
	if ((smodule->mPipeName1 = (char*)malloc(pipeNameLength + 12)) == NULL) { ILIBCRITICALEXIT(254); }
	if ((smodule->mPipeName2 = (char*)malloc(pipeNameLength + 12)) == NULL) { ILIBCRITICALEXIT(254); }
	memcpy(smodule->mPipeName1, "/tmp/pipe/", 10);
	memcpy(smodule->mPipeName2, "/tmp/pipe/", 10);
	memcpy(smodule->mPipeName1 + 10, pipeName, pipeNameLength);
	memcpy(smodule->mPipeName2 + 10, pipeName, pipeNameLength);
	(smodule->mPipeName1)[10 + pipeNameLength] = '1';
	(smodule->mPipeName2)[10 + pipeNameLength] = '2';
	(smodule->mPipeName1)[11 + pipeNameLength] = 0;
	(smodule->mPipeName2)[11 + pipeNameLength] = 0;
	
	if (mkfifo(smodule->mPipeName1, 0660) != 0 || mkfifo(smodule->mPipeName2, 0660) != 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(smodule->man->chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: mkfifo error(%u) Creating ServerPipe[%s]", errno, smodule->mPipeName1);
		ILibRemoteLogging_printf(ILibChainGetLogger(smodule->man->chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: mkfifo error Creating ServerPipe[%s]", smodule->mPipeName2);
		unlink(smodule->mPipeName1);
		unlink(smodule->mPipeName2);
	}
	else
	{
		ILibNamedPipe_Module_StartServer(smodule);
	}
#endif

	
	return(smodule);
}

ILibNamedPipe_Module_Client ILibNamedPipe_Manager_CreateClientPipe(ILibNamedPipe_Manager manager, char* pipeName, int pipeNameLength, void *user, int readBufferSize, ILibNamedPipe_OnClientConnectionHandler onDisconnectCallback)
{
	struct ILibNamedPipe_Manager_Struct* man = (struct ILibNamedPipe_Manager_Struct*)manager;
	struct ILibNamedPipe_Module_struct* retVal = (struct ILibNamedPipe_Module_struct*)malloc(sizeof(struct ILibNamedPipe_Module_struct));

	memset(retVal, 0, sizeof(struct ILibNamedPipe_Module_struct));

#ifdef WIN32
	retVal->pipe1_OVERLAPPED = (struct _OVERLAPPED*)malloc(sizeof(struct _OVERLAPPED));
	retVal->pipe2_OVERLAPPED = (struct _OVERLAPPED*)malloc(sizeof(struct _OVERLAPPED));

	memset(retVal->pipe1_OVERLAPPED, 0, sizeof(struct _OVERLAPPED));
	memset(retVal->pipe2_OVERLAPPED, 0, sizeof(struct _OVERLAPPED));
	retVal->pipe1_OVERLAPPED->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	retVal->pipe2_OVERLAPPED->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
#endif

	retVal->userDisconnectionCallback = onDisconnectCallback;
	retVal->Chain = man->chain;

#ifdef WIN32
	retVal->mPipeName1 = (char*)malloc(pipeNameLength+11);
	retVal->mPipeName2 = (char*)malloc(pipeNameLength+11);
	memcpy(retVal->mPipeName1, "\\\\.\\pipe\\", 9);
	memcpy(retVal->mPipeName2, "\\\\.\\pipe\\", 9);
	memcpy(retVal->mPipeName1+9, pipeName,pipeNameLength);
	memcpy(retVal->mPipeName2+9, pipeName,pipeNameLength);
	(retVal->mPipeName1)[9+pipeNameLength] = '1';
	(retVal->mPipeName2)[9+pipeNameLength] = '2';
	(retVal->mPipeName1)[10+pipeNameLength] = 0;
	(retVal->mPipeName2)[10+pipeNameLength] = 0;
#else
	if ((retVal->mPipeName1 = (char*)malloc(pipeNameLength + 12)) == NULL) { ILIBCRITICALEXIT(254); }
	if ((retVal->mPipeName2 = (char*)malloc(pipeNameLength + 12)) == NULL) { ILIBCRITICALEXIT(254); }
	memcpy(retVal->mPipeName1, "/tmp/pipe/", 10);
	memcpy(retVal->mPipeName2, "/tmp/pipe/", 10);
	memcpy(retVal->mPipeName1 + 10, pipeName, pipeNameLength);
	memcpy(retVal->mPipeName2 + 10, pipeName, pipeNameLength);
	(retVal->mPipeName1)[10 + pipeNameLength] = '1';
	(retVal->mPipeName2)[10 + pipeNameLength] = '2';
	(retVal->mPipeName1)[11 + pipeNameLength] = 0;
	(retVal->mPipeName2)[11 + pipeNameLength] = 0;
#endif

	retVal->manager = man;
	retVal->WriteBuffer = ILibQueue_Create();

#ifdef WIN32
	retVal->pipe1 = CreateFileA(retVal->mPipeName1, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	retVal->pipe2 = CreateFileA(retVal->mPipeName2, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

	if(retVal->pipe1 == INVALID_HANDLE_VALUE || retVal->pipe2 == INVALID_HANDLE_VALUE)
	{
		//
		// Error creating pipe
		//
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Error Creating ClientPipe[%s]", retVal->mPipeName1);
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Error Creating ClientPipe[%s]", retVal->mPipeName2);

		ILibNamedPipe_Destroy(retVal);
		retVal = NULL;
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Created ClientPipe[%s]", retVal->mPipeName1);
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: Created ClientPipe[%s]", retVal->mPipeName2);

		ILibLinkedList_Lock(man->ActivePipes);
		{
			ILibLinkedList_AddTail(man->ActivePipes, retVal);
		}
		ILibLinkedList_UnLock(man->ActivePipes);
	}
#else
	if ((retVal->pipe2 = open(retVal->mPipeName2, O_RDONLY | O_NONBLOCK)) > 0)
	{
		ILibLifeTime_Add(ILibGetBaseTimer(retVal->Chain), retVal, 0, &ILibNamedPipe_Module_StartServerSink, NULL); // Context switch to Microstack Thread, to add ourselves to the Select
	}
	else
	{
		//
		// Error creating pipe
		//
		ILibRemoteLogging_printf(ILibChainGetLogger(retVal->Chain), ILibRemoteLogging_Modules_Microstack_NamedPipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibNamedPipe: open() error (%u) on ServerPipe[%s]", errno, retVal->mPipeName2);
		ILibNamedPipe_Destroy(retVal);
		retVal = NULL;
	}
#endif

	return(retVal);
}
