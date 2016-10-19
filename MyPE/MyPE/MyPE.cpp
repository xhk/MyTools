// MyPE.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "MyPE.h"
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 唯一的应用程序对象

CWinApp theApp;

using namespace std;

int my_main(int argc, TCHAR *argv[]);
bool parse_file(BYTE * file, TCHAR *err);

void * pe_file_buf = NULL;

int main(int argc, TCHAR *argv[])
{
    int nRetCode = 0;

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // 初始化 MFC 并在失败时显示错误
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            // TODO: 更改错误代码以符合您的需要
            wprintf(L"错误: MFC 初始化失败\n");
            nRetCode = 1;
        }
        else
        {
            // TODO: 在此处为应用程序的行为编写代码。
			nRetCode = my_main(argc, argv);
			getchar();
        }
    }
    else
    {
        // TODO: 更改错误代码以符合您的需要
        wprintf(L"错误: GetModuleHandle 失败\n");
        nRetCode = 1;
    }

    return nRetCode;
}

struct ExPortFunction {
	WORD Ordinal;
	TCHAR Fuction[256];
};

struct PE {
	IMAGE_DOS_HEADER        *idh;
	IMAGE_NT_HEADERS        *inh;
	IMAGE_SECTION_HEADER    *ish_list;
	IMAGE_EXPORT_DIRECTORY  *ied;
	IMAGE_IMPORT_DESCRIPTOR *iid;
};

PE g_pe = { 0 };

TCHAR * usage = _T("mype file");

TCHAR *machine_str(int machine)
{
	switch (machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		return _T("x86");
	case IMAGE_FILE_MACHINE_IA64:
		return _T("IA64(Intel Itanium)");
	case IMAGE_FILE_MACHINE_AMD64:
		return _T("x64");
	default:
		return _T("unknown");
		break;
	}

	return _T("unknown");
}

int my_main(int argc, TCHAR *argv[])
{
	//_tprintf(_T("start\n"));
	TCHAR *file = argv[1];
	TCHAR err[1024] = { 0 };

	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

	HANDLE hfile = CreateFile(file,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		_tcscpy_s(err, 128, _T("open file failed"));
		return false;
	}

	HANDLE hFileMapping = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL || hFileMapping == INVALID_HANDLE_VALUE)
	{
		printf("Could not create file mapping object (%d).\n", GetLastError());
		CloseHandle(hfile);
		return false;
	}

	LPBYTE lpBaseAddress = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpBaseAddress == NULL)
	{
		printf("Could not map view of file (%d).\n", GetLastError());
		CloseHandle(hfile);

		return false;
	}


	if (!parse_file(lpBaseAddress, err)) {
		_tprintf(_T("%s\n"), err);
		return -1;
	}

	if (g_pe.inh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		_tprintf(_T("problem\n"));
		return -1;
	}

	_tprintf(_T("sections num:%d CPU:%s RVA:0x%X  \n")
		_T("    导出表rva:%8X 大小:%8X \n")
		_T("    导入表rva:%8X 大小:%8X \n")
		_T("    资源表rva:%8X 大小:%8X \n")
		_T("    异常表rva:%8X 大小:%8X \n")
		_T("基础定位表rva:%8X 大小:%8X \n")
		,
		g_pe.inh->FileHeader.NumberOfSections,
		machine_str(g_pe.inh->FileHeader.Machine), g_pe.inh->OptionalHeader.AddressOfEntryPoint, 
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
		g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
	);

	SetConsoleTextAttribute(hOut, FOREGROUND_RED);
	_tprintf(_T("%-8s|%8s|%8s|%8s|%8s|%8s|%8s|%8s|%8s|%8s\n"),
		_T("Name"),
		_T("VSize"),
		_T("VAddr"),
		_T("SORData"),
		_T("PToRData"),
		_T("PTReloc"),
		_T("PTLine"),
		_T("NOfReloc"),
		_T("NOfLine"),
		_T("属性")
	);
	SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	for (int i = 0; i < g_pe.inh->FileHeader.NumberOfSections; ++i) {
		_tprintf(_T("%-8s|%8X|%8X|%8X|%8X|%8X|%8X|%8X|%8X|%8X\n"),
			g_pe.ish_list[i].Name, 
			g_pe.ish_list[i].Misc.VirtualSize,
			g_pe.ish_list[i].VirtualAddress,
			g_pe.ish_list[i].SizeOfRawData,
			g_pe.ish_list[i].PointerToRawData,
			g_pe.ish_list[i].PointerToRelocations,
			g_pe.ish_list[i].PointerToLinenumbers,
			g_pe.ish_list[i].NumberOfRelocations,
			g_pe.ish_list[i].NumberOfLinenumbers,
			g_pe.ish_list[i].Characteristics
			);
	}

	// export table
	_tprintf(_T("\nexport talbe information:\n"));
	_tprintf(_T("%16s|%8s|%8s|%8s|\n"),
		_T("Name"),
		_T("Base"),
		_T("NoOfFunc"),
		_T("NoOfName")
		);
	_tprintf(_T("%16s|%8X|%8X|%8X|\n"),
		(TCHAR *)(lpBaseAddress + g_pe.ied->Name),
		g_pe.ied->Base,
		g_pe.ied->NumberOfFunctions,
		g_pe.ied->NumberOfNames
		);
	SetConsoleTextAttribute(hOut, BACKGROUND_RED);

	_tprintf(_T("%16s|%32s|%16s\n"),
		_T("Ordinal"),
		_T("Function"),
		_T("Entry Point")
	);

	for (int i = 0; i < g_pe.ied->NumberOfFunctions; ++i) {
		_tprintf(_T("%16X|%32s|%16X\n"),
			*(WORD *)(lpBaseAddress + g_pe.ied->AddressOfNameOrdinals + i * sizeof(WORD)),
			(TCHAR*)(lpBaseAddress + *(DWORD*)(lpBaseAddress + g_pe.ied->AddressOfNames + i*sizeof(DWORD))),
			*(DWORD *)(lpBaseAddress + g_pe.ied->AddressOfFunctions + i * sizeof(DWORD))
			);
	}
	SetConsoleTextAttribute(hOut, BACKGROUND_RED| BACKGROUND_BLUE);

	int nCount = 0;
	while (g_pe.iid[nCount].Characteristics) {
		_tprintf(_T("Name:%s\n"),
			(TCHAR *)(lpBaseAddress + g_pe.iid[nCount].Name)
			);

		int nFuncCount = 0;
		IMAGE_THUNK_DATA *ot = (IMAGE_THUNK_DATA*)(lpBaseAddress+ g_pe.iid[nCount].OriginalFirstThunk);
		IMAGE_THUNK_DATA *ft = (IMAGE_THUNK_DATA*)(lpBaseAddress + g_pe.iid[nCount].FirstThunk);
		while (ot[nFuncCount].u1.Ordinal) {
			//这里通过RVA的最高位判断函数的导入方式，
			//如果最高位为1，按序号导入，否则按名称导入
			if (ot[nFuncCount].u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
				_tprintf(_T("\t %d \n"), ot[nFuncCount].u1.Ordinal& 0xffff);
			}
			else {
				// 按名称导入，我们再次定向到函数序号和名称
				//注意其地址不能直接用，因为仍然是RVA！
				PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)(lpBaseAddress + ot[nFuncCount].u1.Ordinal);
				_tprintf(_T("\t \t %ld \t %s\n"), pFuncName->Hint, pFuncName->Name);
			}

			

			nFuncCount++;
		}
		
		//_tprintf(_T("%s\n"), );

		nCount++;
	}


	UnmapViewOfFile(lpBaseAddress);
	CloseHandle(hFileMapping);
	CloseHandle(hfile);
	return 0;
}

bool parse_file(BYTE *lpBaseAddress, TCHAR *err)
{
	
	g_pe.idh = (IMAGE_DOS_HEADER *)lpBaseAddress;
	if (g_pe.idh->e_magic != IMAGE_DOS_SIGNATURE) {
		_tcscpy_s(err, 128, _T("MZ不正确"));
		return false;
	}

	g_pe.inh =(IMAGE_NT_HEADERS*)( lpBaseAddress + g_pe.idh->e_lfanew);
	if (g_pe.inh->Signature != IMAGE_NT_SIGNATURE) {
		_tcscpy_s(err, 128, _T("不是有效的PE文件"));
		return false;
	}

	g_pe.ish_list = (IMAGE_SECTION_HEADER *)(lpBaseAddress + g_pe.idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	g_pe.ied = (IMAGE_EXPORT_DIRECTORY *)(lpBaseAddress + g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	g_pe.iid = (IMAGE_IMPORT_DESCRIPTOR*)(lpBaseAddress + g_pe.inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	return true;
}