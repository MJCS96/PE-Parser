#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

#define ABORT(s) {\
		if(fileHandle) \
			CloseHandle(fileHandle);\
		if(hMapping)\
			CloseHandle(hMapping);\
		if(inceputFisier)\
			UnmapViewOfFile(inceputFisier);\
		printf("%s\n",s);\
		return 1;\
	}
DWORD virtualToReal(PIMAGE_SECTION_HEADER sections, WORD nr_sec, DWORD virtual_addr) {
	PIMAGE_SECTION_HEADER section;
	DWORD offset;
	DWORD result = 0xFFFFFFFF;

	for (WORD i = 0; i < nr_sec; i++) {
		section = &sections[i];

		if (section->VirtualAddress <= virtual_addr &&
			virtual_addr <= section->VirtualAddress + section->Misc.VirtualSize) {
			offset = virtual_addr - section->VirtualAddress;
			result = section->PointerToRawData + offset;
			break;
		}
	}

	return result;
}
int main() {
	const char fileName[] = "kernel32.dll";
	HANDLE fileHandle = NULL, hMapping = NULL;
	BYTE * inceputFisier = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	fileHandle = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE == fileHandle) {
		ABORT("Fisier inexistent.");
	}
	hMapping = CreateFileMappingA(fileHandle, 0, PAGE_READONLY, 0, 0, 0);
	if (NULL == hMapping) {
		ABORT("Mapping error");
	}
	inceputFisier = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (0 == inceputFisier)
	{
		ABORT("View error");
	}

	pDosHeader = (PIMAGE_DOS_HEADER)inceputFisier;
	printf("%x\n", pDosHeader->e_magic);

	pNtHeaders = (PIMAGE_NT_HEADERS)(inceputFisier + pDosHeader->e_lfanew);
	if (0x4550 != pNtHeaders->Signature)
	{
		ABORT("Missing PE!");
	}

	// pNtHeaders->FileHeader.NumberOfSections

	if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) 
	{
		printf("E DLL \n");
	}
	else
	{
		printf("NU E DLL\n");
	}

	printf("DataDirectory size: %x\n", pNtHeaders->OptionalHeader.DataDirectory[12].Size);

	char nume[9] = "0";

	pSection = (PIMAGE_SECTION_HEADER)((PBYTE)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int j = 0; j < pNtHeaders->FileHeader.NumberOfSections; j++) {
		for (int i = 0; i < 8; i++) {
			nume[i] = pSection[j].Name[i];
		}
	printf("Name of section headers: %s\n", nume);
	}
	DWORD exp = virtualToReal(pSection,
		pNtHeaders->FileHeader.NumberOfSections,
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)inceputFisier + exp);

	printf("The number of func: %x\n", pExportDirectory->NumberOfFunctions);
	ABORT("All ok.");
	return 0;
}