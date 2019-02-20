#include <iostream>
#include "windows.h"
#include "lm.h"
using namespace std;

typedef NET_API_STATUS (WINAPI *NetUserEnum_t)(
	LPCWSTR servername,
	DWORD   level,
	DWORD   filter,
	LPBYTE  *bufptr,
	DWORD   prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	PDWORD  resume_handle
);
typedef NET_API_STATUS (WINAPI *NetLocalGroupEnum_t)(
	LPCWSTR      servername,
	DWORD       level,
	LPBYTE      *bufptr,
	DWORD       prefmaxlen,
	LPDWORD     entriesread,
	LPDWORD     totalentries,
	PDWORD_PTR resumehandle
);

int main()
{
	cout << "Hello!" << endl;
	HMODULE hm = NULL;
	hm = LoadLibraryA("NetApi32.dll");
	if (hm == NULL) {
		cout << "Error loading DLL" << endl;
		return 1;
	}
	NetUserEnum_t nue = NULL;
	LPUSER_INFO_3 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	NET_API_STATUS status;
	nue = (NetUserEnum_t)GetProcAddress((HINSTANCE)hm, "NetUserEnum");
	if (nue == NULL)
	{
		cout << "getProcAddr error" << endl;
		FreeLibrary(hm);
		return 1;
	}
	status = nue(NULL, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	for (DWORD i = 0; i < dwEntriesRead; i++) 
	{
		wcout << pBuf[i].usri3_name << " " << pBuf[i].usri3_priv << " " <<pBuf[i].usri3_user_id<< endl;
	}
	/*
	LPGROUP_INFO_1 pBufG = NULL;
	NetLocalGroupEnum_t
	NetLocalGroupEnum_t(nullptr, 1, (LPBYTE*)&pBufG, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	for (DWORD i = 0; i < dwEntriesRead; i++)
	{
		wcout << pBufG[i].grpi1_name << endl;
	}*/
	system("pause");
	return 0;
}