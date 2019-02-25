#include <iostream>
#include "windows.h"
#include "lm.h"
#include "sddl.h"
#include <ntsecapi.h>
#include <ntstatus.h>
using namespace std;

#define LSA_LOOKUP_ISOLATED_AS_LOCAL 0x80000000

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
typedef NET_API_STATUS (WINAPI* NetGroupEnum_t)(
	LPCWSTR    servername,
	DWORD      level,
	LPBYTE     *bufptr,
	DWORD      prefmaxlen,
	LPDWORD    entriesread,
	LPDWORD    totalentries,
	PDWORD_PTR resume_handle
);
typedef NET_API_STATUS (WINAPI* NetUserGetInfo_t)(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD   level,
	LPBYTE  *bufptr
);

typedef NET_API_STATUS(WINAPI *NetApiBufferFree_t)(
	_Frees_ptr_opt_ LPVOID Buffer
	);


typedef NET_API_STATUS(WINAPI *NetUserGetInfo_t)(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD   level,
	LPBYTE  *bufptr
	);

typedef NET_API_STATUS(WINAPI *NetUserAdd_t)(
	LPCWSTR servername,
	DWORD   level,
	LPBYTE  buf,
	LPDWORD parm_err
	);

typedef NET_API_STATUS(WINAPI *NetUserDel_t)(
	LPCWSTR servername,
	LPCWSTR username
	);

typedef NET_API_STATUS(WINAPI *NetLocalGroupAdd_t)(
	LPCWSTR servername,
	DWORD   level,
	LPBYTE  buf,
	LPDWORD parm_err
	);

typedef NET_API_STATUS(WINAPI *NetLocalGroupDel_t)(
	LPCWSTR servername,
	LPCWSTR groupname
	);

typedef NET_API_STATUS(WINAPI *NetLocalGroupGetMembers_t)(
	LPCWSTR    servername,
	LPCWSTR    localgroupname,
	DWORD      level,
	LPBYTE     *bufptr,
	DWORD      prefmaxlen,
	LPDWORD    entriesread,
	LPDWORD    totalentries,
	PDWORD_PTR resumehandle
	);

typedef NET_API_STATUS(WINAPI *NetLocalGroupAddMembers_t)(
	LPCWSTR servername,
	LPCWSTR groupname,
	DWORD   level,
	LPBYTE  buf,
	DWORD   totalentries
	);

typedef NET_API_STATUS(WINAPI *NetLocalGroupDelMembers_t)(
	LPCWSTR servername,
	LPCWSTR groupname,
	DWORD   level,
	LPBYTE  buf,
	DWORD   totalentries
	);

typedef BOOL(WINAPI *ConvertSidToStringSidA_t)(
	PSID  Sid,
	LPSTR *StringSid
	);

typedef NTSTATUS(WINAPI *LsaOpenPolicy_t)(
	PLSA_UNICODE_STRING    SystemName,
	PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	ACCESS_MASK            DesiredAccess,
	PLSA_HANDLE            PolicyHandle
	);

typedef NTSTATUS(WINAPI *LsaClose_t)(
	LSA_HANDLE ObjectHandle
	);

typedef NTSTATUS(WINAPI *LsaLookupNames2_t)(
	LSA_HANDLE                  PolicyHandle,
	ULONG                       Flags,
	ULONG                       Count,
	PLSA_UNICODE_STRING         Names,
	PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	PLSA_TRANSLATED_SID2        *Sids
	);

typedef ULONG(WINAPI *LsaNtStatusToWinError_t)(
	NTSTATUS Status
	);

typedef NTSTATUS(WINAPI *LsaFreeMemory_t)(
	PVOID Buffer
	);

typedef NTSTATUS(WINAPI *LsaEnumerateAccountRights_t)(
	LSA_HANDLE          PolicyHandle,
	PSID                AccountSid,
	PLSA_UNICODE_STRING *UserRights,
	PULONG              CountOfRights
	);

typedef NTSTATUS(WINAPI *LsaAddAccountRights_t)(
	LSA_HANDLE          PolicyHandle,
	PSID                AccountSid,
	PLSA_UNICODE_STRING UserRights,
	ULONG               CountOfRights
	);

typedef NTSTATUS(WINAPI *LsaRemoveAccountRights_t)(
	LSA_HANDLE          PolicyHandle,
	PSID                AccountSid,
	BOOLEAN             AllRights,
	PLSA_UNICODE_STRING UserRights,
	ULONG               CountOfRights
	);


typedef NTSTATUS (WINAPI * LsaLookupNames2_t)(
	LSA_HANDLE                  PolicyHandle,
	ULONG                       Flags,
	ULONG                       Count,
	PLSA_UNICODE_STRING         Names,
	PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	PLSA_TRANSLATED_SID2        *Sids
);
typedef NTSTATUS(WINAPI *LsaFreeMemory_t)(
	PVOID Buffer
	);


bool InitLsaString(
	PLSA_UNICODE_STRING pLsaString,
	LPCWSTR pwszString
)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

LSA_HANDLE lsahPolicyHandle; // LSA Handle

HMODULE na = NULL;
HMODULE adv = NULL;
NetUserEnum_t nue = NULL;
NetUserGetInfo_t nugi = NULL;
NetLocalGroupEnum_t lge;
LsaLookupNames2_t LLN2;
LsaFreeMemory_t LFreeM;
LsaNtStatusToWinError_t WinError;
LsaOpenPolicy_t OpenPolicy;
LsaEnumerateAccountRights_t EnumerateAccountRights;
LsaFreeMemory_t FreeMemory;
NetLocalGroupEnum_t LocalGroupEnum;
NetLocalGroupGetMembers_t LocalGroupGetMembers;
NetUserAdd_t UAdd;
NetUserDel_t UDel;
NetLocalGroupAdd_t LocalGroupAdd;
NetLocalGroupDel_t LocalGroupDel;
NetLocalGroupAddMembers_t LocalGroupAddMembers;
NetLocalGroupDelMembers_t LocalGroupDelMembers;
LsaAddAccountRights_t AddAccountRights;
LsaRemoveAccountRights_t RemoveAccountRights;
void load()
{
	na = LoadLibraryA("NetApi32.dll");
	if (na == NULL) {
		wcout << "Error loading DLL" << endl;
	}
	adv = LoadLibraryA("Advapi32.dll");
	nue = (NetUserEnum_t)GetProcAddress((HINSTANCE)na, "NetUserEnum");
	nugi = (NetUserGetInfo_t)GetProcAddress((HINSTANCE)na, "NetUserGetInfo");
	lge = (NetLocalGroupEnum_t)GetProcAddress((HINSTANCE)na, "NetLocalGroupEnum");
	LLN2 = (LsaLookupNames2_t)GetProcAddress((HINSTANCE) adv, "LsaLookupNames2");
	LFreeM = (LsaFreeMemory_t)GetProcAddress(adv, "LsaFreeMemory");
	WinError = (LsaNtStatusToWinError_t)GetProcAddress(adv, "LsaNtStatusToWinError");
	OpenPolicy = (LsaOpenPolicy_t)GetProcAddress(adv, "LsaOpenPolicy");
	EnumerateAccountRights = (LsaEnumerateAccountRights_t)GetProcAddress(adv, "LsaEnumerateAccountRights");
	FreeMemory = (LsaFreeMemory_t)GetProcAddress(adv, "LsaFreeMemory");
	LocalGroupEnum = (NetLocalGroupEnum_t)GetProcAddress(na, "NetLocalGroupEnum");
	LocalGroupGetMembers = (NetLocalGroupGetMembers_t)GetProcAddress(na, "NetLocalGroupGetMembers");
	UAdd = (NetUserAdd_t)GetProcAddress(na, "NetUserAdd");
	UDel = (NetUserDel_t)GetProcAddress(na, "NetUserDel");
	LocalGroupAdd = (NetLocalGroupAdd_t)GetProcAddress(na, "NetLocalGroupAdd");
	LocalGroupDel = (NetLocalGroupDel_t)GetProcAddress(na, "NetLocalGroupDel");
	LocalGroupAddMembers = (NetLocalGroupAddMembers_t)GetProcAddress(na, "NetLocalGroupAddMembers");
	LocalGroupDelMembers = (NetLocalGroupDelMembers_t)GetProcAddress(na, "NetLocalGroupDelMembers");
	AddAccountRights = (LsaAddAccountRights_t)GetProcAddress(adv, "LsaAddAccountRights");
	RemoveAccountRights = (LsaRemoveAccountRights_t)GetProcAddress(adv, "LsaRemoveAccountRights");

	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	// Object attributes are reserved, so initialize to zeros.
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	ntsResult = OpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if (STATUS_SUCCESS != ntsResult)
	{
		wprintf(L"Failed Policy - %lu \n",
			WinError(ntsResult));
		return;
	}
	
	/*myLsaClose = (LsaClose_t)GetProcAddress(hAdvapiModule, "LsaClose");
	myLsaFreeMemory = (LsaFreeMemory_t)GetProcAddress(hAdvapiModule, "LsaFreeMemory");
	myLsaLookupNames2 = (LsaLookupNames2_t)GetProcAddress(hAdvapiModule, "LsaLookupNames2");
	myConvertSidToStringSidA = (ConvertSidToStringSidA_t)GetProcAddress(hAdvapiModule, "ConvertSidToStringSidA");
	myLsaEnumerateAccountRights = (LsaEnumerateAccountRights_t)GetProcAddress(hAdvapiModule, "LsaEnumerateAccountRights");
	myLsaAddAccountRights = (LsaAddAccountRights_t)GetProcAddress(hAdvapiModule, "LsaAddAccountRights");
	myLsaRemoveAccountRights = (LsaRemoveAccountRights_t)GetProcAddress(hAdvapiModule, "LsaRemoveAccountRights");

	myNetUserGetInfo = (NetUserGetInfo_t)GetProcAddress(na, "NetUserGetInfo");
	myNetUserEnum = (NetUserEnum_t)GetProcAddress(na, "NetUserEnum");
	myNetApiBufferFree = (NetApiBufferFree_t)GetProcAddress(na, "NetApiBufferFree");
	myNetLocalGroupEnum = (NetLocalGroupEnum_t)GetProcAddress(na, "NetLocalGroupEnum");
	myNetUserAdd = (NetUserAdd_t)GetProcAddress(na, "NetUserAdd");
	myNetUserDel = (NetUserDel_t)GetProcAddress(na, "NetUserDel");
	myNetLocalGroupAdd = (NetLocalGroupAdd_t)GetProcAddress(na, "NetLocalGroupAdd");
	myNetLocalGroupDel = (NetLocalGroupDel_t)GetProcAddress(na, "NetLocalGroupDel");
	my
	my
	*/
}
PSID to_return_SID(LPCWSTR name)
{
	LPTSTR sStringSid = NULL;
	PSID accountSID;
	LSA_UNICODE_STRING lucName;
	PLSA_TRANSLATED_SID2 ltsTranslatedSID;
	PLSA_REFERENCED_DOMAIN_LIST lrdlDomainList;
	LSA_TRUST_INFORMATION myDomain;
	NTSTATUS ntsResult;
	PWCHAR DomainString = NULL;
	if (!InitLsaString(&lucName, name))
	{
		wprintf(L"Failed InitLsaString\n");
		return 0;
	}

	ntsResult = LLN2(
		lsahPolicyHandle,     // handle to a Policy object
		LSA_LOOKUP_ISOLATED_AS_LOCAL,
		1,                // number of names to look up
		&lucName,         // pointer to an array of names
		&lrdlDomainList,  // receives domain information
		&ltsTranslatedSID // receives relative SIDs
	);
	if (STATUS_SUCCESS != ntsResult)
	{
		wprintf(L"Failed LsaLookupNames - %lu \n",
			WinError(ntsResult));
		return 0;
	}

	// Get the domain the account resides in.
	myDomain = lrdlDomainList->Domains[ltsTranslatedSID->DomainIndex];
	LFreeM(lrdlDomainList);
	accountSID = ltsTranslatedSID->Sid;
	return accountSID;
}
void show_users()
{
	LPUSER_INFO_3 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	NET_API_STATUS status;
	if (nue == NULL)
	{
		wcout << "getProcAddr error" << endl;
		return;
	}
	status = nue(NULL, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	wcout << "N Name \t Privilage  \t SID" << endl;
	PSID sid_ptr = NULL;
	DWORD sidLength = 0;
	DWORD sidLengthDomain = 0;
	for (DWORD i = 0; i < dwEntriesRead; i++)
	{
		wcout <<i << ". " <<  pBuf[i].usri3_name << " ";
		if (pBuf[i].usri3_priv == USER_PRIV_GUEST)
			wcout << "Guest" << " ";
		else if (pBuf[i].usri3_priv == USER_PRIV_USER)
			wcout << "User" << " ";
		else if (pBuf[i].usri3_priv == USER_PRIV_ADMIN)
			wcout << "Admin" << " ";	
		LPUSER_INFO_0 ppBuf = NULL;
		LPUSER_INFO_23 pBuf23 = NULL;
		DWORD dwLevel = 23;
		LPTSTR sStringSid = NULL;
		status = nugi(NULL, pBuf[i].usri3_name, dwLevel, (LPBYTE*)&ppBuf);
		pBuf23 = (LPUSER_INFO_23)ppBuf;
		if (ConvertSidToStringSidA(pBuf23->usri23_user_sid, &sStringSid))
		{
			wcout << sStringSid << endl;
			LocalFree(sStringSid);
		}
	}

}

void show_groups()
{
	LPGROUP_INFO_1 pBufG = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	NET_API_STATUS status;
	status = lge(nullptr, 1, (LPBYTE*)&pBufG, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	LPTSTR sStringSid = NULL;
	PSID accountSID;
	LSA_UNICODE_STRING lucName;
	PLSA_TRANSLATED_SID2 ltsTranslatedSID;
	PLSA_REFERENCED_DOMAIN_LIST lrdlDomainList;
	LSA_TRUST_INFORMATION myDomain;
	NTSTATUS ntsResult;
	PWCHAR DomainString = NULL;

	for (DWORD i = 0; i < dwEntriesRead; i++)
	{
		wcout << i+1 << ". " << pBufG[i].grpi1_name << "\t";
		if (!InitLsaString(&lucName, pBufG[i].grpi1_name))
		{
			wprintf(L"Failed InitLsaString\n");
			return;
		}
		
		ntsResult = LLN2(
			lsahPolicyHandle,     // handle to a Policy object
			LSA_LOOKUP_ISOLATED_AS_LOCAL,
			1,                // number of names to look up
			&lucName,         // pointer to an array of names
			&lrdlDomainList,  // receives domain information
			&ltsTranslatedSID // receives relative SIDs
		);
		if (STATUS_SUCCESS != ntsResult)
		{
			wprintf(L"Failed LsaLookupNames - %lu \n",
				WinError(ntsResult));
			return;
		}

		// Get the domain the account resides in.
		myDomain = lrdlDomainList->Domains[ltsTranslatedSID->DomainIndex];
		LFreeM(lrdlDomainList);
		accountSID = ltsTranslatedSID->Sid;
		if (ConvertSidToStringSidA(accountSID, &sStringSid))
		{
			wcout << sStringSid << endl;
			LocalFree(sStringSid);
		}
		PLSA_UNICODE_STRING privs = NULL;
		ULONG privsCount = 0;

		ntsResult = EnumerateAccountRights(
			lsahPolicyHandle,
			accountSID,
			&privs,
			&privsCount
		);

		std::wcout << "\n\tPrivs:" << std::endl;
		for (ULONG j = 0; j < privsCount; j++)
			std::wcout << "\t\t" << privs[j].Buffer << endl;

		FreeMemory(privs);

		// group members
		PLOCALGROUP_MEMBERS_INFO_1 pMemBuf;
		DWORD dwEnt = 0;
		DWORD dwTot = 0;
		DWORD dwRes = 0;
		NET_API_STATUS nStatus;

		nStatus = LocalGroupGetMembers(
			NULL,
			pBufG[i].grpi1_name,
			1,
			(LPBYTE*)&pMemBuf,
			MAX_PREFERRED_LENGTH,
			&dwEnt,
			&dwTot,
			&dwRes
		);

		std::wcout << "\n\tMembers:" << std::endl;
		for (DWORD j = 0; j < dwEnt; j++)
		{
			std::wcout << L"\t\t" << pMemBuf[j].lgrmi1_name << std::endl;
		}

		std::wcout << std::endl;
	}
}


void add_user()
{	
	USER_INFO_1 ui;
	DWORD priv;
	wchar_t name[256], pass[256];
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;
	wcout << "Username? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(name, 256, '\n');
	wcout << "Password?\n>>";
	cin.ignore(1, '\n');
	wcin.getline(pass, 256, '\n');
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_name = name;
	ui.usri1_password = pass;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;

	nStatus = UAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

	if (nStatus == NERR_Success)
		std::wcout << L"User has been successfully added" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

void del_user()
{
	
	NET_API_STATUS nStatus;
	wchar_t name[256];
	wcout << "Username? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(name, 256, '\n');
	nStatus = UDel(NULL, name);

	if (nStatus == NERR_Success)
		std::wcout << L"User has been successfully deleted" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

void add_group()
{
	LOCALGROUP_INFO_0 ui;
	DWORD dwLevel = 0;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;
	wchar_t groupname[256];
	wcout << "Groupname? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256, '\n');
	ui.lgrpi0_name = groupname;

	nStatus = LocalGroupAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

	if (nStatus == NERR_Success)
		std::wcout << L"Group has been successfully added" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

void del_group()
{
	NET_API_STATUS nStatus;
	wchar_t groupname[256];
	wcout << "Groupname? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256, '\n');
	nStatus = LocalGroupDel(NULL, groupname);

	if (nStatus == NERR_Success)
		std::wcout << L"Group has been successfully deleted" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

void add_priv()
{
	LSA_UNICODE_STRING lucPrivilege;
	NTSTATUS ntsResult;
	wchar_t groupname[256], priv[256];
	wcout << "Name? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256, '\n');
	wcout << "Privilage? \n>>";
	wcin.getline(priv, 256, '\n');
	PSID accountSID;
	
	accountSID = to_return_SID(groupname);

	// Create an LSA_UNICODE_STRING for the privilege names.
	if (!InitLsaString(&lucPrivilege, priv))
	{
		wprintf(L"Failed InitLsaString\n");
		return;
	}

	ntsResult = AddAccountRights(
		lsahPolicyHandle,  // An open policy handle.
		accountSID,    // The target SID.
		&lucPrivilege, // The privileges.
		1              // Number of privileges.
	);

	if (ntsResult == STATUS_SUCCESS)
	{
		wprintf(L"Privilege added.\n");
	}
	else
	{
		wprintf(L"Privilege was not added - %lu \n",
			WinError(ntsResult));
	}
}

void del_priv()
{
	LSA_UNICODE_STRING lucPrivilege;
	NTSTATUS ntsResult;

	PSID accountSID;
	wchar_t groupname[256], priv[256];
	wcout << "Name? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256, '\n');
	wcout << "Privilage? \n>>";
	wcin.getline(priv, 256, '\n');
	accountSID = to_return_SID(groupname);

	// Create an LSA_UNICODE_STRING for the privilege names.
	if (!InitLsaString(&lucPrivilege, priv))
	{
		wprintf(L"Failed InitLsaString\n");
		return;
	}

	ntsResult = RemoveAccountRights(
		lsahPolicyHandle,
		accountSID,
		FALSE,
		&lucPrivilege,
		1
	);

	if (ntsResult == STATUS_SUCCESS)
	{
		wprintf(L"Privilege deleted.\n");
	}
	else
	{
		wprintf(L"Privilege was not deleted - %lu \n",
			WinError(ntsResult));
	}
}

void add_member()
{
	NET_API_STATUS nStatus;
	LOCALGROUP_MEMBERS_INFO_3 ui;
	wchar_t username[256], groupname[256];
	wcout << "Groupname? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256);
	wcout << "Username? \n>>";
	wcin.getline(username, 256);
	ui.lgrmi3_domainandname = username;

	nStatus = LocalGroupAddMembers(
		NULL,
		groupname,
		3,
		(LPBYTE)&ui,
		1
	);

	if (nStatus == NERR_Success)
		std::wcout << L"Member has been successfully added" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

void del_member()
{
	NET_API_STATUS nStatus;
	LOCALGROUP_MEMBERS_INFO_3 ui;
	wchar_t username[256], groupname[256];
	wcout << "Groupname? \n>>";
	cin.ignore(1, '\n');
	wcin.getline(groupname, 256, '\n');
	wcout << "Username? \n>>";
	wcin.getline(username, 256, '\n');

	ui.lgrmi3_domainandname = username;

	nStatus = LocalGroupDelMembers(
		NULL,
		groupname,
		3,
		(LPBYTE)&ui,
		1
	);

	if (nStatus == NERR_Success)
		std::wcout << L"Member has been successfully deleted" << std::endl;
	else
		std::wcout << L"A system error has occurred:" << nStatus << std::endl;
}

int main()
{
	int choice = 0;
	setlocale(LC_ALL, "");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	wcout << "Hello! What do you like to do?" << endl << "1. Show users \n2. Show groups\n\
3. Add user\n4. Del user\n5. Add group\n6. Del group\n7. Add member to group\n8. Delete member from group\n\
9. Add privilage\n10. Delete privilage\n>>";
	cin >> choice;
	load();
	while (1) {
		switch (choice)
		{
		case 1:
			show_users();
			break;
		case 2:
			show_groups();
			break;
		case 3:
			add_user();
			break;
		case 4:
			del_user();
			break;
		case 5:
			add_group();
			break;
		case 6:
			del_group();
			break;
		case 7:
			add_member();
			break;
		case 8:
			del_member();
			break;
		case 9:
			add_priv();
			break;
		case 10:
			del_priv();
			break;
		default:
			break;
		}
		wcout << "\n_______________________\n\n"<< "1. Show users \n2. Show groups\n\
3. Add user\n4. Del user\n5. Add group\n6. Del group\n7. Add member to group\n8. Delete member from group\n\
9. Add privilage\n10. Delete privilage\n>>";
		cin >> choice;
	}
	system("pause");
	return 0;
}