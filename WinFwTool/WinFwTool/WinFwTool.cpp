// WinFwTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <netfw.h>
#include <conio.h>

// Forward declarations
void displayUsage();
BOOL comInitialize(__out INetFwPolicy2** ppNetFwPolicy2);
BOOL enableWinFirewall(__in BOOL bEnable);
BOOL arrayOfLongsToVariant(__in unsigned long numItems, __in_ecount(numItems) const long* items, __out VARIANT* dst);
void registerWithWinFw(const std::wstring fwDisplayName);


int __cdecl wmain(int argc, wchar_t* argv[])
{
    BOOL bRet;

    if (argc < 2) {
        displayUsage();
        return 0;
    }
    else
    {
        std::wstring command(argv[1]);
        if (0 == command.compare(L"fwdisable"))
        {
            printf("Disable windows firewall \n");
            bRet = enableWinFirewall(FALSE);
            if (!bRet)
            {
                printf("Failed to disable windows filrewall. \n");
            }
        }
        else if (0 == command.compare(L"fwenable"))
        {
            printf("Enable windows firewall \n");
            bRet = enableWinFirewall(TRUE);
            if (!bRet)
            {
                printf("Failed to enable windows filrewall. \n");
            }
        }
        else if (0 == command.compare(L"registerfw"))
        {
            if (argc < 3) {
                displayUsage();
                return 0;
            }

            registerWithWinFw(argv[2]);
            bRet = TRUE;
        }
        else if (0 == command.compare(L"readrules"))
        {

        }
        else
        {
            displayUsage();
            return 0;
        }
    }

    return 0;
}

void displayUsage()
{
    printf("Commands : \n \
            WinFwTool.exe fwdisable : Disable Windows firewall \n \
            WinFwTool.exe fwenable :  Enable Windows firewall \n \
            WinFwTool.exe registerfw <Firewall_Name>: Register <Firewall_Name> with windows firewall and take ownership. This may need the process to be registered as Protected process(PPL)\n \
            WinFwTool.exe readrules : Read windows firewall rules. \n \
        ");
}

// Instantiate INetFwPolicy2
BOOL comInitialize(__out INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        return FALSE;
    }

    return TRUE;
}

BOOL enableWinFirewall(__in BOOL bEnable)
{
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2* pNetFwPolicy2 = NULL;

    // Initialize COM.
    hrComInit = CoInitializeEx(
        0,
        COINIT_APARTMENTTHREADED
    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto Cleanup;
        }
    }

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)&pNetFwPolicy2);
    if (FAILED(hr))
    {
        printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Disable Windows Firewall for the Domain profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, bEnable);
    if (FAILED(hr))
    {
        printf("put_FirewallEnabled failed for Domain: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Disable Windows Firewall for the Private profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, bEnable);
    if (FAILED(hr))
    {
        printf("put_FirewallEnabled failed for Private: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Disable Windows Firewall for the Public profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, bEnable);
    if (FAILED(hr))
    {
        printf("put_FirewallEnabled failed for Public: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
    {
        CoUninitialize();
    }

    return SUCCEEDED(hr);
}


BOOL arrayOfLongsToVariant(__in unsigned long numItems, __in_ecount(numItems) const long* items, __out VARIANT* dst)
{
    DWORD result = NO_ERROR;
    SAFEARRAYBOUND bound[1];
    SAFEARRAY* sa = NULL;
    VARIANT* data;
    unsigned long i;

    VariantInit(dst);

    if (numItems == 0)
    {
        wprintf(L"arrayOfLongsToVariant Invalid paramter numItems: [%d]\n", numItems);
        return FALSE;
    }

    bound[0].lLbound = 0;
    bound[0].cElements = numItems;

    sa = SafeArrayCreate(VT_VARIANT, ARRAYSIZE(bound), bound);
    if (!sa)
    {
        printf("Memory allocation failure\n");
        return FALSE;
    }

    data = (VARIANT*)(sa->pvData);

    for (i = 0; i < numItems; ++i)
    {
        V_VT(data + i) = VT_I4;
        V_I4(data + i) = items[i];
    }

    V_VT(dst) = VT_ARRAY | VT_VARIANT;
    V_ARRAY(dst) = sa;

    return TRUE;
}


// Registers your firewall with windows firewall and take the ownership.
// Ownership is valid till the registered firewall service is running.
void registerWithWinFw(const std::wstring fwDisplayName)
{
    DWORD result = NO_ERROR;
    HRESULT hr = S_OK;
    INetFwProduct* product = NULL;
    INetFwProducts* products = NULL;
    IUnknown* registration = NULL;
    long* categories = NULL;
    VARIANT varCategories = { VT_EMPTY };
    int numberOfCategories = 1;
    long count = 0;
    BOOL comInit = FALSE;
    BSTR displayName = NULL;

    if (fwDisplayName.empty())
    {
        wprintf(L"arrayOfLongsToVariant Invalid paramter - firewallName\n");
        return;
    }

    //Allocate Memory
    categories = (long*)calloc(numberOfCategories, sizeof(long));
    if (!categories)
    {
        printf("Memory allocation failure\n");
        return;
    }

    // Register with firewall category
    categories[0] = NET_FW_RULE_CATEGORY_FIREWALL;
    result = arrayOfLongsToVariant(numberOfCategories, categories, &varCategories);

    displayName = SysAllocString(fwDisplayName.c_str());
    if (!displayName)
    {
        printf("Memory allocation failure\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        //COM initialize failed
        wprintf(L"CoInitialize failed: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    comInit = TRUE;

    hr = CoCreateInstance(__uuidof(NetFwProduct), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwProduct), (void**)&product);
    if (FAILED(hr))
    {
        //CoCreateInstance Failed
        wprintf(L"CoCreateInstance for INetFwProduct failed: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    hr = product->put_DisplayName(displayName);
    if (FAILED(hr))
    {
        //Put_displayName failed
        wprintf(L"put_DisplayName for INetFwProduct failed Error: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    hr = product->put_RuleCategories(varCategories);
    if (FAILED(hr))
    {
        //Put_rulecategories failed
        wprintf(L"put_RuleCategories failed for INetFwProduct Error: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    hr = CoCreateInstance(__uuidof(NetFwProducts), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwProducts), (void**)&products);
    if (FAILED(hr))
    {
        wprintf(L"CoCreateInstance for INetFwProducts failed: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    hr = products->Register(product, &registration);
    if (!(S_OK == hr))
    {
        //Failed to Register Products
        wprintf(L"Register failed: 0x%08lx\n", hr);
        goto CLEANUP;
    }

    wprintf(L"Check the windows defender firewall UI. Hit any key to unregister.\n");
    _getch();

CLEANUP:
    if (registration != NULL)
    {
        registration->Release();
    }
    if (products != NULL)
    {
        products->Release();
    }
    if (product != NULL)
    {
        product->Release();
    }
    if (comInit)
    {
        CoUninitialize();
    }

    free(categories);
    SysFreeString(displayName);
    VariantClear(&varCategories);

    return;
}



