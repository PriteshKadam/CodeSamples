// Parses pem file to fetch public keys.
// Usage : CertRead.exe <Path to pem file
// Author : Pritesh Kadam

#include <iostream>
#include <stdio.h>
#include <vector>
#include <windows.h>
#include<fstream>
#include<sstream>
#include<string>
#include <regex>

#define SIC_STRING  std::wstring
typedef unsigned long   DWORD;

#define CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define CERT_END "-----END CERTIFICATE-----"

// ------------------------------------------------------------------------------------------------------------------------------------------
// Test Certs  with their respective public keys. -------------------------------------------------------------------------------------------
#define CERT1_BASE64 "\
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx\
GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds\
b2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV\
BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD\
VQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa\
DuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc\
THAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb\
Kk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP\
c1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX\
gzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF\
AAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj\
Y1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG\
j/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH\
hm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC\
X4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\
"


#define CERT2_BASE64 "\
MIICMzCCAZygAwIBAgIJALiPnVsvq8dsMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV\
BAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNVBAcTA2ZvbzEMMAoGA1UEChMDZm9v\
MQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2ZvbzAeFw0xMzAzMTkxNTQwMTlaFw0x\
ODAzMTgxNTQwMTlaMFMxCzAJBgNVBAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNV\
BAcTA2ZvbzEMMAoGA1UEChMDZm9vMQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2Zv\
bzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdGfxi9CNbMf1UUcvDQh7MYB\
OveIHyc0E0KIbhjK5FkCBU4CiZrbfHagaW7ZEcN0tt3EvpbOMxxc/ZQU2WN/s/wP\
xph0pSfsfFsTKM4RhTWD2v4fgk+xZiKd1p0+L4hTtpwnEw0uXRVd0ki6muwV5y/P\
+5FHUeldq+pgTcgzuK8CAwEAAaMPMA0wCwYDVR0PBAQDAgLkMA0GCSqGSIb3DQEB\
BQUAA4GBAJiDAAtY0mQQeuxWdzLRzXmjvdSuL9GoyT3BF/jSnpxz5/58dba8pWen\
v3pj4P3w5DoOso0rzkZy2jEsEitlVM2mLSbQpMM\+\MUVQCQoiG6W9xuCFuxSrwPIS\
pAqEAuV4DNoxQKKWmhVv+J0ptMWD25Pnpxeq5sXzghfJnslJlQND\
"

#define PUBLIC_KEY_CERT1 L"MIIBCgKCAQEA2g7mmY3Oo+NPin778YuDJWvqSB/xKrC5lREEvfBj0eJnZs8c3c8bSCvujYmOmq8pgGWr6cctEsurHExwB6E9CjDNFY1P+N3UjFAVHO9Q7sQu9/zpUvKRfeBt1TUwjl5Dc/JB6dVq47KJOlY5OG8GPIhpWypNxadUuGyJzJv5PMrl/Yn1EjySeJbW3HRuk0Rh0Y3HRrJ1DoboGYrVbWzVeBaVounICjjr8iQTT3NUkxOFOhu8HjS1iwWMuXeLsdsfIJGrCVNukM57N3S5cEeRIlFjFnmusa5BJgjIGSvRRqpI1mQq14M0/ywqwWwZQ0oHhefTfPYhaO/q8lKff5OQzwIDAQAB"

#define PUBLIC_KEY_CERT2 L"MIGJAoGBAM3Rn8YvQjWzH9VFHLw0IezGATr3iB8nNBNCiG4YyuRZAgVOAoma23x2oGlu2RHDdLbdxL6WzjMcXP2UFNljf7P8D8aYdKUn7HxbEyjOEYU1g9r+H4JPsWYindadPi+IU7acJxMNLl0VXdJIuprsFecvz/uRR1HpXavqYE3IM7ivAgMBAAE="

// Test Certs  with their respective public keys. -------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------


// Parses base64 cert data and fetches public key
bool GetPublicKeyFromCert(std::string certString, std::wstring &publicKey)
{
    DWORD certBinaryLen = 0;

    if (!CryptStringToBinaryA(
        certString.c_str(),
        (DWORD)certString.size(),
        CRYPT_STRING_BASE64,
        NULL,
        &certBinaryLen,
        nullptr,
        nullptr))
    {
        DWORD err = GetLastError();
        printf("Error computing Byte length, error %u \n", err);

        return false;
    }

    std::vector<char> certBinary(certBinaryLen, 0);

    if (!CryptStringToBinaryA(certString.c_str(), (DWORD)certString.size(), CRYPT_STRING_BASE64, (unsigned char*)(&certBinary[0]), &certBinaryLen, nullptr, nullptr))
    {
        DWORD err = GetLastError();
        printf("Parse cert Failed to decode input string, error %u \n", err);

        return false;
    }

    PCCERT_CONTEXT pCertCtx = nullptr;

    pCertCtx = CertCreateCertificateContext(
        X509_ASN_ENCODING,
        (unsigned char*)(&certBinary[0]),
        certBinaryLen);

    if (pCertCtx == 0) {
        DWORD err = GetLastError();
        printf("Error decoding certificate, error %u \n", err);
        return false;
    }

    CRYPT_BIT_BLOB& keyBlob = pCertCtx->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    
    DWORD size = 0;

    if (!CryptBinaryToString(keyBlob.pbData, keyBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size))
    {
        printf(": Failed to calculate public key size - error[%lu] size[%u] \n", GetLastError(), size);

        CertFreeCertificateContext(pCertCtx);

        return false;
    }


    printf(": Public key size : [%u] \n", size);

    std::vector<wchar_t> pubKey(size, 0);

    if (!CryptBinaryToString(keyBlob.pbData, keyBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &pubKey[0], &size))
    {
        printf(": Failed to convert public key - error[%lu] size[%u] \n", GetLastError(), size);

        CertFreeCertificateContext(pCertCtx);

        return false;
    }

    publicKey.assign(&pubKey[0]);

    CertFreeCertificateContext(pCertCtx);

    return true;
}

// Parses pem file to get Cert list.
bool GetCertsFromPemData(std::string& pemContent, std::vector<std::string> &certList)
{
    std::vector<std::string> certs; 
    const std::regex re(R"(-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----)");

    std::sregex_token_iterator it{ pemContent.begin(), pemContent.end(), re, -1 };
    std::vector<std::string> tokenized{ it, {} };

    // Additional check to remove empty strings
    tokenized.erase(
        std::remove_if(tokenized.begin(),
            tokenized.end(),
            [](std::string const& s) {
                std::string str = std::regex_replace(s, std::regex("\\r\\n|\\r|\\n"),"");
                return str.size() == 0;
            }),
        tokenized.end());

    certList = std::move(tokenized);

    return true;
}

bool readFile(std::string filePath, std::string& content) {
    std::ifstream f(filePath); //taking file as inputstream
    std::string str;
    if (f) {
        std::ostringstream ss;
        ss << f.rdbuf(); // reading data
        str = ss.str();
    }
    content = str;
    return true;
}

void TestParsePemCerts()
{

    std::string testPemCertBase64;
    std::vector<std::wstring> publicKeysResult, publicKeysExpected;
    std::vector<std::string> certListResult, ExpectedCertList;

    testPemCertBase64.append(CERT_BEGIN);
    testPemCertBase64.append(CERT1_BASE64);
    testPemCertBase64.append(CERT_END);
    testPemCertBase64.append(CERT_BEGIN);
    testPemCertBase64.append(CERT2_BASE64);
    testPemCertBase64.append(CERT_END);

    ExpectedCertList.push_back(CERT1_BASE64);
    ExpectedCertList.push_back(CERT2_BASE64);

    GetCertsFromPemData(testPemCertBase64, certListResult);

    if (ExpectedCertList != certListResult)
    {
        printf(": List Mismatch \n");
    }
    else
    {
        printf(": List Match \n");
    }

    publicKeysExpected.push_back(PUBLIC_KEY_CERT1);
    publicKeysExpected.push_back(PUBLIC_KEY_CERT2);

    for (const std::string& cert : certListResult) {
        std::wstring publicKey;
        if (!GetPublicKeyFromCert(cert, publicKey))
        {
            return;
        }

        std::cout << "publicKey content : \n " << publicKey.c_str() << std::endl;

        publicKeysResult.push_back(publicKey);
    }

    if (publicKeysExpected != publicKeysResult)
    {
        printf(": Public keys Mismatch \n");
    }
    else
    {
        printf(": Public keys Match \n");
    }

    return;
}


int main(int argc, char *argv[])
{
    
    std::string certContent;
    std::vector<std::string> certList;
    
    // TEST Function: Uncomment to unit test the functions.
    //TestParsePemCerts(); return 0;

    std::string filepath(argv[1]);

    bool bret = readFile(filepath, certContent);
    if (!bret) {
        std::cout << "readFile failed "<< std::endl;
        return 1;
    }

    //std::cout << "Cert content : \n " << certContent.c_str() << std::endl;
    bret = GetCertsFromPemData(certContent, certList);
    if (!bret) {
        std::cout << "GetCertsFromPemData failed " << std::endl;
        return 1;
    }

    for (const std::string& cert : certList) {

        std::wstring publicKey;
        bret = GetPublicKeyFromCert(cert, publicKey);
        if (!bret) {
            std::cout << "GetPublicKeyFromCert failed " << std::endl;
            return 1;
        }

        printf(": PUBLIC-KEY : - [%ls] \n", publicKey.c_str());
    }

    return 0;
}
