/*
 * (C) Copyright 2006 VeriSign, Inc.
 * Developed by Sxip Identity
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string>
#include <xmlsec/keysmngr.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/x509.h>
#include "KeyStore.h"
#include "Key.h"
using namespace std;


KeyStore::KeyStore ()
    : mMngr (0)
{
    mMngr = xmlSecKeysMngrCreate();
    if (mMngr == NULL)
    {
        THROW_NORET(MemoryError, "Failed to create keys manager");
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(mMngr) < 0)
    {
        THROW_NORET(KeyError, "Failed to initialize keys manager");
    }
}


KeyStore::~KeyStore ()
{
    if (mMngr)
    {
        xmlSecKeysMngrDestroy(mMngr);
        mMngr = NULL;
    }
}


int KeyStore::addCert (X509CertificatePtr cert, int isTrusted)
{
    assert(mMngr);
    xmlSecKeyDataStorePtr x509Store = xmlSecKeysMngrGetDataStore(mMngr, xmlSecOpenSSLX509StoreId);
    if (!x509Store)
    {
        THROW(LibError, "Failed to get X509 store from keys manager", -1);
    }
    X509* rawcert = cert->getDup();
    if (!rawcert)
    {
        return -1;
    }
    if (xmlSecOpenSSLX509StoreAdoptCert(x509Store, 
                                        rawcert, 
                                        isTrusted ? xmlSecKeyDataTypeTrusted : 0) < 0)
    {
        THROW(LibError, "Unable to adopt cert", -1);
    }
    return 0;
}


int KeyStore::addTrustedCert (X509CertificatePtr cert)
{
    return addCert(cert, 1);
}


int KeyStore::addUntrustedCert (X509CertificatePtr cert)
{
    return addCert(cert, 0);
}


int KeyStore::addCertFromFile (string fileName, string format, int isTrusted)
{
    assert(mMngr);
    xmlSecKeyDataFormat formatId = Key::findKeyDataFormat(format.c_str());
    if (xmlSecOpenSSLAppKeysMngrCertLoad(mMngr, fileName.c_str(),
                                         formatId,
                                         isTrusted ? xmlSecKeyDataTypeTrusted : 0) < 0)
    {
        THROW(IOError, "Unable to load cert", -1);
    }
    return 0;
}


int KeyStore::addTrustedCertFromFile (string fileName, string format)
{
    return addCertFromFile(fileName, format, 1);
}


int KeyStore::addUntrustedCertFromFile (string fileName, string format)
{
    return addCertFromFile(fileName, format, 0);
}


int KeyStore::addKey (KeyPtr key)
{
    if (!key || !key->isValid())
    {
        THROW(KeyError, "Invalid key", -1);
    }
    xmlSecKeyPtr newKey = key->dupKey();
    if (newKey == NULL)
    {
        return -1;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(mMngr, newKey) < 0)
    {
        THROW(LibError, "Can't adopt the key", -1);
    }
    return 0;
}


int KeyStore::addKeyFromFile (string fileName, string format, string name)
{
    return addKeyFromFile(fileName, format, name, "");
}


int KeyStore::addKeyFromFile (string fileName, string format, string name, string password)
{
    KeyPtr key (new Key());

    if (!key)
    {
        THROW(MemoryError, "Unable to allocate new key", -1);
    }
    if (key->loadFromFile(fileName, format, password) < 0)
    {
        return -1;
    }
    key->setName(name);
    return addKey(key);
}


int KeyStore::saveToFile (string fileName)
{
    assert(mMngr);
    if (xmlSecOpenSSLAppDefaultKeysMngrSave(mMngr, fileName.c_str(), xmlSecKeyDataTypeTrusted) < 0)
    {
        THROW(IOError, "Unable to save key store", -1);
    }
    return 0;
}


int KeyStore::loadFromFile (string fileName)
{
    assert(mMngr);
    if (xmlSecOpenSSLAppDefaultKeysMngrLoad(mMngr, fileName.c_str()) < 0)
    {
        THROW(IOError, "Unable to load key store", -1);
    }
    return 0;
}


xmlSecKeysMngrPtr KeyStore::getKeyStore ()
{
    assert(mMngr);
    return mMngr;
}
