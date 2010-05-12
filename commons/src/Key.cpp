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
#include <iostream>
#include <string>
#include <xmlsec/openssl/app.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/xmltree.h>
#include "Key.h"
#include "XmlDoc.h"
#include "KeyInfoCtx.h"
#include "Exceptions.h"
using namespace std;


KeyPtrWrap::KeyPtrWrap (const KeyPtrWrap& key)
    : key(0)
{
    operator=(key);
}


KeyPtrWrap::~KeyPtrWrap ()
{
    freeKey();
}


void KeyPtrWrap::freeKey ()
{
    if (key)
    {
        xmlSecKeyDestroy(key);
        key = 0;
    }
}


const KeyPtrWrap& KeyPtrWrap::operator= (const KeyPtrWrap& newkey)
{
    if (this != &newkey)
    {
        freeKey();
        key = newkey.copy();
    }
    return *this;
}


const KeyPtrWrap& KeyPtrWrap::operator= (xmlSecKeyPtr newkey)
{
    if (key != newkey)
    {
        freeKey();
        key = newkey;
    }
    return *this;
}


bool KeyPtrWrap::isValid () const
{
    return xmlSecKeyIsValid(key);
}


xmlSecKeyPtr KeyPtrWrap::copy () const
{
    if (!isValid())
    {
        return 0;
    }
    return xmlSecKeyDuplicate(key);
}


KeyPtrWrap& KeyPtrWrap::create ()
{
    freeKey();
    key = xmlSecKeyCreate();
    return *this;
}


Key::Key ()
{}


Key::Key (xmlSecKeyPtr newKey)
{
    if (newKey != NULL)
    {
        key = KeyPtrWrap(newKey).copy();
        if (key == NULL)
        {
            THROW_NORET(MemoryError, "Couldn't copy key");
        }
    }
}


Key::Key (X509CertificatePtr cert)
{
    if (cert)
    {
        KeyPtr keyPtr = cert->getKey();
        if (keyPtr)
        {
            this->operator=(*keyPtr);
        }
    }
}


Key::Key (vector<X509CertificatePtr> certs)
{
    if (certs.size())
    {
        KeyPtr keyPtr = certs[0]->getKey();
        if (keyPtr)
        {
            this->operator=(*keyPtr);
            for (vector<X509CertificatePtr>::iterator certIter = certs.begin() + 1;
                    certIter != certs.end(); certIter++)
            {
                addCert(*certIter);
            }
        }
    }
}


Key::Key (const Key& newkey)
{
    this->operator=(newkey);
}


Key::~Key ()
{}


const Key& Key::operator= (const Key& newkey)
{
    if (this != &newkey)
    {
        key = newkey.dupKey();
    }
    return *this;
}


int Key::create ()
{
    key.create();
    if (key == NULL)
    {
        THROW(MemoryError, "Couldn't create key", -1);
    }
    return 0;
}


int Key::isValid () const
{
    return key.isValid();
}


xmlSecKeyPtr Key::getKey () const
{
    return key.getKey();
}


xmlSecKeyPtr Key::dupKey () const
{
    if (!isValid())
    {
        THROW(KeyError, "Invalid key", 0);
    }
    xmlSecKeyPtr newKey = key.copy();
    if (newKey == NULL)
    {
        THROW(MemoryError, "Couldn't create key", 0);
    }
    return newKey;
}


int Key::setName (string name)
{
    if (!isValid())
    {
        THROW(KeyError, "Invalid key", -1);
    }
    if (xmlSecKeySetName(key, BAD_CAST name.c_str()) < 0)
    {
        THROW(LibError, "Failed to set key name", -1);
    }
    return 0;
}


string Key::getName ()
{
    string name;
    if (key)
    {
        const xmlChar* nameStr = xmlSecKeyGetName(key);
        if (nameStr)
        {
            name = string((const char*)nameStr);
        }
    }
    return name;
}


void Key::dump ()
{
    if (key == NULL)
    {
        return;
    }
    // xmlSecKeyDebugDump(key,stdout);
    fprintf(stderr, "Key value:\n");
    xmlSecKeyDataDebugDump(key->value, stderr);
    for (xmlSecSize i = 0; i < xmlSecPtrListGetSize(key->dataList); i++)
    {
        fprintf(stderr, "Key data list (%i):\n", (int)i);
        xmlSecKeyDataPtr keyData =
            (xmlSecKeyDataPtr)xmlSecPtrListGetItem(key->dataList, i);
        if (keyData)
        {
            xmlSecKeyDataDebugDump(keyData, stderr);
        }
    }
}

// This callback is needed for a bug in xmlsec 1.2.9, in which the password is
// unused in favour of a null passphrase callback
int openSSLDummyPasswordCallback (char *buf, int bufsize, int verify, void *userdata) 
{
    char* password = (char*)userdata;
    
    if ((password == NULL) || (strlen(password) + 1 > (unsigned)bufsize)) 
    {
        return(-1);
    }
    
    strcpy(buf, password);
    return (strlen(buf));
}


int Key::loadFromFile (string fileName, string keyDataFormatString, string password)
{
    const char *password_cstr = NULL;
    if (password.length())
    {
        password_cstr = password.c_str();
    }
    key = xmlSecOpenSSLAppKeyLoad(
              fileName.c_str(),
              findKeyDataFormat(keyDataFormatString),
              password_cstr,
              password_cstr == NULL ? NULL : (void*)&openSSLDummyPasswordCallback,
              password_cstr == NULL ? NULL : (void*)password_cstr);
    if (key == NULL)
    {
        THROW(IOError, "Failure loading key file", -1);
    }
    return 0;
}


int Key::loadFromKeyInfoFile (string fileName)
{
    XmlDoc xmlDoc;
    if (xmlDoc.loadFromFile(fileName) < 0)
    {
        return -1;
    }
    return loadFromKeyInfo(xmlDoc);
}


int Key::loadHMACFromString (string hMACString)
{
    create();
    xmlSecKeyDataPtr keyData = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataHmacId);
    if (!xmlSecKeyDataIsValid(keyData))
    {
        THROW(MemoryError, "Unable to create keyData", -1);
    }

    xmlSecBufferPtr buffer = xmlSecKeyDataBinaryValueGetBuffer(keyData);
    if (!buffer)
    {
        THROW(MemoryError, "Unable to get buffer", -1);
    }

    if (xmlSecBufferSetData(buffer, (const unsigned char*)hMACString.c_str(), hMACString.length()) < 0)
    {
        THROW(LibError, "Unable to set buffer data", -1);
    }

    if (xmlSecKeySetValue(key, keyData) < 0)
    {
        THROW(KeyError, "Unable to set key value", -1);
    }
    return 0;
}


int Key::addCertFromFile (string fileName, string format)
{
    if (!isValid())
    {
        THROW(KeyError, "Invalid key", -1);
    }
    if (xmlSecOpenSSLAppKeyCertLoad(key, fileName.c_str(),
                                    findKeyDataFormat(format.c_str())) < 0)
    {
        THROW(IOError, "Failure loading certificate file", -1);
    }
    return 0;
}


int Key::addCert (KeyPtr certKey)
{
    return addCert(certKey->getCertificateChain());
}


int Key::addCert (X509CertificatePtr x509)
{
    if (!isValid())
    {
        THROW(KeyError, "Invalid key", -1);
    }
    if (!x509)
    {
        THROW(ValueError, "Bad x509 parameter", -1);
    }
    xmlSecKeyDataPtr certData = xmlSecKeyEnsureData(key,
                                xmlSecOpenSSLKeyDataX509Id);
    if (certData == NULL)
    {
        THROW(MemoryError, "Couldn't create cert data", -1);
    }
    if (xmlSecOpenSSLKeyDataX509AdoptCert(certData, x509->getDup()) < 0)
    {
        THROW(LibError, "Unable to adopt cert data", -1);
    }
    return 0;
}


int Key::addCert (vector<X509CertificatePtr> certs)
{
    int certsAdded = 0;
    for (vector<X509CertificatePtr>::iterator certIter = certs.begin();
            certIter != certs.end(); certIter++)
    {
        int ret = addCert(*certIter);
        if (ret < 0)
        {
            return ret;
        }
        certsAdded++;
    }
    return certsAdded;
}


X509CertificatePtr Key::getCertificate ()
{
    vector<X509CertificatePtr> certChain = getCertificateChain();
    if (certChain.size())
    {
        return certChain[0];
    }
    return 0;
}


vector<X509CertificatePtr> Key::getCertificateChain ()
{
    vector<X509CertificatePtr> certChain;
    if (!isValid())
    {
        THROW(KeyError, "Invalid key", certChain);
    }
    if (!(xmlSecKeyDataIsValid(key->value) )) // &&
        //          xmlSecKeyDataCheckId(key->value, xmlSecKeyDataStore)))
    {
        THROW(KeyError, "Invalid key value", certChain);
    }
    if (!xmlSecPtrListIsValid(key->dataList))
    {
        return certChain;
    }
    for (xmlSecSize i = 0; i < xmlSecPtrListGetSize(key->dataList); i++)
    {
        xmlSecKeyDataPtr keyData =
            (xmlSecKeyDataPtr)xmlSecPtrListGetItem(key->dataList, i);
        if (keyData && xmlSecKeyDataCheckId(keyData, xmlSecOpenSSLKeyDataX509Id))
        {
            xmlSecSize size = xmlSecOpenSSLKeyDataX509GetCertsSize(keyData);
            for (xmlSecSize j = 0; j < size; j++)
            {
                X509* cert = xmlSecOpenSSLKeyDataX509GetCert(keyData, j);
                if (cert)
                {
                    X509CertificatePtr x509 = new X509Certificate(cert);
                    certChain.push_back(x509);
                }
            }
        }
    }
    return certChain;
}


struct _DsigKeyDataFormatMap
{
    string formatString;
    xmlSecKeyDataFormat keyDataFormat;
}
dsigKeyDataFormatMap[] = {
                             {"binary", xmlSecKeyDataFormatBinary},
                             {"pem", xmlSecKeyDataFormatPem},
                             {"der", xmlSecKeyDataFormatDer},
                             {"pkcs8_pem", xmlSecKeyDataFormatPkcs8Pem},
                             {"pkcs8_der", xmlSecKeyDataFormatPkcs8Der},
                             {"pkcs12", xmlSecKeyDataFormatPkcs12},
                             {"cert_pem", xmlSecKeyDataFormatCertPem},
                             {"cert_der", xmlSecKeyDataFormatCertDer},
                             {"unknown", xmlSecKeyDataFormatUnknown} // sentinel
                         };

xmlSecKeyDataFormat Key::findKeyDataFormat (string formatString)
{
    xmlSecKeyDataFormat keyDataFormat = xmlSecKeyDataFormatUnknown;
    int i = 0;
    while (1)
    {
        if (dsigKeyDataFormatMap[i].formatString == formatString)
        {
            keyDataFormat = dsigKeyDataFormatMap[i].keyDataFormat;
            break;
        }
        if (dsigKeyDataFormatMap[i].keyDataFormat == xmlSecKeyDataFormatUnknown)
            break;
        i++;
    }
    return keyDataFormat;
}


int Key::loadFromKeyInfo (xmlDocPtr xmlDoc, xmlSecKeysMngrPtr keysMngr)
{
    assert(xmlDoc);
    // find keyinfo node
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(xmlDoc),
                                     xmlSecNodeKeyInfo, xmlSecDSigNs);
    if (node == NULL)
    {
        THROW(XMLError, "Can't find key info node", -1);
    }
    return loadFromKeyInfo(node);
}


int Key::loadFromKeyInfo (xmlNodePtr xmlNode, xmlSecKeysMngrPtr keysMngr)
{
    assert(xmlNode);
    if (!xmlSecCheckNodeName(xmlNode, xmlSecNodeKeyInfo, xmlSecDSigNs))
    {
        THROW(XMLError, "Invalid key info node", -1);
    }

    KeyInfoCtx keyInfoCtx (keysMngr);
    if (!keyInfoCtx)
    {
        return -1;
    }
    keyInfoCtx->mode = xmlSecKeyInfoModeRead;
    KeyPtrWrap newKey = xmlSecKeysMngrGetKey(xmlNode, keyInfoCtx);
    if (newKey == NULL)
    {
        THROW(LibError, "Couldn't load key info", -1);
    }
    else
    {
        key = newKey.copy();
        if (key == NULL)
        {
            THROW(MemoryError, "Couldn't copy key", -1);
        }
    }
    return 0;
}

bool Key::hasSameValues(const Key& otherKey) const
{
    // if both are invalid then the keys are the same
    if (!isValid() && !otherKey.isValid())
		return true;

    if (!isValid() || !otherKey.isValid())
		return false;

    const xmlSecKeyPtr thisSecKeyPtr = getKey();
    const xmlSecKeyPtr otherSecKeyPtr = otherKey.getKey();

    // if the same pointers then the keys are the same
    if (thisSecKeyPtr == otherSecKeyPtr)
        return true;

	bool bRet = false;
    if ((thisSecKeyPtr->value->id == otherSecKeyPtr->value->id)
		&& (thisSecKeyPtr->notValidBefore == otherSecKeyPtr->notValidBefore)
		&& (thisSecKeyPtr->notValidAfter == otherSecKeyPtr->notValidAfter)
		&& (thisSecKeyPtr->usage == otherSecKeyPtr->usage))
    {
		if ((xmlSecKeyDataGetType(thisSecKeyPtr->value) == xmlSecKeyDataGetType(otherSecKeyPtr->value))
			&& (xmlSecKeyDataGetSize(thisSecKeyPtr->value) == xmlSecKeyDataGetSize(otherSecKeyPtr->value)))
		{
			xmlSecByte *thisBuffer = NULL;
			xmlSecSize thisSize = 0;
			KeyInfoCtx thisCtx;
			bRet = true; // assume suceess - if the following fails there is nothing more we can do
			if (xmlSecKeyDataBinWrite(thisSecKeyPtr->value->id, thisSecKeyPtr, &thisBuffer, &thisSize, thisCtx) == 0)
			{
				xmlSecByte *otherBuffer = NULL;
				xmlSecSize otherSize = 0;
				KeyInfoCtx otherCtx;

				// if this succeeds then the other will succeed since they have the same Id so
				bRet = false; // assume failure
				if (xmlSecKeyDataBinWrite(otherSecKeyPtr->value->id, otherSecKeyPtr, &otherBuffer, &otherSize, otherCtx) == 0)
				{
					if ((thisSize == otherSize) && (memcmp(thisBuffer, otherBuffer, thisSize) == 0))
					{
						bRet = true;
					}
				}
				if (otherBuffer)
				{
					memset(otherBuffer, 0, otherSize);
					xmlFree(otherBuffer);
				}
			}
			if (thisBuffer)
			{
				memset(thisBuffer, 0, thisSize);
				xmlFree(thisBuffer);
			}
		}
	}
    return bRet;
}
