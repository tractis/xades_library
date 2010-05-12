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
#include <vector>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/openssl/x509.h>
#include "TrustVerifier.h"
#include "XmlCharBuf.h"
#include "KeyInfoCtx.h"
#include "Exceptions.h"
using namespace std;


int TrustVerifier::verifyTrust ()
{
    THROW(TrustVerificationError, "Unable to trust key absence.", 0);
}


int TrustVerifier::verifyTrust (KeyPtr)
{
    return 0;
}


int TrustVerifier::verifyTrust (vector<X509CertificatePtr>)
{
    return 0;
}


SimpleTrustVerifier::SimpleTrustVerifier (vector<KeyPtr> keys)
    : keys (keys)
{}


SimpleTrustVerifier::~SimpleTrustVerifier ()
{}


int SimpleTrustVerifier::verifyTrust (KeyPtr key)
{
    for (vector<KeyPtr>::iterator keyIter = keys.begin();
         keyIter != keys.end(); keyIter++)
    {
        if (*key == **keyIter)
        {
            return 1;
        }
    }
    THROW(TrustVerificationError, 
          "Key to check is not in the collection of trusted keys", 0);
}


int SimpleTrustVerifier::verifyTrust (vector<X509CertificatePtr> chain)
{
    if (chain.size() < 1)
    {
        THROW(KeyError, "No certificates in chain", -1);
    }
    return verifyTrust(chain[0]->getKey());
}


X509TrustVerifier::X509TrustVerifier (vector<X509CertificatePtr> certCollection)
    : certs(certCollection)
{
    for (vector<X509CertificatePtr>::iterator certIter = certs.begin();
         certIter != certs.end(); certIter++)
    {
        keyStore.addTrustedCert(*certIter);
    }
}


X509TrustVerifier::~X509TrustVerifier ()
{}


int X509TrustVerifier::verifyTrust (KeyPtr key)
{
    for (vector<X509CertificatePtr>::iterator certIter = certs.begin();
         certIter != certs.end(); certIter++)
    {
        KeyPtr certKey((*certIter)->getKey());
        if (key->hasSameValues(*certKey))
        {
            return 1;
        }
    }
    THROW(TrustVerificationError, 
          "Key to check is not in the collection of trusted certificates", 0);
}


int X509TrustVerifier::verifyTrust (vector<X509CertificatePtr> chain)
{
    KeyInfoCtx keyInfoCtx (keyStore);
    xmlSecKeyDataStorePtr store = xmlSecKeysMngrGetDataStore(keyStore,
                                                             xmlSecOpenSSLX509StoreId);
    if ((store == NULL) || !xmlSecKeyDataStoreIsValid(store))
    {
        THROW(LibError, "Failed to retrieve keystore data", -1);
    }
    STACK_OF(X509)* crl = sk_X509_new_null();
    STACK_OF(X509)* stack = sk_X509_new_null();
    if (!stack)
    {
        THROW(LibError, "Failed to allocate certificate stack", -1);
    }
    for (vector<X509CertificatePtr>::iterator certIter = chain.begin();
         certIter != chain.end(); certIter++)
    {
        sk_X509_push(stack, (*certIter)->getDup());
    }    
    X509* verifiedCert = xmlSecOpenSSLX509StoreVerify(store, stack, crl, keyInfoCtx);
    sk_X509_free(stack);
    if (!verifiedCert)
    {
        THROW(TrustVerificationError, 
              "Certificate chain does not connect to a trusted authority", 0);
    }
    return 1;
}
