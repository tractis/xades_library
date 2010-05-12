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
#ifndef _KEYSTORE_H
#define _KEYSTORE_H
#include <string>
#include <xmlsec/keysmngr.h>
#include "Exceptions.h"
#include "X509Certificate.h"
using namespace std;

/**
 * Storage of keys and certificates.  
 * Keys and certificates in objects of this class may be used by the
 * Signer and Verifier to create and validate signatures.
 */
class KeyStore
{
public:
    /**
     * Create an empty KeyStore.
     * @throws MemoryError if a null key manager is created
     * @throws KeyError if the key manager can't be initialized
     */
    KeyStore ();
    /**
     * Destroy the key manager.
     */
    ~KeyStore ();
    /**
     * Add a trusted certificate.
     * @param cert A trusted X509Certificate
     * @return 0 on success, -1 on error
     * @throws LibError if the certificate can't be adopted or the key store is bad
     */
    int addTrustedCert (X509CertificatePtr cert);
    /**
     * Add an untrusted certificate.
     * @param cert An untrusted X509Certificate
     * @return 0 on success, -1 on error
     * @throws LibError if the certificate can't be adopted or the key store is bad
     */
    int addUntrustedCert (X509CertificatePtr cert);
    /**
     * Add a trusted certificate from a file.
     * @param fileName The file name
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @return 0 on success, -1 on error
     * @throws IOError if the file can't be read
     */
    int addTrustedCertFromFile (string fileName, string format);
    /**
     * Add an untrusted certificate from a file.
     * @param fileName The file name
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @return 0 on success, -1 on error
     * @throws IOError if the file can't be read
     */
    int addUntrustedCertFromFile (string fileName, string format);
    /**
     * Add a key to the store.
     * @param key The key to add
     * @return 0 on success, -1 on error
     * @throws LibError on key manager adoption error
     */
    int addKey (KeyPtr key);
    /**
     * Add a key from a file.
     * @param fileName The file name
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @param name Name of key
     * @return 0 on success, -1 on error
     * @throws IOError if the file can't be read
     * @throws LibError on key manager adoption error
     */
    int addKeyFromFile (string fileName, string format, string name);
    /**
     * @overload
     * @param fileName The file name
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @param name Name of key
     * @param password Password for key, empty string if unnecessary
     */
    int addKeyFromFile (string fileName, string format, string name, string password);
    /**
     * Save keys/certs to an XML file.
     * @param fileName The file name
     * @return 0 on success, -1 on error
     * @throws IOError if the file can't be written
     */
    int saveToFile (string fileName);
    /**
     * Add keys/certs from an XML file.
     * @param fileName The file name
     * @return 0 on success, -1 on error
     * @throws IOError if the file can't be read
     */
    int loadFromFile (string fileName);

    /// @cond NO_INTERFACE
    /**
     * Get the internal representation of the KeyStore.
     * @return A pointer to the KeyStore.
     */
    xmlSecKeysMngrPtr getKeyStore ();
    xmlSecKeysMngrPtr operator-> ()
    {
        return getKeyStore();
    }
    operator xmlSecKeysMngrPtr ()
    {
        return getKeyStore();
    }

protected:
    /**
     * Internal representation of the KeyStore.
     */
    xmlSecKeysMngrPtr mMngr;

    /**
     * General certificate addition.
     * @param fileName The file name
     * @param format Key format
     * @param isTrusted Flag, true if the key is trusted
     * @return 0 on success, -1 on error
     */
    int addCertFromFile (string fileName, string format, int isTrusted);
    /**
     * General certificate addition.
     * @param cert The X509Certificate
     * @param isTrusted Flag, true if the key is trusted
     * @return 0 on success, -1 on error
     */
    int addCert (X509CertificatePtr cert, int isTrusted);

/// @endcond
};

#include "countptr.h"
typedef CountPtrTo<KeyStore> KeyStorePtr;

#endif

