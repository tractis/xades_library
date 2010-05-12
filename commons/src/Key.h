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
#ifndef _KEY_H
#define _KEY_H
#include <string>
#include <vector>
#include <assert.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include "Exceptions.h"

class Key;

#include "countptr.h"
typedef CountPtrTo<Key> KeyPtr;

#include "X509Certificate.h"
using namespace std;

/// @cond NO_INTERFACE
/**
 * Wrap a raw xmlSecKeyPtr.  Does not reference count.
 */
class KeyPtrWrap
{
public:
    KeyPtrWrap() : key(0)
    {}
    KeyPtrWrap(xmlSecKeyPtr newkey) : key(newkey)
    {}
    KeyPtrWrap(const KeyPtrWrap&);
    ~KeyPtrWrap();

    const KeyPtrWrap& operator= (const KeyPtrWrap&);
    const KeyPtrWrap& operator= (xmlSecKeyPtr);

    xmlSecKeyPtr operator-> ()
    {
        assert(key);
        return key;
    }
    const xmlSecKeyPtr operator-> () const
    {
        assert(key);
        return key;
    }

    operator xmlSecKeyPtr ()
    {
        return key;
    }

    bool isValid () const;
    operator const void* () const
    {
        return isValid() ? key : 0;
    }

    xmlSecKeyPtr copy () const;
    KeyPtrWrap& create ();

    xmlSecKeyPtr getKey () const
    {
        return key;
    }

protected:
    void freeKey();

    xmlSecKeyPtr key;
};
/// @endcond

/**
 * Encapsulates a digital key.  
 * The Key class provides an interface to the lower level xmlsec1 key
 * data structure.  
 *
 * The Key may contain a private or public key associated with
 * the following different algorithms:
 * - dsa - Digital Signature Algorithm
 * - rsa - RSA public key cryptosystem
 * - hmac - HMAC message authentication code
 *
 * Key objects may also contain X.509 certificates (X509Certificate
 * objects), which will then be included in signed documents.  The Key
 * may also be extracted from an X.509 certificate.
 *
 * File formats supported are:
 * - binary key data
 * - PEM key data (cert or public/private key)
 * - DER key data (cert or public/private key)
 * - PKCS8 PEM private key
 * - PKCS8 DER private ke.
 * - PKCS12 format (bag of keys and certs)
 * - PEM cert
 * - DER cert
 */
class Key
{
public:
    /**
     * Create an empty Key object.
     */
    Key ();
    /**
     * Creates a duplicate key from a raw xmlsec pointer.
     * @param key Key to copy
     */
    Key (xmlSecKeyPtr key);
    /**
     * Create a key from an X.509 certificate.
     * @param cert Certificate to create key from
     */
    Key (X509CertificatePtr cert);
    /**
     * Create key from an X.509 certificate chain.
     * @param certs Certificates to create key from (use first in chain)
     */
    Key (vector<X509CertificatePtr> certs);
    /**
     * Destructor.
     * Will free the internal key representation, if one has been created.
     */
    ~Key ();

    /**
     * Load a key from a file.
     * @param fileName The name of the file
     * @param format The key data format string. Must be one of the
     *     following strings:
     *     - binary
     *     - pem
     *     - der
     *     - pkcs8_pem
     *     - pkcs8_der
     *     - pkcs12
     *     - cert_pem
     *     - cert_der
     *     - unknown
     * @param password Optionally provide a password to unlock the
     *     key.  Empty string means "no password".
     * @return 0 on success, -1 if something went wrong
     * @throws IOError on load failure
     */
    int loadFromFile (string fileName, string format, string password);
    /**
     * Load a key from an XML file containing a key info node
     * @param fileName The name of the file
     * @return 0 on success, -1 if something went wrong
     */
    int loadFromKeyInfoFile (string fileName);
    /**
     * Load an HMAC key from a string.
     * @param hMACString A string
     * @return 0 on success, -1 on error
     */
    int loadHMACFromString (string hMACString);

    /**
     * Set key name
     * @param name Name of key
     * @return 0 on success, -1 if something went wrong
     */
    int setName (string name);
    /**
     * Get key name.
     * @return name, possibly empty
     */
    string getName ();
    /**
     * Key validity check.
     * @return true if key and key's id are non-null
     */
    int isValid () const;

    /**
     * Retrieve certificate from key if it exists.
     * @return An X509 certificate, or null if none exists
     */
    X509CertificatePtr getCertificate ();
    /**
     * Retrieve all certificates from key.
     * @return X509 certificates, or an empty list if none exists
     */
    vector<X509CertificatePtr> getCertificateChain ();

    /// @cond NO_INTERFACE
    /**
     * Copy constructor, creates duplicate key.
     * @param key Key to copy
     */
    Key (const Key& key);
    /**
     * Assignment operator creates duplicate key
     * @param key Key to copy
     * @return Copied key
     */
    const Key& operator= (const Key& key);
    /**
     * Create a new key
     * @return 0 on success, -1 if something went wrong
     */
    int create ();
    /**
     * Dump the contents of the key to stdout.
     * Handy for debugging.
     */
    void dump ();
    /**
     * Return the internal representation of the key
     * Returns a "xmlSecKeyPtr"
     * @return The internal representation of the key, or NULL if the key has not been loaded.
     */
    xmlSecKeyPtr getKey () const;
    /**
     * Cast to xmlSecKeyPtr type
     */
    operator xmlSecKeyPtr ()
    {
        return getKey();
    }
    /**
     * Conversion to xmlSecKeyPtr type
     */
    xmlSecKeyPtr operator-> ()
    {
        assert(key);
        return getKey();
    }
    /**
     * Return a duplicate of the internal representation of the key
     * Returns a "xmlSecKeyPtr"
     * @return The duplicate key, or NULL if the key has not been loaded.
     */
    xmlSecKeyPtr dupKey () const;
    /**
     * @return true if valid, false if invalid
     */
    operator int ()
    {
        return isValid();
    }
    /**
     * @return false if valid, true if invalid
     */
    int operator! ()
    {
        return !isValid();
    }
	/**
	 * @return true if otherKey has same values this key, false otherwise
	 */
	bool operator==(const Key& otherKey) const
	{
		return hasSameValues(otherKey);
	}
	/**
	 * @return false if otherKey has same values this key, true otherwise
	 */
	bool operator!=(const Key& otherKey) const
	{
		return !hasSameValues(otherKey);
	}
    /**
     * Attach a certificate to the key.
     * @param cert X509 certificate
     * @return 0 on success, -1 if something went wrong
     */
    int addCert (X509CertificatePtr cert);
    /**
     * Attach a list of certificate to the key.
     * @param certs X509 certificates
     * @return Number of certs added on success, -1 if something went wrong
     */
    int addCert (vector<X509CertificatePtr> certs);
    /**
     * Attach certificates from another key to this key.
     * @param certKey key containing X509 certificates
     * @return Number of certs added on success, -1 if something went wrong
     */
    int addCert (KeyPtr certKey);
    /**
     * Attach a certificate from a file.
     * @param fileName The name of the file
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @return 0 on success, -1 if something went wrong
     */
    int addCertFromFile (string fileName, string format);
    /**
     * Lookup the xmlsec keyDataFormat, given a string.
     * @param formatString Key data format string (see Key::loadFromFile() for format list)
     * @return The xmlSecKeyDataFormat.  Returns xmlSecKeyDataFormatUnknown 
     * if the string does not match a known type.
     */
    static xmlSecKeyDataFormat findKeyDataFormat (string formatString);
    /**
     * Find key info in document and load the key from there.
     * @param xmlDoc XML document pointer
     * @param keysMngr optional keys manager pointer
     * @return 0 on success, -1 if something went wrong
     */
    int loadFromKeyInfo (xmlDocPtr xmlDoc, xmlSecKeysMngrPtr keysMngr = 0);
    /**
     * Load the key from a key info node.
     * @param xmlNode XML node pointer pointing to a key info node
     * @param keysMngr optional keys manager pointer
     * @return 0 on success, -1 if something went wrong
     */
    int loadFromKeyInfo (xmlNodePtr xmlNode, xmlSecKeysMngrPtr keysMngr = 0);
	/**
	 * @return true if otherKey has same values this key, false otherwise
	 */
	bool hasSameValues(const Key& otherKey) const;

protected:
    /**
     * The internal representation of the key.
     */
    KeyPtrWrap key;
/// @endcond
};

#endif
