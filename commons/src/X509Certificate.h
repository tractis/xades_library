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
#ifndef _X509CERTIFICATE_H
#define _X509CERTIFICATE_H

#include <string>
#include <openssl/x509.h>

class X509Certificate;

#include "countptr.h"
typedef CountPtrTo<X509Certificate> X509CertificatePtr;

#include "Key.h"
using namespace std;

/**
 * An X.509 certificate class.
 * X509Certificate wraps the OpenSSL representation of the X509
 * structure.
 */
class X509Certificate
{
public:
    /**
     * Construct an empty certificate object.
     */
    X509Certificate ();
    /**
     * Copy constructor
     * @param cert another X509Certificate object
     */
    X509Certificate (const X509Certificate& cert);
    /**
     * Destructor.  Frees the internal OpenSSL X509 object.
     */
    ~X509Certificate ();
    /**
     * Load a certificate from a file.
     * @param fileName The name of the file
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @return 0 on success, -1 if something went wrong
     * @throws IOError on failure to read the certificate from the file
     */
    int loadFromFile (string fileName, string format);
    /**
     * Get the subject DN from the certificate.
     * @return the subject DN as a string
     * @throws LibError if cert not loaded
     */
    string getSubjectDN ();
    /**
     * Get the issuer DN from the certificate.
     * @return the subject DN as a string
     * @throws LibError if cert not loaded
     */
    string getIssuerDN ();
    /**
     * Get the version of the cert.
     * @return the version of the cert 
     * @throws LibError if cert not loaded
     */
    int getVersion ();
    /**
     * Determine if the certificate is currently valid based on the notBefore and notAfter fields.
     * @return 1 if valid, 0 if not valid
     * @throws LibError if cert not loaded or invalid cert data
     */
    int isValid ();
    /**
     * Create a Key from the certificate.
     * @return the key contained in the certificate
     * @throws LibError on failure to create the key or retrieve the key data
     */
    KeyPtr getKey () const;
    /**
     * Verify that the certificate was signed by the private key
     * corresponding to the given public key.
     * @param key public key to check certificate against
     * @return >0 if verifies, 0 if verify fails, <0 on error
     * @throws KeyError if the key is invalid or the wrong type
     * @throws LibError if the X509_verify library call fails
     */
    int verify (KeyPtr key);
    
    // stub
    int getBasicConstraints ();

    /// @cond NO_INTERFACE
    /**
     * Construct from copy of a raw OpenSSL certificate pointer.
     * @param x509ptr a raw OpenSSL certificate pointer
     * @throws MemoryError if unable to create a copy of the certificate
     */
    X509Certificate (X509* x509ptr);
    /**
     * Assignment operator creates a duplicate X509Certificate.
     * @param cert X509Certificate to copy
     * @return Copied certificate
     */
    const X509Certificate& operator= (const X509Certificate& cert);
    /**
     * Create a duplicate X509 certificate
     * @return a raw pointer to an OpenSSL certificate, null on failure
     * @throws MemoryError if unable to create a copy of the certificate
     */
    X509* getDup () const;
    /**
     * Casting operator to convert to an X509* pointer
     */
    operator X509* ()
    {
        return ptr;
    }
    /**
     * Compare this X509Certificate with another one.
     * @param other X509Certificate to compare with this one
     * @return 1 if certificates are equal, 0 if they are not
     */
    int isEqualTo (X509Certificate& other);

protected:
    X509* ptr;
    /**
     * Extract a string from a X509_NAME object
     * @return the subject name
     */
    xmlChar* nameToString (X509_NAME* nm);
/// @endcond
};

#endif // _X509CERTIFICATE_H
