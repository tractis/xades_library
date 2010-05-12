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
#ifndef _TRUSTVERIFIER_H
#define _TRUSTVERIFIER_H

#include <string>
#include <vector>
#include "Key.h"
#include "X509Certificate.h"
#include "KeyStore.h"
using namespace std;

/**
 * Checks whether a given public key or certificate chain is
 * trusted. Using this interface allows the trust policy to be
 * decoupled from the various entities that need to verify trust.
 *
 * To comply with this interface's contract, users should call the
 * method that gives the most information. Depending on the
 * information available, choose a method based on the following list
 * in decreasing order of preferred usage.
 *
 * -# Call verifyTrust(vector<X509CertificatePtr>) if one or more certificates
 *    are available.
 * -# Call verifyTrust(KeyPtr,std::string) if a public key and an XML
 *    Signature key name are both available.
 * -# Call verifyTrust(KeyPtr) if only a public key is available.
 * -# Call verifyTrust() if no trust material is available.
 */
class TrustVerifier
{
public:
    TrustVerifier ()
    {}
    virtual ~TrustVerifier ()
    {}

    /**
     * Verifies that the absence of a key or certificate (e.g., an
     * unsigned message) can be trusted. Returns silently if the
     * message is trusted, or throws an exception if not.
     *
     * TrustVerifier does not consider the absence of a key or
     * certificate to be trusted and will always throw an exception
     * when this method is called.
     *
     * @return <0 on error
     * @throws TrustVerificationError if unable to trust the absence of a key
     */
    virtual int verifyTrust ();
    /** 
     * Verifies that a public key is trusted. Returns silently if the
     * key is trusted, or throws an exception indicating the reason it
     * is not.
     * @param key the public key to check
     * @return <0 on error, 0 on failure to verify, 1 on verification passed
     * @throws TrustVerificationError if unable to trust the public key
     */
    virtual int verifyTrust (KeyPtr key);
    /**
     * Verifies that a certificate chain is trusted. The chain must be
     * presented in order from leaf entity toward root CA, such that
     * for all i, 0 <= i < (chain.length - 1) implies
     * chain[i].verify(chain[i+1].getPublicKey()) will
     * succeed. Returns silently if the chain is trusted, or throws an
     * exception indicating the reason if not.
     * @param chain certificate chain
     * @return <0 on error, 0 on failure to verify, 1 on verification passed
     * @throws TrustVerificationError f the given chain cannot be
     *     trusted, or if an error occurs while trying to determine trust
     */
    virtual int verifyTrust (vector<X509CertificatePtr> chain);
};


/**
 * A simple TrustVerifier implementation based on a collection of
 * trusted public keys.
 *
 * A key is trusted if it is in the trusted collection; a certificate
 * chain is trusted if the public key of the leaf certificate is in
 * the trusted collection.
 *
 * When verifyTrust() is called, an exception is always thrown by this
 * class.
 */
class SimpleTrustVerifier : public TrustVerifier
{
public:
    /**
     * Create the SimpleTrustVerifier with a set of trusted keys.
     * @param keys a set of trusted public keys
     */
    SimpleTrustVerifier (vector<KeyPtr> keys);
    /**
     * Destroy the SimpleTrustVerifier.
     */
    ~SimpleTrustVerifier ();
    
    /// @copydoc TrustVerifier::verifyTrust()
    int verifyTrust ()
    {
        return TrustVerifier::verifyTrust();
    }
    /// @copydoc TrustVerifier::verifyTrust(KeyPtr)
    int verifyTrust (KeyPtr key);
    /// @copydoc TrustVerifier::verifyTrust(vector<X509CertificatePtr>)
    int verifyTrust (vector<X509CertificatePtr> chain);

    /// @cond NO_INTERFACE
protected:
    vector<KeyPtr> keys;
/// @endcond
};


/**
 * A trust verifier based on a collection of trusted certificates. A
 * KeyStore may be passed to the X509TrustVerifier constructor to use
 * the trusted certificates stored in the KeyStore.
 *
 * A key is trusted if it is the public key of one of the trusted
 * certificates; a certificate chain is trusted if it can be traced
 * back to a trusted certificate.
 *
 * When verifyTrust() is called, an exception is always thrown by this
 * class.
 */
class X509TrustVerifier : public TrustVerifier
{
public:
    /**
     * Create the X509TrustVerifier object with a collection of 
     * trusted certificates.
     * @param certs A list of trusted certificates
     */
    X509TrustVerifier (vector<X509CertificatePtr> certs);
    /**
     * Destroy the X509TrustVerifier.
     */
    ~X509TrustVerifier ();

    /// @copydoc TrustVerifier::verifyTrust()
    int verifyTrust ()
    {
        return TrustVerifier::verifyTrust();
    }
    /// @copydoc TrustVerifier::verifyTrust(KeyPtr)
    int verifyTrust (KeyPtr key);
    /// @copydoc TrustVerifier::verifyTrust(vector<X509CertificatePtr>)
    int verifyTrust (vector<X509CertificatePtr> chain);

    /// @cond NO_INTERFACE
protected:
    vector<X509CertificatePtr> certs;
    KeyStore keyStore;
/// @endcond
};

#endif // _TRUSTVERIFIER_H
