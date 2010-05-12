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
#ifndef _VERIFIER_H
#define _VERIFIER_H
#include <vector>
#include "Key.h"
#include "XmlDoc.h"
#include "XPath.h"
#include "KeyStore.h"
#include "X509Certificate.h"
#include "XmlElement.h"
#include "Exceptions.h"
#include "NodeSet.h"
using namespace std;


/**
 * Verifier verifies XML signatures according to the W3C XML-Signature specification (http://www.w3.org/2000/09/xmldsig#).
 *
 * A DOM document may contain several signatures. This class can
 * verify all signatures in a document, one at a time, with either the
 * verification key supplied in the document, or with a user-supplied
 * key.
 * 
 * Usage:
 * 
 * -# Construct the Verifier. You must provide the Verifier with 
 *    -# the XML document that contains the signature 
 *    -# (optional) the location of the signature within the XML
 *       document. To provide the location of the signature within an
 *       XML document, you must use an XPath expression. For more on
 *       constructing XPaths, see http://www.w3.org/TR/xpath. If no
 *       location is specified, Verifier will attempt to verify the
 *       first Signature element it finds in the document.
 * -# Supply the verification key. This key may be taken from the
 *    document (if available) by default, or a specific key may be
 *    supplied by the user.
 * -# Verify the signature. Note that the Verifier will locate and
 *    verify the signature specified in Step 1.
 * 
 * Note: An XML document may contain several signatures, but this API
 * only supports verification of one signature per Verifier. If you
 * need to verify multiple signatures, create a new Verifier for each
 * signature.
 * 
 * Example use (C++):
 *
 * @code
 *       XPath signatureLocation("//ds:Signature");
 *       signatureLocation.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
 *       Verifier verifier(doc, signatureLocation);       
 *       bool isVerified = verifier.verify();
 * @endcode
 *
 * In the above example, we try to verify the signature by
 * \e signatureLocation using the key found within the signature at
 * \e signatureLocation. If \e signatureLocation does not contain a single
 * signature, an exception is thrown. To set the key used to verify
 * the signature:
 *
 * @code
 *       XPath signatureLocation("//ds:Signature");
 *       signatureLocation.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
 *       Verifier verifier(doc, signatureLocation);       
 *       Key verifyingKey = some_public_key;
 *       bool isVerified = verifier.verify(verifyingKey);
 * @endcode
 * 
 * If exceptions are enabled, error codes will not be returned.
 */
class Verifier
{
public:
    /**
     * Creates a Verifier that points to the first Signature in the document.
     * @param doc An XML document
     * @throws MemoryError
     */
    Verifier (XmlDocClassPtr doc);
    /**
     * Creates a Verifier that points to a single Signature within the document.
     * @param doc An XML document
     * @param xpath  An XPath expression that points to a single signature
     * @throws MemoryError
     */
    Verifier (XmlDocClassPtr doc, XPathPtr xpath);
    /**
     * Destroy the Verifier object.
     */
    ~Verifier ();

    /**
     * Use trusted certificates from a KeyStore to verify the signature.
     * @param keyStore A key store
     * @return 0 on success, -1 on error
     * @throws ValueError If the keyStore is invalid
     */
    int setKeyStore (KeyStorePtr keyStore);
    /**
     * Verifies the signature using the public key embedded in the document.
     * @return 1 if signature valid, 0 if not valid, -1 on error
     * @throws DocError The document to verify is invalid in some way
     * @throws KeyError No verifying key is available
     * @throws XMLError A signature couldn't be found in the document
     */
    int verify ();
    /**
     * Verifies the signature at the previously given signature
     * location using the supplied key. Note that all keying
     * information in the signature being verified is ignored, and the
     * supplied key will be used.
     * @param key A public key
     * @return 1 if signature valid, 0 if not valid, -1 on error
     * @throws DocError The document to verify is invalid in some way
     * @throws KeyError The verifying key is invalid
     * @throws XMLError A signature couldn't be found in the document
     */
    int verify (KeyPtr key);
    /**
     * Returns the verification key in the document. The verifying key
     * will be retrieved from the Signature element pointed to by the
     * XPath supplied in the constructor.  If no XPath was specified, 
     * uses the first Signature element found in the document.
     * @return Pointer to the key, or null if none is found, or for cases 
	 *     where both a key and a certificate are part of the signature's
	 *     keying information, null is returned, if the key is not equal
	 *     to the certificate's key.
     * @throws DocError The document to verify is invalid in some way
     * @throws XMLError A signature couldn't be found in the document
     * @throws LibError An error occurred in one of the base libraries
     */
    KeyPtr getVerifyingKey ();
    /**
     * Returns whether the element at the given XPath is contained by
     * one of the Signature references, i.e., whether it is signed.
     * @param xpath  An XPath expression pointing to the signature
     * @return 1 if element is referenced, 0 if not, -1 on error
     */
    int isReferenced (XPathPtr xpath);
    /**
     * Returns all elements referenced by the Signature.
     * @return a (possibly empty) list of elements
     */ 
    vector<XmlElementPtr> getReferencedElements ();

    /**
     * Returns the certificate in the document. If there are multiple
     * certificates available, only the first (in document order) will
     * be returned.
     * @return Pointer to the certificate found at the XPath
     *     expression; null if no certificate can be found, or if both
     *     a key and a certificate is part of the signature's keying
     *     information, and the key is not equal to the certificate's
     *     key.
     * @throws DocError The document to verify is invalid in some way
     * @throws XMLError A signature couldn't be found in the document
     * @throws LibError An error occurred in one of the base libraries
     * @throws XPathError if xpath results in no usable certificate 
     *     (as defined by http://www.w3.org/2000/09/xmldsig:KeyInfo/X509Data)
     */
    X509CertificatePtr getCertificate ();
    /**
     * Retrieve the certificate chain from the signature element.
     * @return the certificate chain found at the xpath expression;
     *     null if no certificate chain can be found, or if both a key
     *     and at least one certificate is part of the signature's
     *     keying information, and the key is not equal to the leaf
     *     certificate's key.  If there is a single certificate found,
     *     a vector of size 1 will be returned.
     * @throws XPathError if xpath results in no usable certificate 
     *     (as defined by http://www.w3.org/2000/09/xmldsig:KeyInfo/X509Data)
     */
    vector<X509CertificatePtr> getCertificateChain ();
    /**
     * Set whether or not to check certificate chain on verify.
     * (default is to do so.)  
     * @param skip 1 to NOT check certificate chain on verify, 0 to do so
     */
    void skipCertCheck (int skip = 1) { skipCertCheckFlag = (skip != 0); }
    
    /// @cond NO_INTERFACE

protected:
    /**
     * The XML document to verify.
     */
    XmlDocClassPtr mXmlDoc;
    /**
     * The (possibly null) XPath expression pointing to a signature.
     */
    XPathPtr xPath;
    /**
     * The KeyStore.
     */
    KeyStorePtr mKeyStore;
    /**
     * Default keystore created internally.
     */
    KeyStorePtr mDefaultKeyStore;
    /**
     * Don't check certificate chain on verification.
     */
    bool skipCertCheckFlag;

    /**
     * Get internal representation of keystore.
     */
    xmlSecKeysMngrPtr getKeysMngr ();
    /**
     * Set node to the first one returned by the xpath expression.
     */
    int findSignatureXPath (xmlDocPtr doc, xmlNodePtr* node);
    /**
     * Find the signature node.
     */
    int findStartNode (xmlDocPtr doc, xmlNodePtr* node);
    /**
     * Verify a signature specified by the node.
     */
    int verifyNode (xmlDocPtr doc, xmlNodePtr node, KeyPtr key);
    /**
     * Verify a signature specified by the node (internal method called by verify(*)
     */
    int doVerify (KeyPtr verifyingKey);
    /**
     * Initialiser.
     */
    void verifierInit ();
    /**
     * Check if element referred to by XPath expression is contained
     * in the nodeset.
     */
    int isContained (xmlSecNodeSetPtr nodeSet, XPathPtr xPathElem);
    /**
     * Get a nodeset for the initial transform context.
     */
    xmlSecNodeSetPtr nodeSetFromTransformCtx (xmlSecTransformCtxPtr ctx,
            xmlDocPtr doc);
    /**
     * Get certificates from X509Data element.
     * @param node Signature data node under which X509Data node exists
     * @return list of X509 certificates
     */
    vector<X509CertificatePtr> getX509Data (xmlNodePtr node);
    /**
     * Get the X509 certificate from the X509Certificate node.
     * @param node X509Certificate element
     * @return certificate pointer, null on error
     */
    X509CertificatePtr getX509CertificateNode (xmlNodePtr node);
    /**
     * Callback type for Verifier::refNodes().
     * @param nset node set for referenced nodes
     * @param verifier verifier object we're operating on
     * @param data user data pointer
     * @return nonzero to abort (negative is an error)
     */
    typedef int (*refNodesCallback) (xmlSecNodeSetPtr nset, Verifier* verifier, void* data);
    /**
     * Callback for Verifier::isReferenced(), passed to Verifier::refNodes().
     * @param nset node set for referenced nodes
     * @param verifier verifier object we're operating on
     * @param data pointer to XPathPtr object
     * @return nonzero if XPath expression is contained (negative is an error)
     */
    static int isReferencedCallback (xmlSecNodeSetPtr nset, Verifier* verifier, void* data);
    /**
     * Callback for xmlSecNodeSetWalk, running through elements and adding copies
     * of them to the vector in the user data pointer.
     * @param cur the current node
     * @param data pointer to vector<XmlElementPtr>
     * @return 0, keep running through referenced nodesets or -1 on error
     */
    static int getElementsCallback (xmlSecNodeSetPtr, xmlNodePtr cur, xmlNodePtr, void *data);
    /**
     * Callback for Verifier::getReferencedElements(), passed to Verifier::refNodes().
     * @param nset node set for referenced nodes
     * @param verifier verifier object we're operating on
     * @param data pointer to vector<XmlElementPtr>
     * @return 0, keep running through referenced nodesets or -1 on error
     * @throw LibError if the node set walk call fails
     */
    static int getReferencedElementsCallback (xmlSecNodeSetPtr nset, Verifier* verifier, void* data);
    /**
     * Get the set of nodes referenced by the signature, executing the callback
     * for each node set.
     * @param callbackFn function to call for each reference node set
     * @data data pointer to pass to callback
     * @return set of nodes, null on error
     * @throws DocError if no document
     * @throws XMLError if the signature can't be found
     * @throws LibError on various xmlsec errors
     */
    int refNodes (refNodesCallback callbackFn, void* data);

/// @endcond
};

#endif
