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
#ifndef _SIGNER_H
#define _SIGNER_H

#include <string>
#include <vector>
#include <xmlsec/transforms.h>
#include "XmlDoc.h"
#include "Key.h"
#include "XPath.h"
#include "KeyStore.h"
#include "X509Certificate.h"
using namespace std;

/**
 * Signer signs XML documents according to the W3C XML-Signature specification (http://www.w3.org/2000/09/xmldsig#).
 * 
 * There are three modes of operation specified:
 * 
 *     - Enveloping signature, in which the signature is over content
 *       found within an Object element of the signature itself.
 *     - Enveloped signature, in which the original document contains the
 *       signature as an element.
 *     - Detached signature. Similar to Enveloped signature, but the
 *       Signature element is detached from the signed element.
 * 
 * This implementation supports all three modes of signing. Its usage:
 * 
 *    -# Construct the Signer. You must provide the Signer with
 *        -# the XML document that you want to sign, and
 *        -# the signing key.
 *       Optionally, you can supply the verification key and attach it in the Signature.
 *    -# If desired, add references.
 *    -# Sign the document. Explicitly choose which way to sign, or
 *       accept default, depending on references added. You may supply
 *       a location in the resulting Document where the Signature will
 *       be placed. An enveloping signature will be created if you
 *       provide no location for the signature.
 *
 * You can choose whether to sign the document in place, or to
 * return a new, signed, document, leaving the original intact with
 * the sign() and signInPlace() APIs.
 * 
 * Note: An XML document may have several associated signatures, but
 * this API only supports a single signature. If you need to sign
 * multiple times, create a new Signer on the result from sign( and
 * then iterate.
 * 
 * Example usage (C++):
 * @code
 *       Signer signer(doc, privateKey, publicKey);
 * 
 *       XPath loc1("id('someID')");
 *       signer.addReference(loc1);
 * 
 *       XPath loc2("/some/element");
 *       signer.addReference(loc2);
 * 
 *       XPath output("/");
 *       XmlDocPtr d = signer.sign(output);
 * @endcode
 * 
 * In the example above, we sign a document and implicitly tell it to
 * add the public verification key to its output. We supply two
 * locations, loc1 and loc2, to be signed (these locations will be two
 * references in the resulting signature) and a location, output, where
 * we want the resulting signature to be placed. Since we supply an
 * output location, an enveloped signature will be created. If we had
 * instead signed like this:
 * @code
 *       Document d = signer.sign();
 * @endcode
 *
 * then we would have forced an enveloping signature.
 * 
 * Note that this API only allows XPath expressions that evaluate to a
 * single node. Nor are relative XPath expressions (e.g., "../element")
 * allowed since the Signature reference's context changes at the time of
 * signing.
 */
class Signer
{
public:
    /**
     * Creates a signer with a signing key. No verification key is
     * added to the signature. The recipient of the signed document
     * must obtain this key from a source other than the signed
     * document.
     * @param doc An XML document
     * @param key key used to sign the document
     */
    Signer (XmlDocClassPtr doc, KeyPtr key);
    /**
     * Creates a Signer with a signing key and a verifying key as part
     * of the Signature element.
     * @param doc An XML document
     * @param key key used to sign the document
     * @param verifyKey A public or verifying key that will be appended to the signature
     */
    Signer (XmlDocClassPtr doc, KeyPtr key, KeyPtr verifyKey);
    /**
     * Creates a Signer with a private key and a certificate that
     * contains a public key. No verification key is added to the
     * signature. The recipient of the signed document is assumed to
     * have knowledge of this key. The certificate passed is appended
     * to the KeyInfo element.
     * @param doc An XML document
     * @param key key used to sign the document
     * @param cert A certificate containing a public key to include in the signature
     */
    Signer (XmlDocClassPtr doc, KeyPtr key, X509CertificatePtr cert);
    /**
     * Creates a Signer with a private key and a certificate
     * chain. The chain's first element (at index 0) is used for
     * signing, the rest of the certificates will be appended into the
     * X509Data element.
     *
     * Only the first certificate in the chain will have its Issuer
     * Serial information, Subject name and SKI copied; the rest of
     * the certificates will have only the X509Certificate.
     *
     * No verification key is added to the signature.
     * 
     * @param doc An XML document
     * @param key key used to sign the document
     * @param cert a X.509 certificate chain that will be output into the resulting document.
     */
    Signer (XmlDocClassPtr doc, KeyPtr key, vector<X509CertificatePtr> cert);
    /**
     * Destroy the Signer object.
     */
    ~Signer ();

    /**
     * Signs the document and returns a new document containing a
     * Signature element enveloping the signed data.
     * @return a new XmlDoc on success, NULL on failure 
     */
    XmlDocClassPtr sign ();
    /**
     * Signs the document and inserts the Signature element according
     * to the XPath expression (appending the resulting
     * signature). The returned document contains the original
     * document with a Signature element either enveloped or detached,
     * depending on whether the references contain the signature.
     * @param xPath The XPath expression pointing to a single node
     *     that the resulting Signature will be appended to. Note that
     *     it is an error if the xpath expression evaluates to a
     *     NodeList (i.e., must be a single Node)
     * @return a new XmlDoc on success, NULL on failure 
     */
    XmlDocClassPtr sign (XPathPtr xPath);
    /**
     * Signs the document and inserts the Signature element according
     * to the XPath expression (appending the resulting
     * signature). The returned document contains the original
     * document with a Signature element either enveloped or detached,
     * depending on whether the references contain the signature.
     * @param xPath An XPath expression
     * @param insertBefore if true, the signature will be inserted before
     *  the resulting node of the xpath expression; if false, the signature 
     *  will be appended as a child to the resulting node of the Xpath 
     *  expression.
     * @return a new XmlDoc on success, NULL on failure 
     */
    XmlDocClassPtr sign (XPathPtr xPath, bool insertBefore);
    /**
     * Signs the document and returns it. The returned document
     * contains a Signature element enveloping the signed data
     * (replacing previous contents of document).
     * @return 0 if success, -1 if something went wrong
     */
    int signInPlace ();
    /**
     * Signs the document and inserts the Signature element according
     * to the XPath expression. The original document will be
     * returned, amended with a Signature element enveloped or
     * detached, depending on whether the references contain the
     * signature.
     * @param xPath The XPath expression pointing to a single node
     *     that the resulting Signature will be appended to. Note that
     *     it is an error if the xpath expression evaluates to a
     *     NodeList (i.e., must be a single Node)
     * @return 0 if success, -1 if something went wrong
     */
    int signInPlace (XPathPtr xPath);
    /**
     * Signs the document and inserts the Signature element according
     * to the XPath expression (appending the resulting
     * signature). The original document containsis returned. It will
     * contain a Signature element either enveloped or detached,
     * depending on whether the references contain the signature.
     * @param xPath The XPath expression pointing to a single node
     *     that the resulting Signature will be appended to. Note that
     *     it is an error if the xpath expression evaluates to a
     *     NodeList (i.e., must be a single Node)
     * @param insertBefore if true, the signature will be inserted
     *     before the resulting node of the xpath expression; if
     *     false, the signature will be appended as a child to the
     *     resulting node of the Xpath expression.
     * @return 0 if success, -1 if something went wrong
     */
    int signInPlace (XPathPtr xPath, bool insertBefore);
    /**
     * This signer will use the exclusive signature as defined by 
     * http://www.w3.org/2001/10/xml-exc-c14n#.
     * The exclusive c14n algorithm will be used for canonicalization
     * of the signature, as well as for all added transformations
     * The inclusive canonicalization algorithm is the default.
     * @param prefixes string containing space delimited list of ns
     *     prefixes - the inclusive prefix list as defined by the
     *     specification. Any namespace prefix in the list that are
     *     not visibly used in the context will be silently ignored.
     * @return 0 if success, -1 if something went wrong
     */
    int useExclusiveCanonicalizer (string prefixes);
    /**
     * Adds a reference to an existing set of Elements in the
     * document. These elements will be part of the data to be
     * signed. Validation of the XPath expression occurs at signing
     * time.
     * @param xPath An XPath expression
     */
    void addReference (XPathPtr xPath);
    /**
     * Specify that you want to attach a public key to the signature when
     * sign() or signInPlace() is called.  In the case of a DSA or RSA private
     * key, this will cause the public key to be extracted from the private key
     * and attached.  This can only be done for asymmetric keys.  Setting a true value
     * here will not cause a symmetric key to be attached (e.g. HMAC).
     *
     * Default is to not attach the public key.
     *
     * @param value - 1 = attach a public key, 0 - don't attach.
     */
    void attachPublicKey (int value);
    /**
     * Use key from a KeyStore to sign the signature.
     * @param keyStore A key store
     * @return 0 on success, -1 on error
     */
    int setKeyStore (KeyStorePtr keyStore);
    /**
     * Add a certificate to the signature from a file.
     * @param fileName File containing an X509 Certificate
     * @param format Key data format string (see Key::loadFromFile() for format list)
     * @return 0 if success, -1 if something went wrong
     */
    int addCertFromFile (string fileName, string format);
    /**
     * Add a certificate to the signature.
     * @param cert An X509 certificate object
     * @return 0 if success, -1 if something went wrong
     */
    int addCert (X509CertificatePtr cert);

/// @cond NO_INTERFACE
protected:
    /**
     * The XML Document.
     */
    XmlDocClassPtr mXmlDoc;
    /**
     * The private key.
     */
    KeyPtr mKey;
    /**
     * The verifiying key
     */
    KeyPtr mVerifyKey;
    /**
     * XPath references
     */
    vector<XPath> xPathRefs;
    /**
     * Flag for exclusive c14n
     */
    int c14n_excl;
    /**
     * Inclusive ns prefixes for exclusive c14n
     */
    string c14n_excl_incprefixes;
    /**
     * Should we add a keyInfo node?
     */
    int mAddKeyInfo;
    /**
     * Should we add a keyValue node?
     */
    int mAddKeyValue;
    /**
     * KeyStore
     */
    KeyStorePtr keyStore;

    /**
     * Return c14n method based on exclusive flag
     * @return c14n method id
     */
    xmlSecTransformId c14nMethod () const;
    /**
     * Apply c14n method to reference element as transform
     * @param refNode reference element in signature template
     * @return result transform element, or null if error
     */
    xmlNodePtr c14nMethodTransform (xmlNodePtr refNode);
    /**
     * Check if reference element is enveloped in associated XPath expression
     * @param refNode 
     * @param xPath 
     * @return 1 if enveloped, 0 if not, negative on error
     */
    int isEnveloped (xmlNodePtr refNode, XPath& xPath);
    /**
     * Return true if a certificate has been attached to the
     * signing key.
     * @return 1 if a certificate exists, 0 if not, negative on error
     */
    int certAdded ();
    /**
     * Validate the set of XPath references on the current document
     * @return true if all XPath expressions are valid
     */
    int validateXPathRefs ();
    /**
     * Evaluate the XPath expression and return the element referred to
     * The expression must refer to a single node. 
     * @param xPath An XPath expression
     * @return a node pointer, null on error
     */
    xmlNodePtr locateSignature (XPathPtr xPath);
    /**
     * Check for a pre-existing signature element on the given node
     */
    xmlNodePtr checkForSignatureElement (xmlNodePtr node, int insertBefore);
    /**
     * Create a new signature template
     * @param doc A raw xml document pointer
     * @param node the node following which the signature node should be created;
     *  if null, assume an enveloping signature
     * @param insertBefore if true, the signature will be inserted before
     *  the resulting node of the xpath expression; if false, the signature 
     *  will be appended as a child to the resulting node of the Xpath 
     *  expression.
     * @return the signature node pointer, null on failure
     */
    xmlNodePtr createTemplate (xmlDocPtr doc, xmlNodePtr node = 0,
                               bool insertBefore = false);
    /**
     * Signs the document at the specified signature node.
     * @param sigNode signature node
     * @return 0 if success, -1 if something went wrong
     */
    int signNode (xmlNodePtr sigNode);
/// @endcond
};

#endif // _SIGNER_H
