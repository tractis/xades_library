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

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/debugXML.h>
#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#if defined(WIN32) && defined(PHP_EXPORTS)
#define IN_XMLSEC
#endif
#include <xmlsec/openssl/symbols.h>
#include <assert.h>

#include "Signer.h"
#include "Key.h"
#include "XmlDoc.h"
#include "XPath.h"
#include "DSigCtx.h"
#include "KeysMngrWrap.h"
#include "XmlCharBuf.h"
using namespace std;


Signer::Signer (XmlDocClassPtr doc, KeyPtr key)
    : mXmlDoc(doc),
      mKey(key),
      mVerifyKey(0),
      c14n_excl(0),
      mAddKeyInfo(0),
      mAddKeyValue(0)
{}


Signer::Signer (XmlDocClassPtr doc, KeyPtr key, KeyPtr verifyKey)
    : mXmlDoc(doc),
      mKey(key),
      mVerifyKey(verifyKey),
      c14n_excl(0),
      mAddKeyInfo(0),
      mAddKeyValue(0)
{
    if (!mVerifyKey)
    {
        return;
    }
    key->addCert(mVerifyKey);
    mAddKeyInfo = 1;
    mAddKeyValue = 1;
}


Signer::Signer (XmlDocClassPtr doc, KeyPtr key, X509CertificatePtr cert)
    : mXmlDoc(doc),
      mKey(key),
      mVerifyKey(0),
      c14n_excl(0),
      mAddKeyInfo(0),
      mAddKeyValue(0)
{
    if (key && key->isValid() && cert)
    {
        mVerifyKey = cert->getKey();
        if (mKey->addCert(cert) >= 0)
        {
            mAddKeyInfo = 1;
        }
    }
}


Signer::Signer (XmlDocClassPtr doc, KeyPtr key, vector<X509CertificatePtr> cert)
    : mXmlDoc(doc),
      mKey(key),
      mVerifyKey(0),
      c14n_excl(0),
      mAddKeyInfo(0),
      mAddKeyValue(0)
{
    if (key && key->isValid() && (cert.size() > 0))
    {
        mVerifyKey = cert[0]->getKey();
        if (mKey->addCert(cert) >= 0)
        {
            mAddKeyInfo = 1;
        }
    }
}


Signer::~Signer ()
{}


XmlDocClassPtr Signer::sign ()
{
    return sign((XPathPtr)0);
}


XmlDocClassPtr Signer::sign (XPathPtr xPath)
{
    return sign(xPath, false);
}


XmlDocClassPtr Signer::sign (XPathPtr xPath, bool insertBefore)
{
    assert(mXmlDoc);
    XmlDocClassPtr copyDoc = new XmlDoc(*mXmlDoc);
    if (!copyDoc)
    {
        THROW(MemoryError, "Unable to create duplicate XML document", 0);
    }
    XmlDocClassPtr origXmlDoc = mXmlDoc;
    mXmlDoc = copyDoc;
    int retVal = xPath ? signInPlace(xPath, insertBefore) : signInPlace();
    mXmlDoc = origXmlDoc;
    if (retVal < 0)
    {
        return 0;
    }
    return copyDoc;
}


int Signer::signInPlace ()
{
    assert(mXmlDoc);
    if (!*mXmlDoc)
    {
        THROW(DocError, "Document was not loaded", -1);
    }
    if (!validateXPathRefs())
    {
        THROW(XPathError, "Invalid XPath references", -1);
    }
    xmlNodePtr sigNode = xmlSecFindNode(xmlDocGetRootElement(*mXmlDoc),
                                        xmlSecNodeSignature, xmlSecDSigNs);
    if (sigNode == NULL)
    {
        sigNode = createTemplate(*mXmlDoc, 0, false);
    }
    return signNode(sigNode);
}


int Signer::signInPlace (XPathPtr xPath)
{
    return signInPlace(xPath, false);
}


int Signer::signInPlace (XPathPtr xPath, bool insertBefore)
{
    assert(xPath);
    assert(mXmlDoc);
    if (!*mXmlDoc)
    {
        THROW(DocError, "Document was not loaded", -1);
    }
    if (!validateXPathRefs())
    {
        THROW(XPathError, "Invalid XPath references", -1);
    }
    xmlNodePtr node = locateSignature(xPath);
    if (!node)
    {
        return -1;
    }
    xmlNodePtr sigNode = checkForSignatureElement(node, insertBefore);
    if (!sigNode)
    {
        sigNode = createTemplate(*mXmlDoc, node, insertBefore);
    }
    return signNode(sigNode);
}


xmlNodePtr Signer::locateSignature (XPathPtr xPath)
{
    xmlXPathObjectPtr xpObj = xPath->evalExpression(mXmlDoc);
    if (xpObj == NULL)
    {
        THROW(XPathError, "Unable to evaluate XPath expression", 0);
    }
    //fprintf(stderr, "'%s' found %d nodes\n", xpathstr, xpObj->nodesetval->nodeNr);
    if (xpObj->nodesetval->nodeNr == 0)
    {
        THROW(XPathError, "No nodes found for XPath expression", 0);
    }
    if (xpObj->nodesetval->nodeNr > 1)
    {
        THROW(XPathError, "Multiple nodes found for XPath expression", 0);
    }
    xmlNodePtr node = *(xpObj->nodesetval->nodeTab);
    if (node->type == XML_DOCUMENT_NODE)
    {
        // take care of the "/" xpath case; we sign the first child of the doc
        // instead of the entire doc (a fine but necessary distinction)
        node = node->children;
    }
    //xmlElemDump(stderr, *mXmlDoc, node);
    return node;
}


xmlNodePtr Signer::checkForSignatureElement (xmlNodePtr node, int insertBefore)
{
    xmlNodePtr sigNode = 0;
    if (node)
    {
        if (insertBefore && (node->parent->type != XML_DOCUMENT_NODE))
        {
            // Check previous sibling
            node = node->prev;
        }
        else
        {
            // Check children
            node = xmlSecFindChild(node, xmlSecNodeSignature, xmlSecDSigNs);
        }
    }
    else
    {
        // check root element
        node = xmlDocGetRootElement(*mXmlDoc);
    }
    if (node && xmlSecCheckNodeName(node, xmlSecNodeSignature, xmlSecDSigNs))
    {
        sigNode = node;
    }
    return sigNode;
}


int Signer::setKeyStore (KeyStorePtr newKeyStore)
{
    keyStore = newKeyStore;
    return keyStore ? 0 : -1;
}


void Signer::attachPublicKey (int value)
{
    mAddKeyValue = value;
}


int Signer::addCertFromFile (string fileName, string format)
{
    assert(mKey);
    if (mKey->addCertFromFile(fileName, format) < 0)
    {
        return -1;
    }
    mAddKeyInfo = 1;
    return 0;
}


int Signer::addCert (X509CertificatePtr cert)
{
    assert(mKey);
    if (mKey->addCert(cert) < 0)
    {
        return -1;
    }
    mAddKeyInfo = 1;
    return 0;
}


int Signer::useExclusiveCanonicalizer (string prefixes)
{
    c14n_excl = 1;
    c14n_excl_incprefixes = prefixes;
    return 0;
}


void Signer::addReference (XPathPtr xPathPtr)
{
    assert(xPathPtr);
    XPath xPath (*xPathPtr);
    xPathRefs.push_back(xPath);
}


xmlSecTransformId Signer::c14nMethod () const
{
    return c14n_excl ?
           xmlSecTransformExclC14NId :
           xmlSecTransformInclC14NId;
}


xmlNodePtr Signer::c14nMethodTransform (xmlNodePtr refNode)
{
    assert(refNode);
    xmlNodePtr xformNode = xmlSecTmplReferenceAddTransform(refNode,
                           c14nMethod());
    if (xformNode == 0)
    {
        THROW(LibError, "Failed to add c14n transform to reference", 0);
    }
    return xformNode;
}


int Signer::isEnveloped (xmlNodePtr refNode, XPath& xPath)
{
    xmlXPathObjectPtr xpObj = xPath.evalExpression(mXmlDoc);
    if (xpObj == NULL)
    {
        THROW(XPathError, "Unable to evaluate XPath expression", -1);
    }
    xmlSecNodeSetPtr nodes = xmlSecNodeSetCreate(*mXmlDoc,
                             xpObj->nodesetval,
                             xmlSecNodeSetTree);
    if (nodes == NULL)
    {
        THROW(LibError, "Unable to create node set from XPath results", -1);
    }
    int ret = xmlSecNodeSetContains(nodes, refNode, refNode->parent);
    if (ret < 0)
    {
        THROW(LibError, "Failure checking containment in node set", ret);
    }
    return ret;
}


int Signer::certAdded ()
{
    int certAdded = 0;
    if (mKey)
    {
        X509CertificatePtr cert = mKey->getCertificate();
        certAdded = ((const void*)cert != 0);
    }
    return certAdded;
}


xmlNodePtr Signer::createTemplate (xmlDocPtr doc, xmlNodePtr node, bool insertBefore)
{
    assert(doc);
    assert(mKey);
    assert(mKey->getKey());
    assert(mKey->getKey()->value);
    assert(mKey->getKey()->value->id);

    XmlCharBuf objectId (xmlSecGenerateID(BAD_CAST "obj-", 10));
    if (!(int)objectId)
    {
        THROW(MemoryError, "Unable to allocate generated ID", 0);
    }

    xmlSecKeyDataId keyDataId = mKey->getKey()->value->id;
    xmlSecTransformId signatureTransformId = NULL;
    if (keyDataId == xmlSecKeyDataDsaId)
    {
        signatureTransformId = xmlSecTransformDsaSha1Id;
    }
    else if (keyDataId == xmlSecKeyDataRsaId)
    {
        signatureTransformId = xmlSecTransformRsaSha1Id;
    }
    else if (keyDataId == xmlSecKeyDataHmacId)
    {
        signatureTransformId = xmlSecTransformHmacSha1Id;
    }
    else
    {
        THROW(KeyError, "Unable to find signature transform for key type", 0);
    }
    xmlNodePtr sigNode =
#ifdef HAVE_XMLSECTMPLSIGNATURECREATENSPREF
        xmlSecTmplSignatureCreateNsPref(doc, c14nMethod(), signatureTransformId, NULL, BAD_CAST "ds");
#else
        xmlSecTmplSignatureCreate(doc, c14nMethod(), signatureTransformId, NULL);
#endif
    if (sigNode == NULL)
    {
        THROW(LibError, "Failed to create signature template", 0);
    }

    // enveloping if no location to put the signature
    if (node == NULL)
    {
        // add <dsig:Signature/> node to the doc
        xmlNodePtr objContents = xmlDocGetRootElement(doc);
        xmlDocSetRootElement(doc, sigNode);

        // Add ObjectNode
        xmlNodePtr objNode = xmlSecTmplSignatureAddObject(xmlDocGetRootElement(doc),
                             BAD_CAST objectId, NULL, NULL);
        if (objNode == NULL)
        {
            THROW(LibError, "Failed to add object to signature template", 0);
        }

        xmlAddChild(objNode, objContents);
    }

    if (c14n_excl)
    {
        xmlNodePtr c14nMethodNode = xmlSecTmplSignatureGetC14NMethodNode(sigNode);
        if (c14nMethodNode == NULL)
        {
            THROW(LibError, "Couldn't retrieve C14N method node", 0);
        }
        if (c14n_excl_incprefixes.length() > 0)
        {
            if (xmlSecTmplTransformAddC14NInclNamespaces(c14nMethodNode,
                    BAD_CAST c14n_excl_incprefixes.c_str()) < 0)
            {
                THROW(LibError, "Couldn't set C14N incl namespaces", 0);
            }
        }
    }

    if (xPathRefs.size() > 0)
    {
        for (vector<XPath>::iterator xPathRef = xPathRefs.begin();
                xPathRef != xPathRefs.end(); xPathRef++)
        {
            int enveloped = 0;
            string uri ("");
            // don't use xpointer(/), use "" instead for greater compatibility
            if (xPathRef->getXPath() != "/")
            {
                uri = "#";
                uri += xPathRef->getNamespaceStr();
                if (node == NULL)
                {
                    uri += "xmlns(dsig=http://www.w3.org/2000/09/xmldsig#)xpointer(";
                    uri += "/descendant::dsig:Object[@Id='";
                    uri += (const char*)objectId;
                    uri += "']";
                }
                else
                {
                    uri += "xpointer(";
                }
                uri += xPathRef->getXPath();
                uri += ")";
            }
            else
            {
                // reference is "/", so we're definitely enveloped
                enveloped = 1;
            }
            xmlNodePtr refNode =
                xmlSecTmplSignatureAddReference(sigNode, xmlSecTransformSha1Id,
                                                NULL, BAD_CAST uri.c_str(), NULL);
            if (refNode == NULL)
            {
                THROW(LibError, "Failed to add reference to signature template", 0);
            }
            if (node)
            {
                enveloped = enveloped || isEnveloped(node, *xPathRef);
                if (enveloped < 0)
                {
                    return 0;
                }
                else if (enveloped)
                {
                    // add enveloped transform
                    if (xmlSecTmplReferenceAddTransform(refNode,
                                                        xmlSecTransformEnvelopedId) == NULL)
                    {
                        THROW(LibError, "Failed to add enveloped transform to reference", 0);
                    }
                }
            }
            if (c14nMethodTransform(refNode) == 0)
            {
                return 0;
            }
        }
    }
    else if (node)
    {
        // add reference
        xmlNodePtr refNode =
            xmlSecTmplSignatureAddReference(sigNode, xmlSecTransformSha1Id,
                                            NULL, BAD_CAST "", NULL);
        if (refNode == NULL)
        {
            THROW(LibError, "Failed to add reference to signature template", 0);
        }

        // add enveloped transform
        if (xmlSecTmplReferenceAddTransform(refNode,
                                            xmlSecTransformEnvelopedId) == NULL)
        {
            THROW(LibError, "Failed to add enveloped transform to reference", 0);
        }
        if (c14nMethodTransform(refNode) == 0)
        {
            return 0;
        }
    }
    else
    {
        string objectRef;
        objectRef += "#";
        objectRef += (const char*)objectId;
        xmlNodePtr refNode =
            xmlSecTmplSignatureAddReference(xmlDocGetRootElement(doc),
                                            xmlSecTransformSha1Id,
                                            NULL, BAD_CAST objectRef.c_str(), NULL);
        if (refNode == NULL)
        {
            THROW(LibError, "Failed to add reference to signature template", 0);
        }
        if (c14nMethodTransform(refNode) == 0)
        {
            return 0;
        }
    }

    // add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name
    // in the signed document
    // Don't add <dsig:KeyInfo/> unless absolutely necessary though
    xmlNodePtr keyInfoNode = NULL;

    if (mAddKeyInfo || mAddKeyValue || keyStore)
    {
        if (!keyInfoNode)
        {
            keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(sigNode, NULL);
            if (keyInfoNode == NULL)
            {
                THROW(LibError, "Failed to add key info to signature template", 0);
            }
        }
        if (mAddKeyValue) {
            if (xmlSecTmplKeyInfoAddKeyValue(keyInfoNode) == NULL)
            {
                THROW(LibError, "Failed to add key value to signature template", 0);
            }
        }
    }

    if (certAdded() > 0)
    {
        if (!keyInfoNode)
        {
            keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(sigNode, NULL);
            if (keyInfoNode == NULL)
            {
                THROW(LibError, "Failed to add key info to signature template", 0);
            }
        }
        if (xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL)
        {
            THROW(LibError, "Failed to add X509Data node to signature template", 0);
        }
    }

    if (mKey->getName().length())
    {
        if (!keyInfoNode)
        {
            keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(sigNode, NULL);
            if (keyInfoNode == NULL)
            {
                THROW(LibError, "Failed to add key info to signature template", 0);
            }
        }
        if (xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL)
        {
            THROW(LibError, "Failed to add key name to signature template", 0);
        }
    }

    if (node)
    {
        if (insertBefore && (node->parent->type != XML_DOCUMENT_NODE))
        {
            return xmlAddPrevSibling(node, sigNode);
        }
        return xmlAddChild(node, sigNode);
    }
    return xmlDocGetRootElement(doc);
}


int Signer::signNode (xmlNodePtr sigNode)
{
    //xmlDocDump(stderr, sigNode->doc);
    if (!sigNode ||
            !xmlSecCheckNodeName(sigNode, xmlSecNodeSignature, xmlSecDSigNs))
    {
        THROW(XMLError, "Invalid signature node", -1);
    }

    if (!mKey || !(*mKey))
    {
        THROW(KeyError, "Key was not loaded", -1);
    }

    // create a keys manager if necessary
    KeysMngr localKeysMngr;
    xmlSecKeysMngrPtr keysMngr = 0;
    if (keyStore)
    {
        keysMngr = *keyStore;
    }
    else
    {
        keysMngr = localKeysMngr;
    }

    if (mVerifyKey)
    {
        if ((!keysMngr) ||
                (xmlSecOpenSSLAppDefaultKeysMngrInit(keysMngr) < 0))
        {
            THROW(LibError, "Key manager not created", -1);
        }
        // create a duplicate so keys mngr can adopt it & destroy later
        xmlSecKeyPtr vKey = mVerifyKey->dupKey();
        if (vKey == NULL)
        {
            return -1;
        }
        if (xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(keysMngr, vKey) < 0)
        {
            THROW(LibError, "Unable to adopt verify key into key manager", -1);
        }
    }

    DSigCtx dsigCtx(keysMngr);
    if (!dsigCtx)
    {
        return -1;
    }
    // dsigCtx destruction also tries to free key, so give it a dup
    dsigCtx->signKey = mKey->dupKey();

    // sign the template
    if (xmlSecDSigCtxSign(dsigCtx, sigNode) < 0)
    {
        THROW(LibError, "Signature failed", -1);
    }
    // success
    return 0;
}


int Signer::validateXPathRefs ()
{
    int valid = 1;
    for (vector<XPath>::iterator xPathRef = xPathRefs.begin();
            xPathRef != xPathRefs.end(); xPathRef++)
    {
        valid = valid && (xPathRef->evalExpression(mXmlDoc) != 0);
        // fprintf(stderr, "Checking '%s': valid %d\n",
        //        xPathRef->getXPath().c_str(), valid);
    }
    return valid;
}
