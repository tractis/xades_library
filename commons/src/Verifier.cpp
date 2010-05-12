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
#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/base64.h>
#include <assert.h>

#include "Verifier.h"
#include "Key.h"
#include "XmlDoc.h"
#include "DSigCtx.h"
#include "KeyStore.h"
#include "XPath.h"
#include "KeyInfoCtx.h"
#include "BioWrap.h"
#include "XmlCharBuf.h"
#include "NodeSet.h"
using namespace std;


Verifier::Verifier (XmlDocClassPtr doc)
    : mXmlDoc (doc),
      xPath (0),
      skipCertCheckFlag (0)
{
    verifierInit();
}


Verifier::Verifier (XmlDocClassPtr doc, XPathPtr newXPath)
    : mXmlDoc (doc),
      xPath (newXPath),
      skipCertCheckFlag (0)
{
    verifierInit();

	// Check that xPath points to a single Signature element
	xmlXPathObjectPtr isRefXP = xPath ? xPath->evalExpression(mXmlDoc) : NULL;
    if (isRefXP && isRefXP->nodesetval->nodeNr != 1)
    {
        THROW_NORET(XPathError, "XPath expression must refer to a single node");
    }
}


void Verifier::verifierInit ()
{
    mKeyStore = NULL;
    mDefaultKeyStore = new KeyStore();
    if (!mDefaultKeyStore)
    {
        THROW_NORET(MemoryError, "Could not create default KeyStore");
    }
}


Verifier::~Verifier ()
{
    assert(mDefaultKeyStore);
    mDefaultKeyStore = 0;
}


int Verifier::setKeyStore (KeyStorePtr keyStore)
{
    assert(keyStore);
    if (keyStore->getKeyStore() == NULL)
    {
        THROW(ValueError, "Invalid keystore parameter", -1);
    }
    mKeyStore = keyStore;
    return 0;
}


int Verifier::verify ()
{
    return doVerify(NULL);
}


int Verifier::verify (KeyPtr verifyingKey)
{
    return doVerify(verifyingKey);
}


int Verifier::doVerify (KeyPtr verifyingKey)
{
    KeyPtr key = verifyingKey;
    if (!key)
    {
        key = getVerifyingKey();
    }
    if (!key && !mKeyStore)
    {
        THROW(KeyError, "No verifying key available", -1);
    }
    if (!mXmlDoc || !(*mXmlDoc))
    {
        THROW(DocError, "XML document was not loaded", -1);
    }

    xmlNodePtr node = NULL;
    if ((findStartNode(*mXmlDoc, &node) < 0) || (node == NULL))
    {
        THROW(XMLError, "Can't find start node in document", -1);
    }

    int ret = verifyNode(*mXmlDoc, node, key);
    return ret;
}


int Verifier::findStartNode (xmlDocPtr doc, xmlNodePtr* node)
{
    int res = -1;
    if (xPath)
    {
        if (findSignatureXPath(doc, node) < 0)
        {
            return res;
        }
    }
    else
    {
        *node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature,
                               xmlSecDSigNs);
    }
    return 0;
}


int Verifier::findSignatureXPath (xmlDocPtr doc, xmlNodePtr* node)
{
    assert(xPath);
    xmlXPathObjectPtr xpObj = xPath->evalExpression(mXmlDoc);
    if (xpObj == NULL)
    {
        THROW(XPathError, "Unable to evaluate XPath expression", -1);
    }
    //fprintf(stderr, "'%s' found %d nodes\n", xPath->getXPath().c_str(),
    //        xpObj->nodesetval->nodeNr);
    if (xpObj->nodesetval->nodeNr <= 0)
    {
        THROW(XPathError, "Can't find signature node at XPath expression", -1);
    }
    // Return only the first node in the xpath node set
    *node = xpObj->nodesetval->nodeTab[0];
    return 0;
}


xmlSecKeysMngrPtr Verifier::getKeysMngr ()
{
    KeyStorePtr keyStore = mDefaultKeyStore;
    if (mKeyStore)
    {
        keyStore = mKeyStore;
    }
    assert(keyStore);
    return keyStore->getKeyStore();
}


int Verifier::verifyNode (xmlDocPtr doc, xmlNodePtr node, KeyPtr key)
{
    assert(doc);
    assert(node);

    // create signature context
    DSigCtx dsigCtx (getKeysMngr());
    if (!dsigCtx)
    {
        return -1;
    }
    if (key)
    {
        dsigCtx->signKey = key->dupKey();
    }

    // Set cert chain not to verify on key info read if requested
    if (skipCertCheckFlag)
    {
        dsigCtx->keyInfoReadCtx.flags |=
            XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
    }

    // Verify signature
    if (xmlSecDSigCtxVerify(dsigCtx, node) < 0)
    {
        THROW(LibError, "Signature verify fn failure", -1);
    }

    // return verification result
    return (dsigCtx->status == xmlSecDSigStatusSucceeded);
}


KeyPtr Verifier::getVerifyingKey ()
{
    if (!mXmlDoc || !(*mXmlDoc))
    {
        THROW(DocError, "XML document was not loaded", 0);
    }

    xmlNodePtr sigNode = NULL;
    if (findStartNode(*mXmlDoc, &sigNode) < 0)
    {
        THROW(XMLError, "Can't find start node in document", 0);
    }
    // find keyinfo node
    xmlNodePtr node = xmlSecFindNode(sigNode, xmlSecNodeKeyInfo, xmlSecDSigNs);
    if (node == NULL)
    {
        // not an error, keyinfo may not exist
        return 0;
    }

    KeyPtr keyObj = new Key();
    int ret = -1;
    try
    {
        ret = keyObj->loadFromKeyInfo(node, getKeysMngr());
		if (ret >= 0)
		{
			X509CertificatePtr x509cert = getCertificate();
			if (x509cert)
			{
				// Return null if key is not equal to certificate's key
				// since both exists
				KeyPtr certKeyObj = x509cert->getKey();
				if (*certKeyObj != *keyObj)
					return 0;
			}
		}
    }
    catch (LibError&)
    {}
    if (ret < 0)
    {
        X509CertificatePtr x509cert = getCertificate();
        if (x509cert)
        {
            keyObj = x509cert->getKey();
        }
    }
    return keyObj;
}


X509CertificatePtr Verifier::getCertificate ()
{
    vector<X509CertificatePtr> certChain = getCertificateChain();
    if (certChain.size())
    {
        return certChain[0];
    }
    return 0;
}


// TODO sort chain into subject-issuer order?
vector<X509CertificatePtr> Verifier::getCertificateChain ()
{
    vector<X509CertificatePtr> certChain;
    if (!mXmlDoc || !(*mXmlDoc))
    {
        THROW(DocError, "XML document was not loaded", certChain);
    }

    xmlNodePtr sigNode = NULL;
    if (findStartNode(*mXmlDoc, &sigNode) < 0)
    {
        THROW(XMLError, "Can't find start node in document", certChain);
    }
    // find keyinfo node
    xmlNodePtr node = xmlSecFindNode(sigNode, xmlSecNodeKeyInfo, xmlSecDSigNs);
    if (node == NULL)
    {
        // not an error, keyinfo may not exist
        return certChain;
    }
    if (!xmlSecCheckNodeName(node, xmlSecNodeKeyInfo, xmlSecDSigNs))
    {
        THROW(XMLError, "Invalid key info node", certChain);
    }
    KeyInfoCtx keyInfoCtx;
    if (!keyInfoCtx)
    {
        return certChain;
    }
    keyInfoCtx->mode = xmlSecKeyInfoModeRead;
    keyInfoCtx->flags = XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND |
                        XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
    keyInfoCtx->keysMngr = getKeysMngr();
    Key keyObj;
    keyObj.create();
    if (xmlSecKeyInfoNodeRead(node, keyObj, keyInfoCtx) < 0)
    {
        THROW(LibError, "Couldn't read key info node", certChain);
    }
    if (!keyObj)
    {
        try
        {
            certChain = getX509Data(node);
        }
        catch (XMLError&)
        {}
    }
    else
    {
        certChain = keyObj.getCertificateChain();
    }
    return certChain;
}


vector<X509CertificatePtr> Verifier::getX509Data (xmlNodePtr node)
{
    vector<X509CertificatePtr> certChain;

    node = xmlSecFindNode(node, xmlSecNodeX509Data, xmlSecDSigNs);
    if (node == NULL)
    {
        THROW(XMLError, "Can't find X509Data node", certChain);
    }
    for (xmlNodePtr cur = xmlSecGetNextElementNode(node->children);
            cur != NULL;
            cur = xmlSecGetNextElementNode(cur->next))
    {
        if (xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs))
        {
            X509CertificatePtr x509 = getX509CertificateNode(cur);
            if (x509)
            {
                certChain.push_back(x509);
            }
        }
    }
    return certChain;
}


X509CertificatePtr Verifier::getX509CertificateNode (xmlNodePtr node)
{
    if ((node == NULL) ||
            (!xmlSecCheckNodeName(node, xmlSecNodeX509Certificate, xmlSecDSigNs)))
    {
        return 0;
    }
    XmlCharBuf buf (xmlNodeGetContent(node));
    if (!(int)buf || xmlSecIsEmptyString(buf))
    {
        THROW(XMLError, "X509Certificate has no content", 0);
    }
    int size = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf));
    if (size < 0)
    {
        THROW(XMLError, "Failed to decode X509Certificate content", 0);
    }
    BioWrap mem;
    if (!(int)mem || (mem.write(buf, size) <= 0))
    {
        return 0;
    }
    X509* cert = d2i_X509_bio(mem, NULL);
    if (cert == NULL)
    {
        THROW(LibError, "Couldn't load certificate from BIO", 0);
    }
    return new X509Certificate(cert);
}


int Verifier::isContained (xmlSecNodeSetPtr nodeSet, XPathPtr xPathElem)
{
    assert(xPathElem);
    xmlXPathObjectPtr isRefXP = xPathElem->evalExpression(mXmlDoc);
    if (isRefXP == 0)
    {
        return -1;
    }
    if (isRefXP->nodesetval->nodeNr != 1)
    {
        THROW(XPathError, "XPath expression must refer to a single node", -1);
    }
    xmlNodePtr node = *(isRefXP->nodesetval->nodeTab);
    assert(node);

    return xmlSecNodeSetContains(nodeSet, node, node->parent);
}


int Verifier::refNodes (Verifier::refNodesCallback callbackFn, void* data)
{
    assert(mXmlDoc);
    if (!mXmlDoc || !(*mXmlDoc))
    {
        THROW(DocError, "XML document was not loaded", -1);
    }

    // create signature context
    DSigCtx dsigCtx (getKeysMngr());
    if (!dsigCtx)
    {
        return -1;
    }
    xmlNodePtr node = 0;
    if (findStartNode(*mXmlDoc, &node) < 0)
    {
        THROW(XMLError, "Can't find start node in document", -1);
    }
    dsigCtx->operation = xmlSecTransformOperationVerify;
    dsigCtx->status = xmlSecDSigStatusUnknown;
    dsigCtx->id = xmlGetProp(node, xmlSecAttrId);
    //xmlSecAddIDs(node->doc, node, xmlSecDSigIds);

    node = xmlSecGetNextElementNode(node->children);
    if ((node == NULL) ||
            (!xmlSecCheckNodeName(node, xmlSecNodeSignedInfo, xmlSecDSigNs)))
    {
        THROW(XMLError, "Expected signed info node", -1);
    }

    // Get c14 method and add it to new transform ctx
    xmlNodePtr cur = xmlSecGetNextElementNode(node->children);
    if ((cur != NULL) &&
            (xmlSecCheckNodeName(cur, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs)))
    {
        dsigCtx->c14nMethod =
            xmlSecTransformCtxNodeRead(&(dsigCtx->transformCtx),
                                       cur,
                                       xmlSecTransformUsageC14NMethod);
        if (dsigCtx->c14nMethod == NULL)
        {
            THROW(LibError, "Unable to create transform context with c14n method from node", -1);
        }
    }
    else if (dsigCtx->defC14NMethodId != xmlSecTransformIdUnknown)
    {
        dsigCtx->c14nMethod =
            xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx),
                                              dsigCtx->defC14NMethodId);
        if (dsigCtx->c14nMethod == NULL)
        {
            THROW(LibError, "Unable to create transform ctx with c14n method", -1);
        }
    }
    else
    {
        THROW(XMLError, "Expected c14n method", -1);
    }

    // Set up signature method
    cur = xmlSecGetNextElementNode(cur->next);
    if ((cur != NULL) &&
            (xmlSecCheckNodeName(cur, xmlSecNodeSignatureMethod, xmlSecDSigNs)))
    {
        dsigCtx->signMethod =
            xmlSecTransformCtxNodeRead(&(dsigCtx->transformCtx),
                                       cur, xmlSecTransformUsageSignatureMethod);
        if (dsigCtx->signMethod == NULL)
        {
            THROW(LibError, "Unable to read signature method from node", -1);
        }
    }
    else if (dsigCtx->defSignMethodId != xmlSecTransformIdUnknown)
    {
        dsigCtx->signMethod =
            xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx),
                                              dsigCtx->defSignMethodId);
        if (dsigCtx->signMethod == NULL)
        {
            THROW(LibError, "Unable to create signature method", -1);
        }
    }
    else
    {
        THROW(XMLError, "Expected signature method", -1);
    }

    cur = xmlSecGetNextElementNode(cur->next);
    while ((cur != NULL) &&
            (xmlSecCheckNodeName(cur, xmlSecNodeReference, xmlSecDSigNs)))
    {
        // Don't have to call xmlSecDSigReferenceCtxDestroy because
        // dsigCtx will own dsigRefCtx
        xmlSecDSigReferenceCtxPtr dsigRefCtx =
            xmlSecDSigReferenceCtxCreate(dsigCtx,
                                         xmlSecDSigReferenceOriginSignedInfo);
        if (dsigRefCtx == NULL)
        {
            THROW(LibError, "Couldn't create DSIG reference context", -1);
        }
        if (xmlSecPtrListAdd(&(dsigCtx->signedInfoReferences), dsigRefCtx) < 0)
        {
            THROW(LibError, "Couldn't add reference ctx to dsigCtx", -1);
        }
        if (xmlSecDSigReferenceCtxProcessNode(dsigRefCtx, cur) < 0)
        {
            THROW(LibError, "Failed to process reference node", -1);
        }
        if (dsigRefCtx->status != xmlSecDSigStatusSucceeded)
        {
            THROW(LibError, "Process reference node status failure", -1);
        }
        // xmlSecDSigReferenceCtxDebugDump(dsigRefCtx, stderr);
        NodeSet nodes (nodeSetFromTransformCtx(&(dsigRefCtx->transformCtx), *mXmlDoc));
        if (!nodes)
        {
            return 0;
        }
        dsigRefCtx->transformCtx.result = NULL;
        dsigRefCtx->transformCtx.status = xmlSecTransformStatusNone;

        xmlSecTransformPtr transformPtr = dsigRefCtx->transformCtx.first;
        while (transformPtr != NULL)
        {
            transformPtr->inNodes = NULL;
            transformPtr->outNodes = NULL;
            transformPtr = transformPtr->next;
        }

        if (xmlSecTransformCtxXmlExecute(&(dsigRefCtx->transformCtx), nodes) < 0)
        {
            THROW(LibError, "Transform execute failure", -1);
        }

        transformPtr = dsigRefCtx->transformCtx.first;
        while (transformPtr != NULL)
        {
            if (transformPtr->next &&
                    (transformPtr->next->id->usage | xmlSecTransformUsageC14NMethod))
            {
                break;
            }
            transformPtr = transformPtr->next;
        }
        if (!transformPtr || !transformPtr->outNodes)
        {
            THROW(XMLError, "Couldn't find transform node", -1);
        }
        { 
            int ret = (*callbackFn)(transformPtr->outNodes, this, data);
            if (ret != 0)
            {
                return ret;
            }
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }
    return 0;
}


int Verifier::isReferencedCallback (xmlSecNodeSetPtr nset, Verifier* verifier, void* data)
{
    assert(verifier);
    assert(data);
    if (nset == NULL)
    {
        return 0;
    }
    XPathPtr xPathElem (*(XPathPtr*)data);
    return verifier->isContained(nset, xPathElem);
}


int Verifier::isReferenced (XPathPtr xPathElem)
{
    assert(xPathElem);
    return refNodes(Verifier::isReferencedCallback, &xPathElem);
}


int Verifier::getElementsCallback (xmlSecNodeSetPtr, xmlNodePtr cur, xmlNodePtr, void *data)
{
    try
    {
        XmlElementPtr element (new XmlElement(cur));
        if (element)
        {
            if (*element)
            {
                vector<XmlElementPtr>& elementVec (*(vector<XmlElementPtr>*)data);
                elementVec.push_back(element);
            }
        }
    }
    // ignore exception thrown if cur node is not of element type
    catch (XMLError) 
    {}
    return 0;
}


int Verifier::getReferencedElementsCallback (xmlSecNodeSetPtr nset, Verifier* verifier, void* data)
{
    assert(verifier);
    assert(data);
    if (nset == NULL)
    {
        return 0;
    }
    if (xmlSecNodeSetWalk(nset, Verifier::getElementsCallback, data) < 0)
    {
        THROW(LibError, "Node set walk failure", -1);
    }
    return 0;
}


vector<XmlElementPtr> Verifier::getReferencedElements ()
{
    vector<XmlElementPtr> elementVec;
    if (refNodes(Verifier::getReferencedElementsCallback, &elementVec) < 0)
    {
        vector<XmlElementPtr> nullVec;
        return nullVec;
    }
    return elementVec;
}


xmlSecNodeSetPtr Verifier::nodeSetFromTransformCtx (xmlSecTransformCtxPtr ctx, xmlDocPtr doc)
{
    xmlSecNodeSetPtr nodes;

    if ((ctx->uri != NULL) &&
            (xmlStrlen(ctx->uri) > 0))
    {
        return NULL;
    }

    if ((ctx->xptrExpr != NULL) && (xmlStrlen(ctx->xptrExpr) > 0))
    {
        // our xpointer transform takes care of providing correct nodes set
        nodes = xmlSecNodeSetCreate(doc, NULL, xmlSecNodeSetNormal);
    }
    else
    {
        // we do not want to have comments for empty URI
        nodes = xmlSecNodeSetGetChildren(doc, NULL, 0, 0);
    }
    if (nodes == NULL)
    {
        THROW(LibError, "Unable to create nodeset", 0);
    }
    return nodes;
}
