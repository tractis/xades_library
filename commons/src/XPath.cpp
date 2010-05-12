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
#include "XPath.h"
#include "XPathCtx.h"
#include <libxml/xpathInternals.h>
#include <assert.h>


XPath::XPath ()
    : xpObj(0)
{}


XPath::XPath (string expr)
    : xpExpr(expr),
      xpObj(0)
{}


XPath::XPath (const XPath& xpath)
    : xpObj(0)
{
    XPath::operator=(xpath);
}


XPath::~XPath ()
{
    freeXPObj();
}


const XPath& XPath::operator= (const XPath& xpath)
{
    if (&xpath != this)
    {
        xpExpr = xpath.xpExpr;
        nsList = xpath.nsList;
        freeXPObj();
        if (xpath.xpObj != NULL)
        {
            xpObj = xmlXPathObjectCopy(xpath.xpObj);
        }
    }
    return *this;
}


void XPath::freeXPObj ()
{
    if (xpObj)
    {
        xmlXPathFreeObject(xpObj);
        xpObj = NULL;
    }
}


int XPath::addNamespace (string prefix, string uri)
{
    if (uri.size())
    {
        nsList[prefix] = uri;
    }
    else
    {
        nsList.erase(prefix);
    }
    return 0;
}


string XPath::getNamespaceStr ()
{
    string nsStr = "";
    for (XPathNSMap::iterator iter = nsList.begin();
            iter != nsList.end(); iter++)
    {
        nsStr += "xmlns(";
        nsStr += iter->first;
        nsStr += "=";
        nsStr += iter->second;
        nsStr += ")";
    }
    return nsStr;
}


int XPath::registerNamespaces (xmlXPathContextPtr xpCtx)
{
    assert(xpCtx);
    XPathNSMap::iterator iter;
    for (iter = nsList.begin(); iter != nsList.end(); iter++)
    {
        int ret = xmlXPathRegisterNs(xpCtx,
                                     BAD_CAST iter->first.c_str(),
                                     BAD_CAST iter->second.c_str());
        if (ret < 0)
        {
            THROW(LibError, "Failed to register XPath namespace", ret);
        }
    }
    return 0;
}


int XPath::registerNamespaces (xmlXPathContextPtr xpCtx, XmlDocClassPtr xmlDoc)
{
    assert(xpCtx);
    assert(xmlDoc);

    xmlNodePtr rootNode = xmlDocGetRootElement(xmlDoc->getDoc());
    if (!rootNode)
    {
        THROW(XMLError, "Couldn't retrieve document root element", -1);
    }
    for (xmlNsPtr ns = rootNode->nsDef; ns != NULL; ns = ns->next)
    {
        if (ns->prefix)
        {
            int ret = xmlXPathRegisterNs(xpCtx, ns->prefix, ns->href);
            if (ret < 0)
            {
                THROW(LibError, "Failed to register XPath namespace", ret);
            }
        }
    }
    return 0;
}


void XPath::setXPath (string expr)
{
    xpExpr = expr;
    freeXPObj();
}


xmlXPathObjectPtr XPath::evalExpression (XmlDocClassPtr xmlDoc, string expr)
{
    setXPath(expr);
    return evalExpression(xmlDoc);
}


xmlXPathObjectPtr XPath::evalExpression (XmlDocClassPtr xmlDoc)
{
    assert(xmlDoc);
    XPathCtx xpCtx (xmlDoc);
    if (!xpExpr.size())
    {
        THROW(XPathError, "Invalid XPath expression", 0);
    }
    registerNamespaces(xpCtx, xmlDoc);
    registerNamespaces(xpCtx);
    freeXPObj();
    xpObj = xmlXPathEvalExpression(BAD_CAST xpExpr.c_str(), xpCtx);
    return xpObj;
}
