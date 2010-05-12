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
#ifndef _XPATH_H
#define _XPATH_H
#include <string>
#include <map>
#include <functional>
#include <libxml/xpath.h>
#include "XmlDoc.h"
#include "Exceptions.h"
using namespace std;

typedef map<string, string, less<string> > XPathNSMap;

/**
 * XPath encapsulates a W3C XPath
 * (http://www.w3.org/TR/1999/REC-xpath-19991116) expression and
 * namespaces that relate to the expression.
 */
class XPath
{
public:
    /**
     * Creates an empty XPath helper.
     */
    XPath();
    /**
     * Creates an XPath helper with an XPath expression.
     * @param expr An XPath expression
     */
    XPath(string expr);
    /**
     * Frees the XPath object and any results.
     */
    ~XPath();

    /**
     * Add namespace prefix.
     * @return 0 on success, -1 on error
     */
    int addNamespace (string prefix, string uri);
    /**
     * Get the XPath expression.
     * @return string containing expression
     */
    string getXPath () const
    {
        return xpExpr;
    }
    /**
     * Set the XPath expression.
     * @param expr XPath expression
     * @return 0 on success, -1 on error
     */
    void setXPath (string expr);

    /// @cond NO_INTERFACE
    /**
     * Creates a copy of an XPath helper.
     * @param xpath An XPath helper object
     */
    XPath(const XPath& xpath);
    /**
     * Copy the given XPath object.
     * @param xpath An XPath helper object
     * @return The copy of the object
     */
    const XPath& operator=(const XPath& xpath);
    /**
     * Get namespace prefix definitions in a form appropriate for
     * including in a Reference URI attribute.
     * @return namespace prefix string of the form xmlns(prefix=uri);
     *     multiple definitions are concatenated
     */
    string getNamespaceStr ();
    /**
     * Evaluate current expression.
     * @param doc pointer to XmlDoc to execute XPath expression on
     * @return xmlXPathObjectPtr with results, null on failure
     * @throws XPathError on an invalid XPath expression
     */
    xmlXPathObjectPtr evalExpression (XmlDocClassPtr doc);
    /**
     * Evaluate given expression.
     * @param doc pointer to XmlDoc to execute XPath expression on
     * @param expr XPath expression
     * @return xmlXPathObjectPtr with results, null on failure
     * @throws XPathError on an invalid XPath expression
     */
    xmlXPathObjectPtr evalExpression (XmlDocClassPtr doc, string expr);
    /**
     * Return the current expression results
     * @return xmlXPathObjectPtr with results, null if none exist
     */
    xmlXPathObjectPtr getObj()
    {
        return xpObj;
    }

protected:
    /**
     * Current XPath expression
     */
    string xpExpr;
    /**
     * List of prefix->uri mappings for XPath namespaces
     */
    XPathNSMap nsList;
    /**
     * The current expression results
     */
    xmlXPathObjectPtr xpObj;

    /**
     * Register the namespaces in nsList with the XPath context.
     * @param xpCtx XPath context pointer
     * @return 0 on success, -1 on error
     * @throws LibError if it fails to register a namespace
     */
    int registerNamespaces (xmlXPathContextPtr xpCtx);
    /**
     * Register the namespaces defined in the root node of the
     * document with the XPath context.
     * @param xpCtx XPath context pointer
     * @param xmlDoc XML document to get namespaces from
     * @return 0 on success, -1 on error
     * @throws LibError if it fails to register a namespace
     * @throws XMLError if unable to retrieve the root element of the document
     */
    int registerNamespaces (xmlXPathContextPtr xpCtx, XmlDocClassPtr xmlDoc);

    /**
     * Dispose of current expression results
     */
    void freeXPObj ();
/// @endcond
};

#include "countptr.h"
typedef CountPtrTo<XPath> XPathPtr;

#endif
