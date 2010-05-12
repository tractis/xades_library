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
#ifndef _XMLDOC_H
#define _XMLDOC_H
#include <string>
#include <vector>
#include <libxml/parser.h>
#include "Exceptions.h"
using namespace std;

/**
 * An XML document.
 * Encapsulates a LibXML2 XML Document object.  Provides methods
 * to load and save to other formats.  For now it just loads/saves the
 * document to a file or a string, but more methods could be added to load/save
 * to/from other XML representations/objects.
 */
class XmlDoc
{
public:
    /**
     * Construct an empty document.
     */
    XmlDoc();
    /**
     * Destroy document object.
     * Frees document object if one was created.
     */
    ~XmlDoc();

    /**
     * Load directly from an LibXML2 xmlDocPtr.
     * @return 0 on success, -1 on error
     */
    int loadFromXmlDocPtr(xmlDocPtr newdoc);
    /**
     * Get the internal representation of the XML document.
     * @return Pointer to the XML document structure
     */
    xmlDocPtr getDoc();
    /**
     * Load an XML document from a string.
     * @param xmlData A string containing an XML document
     * @return 0 on success, -1 on error
     */
    int loadFromString(string xmlData);
    /**
     * Load an XML document from a file.
     * @param fileName The filename
     * @return 0 on success, -1 on error
     */
    int loadFromFile(string fileName);
    /**
     * Emits the XML document as a string.
     * Caller is responsible for freeing/deleting the string.
     * @return The XML Document as a string.  If none was loaded, returns empty string.
     */
    string toString();
    /**
     * Emits the XML document to a file.
     * @param fileName The filename
     * @return 0 on success, -1 on error
     */
    int toFile(string fileName);
    /**
     * @internal
     * Dump the XML document to stdout.
     * Handy when debugging.
     */
    void dump();
    /**
     * Declare an ID attribute for nodes of a given name
     * of why this may be necessary.
     * @param attrName The attribute name
     * @param nodeName The node name
     * @param nsHref The namespace href (optional)
     * @return 0 on success, -1 on error
     */
    int addIdAttr(string attrName, string nodeName, string nsHref);

    /// @cond NO_INTERFACE
    /**
     * Copy an existing document object.
     * @param doc XmlDoc class to be copied
     */
    XmlDoc(const XmlDoc& doc);
    /**
     * Assignment operator creates duplicate document.
     * @param doc XmlDoc class to be copied
     * @return Copied document
     */
    const XmlDoc& operator= (const XmlDoc& doc);
    /**
     * @return true if valid, false if no document
     */
    operator int ()
    {
        return doc != NULL;
    }
    /**
     * @return false if valid, true if no document
     */
    int operator! ()
    {
        return doc == NULL;
    }
    /**
     * Cast the document object to the xmlDocPtr.
     * @return Pointer to the XML document structure
     */
    operator xmlDocPtr ()
    {
        return getDoc();
    }
    /**
     *  List of ID attributes that have been added to the document.
     *  Required by copy constructor, since these don't move with the
     *  document normally.
     */
    vector<string> idAttrs;

protected:
    /**
     * The internal representation of the XML document.
     */
    xmlDocPtr doc;

    /**
     * Free the internal representation of the XML document.
     */
    void freeDoc();

    /**
     * Add an ID attribute to a node
     */
    static int addIdAttrToNode(xmlNodePtr node, const xmlChar* attrName, const xmlChar* nodeName, const xmlChar* nsHref);
/// @endcond
};

#include "countptr.h"
typedef CountPtrTo<XmlDoc> XmlDocClassPtr;

#endif
