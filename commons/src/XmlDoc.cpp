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
#include <string>
#include <vector>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <xmlsec/xmltree.h>
#include "XmlDoc.h"
#include "XmlCharBuf.h"
using namespace std;


XmlDoc::XmlDoc ()
    : doc (0)
{}


XmlDoc::XmlDoc (const XmlDoc& xmlDoc)
    : doc (0)
{
    this->operator=(xmlDoc);
}


XmlDoc::~XmlDoc ()
{
    freeDoc();
}


const XmlDoc& XmlDoc::operator= (const XmlDoc& xmlDoc)
{
    if (this != &xmlDoc)
    {
        freeDoc();
        if (xmlDoc.doc)
        {
            // recursive copy of original doc
            doc = xmlCopyDoc(xmlDoc.doc, 1);
            // copy over ID attributes too
            if (doc)
            {
                idAttrs = xmlDoc.idAttrs;
                for (unsigned i = 0; i < xmlDoc.idAttrs.size(); i += 3)
                {
                    addIdAttr(xmlDoc.idAttrs[i],
                              xmlDoc.idAttrs[i + 1],
                              xmlDoc.idAttrs[i + 2]);
                }
            }
        }
    }
    return *this;
}


void XmlDoc::freeDoc ()
{
    if (doc)
    {
        xmlFreeDoc(doc);
        doc = NULL;
        idAttrs.clear();
    }
}


xmlDocPtr XmlDoc::getDoc ()
{
    return doc;
}


int XmlDoc::loadFromXmlDocPtr (xmlDocPtr newdoc)
{
    if (!newdoc)
    {
        THROW(ValueError, "Invalid document to copy", -1);
    }
    freeDoc();
    doc = xmlCopyDoc(newdoc, 1);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL))
    {
        THROW(LibError, "Error parsing XML document", -1);
    }
    return 0;
}


int XmlDoc::loadFromString (string xmlData)
{
    freeDoc();
    doc = xmlReadDoc((xmlChar*) xmlData.c_str(), "", NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL))
    {
        THROW(LibError, "Error parsing XML document", -1);
    }
    return 0;
}


int XmlDoc::loadFromFile (string fileName)
{
    freeDoc();
    doc = xmlReadFile(fileName.c_str(), NULL, 0);
    if (doc == NULL)
    {
        THROW(IOError, "Failure loading XML document", -1);
    }
    if (xmlDocGetRootElement(doc) == NULL)
    {
        THROW(LibError, "Error parsing XML document", -1);
    }
    return 0;
}


void XmlDoc::dump ()
{
    if (doc)
    {
        xmlDocDump(stdout, doc);
    }
}


string XmlDoc::toString ()
{
    string str = "";
    if (doc)
    {
        XmlCharBuf buf;
        int len = 0;
        xmlDocDumpMemory(doc, (xmlChar**)buf, &len);
        str = string((const char*)buf, len);
    }
    return str;
}


int XmlDoc::toFile (string fileName)
{
    if (doc)
    {
        int res = xmlSaveFile(fileName.c_str(), doc);
        if (res < 0)
        {
            THROW(LibError, "Document dump failure", res);
        }
    }
    return 0;
}


int XmlDoc::addIdAttr (string attrName, string nodeName, string nsHref)
{
    assert(doc);
    assert(attrName.length());
    assert(nodeName.length());
    const char* nsHrefChr = NULL;
    int added = 0;
    if (nsHref.length())
    {
        nsHrefChr = nsHref.c_str();
    }
    xmlNodePtr cur = xmlSecGetNextElementNode(doc->children);
    while (cur != NULL)
    {
        if (addIdAttrToNode(cur, 
                            (xmlChar*)attrName.c_str(), 
                            (xmlChar*)nodeName.c_str(), 
                            (xmlChar*)nsHrefChr) < 0)
        {
            return -1;
        }
        cur = xmlSecGetNextElementNode(cur->next);
        added++;
    }
    if (added)
    {
        idAttrs.push_back(attrName);
        idAttrs.push_back(nodeName);
        idAttrs.push_back(nsHref);
    }
    return 0;
}


int XmlDoc::addIdAttrToNode (xmlNodePtr node, 
                             const xmlChar* attrName, 
                             const xmlChar* nodeName, 
                             const xmlChar* nsHref)
{
    xmlAttrPtr attr, tmpAttr;
    xmlNodePtr cur;

    if ((node == NULL) || (attrName == NULL) || (nodeName == NULL))
    {
        THROW(ValueError, "Bad parameters", -1);
    }

    /* process children first because it does not matter much but does simplify code */
    cur = xmlSecGetNextElementNode(node->children);
    while (cur != NULL)
    {
        int ret = addIdAttrToNode(cur, attrName, nodeName, nsHref);
        if (ret < 0)
        {
            return (ret);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }


    /* node name must match */
    if (!xmlStrEqual(node->name, nodeName))
    {
        return (0);
    }

    /* if nsHref is set then it also should match */
    if ((nsHref != NULL) && (node->ns != NULL) && 
        (!xmlStrEqual(nsHref, node->ns->href)))
    {
        return (0);
    }

    /* the attribute with name equal to attrName should exist */
    for (attr = node->properties; attr != NULL; attr = attr->next)
    {
        if (xmlStrEqual(attr->name, attrName))
        {
            break;
        }
    }
    if (attr == NULL)
    {
        return (0);
    }

    /* and this attr should have a value */
    XmlCharBuf id (xmlNodeListGetString(node->doc, attr->children, 1));
    if (!(int)id)
    {
        return (0);
    }

    /* check that we don't have same ID already */
    tmpAttr = xmlGetID(node->doc, id);
    if (tmpAttr == NULL)
    {
        xmlAddID(NULL, node->doc, id, attr);
    }
    else if (tmpAttr != attr)
    {
        THROW(XMLError, "Duplicate ID attribute", -1);
    }
    return (0);
}

