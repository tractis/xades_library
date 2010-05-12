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
#include "XmlElement.h"
#include "XmlCharBuf.h"
using namespace std;


XmlElement::XmlElement ()
    : node (0)
{}


XmlElement::XmlElement (xmlNodePtr copyNode)
    : node (0)
{
    assert(copyNode);
    if (!copyNode)
    {
        THROW_NORET(MemoryError, "Bad pointer passed to XmlElement");
    }
    if (copyNode->type != XML_ELEMENT_NODE)
    {
        THROW_NORET(XMLError, "Not an element node");
    }
    // recursive copy of original node
    node = xmlCopyNode(copyNode, 
                       2); // 2=copy attr but no children
    if (!node)
    {
        THROW_NORET(LibError, "Failed to copy node");
    }
}


XmlElement::XmlElement (const XmlElement& xmlNode)
    : node (0)
{
    this->operator=(xmlNode);
}


XmlElement::~XmlElement ()
{
    freeNode();
}


const XmlElement& XmlElement::operator= (const XmlElement& xmlNode)
{
    if (this != &xmlNode)
    {
        freeNode();
        if (xmlNode.node)
        {
            // recursive copy of original node
            node = xmlCopyNode(xmlNode.node, 
                               2); // 2=copy attr but no children
            if (!node)
            {
                THROW(LibError, "Failed to copy node", *this);
            }
        }
    }
    return *this;
}


void XmlElement::freeNode ()
{
    if (node)
    {
        xmlFreeNode(node);
        node = NULL;
    }
}


xmlNodePtr XmlElement::getNode ()
{
    return node;
}


string XmlElement::getTagName ()
{
    if (!*this)
    {
        THROW(XMLError, "Invalid element node", "");
    }
    if (!node->name)
    {
        return "";
    }
    return string((const char*)node->name);
}


string XmlElement::getAttribute (string name)
{
    if (!*this)
    {
        THROW(XMLError, "Invalid element node", "");
    }
    XmlCharBuf buf(xmlGetProp(node, BAD_CAST name.c_str()));
    return string(buf);
}


string XmlElement::getAttribute (string name, string nameSpace)
{
    if (!*this)
    {
        THROW(XMLError, "Invalid element node", "");
    }
    XmlCharBuf buf(xmlGetNsProp(node, BAD_CAST name.c_str(), BAD_CAST nameSpace.c_str()));
    return string(buf);
}


string XmlElement::getNodePath ()
{
    if (!*this)
    {
        THROW(XMLError, "Invalid element node", "");
    }
    XmlCharBuf buf(xmlGetNodePath(node));
    return string(buf);
}
