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
#ifndef _XMLELEMENT_H
#define _XMLELEMENT_H
#include <string>
#include <vector>
#include <libxml/parser.h>
#include "Exceptions.h"
using namespace std;

/**
 * An XML element.
 * Encapsulates a LibXML2 XML node object.  
 */
class XmlElement
{
public:
    /**
     * Construct an empty element object.
     */
    XmlElement ();
    /**
     * Copy an existing raw element.
     */
    XmlElement (xmlNodePtr copyNode);
    /**
     * Destroy element object.
     * Frees element object if one was created.
     */
    ~XmlElement ();

    /**
     * Get the internal representation of the XML element.
     * @return Pointer to the XML node structure
     */
    xmlNodePtr getNode ();
    /**
     * Get the name of the element.
     * @return the name of the element node
     * @throws XMLError if the node is invalid
     */
    string getTagName ();
    /**
     * Search and get the value of an attribute associated to a node. 
     * This does the entity substitution.
     * @param name the attribute name
     * @return the attribute value or null if not found
     * @throws XMLError if the node is invalid
     */
    string getAttribute (string name);
    /**
     * Search and get the value of an attribute associated to a node.
     * This attribute has to be anchored in the namespace
     * specified. This does the entity substitution.
     * @param name the attribute name
     * @param nameSpace the URI of the namespace
     * @return the attribute value or null if not found
     * @throws XMLError if the node is invalid
     */
    string getAttribute (string name, string nameSpace);
    /**
     * Build a structure based Path for the node.
     * @return a path in string form
     * @throws XMLError if the node is invalid
     */
    string getNodePath ();

    /// @cond NO_INTERFACE
    /**
     * Copy an existing element object.
     * @param element XmlElement class to be copied
     */
    XmlElement(const XmlElement& element);
    /**
     * Assignment operator creates duplicate element.
     * @param element XmlElement class to be copied
     * @return Copied element
     */
    const XmlElement& operator= (const XmlElement& element);
    /**
     * @return true if valid, false if no element
     */
    operator int ()
    {
        return (node != NULL) && (node->type == XML_ELEMENT_NODE);
    }
    /**
     * @return false if valid, true if no element
     */
    int operator! ()
    {
        return (node == NULL) || (node->type != XML_ELEMENT_NODE);
    }
    /**
     * Cast the element object to the xmlNodePtr.
     * @return Pointer to the XML element structure
     */
    operator xmlNodePtr ()
    {
        return getNode();
    }

protected:
    /**
     * The internal representation of the XML node.
     */
    xmlNodePtr node;

    /**
     * Free the internal representation of the XML node.
     */
    void freeNode();

/// @endcond
};

#include "countptr.h"
typedef CountPtrTo<XmlElement> XmlElementPtr;

#endif
