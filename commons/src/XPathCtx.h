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
#ifndef _XPATHCTX_H
#define _XPATHCTX_H

#include <assert.h>
#include <libxml/xpath.h>
#include "Exceptions.h"

class XPathCtx
{
public:
    XPathCtx (XmlDocClassPtr xmlDoc)
        : xpathCtx (0)
    {
        xpathCtx = xmlXPathNewContext(xmlDoc->getDoc());
        if (!xpathCtx)
        {
            THROW_NORET(MemoryError, "Couldn't create XPath evaluation context");
        }
    }

    ~XPathCtx ()
    {
        if (xpathCtx)
        {
            xmlXPathFreeContext(xpathCtx);
            xpathCtx = 0;
        }
    }

    operator int ()
    {
        return xpathCtx != NULL;
    }
    int operator! ()
    {
        return xpathCtx == NULL;
    }
    xmlXPathContextPtr operator-> ()
    {
        assert(xpathCtx);
        return xpathCtx;
    }
    operator xmlXPathContextPtr ()
    {
        return xpathCtx;
    }

protected:
    xmlXPathContextPtr xpathCtx;
};

#endif
