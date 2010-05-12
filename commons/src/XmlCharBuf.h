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
#ifndef _XMLCHARBUF_H
#define _XMLCHARBUF_H

#include <libxml/globals.h>

class XmlCharBuf
{
public:
    XmlCharBuf ()
        : mbuf(0)
    {}
    XmlCharBuf (xmlChar* buf) 
        : mbuf(buf)
    {}
    ~XmlCharBuf ()
    {
        if (mbuf != 0)
        {
            xmlFree(mbuf);
        }
    }

    operator xmlChar** ()
    {
        return &mbuf;
    }
    operator xmlChar* ()
    {
        return mbuf;
    }
    operator const char* ()
    {
        return (const char*)mbuf;
    }
    operator int ()
    {
        return mbuf != 0;
    }

protected:
    xmlChar* mbuf;
};

#endif
