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
#ifndef _KEYINFOCTX_H
#define _KEYINFOCTX_H

#include <xmlsec/keyinfo.h>
#include <assert.h>
#include "Exceptions.h"

class KeyInfoCtx
{
public:
    KeyInfoCtx (xmlSecKeysMngrPtr keysMngr = 0)
        : keyInfoCtx (0)
    {
        keyInfoCtx = xmlSecKeyInfoCtxCreate(keysMngr);
        if (!keyInfoCtx)
        {
            THROW_NORET(MemoryError, "Couldn't create key info context");
        }
    }

    ~KeyInfoCtx ()
    {
        if (keyInfoCtx)
        {
            xmlSecKeyInfoCtxDestroy(keyInfoCtx);
        }
    }

    operator int ()
    {
        return keyInfoCtx != NULL;
    }
    int operator! ()
    {
        return keyInfoCtx == NULL;
    }
    xmlSecKeyInfoCtxPtr operator-> ()
    {
        assert(keyInfoCtx);
        return keyInfoCtx;
    }
    operator xmlSecKeyInfoCtxPtr ()
    {
        return keyInfoCtx;
    }

protected:
    xmlSecKeyInfoCtxPtr keyInfoCtx;
};

#endif
