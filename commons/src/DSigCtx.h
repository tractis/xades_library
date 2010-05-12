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
#ifndef _DSIGCTX_H
#define _DSIGCTX_H

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <assert.h>
#include "Exceptions.h"

class DSigCtx
{
public:
    DSigCtx (xmlSecKeysMngrPtr keysMngr = 0) 
        : dsigCtx (0)
    {
        dsigCtx = xmlSecDSigCtxCreate(keysMngr);
        if (!dsigCtx)
        {
            THROW_NORET(MemoryError, "Couldn't create DSIG context");
        }
    }
    ~DSigCtx ()
    {
        if (dsigCtx)
        {
            xmlSecDSigCtxDestroy(dsigCtx);
        }
    }

    operator int ()
    {
        return dsigCtx != NULL;
    }
    int operator! ()
    {
        return dsigCtx == NULL;
    }
    xmlSecDSigCtxPtr operator-> ()
    {
        assert(dsigCtx);
        return dsigCtx;
    }
    operator xmlSecDSigCtxPtr ()
    {
        return dsigCtx;
    }

    void dump (FILE* file)
    {
        xmlSecDSigCtxDebugDump(dsigCtx, file);
    }

protected:
    xmlSecDSigCtxPtr dsigCtx;
};

#endif
