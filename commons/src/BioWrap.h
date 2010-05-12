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
#ifndef _BIOWRAP_H
#define _BIOWRAP_H

#include <openssl/bio.h>
#include <iostream>
#include "Exceptions.h"

/// @cond NO_INTERFACE
/**
 * Wrap OpenSSL BIO object
 */
class BioWrap
{
public:
    /**
     * Create a new memory BIO.
     * @throws MemoryError if one couldn't be allocated
     */
    BioWrap () : mem(0)
    {
        mem = BIO_new(BIO_s_mem());
        if (mem == NULL)
        {
            THROW_NORET(MemoryError, "Couldn't allocate BIO");
        }
    }
    /**
     * Destroy BIO, freeing its memory.
     */
    ~BioWrap ()
    {
        if (mem)
        {
            BIO_free_all(mem);
            mem = 0;
        }
    }
    /**
     * Write the buffer to the BIO.
     * @param buf Character buffer to write
     * @param size Size of buffer
     * @throws IOError on write failure
     * @return 0 on success, <0 on failure
     */
    int write (xmlChar* buf, xmlSecSize size)
    {
        // cast size to int (same as in xmlsec library)
        int ret = BIO_write(mem, buf, (int)size);
        if (ret <= 0)
        {
            THROW(IOError, "BIO write failure", ret);
        }
        return ret;
    }
    /**
     * Cast to a BIO pointer.
     */
    operator BIO* ()
    {
        return mem;
    }
    /** 
     * Cast to a void pointer, good for null checks.
     */
    operator const void* ()
    {
        return mem;
    }
    /**
     * Cast to an integer, nonzero if BIO is valid.
     */
    operator int ()
    {
        return mem != 0;
    }

protected:
    BIO* mem;
};
/// @endcond

#endif
