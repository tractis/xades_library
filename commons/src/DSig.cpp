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
#include <stdio.h>
#include <string>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

#include "DSig.h"
#include "Exceptions.h"

static int dsigInitialized = 0;

extern "C" const char *xmlsec_lt_dlerror(void);


int dsigInit ()
{
    if (dsigInitialized)
    {
        return 0;
    }
    else
    {
        dsigInitialized = 1;
    }

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif // XMLSEC_NO_XSLT

    // Init xmlsec library
    if (xmlSecInit() < 0)
    {
        THROW(LibError, "xmlsec initialization failed", -1);
    }
    // Check loaded library version
    if (xmlSecCheckVersion() != 1)
    {
        THROW(LibError, "Loaded xmlsec library version is not compatible", -1);
    }
    if (xmlSecOpenSSLAppInit(NULL) < 0)
    {
        THROW(LibError, "OpenSSL application initialization failed", -1);
    }
    // Init crypto library
    if (xmlSecOpenSSLInit() < 0)
    {
        THROW(LibError, "xmlsec OpenSSL initialization failed", -1);
    }
    initErrorHandler();
    return 0;
}


int dsigShutdown ()
{
    if (!dsigInitialized)
    {
        return -1;
    }
    // Shutdown xmlsec-crypto library
    xmlSecOpenSSLShutdown();

    // Shutdown crypto library
    //xmlSecCryptoAppShutdown();

    // Shutdown xmlsec library
    xmlSecShutdown();

    // Shutdown libxslt/libxml
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();
#endif // XMLSEC_NO_XSLT

    xmlCleanupParser();
    return 0;
}
