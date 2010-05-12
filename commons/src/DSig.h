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
#ifndef _DSIG_H
#define _DSIG_H

#include "Exceptions.h"

/**
 * \mainpage
 * 
 * XMLSig is a C++ wrapper around the xmlsec library, providing a simple
 * object oriented interface for dynamic languages.  Its main objectives
 * are:
 * 
 * - To be a fully compliant XML Signature implementation.
 *   See http://www.w3.org/TR/xmldsig-core/.
 * - To have an API resembling Apache TSIK.
 *   See http://incubator.apache.org/tsik/.
 * 
 * Secondary objectives include:
 * 
 * - Make it easy to bind to many dynamic languages.  
 *   This can be seen in the minimal amount of type-mapping needed to
 *   bind to XMLSig.  Only XMLSig objects and common C/C++ types are
 *   exposed.  This gives the XMLSig interface a
 *   lowest-common-denominator feel, and it is expected that language
 *   enthusiasts will create wrapper modules that have a more
 *   language-specific feel.
 * - Play nicely with native language objects as much as possible.
 *   One goal of XMLSig is to provide language-specific methods so
 *   that developers can still use their language's standard libraries
 *   with XMLSig.  For example, XMLSig encapsulates XML processing,
 *   but different languages have their own favorite XML libraries, so
 *   XMLSig should make it possible for developers to use their
 *   language's standard XML API.
 *
 * \section license License
 *
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

/**
 *  Initialize the library.  Initializes the libxml2, libxslt, xmlsec
 *  and OpenSSL libraries.  Also calls initErrorHandler.  This
 *  function may be called more than once.
 */
int dsigInit();
/**
 *  Shutdown the library.  Calls the de-initialize functions for the
 *  libxml2, libxslt, xmlsec and OpenSSL libraries.  
 */
int dsigShutdown();

#endif
