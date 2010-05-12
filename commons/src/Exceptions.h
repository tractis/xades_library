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
#ifndef _EXCEPTIONS_H
#define _EXCEPTIONS_H

#include <string>
#ifndef NDEBUG
#ifndef DEBUG_EXCEPTIONS
#define DEBUG_EXCEPTIONS
#endif // DEBUG_EXCEPTIONS
#endif // NDEBUG

#ifdef DEBUG_EXCEPTIONS
#include <iostream>
#endif // DEBUG_EXCEPTIONS

using namespace std;

/**
 * Base class for all exceptions thrown by this library
 */
class DsigException
{
public:
    /**
     * Create an empty exception.  The description will be "Unknown
     * exception".
     */
    DsigException () : what_str("Unknown exception")
    {}
    /**
     * Create an exception with the given description string.
     * @param what_str Description string
     */
    DsigException (string what_str) : what_str(what_str)
    {}
    /**
     * Copy another exception, duplicating the description string.
     * @param excp Exception to copy
     */
    DsigException (const DsigException& excp)
    {
        if (this != &excp)
        {
            what_str = excp.what_str;
        }
    }
    virtual ~DsigException ()
    {}

    /**
     * Describe the exception.
     * @return Description string
     */
    const char* what () const
    {
        return what_str.c_str();
    }

protected:
    string what_str;
};


/**
 * Macro to declare a generic exception derived from one similar to DsigException.
 */
#define DERIVED_EXCEPTION(newclass,baseclass) \
    class newclass : public baseclass \
    { \
    public: \
        newclass() : baseclass() {} \
        newclass (string what_str) : baseclass(what_str) {} \
        newclass (const newclass& excp) : baseclass(excp) {} \
        virtual ~newclass () {} \
    }

/*
 TSIK Java exceptions:
 
 SignatureException
 InvalidKeyException
 NoSuchAlgorithmException
 XPathException
*/


// Generic exceptions (with Swig analogs)

/** \class IOError
 * Generic I/O exception class.
 */
DERIVED_EXCEPTION(IOError, DsigException);      // SWIG_IOError
/** \class MemoryError
 * Generic memory error exception class.
 */
DERIVED_EXCEPTION(MemoryError, DsigException);  // SWIG_MemoryError
/** \class ValueError
 * Generic value error exception class.
 */
DERIVED_EXCEPTION(ValueError, DsigException);   // SWIG_ValueError

// Exception classes specific to DSIG

/** \class XMLError
 * Error parsing XML, or elements not found.
 */
DERIVED_EXCEPTION(XMLError, DsigException);
/** \class KeyError
 * Key missing or invalid.
 */
DERIVED_EXCEPTION(KeyError, DsigException);
/** \class DocError
 * Document missing, invalid or malformed
 */
DERIVED_EXCEPTION(DocError, DsigException);
/** \class XPathError
 * XPath expression syntax or result set issue.
 */
DERIVED_EXCEPTION(XPathError, DsigException);
/** \class TrustVerificationError
 * Indicates that trust verification failed. 
 */
DERIVED_EXCEPTION(TrustVerificationError, DsigException);
//DERIVED_EXCEPTION(SignatureError, DsigException);


/**
 * Encapsulates errors reported by libraries: xmlsec, libxml, libxslt, openssl.
 * Error messages logged by libraries are saved and returned as part of the
 * description string.
 */
class LibError : public DsigException
{
public:
    LibError();
    LibError(string what_str);
    LibError(const LibError& excp) : DsigException(excp)
    {}
    virtual ~LibError ()
    {}
    /**
     * Erase any library errors that have already been logged.
     */
    static void clearErrorLogs ();

protected:
    void appendAll ();
    void appendWhat (char* str);
};


/**
 * \def THROW_NORET(e,what) 
 * Throws an exception or returns with no value, based on whether
 * exceptions are enabled.
 * Throws the exception class "e", with the string parameter "what"
 * unless NO_EXCEPTIONS is defined, in which case it just returns
 * (with no return value).  If DEBUG_EXCEPTIONS is not defined, THROW
 * spits out debug info to stderr.
 */

/**
 * \def THROW(e,what,ret) 
 * Throws an exception or returns a value, based on whether
 * exceptions are enabled.
 * Throws the exception class "e", with the string parameter "what"
 * unless NO_EXCEPTIONS is defined, in which case it just returns "ret".
 * If DEBUG_EXCEPTIONS is not defined, THROW spits out debug info to stderr.
 */

#ifndef NO_EXCEPTIONS
#define THROW_NORET(e,what) THROW(e,what,void)
#ifndef DEBUG_EXCEPTIONS
#define THROW(e,what,ret) throw e(what)
#else
#define THROW(e,what,ret) do \
    { fprintf(stderr, "%s:%d:%s: %s\n", __FILE__, __LINE__, #e, what); \
        throw e(what); } while(0)
#endif // DEBUG_EXCEPTIONS
#else
#ifndef DEBUG_EXCEPTIONS
#define THROW_NORET(e,what) return
#define THROW(e,what,ret) return (ret)
#else
#define THROW_NORET(e,what) do \
    { fprintf(stderr, "%s:%d:%s: %s\n", __FILE__, __LINE__, #e, what); \
        return; } while(0)
#define THROW(e,what,ret) do \
    { fprintf(stderr, "%s:%d:%s: %s\n", __FILE__, __LINE__, #e, what); \
        return ret; } while(0)
#endif // DEBUG_EXCEPTIONS
#endif // NO_EXCEPTIONS

/**
 * Initialize the error handlers for xmlsec1, libxml2, libxslt
 */
void initErrorHandler ();

#endif
