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
#include "X509Certificate.h"
#include <libxml/tree.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <iostream>
#include "BioWrap.h"

X509Certificate::X509Certificate ()
    : ptr(0)
{}


X509Certificate::X509Certificate (X509* x509ptr)
    : ptr(0)
{
    if (x509ptr)
    {
        ptr = X509_dup(x509ptr);
        if (ptr == NULL)
        {
            THROW_NORET(MemoryError, "Unable to copy certificate data");
        }
    }
}


X509Certificate::X509Certificate (const X509Certificate& cert)
    : ptr(0)
{
    operator=(cert);
}


const X509Certificate& X509Certificate::operator= (const X509Certificate& cert)
{
    if (&cert != this)
    {
        ptr = cert.getDup();
    }
    return *this;
}


X509Certificate::~X509Certificate ()
{
    if (ptr)
    {
        X509_free(ptr);
    }
}


X509* X509Certificate::getDup () const
{
    X509* dupCert = X509_dup(ptr);
    if (dupCert == NULL)
    {
        THROW(MemoryError, "Unable to copy certificate data", 0);
    }
    return dupCert;
}


KeyPtr X509Certificate::getKey () const
{
    KeyPtr keyPtr;
    if (!ptr)
    {
        return 0;
    }
    xmlSecKeyDataPtr keyDataPtr = xmlSecOpenSSLX509CertGetKey(ptr);
    if (!keyDataPtr)
    {
        return 0;
    }
    keyPtr = KeyPtr(new Key);
    keyPtr->create();
    if (xmlSecKeySetValue(*keyPtr, keyDataPtr) < 0)
    {
        THROW(LibError, "Couldn't set key value", 0);
    }

    xmlSecKeyDataPtr certData = xmlSecKeyEnsureData(*keyPtr,
                                xmlSecOpenSSLKeyDataX509Id);
    if (certData == NULL)
    {
        THROW(LibError, "Couldn't create cert data", 0);
    }
    if (xmlSecOpenSSLKeyDataX509AdoptCert(certData, getDup()) < 0)
    {
        THROW(LibError, "Unable to adopt cert data", 0);
    }
    return keyPtr;
}

int X509Certificate::loadFromFile (string fileName, string format)
{
    Key key;
    if (ptr)
    {
        X509_free(ptr);
    }
    int ret = key.loadFromFile(fileName, format, "");
    if (ret < 0)
    {
        THROW(IOError, "Unable to load X509 certificate key", ret);
    }
    X509CertificatePtr cert = key.getCertificate();
    if (cert)
    {
        operator=(*cert);
    }
    else
    {
        return -1;
    }
    return 0;
}

string X509Certificate::getSubjectDN()
{
    string name;
    if (!ptr) {
        THROW(LibError, "Certificate not loaded", name);
    }
    const xmlChar* buf = nameToString(X509_get_subject_name(ptr));
    if (buf) {
        name = string((const char*)buf);
    }
    return name;
}

string X509Certificate::getIssuerDN()
{
    string name;
    if (!ptr) {
        THROW(LibError, "Certificate not loaded", name);
    }
    const xmlChar* buf = nameToString(X509_get_issuer_name(ptr));
    if (buf) {
        name = string((const char*)buf);
    }
    return name;
}

int X509Certificate::getVersion()
{
    if (!ptr) {
        THROW(LibError, "Certificate not loaded", -1);
    }
    return X509_get_version(ptr)+1;
}

int X509Certificate::isValid()
{
    if (!ptr) {
        THROW(LibError, "Certificate not loaded", -1);
    }
    int i = X509_cmp_time(X509_get_notBefore(ptr), NULL);
    if (i == 0) {
        THROW(LibError, "Invalid data in certificate notBefore field", 0);
    }
    if (i > 0) {
        return 0;
    }
    i = X509_cmp_time(X509_get_notAfter(ptr), NULL);
    if (i == 0) {
        THROW(LibError, "Invalid data in certificate notAfter field", 0);
    }
    if (i < 0) {
        return 0;
    }
    return 1;
}

// yanked from xmlsec/src/openssl/x509.c
xmlChar*
X509Certificate::nameToString(X509_NAME* nm) {
    xmlChar *res = NULL;
    BIO *mem = NULL;
    long size;

    xmlSecAssert2(nm != NULL, NULL);

    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
        	    NULL,
        	    "BIO_new",
        	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
        	    "BIO_s_mem");
        return(NULL);
    }

    if (X509_NAME_print_ex(mem, nm, 0, XN_FLAG_RFC2253) <=0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
        	    NULL,
        	    "X509_NAME_print_ex",
        	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
        	    XMLSEC_ERRORS_NO_MESSAGE);
        BIO_free_all(mem);
        return(NULL);
    }

    BIO_flush(mem); /* should call flush ? */

    size = BIO_pending(mem);
    res = (xmlChar*) xmlMalloc(size + 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }

    size = BIO_read(mem, res, size);
    res[size] = '\0';

    BIO_free_all(mem);
    return(res);
}


int X509Certificate::verify (KeyPtr key)
{
    if (!key || !key->isValid())
    {
        THROW(KeyError, "Invalid key", -1);
    }
    xmlSecKeyPtr secKey = key->getKey();
    if (!secKey || !secKey->value)
    {
        THROW(KeyError, "Invalid key", -1);
    }
    EVP_PKEY* evp_pkey = xmlSecOpenSSLEvpKeyDataGetEvp(secKey->value);
    if (!evp_pkey)
    {
        THROW(KeyError, "Key is not a public key", -1);
    }
    int ret = X509_verify(ptr, evp_pkey);
    if (ret < 0)
    {
        THROW(LibError, "X509 verify failed", -1);
    }
    return ret;
}

#ifdef WIN32
#define strncasecmp _strnicmp
#endif

int X509Certificate::getBasicConstraints () {
    if (!ptr) {
        THROW(LibError, "Certificate not loaded", -1);
    }
    X509_EXTENSION *ext = NULL;
    int pathlen = -1;
    X509V3_EXT_METHOD *method = NULL;
    STACK_OF(CONF_VALUE) *vals = NULL;
    void *ext_str = NULL;

    int index = X509_get_ext_by_NID(ptr, NID_basic_constraints, -1);
    if((index >= 0)  && (ext = X509_get_ext(ptr, index))) {
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
        const unsigned char **ext_value_data;
        ext_value_data = (const_cast<const unsigned char **> (&ext->value->data));
#else
        unsigned char **ext_value_data = &ext->value->data;
#endif
        if (!ext_value_data) {
            goto end;
        }
        method = X509V3_EXT_get(ext);
        if (!method || !method->i2v) {
            goto end;
        }
        ext_str = ASN1_item_d2i(NULL, ext_value_data, ext->value->length, ASN1_ITEM_ptr(method->it));
        if (!ext_str) {
            goto end;
        }
        vals = method->i2v(method, ext_str, NULL);
        if (!vals) {
            goto end;
        }
        int isCA = 0;
        for(int i = 0; i < sk_CONF_VALUE_num(vals); i++) {
            CONF_VALUE *val = sk_CONF_VALUE_value(vals, i);
            if (!val) {
                goto end;
            }
            if ((strncasecmp(val->name,"CA", 2)==0) && (strncasecmp(val->value, "TRUE", 4)==0))
                isCA=1;
            if ((strncasecmp(val->name,"pathlen", 2)==0))
                 pathlen=atoi(val->value);
        }
        if (isCA) {
            if (pathlen == -1) {
                pathlen = 0x7fffffff;
            }
        }
    }
    end:
        if (ext_str) ASN1_item_free((ASN1_VALUE*)ext_str, ASN1_ITEM_ptr(method->it));
        if (vals) sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
        return pathlen;
}


int X509Certificate::isEqualTo (X509Certificate& other)
{
    BioWrap bioSelf, bioOther;

    i2d_X509_bio(bioSelf, ptr);
    BIO_flush(bioSelf);

    i2d_X509_bio(bioOther, other.ptr);
    BIO_flush(bioOther);

    xmlSecByte *memSelf=0, *memOther=0;
    long sizeSelf=0, sizeOther=0;
    sizeSelf = BIO_get_mem_data(bioSelf, &memSelf);
    sizeOther = BIO_get_mem_data(bioOther, &memOther);

    if (sizeSelf != sizeOther)
    {
        return 0;
    }

    while (sizeSelf)
    {
        if (*memSelf++ != *memOther++)
        {
            return 0;
        }
        sizeSelf--;
    }
    return 1;
}
