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
#include "Exceptions.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <libxml/xmlerror.h>
#include <libxslt/xsltutils.h>
#include <iostream>
#include <stdarg.h>

#ifdef _WIN32
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif

#define SEC_ERRORSTR_SIZE 2048
char sec_error_str[SEC_ERRORSTR_SIZE] = "";
#define ERRORSTR_SIZE 1024
char xml_error_str[ERRORSTR_SIZE] = "";
char xslt_error_str[ERRORSTR_SIZE] = "";


void secErrorCallback (const char *file,
                       int line,
                       const char *func,
                       const char *errorObject,
                       const char *errorSubject,
                       int reason,
                       const char *msg)
{
    const char* error_msg = NULL;

    for (xmlSecSize i = 0;
            (i < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(i) != NULL);
            ++i)
    {
        if (xmlSecErrorsGetCode(i) == reason)
        {
            error_msg = xmlSecErrorsGetMsg(i);
            break;
        }
    }
    char* str = sec_error_str;
    for (; (*str && ((str - sec_error_str) < SEC_ERRORSTR_SIZE)); str++);
    snprintf(str, SEC_ERRORSTR_SIZE - (str - sec_error_str),
             "func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s:%s\n",
             (func != NULL) ? func : "unknown",
             (file != NULL) ? file : "unknown",
             line,
             (errorObject != NULL) ? errorObject : "unknown",
             (errorSubject != NULL) ? errorSubject : "unknown",
             reason,
             (error_msg != NULL) ? error_msg : "",
             (msg != NULL) ? msg : "");
#ifdef DEBUG_EXCEPTIONS
    fprintf(stderr,
            "func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s:%s\n",
            (func != NULL) ? func : "unknown",
            (file != NULL) ? file : "unknown",
            line,
            (errorObject != NULL) ? errorObject : "unknown",
            (errorSubject != NULL) ? errorSubject : "unknown",
            reason,
            (error_msg != NULL) ? error_msg : "",
            (msg != NULL) ? msg : "");
#endif // DEBUG_EXCEPTIONS
}


void xmlErrorCallback (void* str, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vsnprintf((char*)str, ERRORSTR_SIZE, msg, args);
#ifdef DEBUG_EXCEPTIONS
    vfprintf(stderr, msg, args);
#endif // DEBUG_EXCEPTIONS
    va_end(args);
}


void initErrorHandler ()
{
    xmlSecErrorsSetCallback(secErrorCallback);
    xmlSetGenericErrorFunc(xml_error_str, xmlErrorCallback);
#ifndef XMLSEC_NO_XSLT
    xsltSetGenericErrorFunc(xslt_error_str, xmlErrorCallback);
#endif
}


LibError::LibError ()
    : DsigException()
{
    appendAll();
}


LibError::LibError (string what_str)
    : DsigException(what_str)
{
    appendAll();
}


void LibError::clearErrorLogs ()
{
    char* strs[] = { sec_error_str, xml_error_str, xslt_error_str, "" };
    for (char** str = strs; **str; str++)
    {
        **str = '\0';
    }
}

void LibError::appendAll ()
{
    char* strs[] = { sec_error_str, xml_error_str, xslt_error_str, "" };
    for (char** str = strs; **str; str++)
    {
        appendWhat(*str);
    }
}


void LibError::appendWhat (char* str)
{
    if (*str)
    {
        if (what_str.length() && (what_str[what_str.length()] != '\n'))
        {
            what_str += "\n";
        }
        what_str += str;
        *str = '\0';
    }
}

