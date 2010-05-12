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
#ifndef COUNTPTR_H
#define COUNTPTR_H

#include <assert.h>
#ifdef DEBUGALLOC
#include <stdio.h>
#endif

/// @cond NO_INTERFACE
/**
 * Reference counted pointer class.
 */
template <class T>
class CountPtrTo
{
public:
    /**
     * Create an empty (null) pointer.
     */
    CountPtrTo ();
    /**
     * Create a reference counted pointer to the given raw pointer.
     * Useful for the following idiom:
     * \code
     * CountPtrTo<T> pointer (new T);
     * \endcode
     * @param t Raw pointer
     */
    CountPtrTo (T* t);
    /**
     * Copy constructor, increments reference count.
     * @param cpt A counted pointer to "copy"
     */
    CountPtrTo (const CountPtrTo<T>& cpt);
    /**
     * Decrement reference count and delete contained pointer if
     * references are exhausted.
     */
    ~CountPtrTo ();

    /**
     * Assignment operator, increments reference count.
     * @param cpt A counted pointer to "copy"
     */
    const CountPtrTo<T>& operator= (const CountPtrTo<T>& cpt);

    /**
     * Member reference operator, asserts on null pointer.
     */
    T* operator-> ();
    /**
     * Member reference operator, asserts on null pointer.
     */
    const T* operator-> () const;
    /**
     * Dereference operator, asserts on null pointer.
     */
    T& operator* ();
    /**
     * Dereference operator, asserts on null pointer.
     */
    const T& operator* () const;
    /**
     * Cast to a void pointer, good for null checks.
     * Does not assert on null.
     */
    operator const void* () const;

    /**
     * Equality operator, true if the counted pointers refer to the
     * same raw pointer.
     */
    int operator== (const CountPtrTo<T>&) const;
    /**
     * Inequality operator, true if the counted pointers do NOT refer
     * to the same raw pointer.
     */
    int operator!= (const CountPtrTo<T>&) const;

protected:
    class CountPtr
    {
    public:
        unsigned count;
        T* pval;

        CountPtr (T* pT)
                : count (1), pval (pT)
        {
            assert(pval);
#ifdef DEBUGALLOC

            printf("AddRef(%lx, %lx, %d)\n",
                   (unsigned long)this,
                   (unsigned long)pval,
                   count);
#endif // DEBUGALLOC
        }

        ~CountPtr ()
        {
            delete pval;
        }
    }
    * ptr;

    void AddRef (CountPtr*);
    void DelRef ();
};


template <class T>
inline CountPtrTo<T>::CountPtrTo ()
    : ptr (0)
{}


template <class T>
CountPtrTo<T>::CountPtrTo (T* pT)
    : ptr (0)
{
    if (pT)
    {
        ptr = new CountPtr(pT);
    }
}


template <class T>
inline CountPtrTo<T>::CountPtrTo (const CountPtrTo<T>& rCP)
    : ptr (0)
{
    AddRef(rCP.ptr);
}


template <class T>
inline CountPtrTo<T>::~CountPtrTo ()
{
    DelRef();
}


template <class T>
const CountPtrTo<T>& CountPtrTo<T>::operator= (const CountPtrTo<T>& rCP)
{
    if (this != &rCP)
    {
        DelRef();
        AddRef(rCP.ptr);
    }
    return *this;
}


template <class T>
inline T* CountPtrTo<T>::operator-> ()
{
    assert(ptr);
    return ptr->pval;
}


template <class T>
inline const T* CountPtrTo<T>::operator-> () const
{
    assert(ptr);
    return ptr->pval;
}


template <class T>
inline T& CountPtrTo<T>::operator* ()
{
    assert(ptr);
    return *(ptr->pval);
}


template <class T>
inline const T& CountPtrTo<T>::operator* () const
{
    assert(ptr);
    return *(ptr->pval);
}


template <class T>
inline CountPtrTo<T>::operator const void* () const
{
    return ptr ? this : 0;
}


template <class T>
inline int CountPtrTo<T>::operator== (const CountPtrTo<T>& rCP) const
{
    return ptr == rCP.ptr;
}


template <class T>
inline int CountPtrTo<T>::operator!= (const CountPtrTo<T>& rCP) const
{
    return ptr != rCP.ptr;
}


template <class T>
void CountPtrTo<T>::AddRef (CountPtr* pSt)
{
    //DelRef();
    ptr = pSt;
#ifdef DEBUGALLOC
    printf("AddRef(%lx, %lx, %d)\n",
           (unsigned long)ptr,
           (unsigned long)(ptr ? ptr->pval : 0),
           ptr ? ptr->count + 1 : 0);
#endif // DEBUGALLOC
    if (ptr)
    {
        ptr->count++;
    }
}


template <class T>
void CountPtrTo<T>::DelRef ()
{
#ifdef DEBUGALLOC
    printf("DelRef(%lx, %lx, %d)\n",
           (unsigned long)ptr,
           (unsigned long)(ptr ? ptr->pval : 0),
           ptr ? ptr->count - 1 : 0);
#endif // DEBUGALLOC

    if (ptr && (--ptr->count == 0))
    {
        delete ptr;
    }
}
/// @endcond

#endif // COUNTPTR_H
