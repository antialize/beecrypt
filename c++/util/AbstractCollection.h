/*
 * Copyright (c) 2005 Beeyond Software Holding BV
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*!\file AbstractCollection.h
 * \ingroup CXX_UTIL_m
 */

#ifndef _ABSTRACT_CLASS_BEE_UTIL_ABSTRACTCOLLECTION_H
#define _ABSTRACT_CLASS_BEE_UTIL_ABSTRACTCOLLECTION_H

#ifdef __cplusplus

#include "beecrypt/c++/lang/Comparable.h"
using beecrypt::lang::Comparable;
#include "beecrypt/c++/lang/StringBuilder.h"
using beecrypt::lang::StringBuilder;
#include "beecrypt/c++/lang/ClassCastException.h"
using beecrypt::lang::ClassCastException;
#include "beecrypt/c++/lang/UnsupportedOperationException.h"
using beecrypt::lang::UnsupportedOperationException;
#include "beecrypt/c++/util/Collection.h"
using beecrypt::util::Collection;

namespace beecrypt {
	namespace util {
		/*!\ingroup CXX_UTIL_m
		 * \warning See the description of beecrypt::util:Collection for limitations
		 *  on template parameter class E.
		 */
		template<class E> class AbstractCollection : public beecrypt::lang::Object, public virtual beecrypt::util::Collection<E>
		{
		protected:
			AbstractCollection() {}

		public:
			virtual ~AbstractCollection() {}

			virtual bool add(E* e)
			{
				throw UnsupportedOperationException();
			}
			virtual bool addAll(const Collection<E>& c)
			{
				bool result = false;
				Iterator<E>* it = iterator();
				assert(it != 0);
				while (it->hasNext())
				{
					if (add(it->next()))
						result = true;
				}
				delete it;
				return result;
			}
			virtual void clear()
			{
				Iterator<E>* it = iterator();
				assert(it != 0);
				while (it->hasNext())
				{
					it->next();
					it->remove();
				}
				delete it;
			}
			virtual bool contains(const E* e) const
			{
				bool result = false;
				Iterator<E>* it = iterator();
				assert(it != 0);
				if (e)
				{
					while (it->hasNext())
					{
						E* tmp = it->next();
						if (tmp && tmp->equals(e))
						{
							result = true;
							break;
						}
					}
				}
				else
				{
					while (it->hasNext())
						if (!it->next())
						{
							result = true;
							break;
						}
				}
				delete it;
				return result;
			}
			virtual bool containsAll(const Collection<E>& c) const
			{
				Iterator<E>* cit = c.iterator();
				assert(cit != 0);
				while (cit->hasNext())
					if (!contains(cit->next()))
					{
						delete cit;
						return false;
					}
				delete cit;
				return true;
			}
			virtual bool equals(const Object* obj) const throw ()
			{
				return Object::equals(obj);
			}
			virtual jint hashCode() const throw ()
			{
				return Object::hashCode();
			}
			virtual bool isEmpty() const throw ()
			{
				return size() == 0;
			}
			virtual Iterator<E>* iterator() = 0;
			virtual Iterator<E>* iterator() const = 0;
			virtual bool remove(const E* e)
			{
				bool result = false;
				Iterator<E>* it = iterator();
				assert(it != 0);
				if (e)
				{
					while (it->hasNext())
					{
						E* tmp = it->next();
						if (tmp && tmp->equals(e))
						{
							it->remove();
							result = true;
							break;
						}
					}
				}
				else
				{
					while (it->hasNext())
						if (!it->next())
						{
							it->remove();
							result = true;
							break;
						}
				}
				delete it;
				return result;
			}
			virtual bool removeAll(const Collection<E>& c)
			{
				bool result = false;
				Iterator<E>* it = iterator();
				assert(it != 0);
				while (it->hasNext())
					if (c.contains(it->next()))
					{
						it->remove();
						result = true;
						break;
					}
				delete it;
				return result;
			}
			virtual bool retainAll(const Collection<E>& c)
			{
				bool result = false;
				Iterator<E>* it = c.iterator();
				assert(it != 0);
				while (it->hasNext())
					if (!c.contains(it->next()))
					{
						it->remove();
						result = true;
						break;
					}
				delete it;
				return result;
			}
			virtual jint size() const throw () = 0;
			virtual array<E*> toArray() const
			{
				array<E*> result(size());
				Iterator<E>* it = iterator();
				assert(it != 0);
				for (jint i = 0; it->hasNext(); i++)
					result[i] = it->next();
				delete it;
				return result;
			}
			virtual String toString() const throw ()
			{
				StringBuilder buf("[");

				Iterator<E>* it = iterator();
				assert(it != 0);

				bool hasNext = it->hasNext();
				while (hasNext)
				{
					E* e = it->next();
					if (reinterpret_cast<const void*>(e) == reinterpret_cast<const void*>(this))
						buf.append("(this Collection)");
					else
						buf.append(e);
					if ((hasNext = it->hasNext()))
						buf.append(", ");
				}
				delete it;

				buf.append("]");

				return buf.toString();
			}
		};
	}
}

#endif

#endif
