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

/*!\file AbstractList.h
 * \ingroup CXX_UTIL_m
 */

#ifndef _ABSTRACT_CLASS_BEE_UTIL_ABSTRACTLIST_H
#define _ABSTRACT_CLASS_BEE_UTIL_ABSTRACTLIST_H

#ifdef __cplusplus

#include "beecrypt/c++/util/AbstractCollection.h"
using beecrypt::util::AbstractCollection;
#include "beecrypt/c++/util/List.h"
using beecrypt::util::List;
#include "beecrypt/c++/lang/IllegalStateException.h"
using beecrypt::lang::IllegalStateException;
#include "beecrypt/c++/util/ConcurrentModificationException.h"
using beecrypt::util::ConcurrentModificationException;

namespace beecrypt {
	namespace util {
		/*!\ingroup CXX_UTIL_m
		 * \warning class E must be a subclass of Object
		 */
		template<class E> class AbstractList : public beecrypt::util::AbstractCollection<E>, public virtual beecrypt::util::List<E>
		{
		private:
			class Iter : public beecrypt::lang::Object, public virtual beecrypt::util::Iterator<E>
			{
			private:
				      AbstractList*       _list;
				const AbstractList* _const_list;
				jint _pos;
				jint _last;
				jint _expect;

			public:
				Iter(AbstractList* list) : _list(list), _const_list(list)
				{
					_pos = 0;
					_last = -1;
					_expect = _const_list->modCount;
				}
				Iter(const AbstractList* list) : _list(0), _const_list(list)
				{
					_pos = 0;
					_last = -1;
					_expect = _const_list->modCount;
				}
				virtual ~Iter() {}

				virtual bool hasNext() throw ()
				{
					return _pos < _const_list->size();
				}
				virtual E* next() throw (NoSuchElementException)
				{
					if (_expect != _const_list->modCount)
						throw ConcurrentModificationException();

					try
					{
						E* e = _const_list->get(_pos);
						_last = _pos++;
						return e;
					}
					catch (IndexOutOfBoundsException&)
					{
						if (_expect != _const_list->modCount)
							throw ConcurrentModificationException();

						throw NoSuchElementException();
					}
				}
				virtual void remove()
				{
					if (!_list)
						throw UnsupportedOperationException("Cannot remove items in a const iterator");

					if (_last == -1)
						throw IllegalStateException();

					if (_expect != _list->modCount)
						throw ConcurrentModificationException();

					try
					{
						E* e = _list->remove(_last);
						if (e)
	 						collection_rcheck(e);
						if (_last < _pos)
							_pos--;
						_last = -1;
						_expect = _list->modCount;
					}
					catch (IndexOutOfBoundsException&)
					{
						throw ConcurrentModificationException();
					}
				}
			};

			class ListIter : public beecrypt::lang::Object, public virtual beecrypt::util::ListIterator<E>
			{
			private:
				      AbstractList*       _list;
				const AbstractList* _const_list;
				jint _pos;
				jint _last;
				jint _expect;

			public:
				ListIter(AbstractList* list, jint index) throw (IndexOutOfBoundsException) : _list(list), _const_list(list)
				{
					if (index < 0 || index > list->size())
						throw IndexOutOfBoundsException();

					_pos = index;
					_last = -1;
					_expect = _const_list->modCount;
				}
				ListIter(const AbstractList* list, jint index) throw (IndexOutOfBoundsException) : _list(0), _const_list(list)
				{
					if (index < 0 || index > list->size())
						throw IndexOutOfBoundsException();

					_pos = index;
					_last = -1;
					_expect = _const_list->modCount;
				}
				virtual ~ListIter() {}

				virtual void add(E* e)
				{
					if (!_list)
						throw UnsupportedOperationException("Cannot add items in a const iterator");

					if (_expect != _list->modCount)
						throw ConcurrentModificationException();

					try
					{
						_list->add(_pos++, e);
						_last = -1;
						_expect = _list->modCount;
					}
					catch (IndexOutOfBoundsException&)
					{
						throw ConcurrentModificationException();
					}
				}
				virtual bool hasNext() throw ()
				{
					return _pos < _const_list->size();
				}
				virtual bool hasPrevious() throw ()
				{
					return _pos > 0;
				}
				virtual E* next() throw (NoSuchElementException)
				{
					if (_expect != _const_list->modCount)
						throw ConcurrentModificationException();

					try
					{
						E* e = _const_list->get(_pos);
						_last = _pos++;
						return e;
					}
					catch (IndexOutOfBoundsException&)
					{
						if (_expect != _const_list->modCount)
							throw ConcurrentModificationException();

						throw NoSuchElementException();
					}
				}
				virtual jint nextIndex() throw ()
				{
					return _pos;
				}
				virtual E* previous() throw (NoSuchElementException)
				{
					if (_expect != _const_list->modCount)
						throw ConcurrentModificationException();

					try
					{
						E* e = _const_list->get(_pos-1);
						_last = _pos--;
						return e;
					}
					catch (IndexOutOfBoundsException&)
					{
						if (_expect != _const_list->modCount)
							throw ConcurrentModificationException();

						throw NoSuchElementException();
					}
				}
				virtual jint previousIndex() throw ()
				{
					return _pos-1;
				}
				virtual void remove()
				{
					if (!_list)
						throw UnsupportedOperationException("Cannot remove items in a const iterator");

					if (_last == -1)
						throw IllegalStateException();

					if (_expect != _list->modCount)
						throw ConcurrentModificationException();

					try
					{
						E* e = _list->remove(_last);
						if (e)
							collection_rcheck(e);
						if (_last < _pos)
							_pos--;
						_last = -1;
						_expect = _list->modCount;
					}
					catch (IndexOutOfBoundsException&)
					{
						throw ConcurrentModificationException();
					}
				}
				virtual void set(E* e)
				{
					if (!_list)
						throw UnsupportedOperationException("Cannot set items in a const iterator");

					if (_last == -1)
						throw IllegalStateException();

					if (_expect != _list->modCount)
						throw ConcurrentModificationException();

					try
					{
						_list->set(_last, e);
						_expect = _list->modCount;
					}
					catch (IndexOutOfBoundsException&)
					{
						throw ConcurrentModificationException();
					}
				}
			};

		protected:
			jint modCount;

		protected:
			AbstractList()
			{
				modCount = 0;
			}

		public:
			virtual ~AbstractList() {}

			virtual bool add(E* e)
			{
				add(size(), e);
				return true;
			}
			virtual void add(jint index, E* e)
			{
				throw UnsupportedOperationException();
			}
			virtual bool addAll(jint index, const Collection<E>& c)
			{
				bool result = false;
				Iterator<E>* cit = c.iterator();
				assert(cit != 0);
				while (cit->hasNext())
				{
					add(index++, cit->next());
					result = true;
				}
				delete cit;
				return result;
			}
			virtual void clear()
			{
				while (size())
				{
					E* e = remove(0);
					if (e)
						collection_rcheck(e);
				}
			}
			virtual bool equals(const Object* obj) const throw ()
			{
				if (this == obj)
					return true;

				if (obj)
				{
					const AbstractList<E>* abs = dynamic_cast<const AbstractList<E>*>(obj);
					if (abs)
					{
						bool result = true;

						ListIterator<E>* lit1 = listIterator();
						assert(lit1 != 0);
						ListIterator<E>* lit2 = abs->listIterator();
						assert(lit2 != 0);

						while (lit1->hasNext() && lit2->hasNext())
						{
							E* e1 = lit1->next();
							if (e1)
							{
								E* e2 = lit2->next();
								if (!(e2 && e2->equals(e1)))
								{
									result = false;
									break;
								}
							}
							else
							{
								if (lit2->next())
								{
									result = false;
									break;
								}
							}
						}

						if (result)
						{
							// if either of the iterators has any elements left, the lists differ
							result = !(lit1->hasNext() || lit2->hasNext());
						}

						delete lit1;
						delete lit2;

						return result;
					}
				}
				return false;
			}
			virtual E* get(jint index) const throw (IndexOutOfBoundsException) = 0;
			virtual jint hashCode() const throw ()
			{
				register jint result = 1;
				Iterator<E>* it = iterator();
				assert(it != 0);
				while (it->hasNext())
				{
					E* e = it->next();
					result *= 31;
					if (e)
						result += e->hashCode();
				}
				delete it;
				return result;
			}
			virtual jint indexOf(const E* e) const
			{
				jint result = -1;
				ListIterator<E>* lit = listIterator();
				assert(lit != 0);
				if (e)
				{
					while (lit->hasNext())
					{
						E* tmp = lit->next();
						if (tmp && tmp->equals(e))
						{
							result = lit->previousIndex();
							break;
						}
					}
				}
				else
				{
					while (lit->hasNext())
						if (!lit->next())
						{
							result = lit->previousIndex();
							break;
						}
				}
				delete lit;
				return result;
			}
			virtual Iterator<E>* iterator()
			{
				return new Iter(this);
			}
			virtual Iterator<E>* iterator() const
			{
				return new Iter(this);
			}
			virtual jint lastIndexOf(const E* e) const
			{
				jint result = -1;
				ListIterator<E>* lit = listIterator(size());
				assert(lit != 0);
				if (e)
				{
					while (lit->hasPrevious())
					{
						E* tmp = lit->previous();
						if (tmp && tmp->equals(e))
						{
							result = lit->nextIndex();
							break;
						}
					}
				}
				else
				{
					while (lit->hasPrevious())
						if (!lit->previous())
						{
							result = lit->nextIndex();
							break;
						}
				}
				delete lit;
				return result;
			}
			virtual ListIterator<E>* listIterator(jint index = 0) throw (IndexOutOfBoundsException)
			{
				return new ListIter(this, index);
			}
			virtual ListIterator<E>* listIterator(jint index = 0) const throw (IndexOutOfBoundsException)
			{
				return new ListIter(this, index);
			}
			virtual E* remove(jint index)
			{
				throw UnsupportedOperationException();
			}
			virtual E* set(jint index, E* e)
			{
				throw UnsupportedOperationException();
			}
			virtual jint size() const throw () = 0;
		};
	}
}

#endif

#endif
