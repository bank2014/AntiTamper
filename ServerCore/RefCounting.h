#pragma once

/*---------------
   RefCountable
----------------*/

class RefCountable
{
public:
	RefCountable() : _refCount(1) { }
	virtual ~RefCountable() { }

	int32 GetRefCount() { return _refCount; }

	int32 AddRef() { return ++_refCount; }
	int32 ReleaseRef()
	{
		int32 refCount = --_refCount;
		if (refCount == 0)
		{
			delete this;
		}
		return refCount;
	}

protected:
	atomic<int32> _refCount;
};


/*---------------
   SharedPtr
----------------*/

template<typename T>
class TSharedPtr
{
public:
	TSharedPtr() { }
	TSharedPtr(T* ptr) { Set(ptr); }
	~TSharedPtr() { Release(); }

public:

	bool IsNull() { return _ptr == nullptr; }

private:
	inline void Set(T* ptr)
	{
		_ptr = ptr;
		if (ptr)
			ptr->AddRef();
	}

	inline void Release()
	{
		if (_ptr != nullptr)
		{
			_ptr->ReleaseRef();
			_ptr = nullptr;
		}
	}

private:
	T* _ptr = nullptr;
};