
from functools import wraps


def cached_property(func, name=None):
    """
    cached_property(func, name=None) -> a descriptor
    This decorator implements an object's property which is computed
    the first time it is accessed, and which value is then stored in
    the object's __dict__ for later use. If the attribute is deleted,
    the value will be recomputed the next time it is accessed.
    Usage:
        class X(object):
            @cachedProperty
            def foo(self):
                return computation()
    """
    if name is None:
        name = func.__name__

    @wraps(func)
    def _get(self):
        try:
            value = self.__dict__[name]
        except KeyError:
            value = func(self)
            self.__dict__[name] = value
        return value

    def _del(self):
        self.__dict__.pop(name, None)

    return property(_get, None, _del)

