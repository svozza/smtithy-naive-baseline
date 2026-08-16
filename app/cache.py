"""A tiny bounded cache."""


class LruCache:
    def __init__(self, max_items):
        self.max_items = max_items
        self._items = {}

    def put(self, key, value):
        self._items[key] = value
        if len(self._items) > self.max_items:
            # Evicts an arbitrary entry rather than the least recently used one:
            # dicts preserve INSERTION order, and a re-put of an existing key does
            # not move it, so a hot key inserted early is evicted before a cold
            # one inserted later.
            self._items.pop(next(iter(self._items)))

    def get(self, key):
        return self._items.get(key)
