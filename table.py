from threading import Lock

# This data structure is necessary to ensure that events are sorted in chronological order.
# Unfortunately, while unpacking an event, another one may be processed due to using one thread
# per probe.
# A tid is used to index linked list "buckets", one per thread in the process emitting probes.
# Every time an event comes through, it is slotted into the appropriate bucket. If it is in 
# order, it is merely appended to the end. Otherwise, if it happened at an earlier time than the 
# last event in the bucket, the bucket is reverse-searched for the appropriate slot to insert the event.

class DoublyLinkedNode:
    def __init__(self, value, nxt = None):
        self.value = value
        self.next = nxt
        if self.next != None:
            self.next.prev = self
        self.prev = None

    def link(self, value):
        self.next = DoublyLinkedNode(value, self.next)
        self.next.prev = self

class DoublyLinkedList:
    def __init__(self, value):
        self.head = DoublyLinkedNode(value)
        self.tail = self.head

    def append(self, value):
        self.tail.link(value)
        self.tail = self.tail.next

    def replace_head(self, value):
        self.head = DoublyLinkedNode(value, self.head)

class SortedTable:
    def __init__(self, idx_key, sort_key):
        self.buckets = {}
        self._idx_key = idx_key
        self._sort_key = sort_key
        # this is slow, TODO: more appropriate mutex
        self._lock = Lock()

    def _is_ascending(self, item_old, item_new):
        return getattr(item_old, self._sort_key) <= getattr(item_new, self._sort_key)

    def add(self, item):
        idx_key = getattr(item, self._idx_key)

        with self._lock:
            bucket = self.buckets.get(idx_key)
            if bucket == None:
                self.buckets[idx_key] = DoublyLinkedList(item)
                return 
            # Ensure sort order ascending by sort_key, since threading & lock contention can result in
            # items arriving out of chronological sort order :(
            # While looping back to find the right slot is potentially O(elements in bucket),
            # and inserting results in the
            # the assumption is that at most one or two steps will be necessary most of the time.
            if self._is_ascending(bucket.tail.value, item):
                # easy case, item is in ascending order
                bucket.append(item)
            else:
                node = bucket.tail.prev
                while node != None and not self._is_ascending(node.value, item):
                    node = node.prev
                if node == None:
                    bucket.replace_head(item)
                else:
                    node.link(item)
