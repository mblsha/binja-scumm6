"""Sorted list utility for efficient address lookups."""

from typing import List, Optional
import bisect


class SortedList:
    """A list that maintains sorted order for efficient lookups."""

    def __init__(self) -> None:
        self._list: List[int] = []

    def __len__(self) -> int:
        return len(self._list)

    def insert_sorted(self, value: int) -> None:
        """Insert a value while maintaining sorted order."""
        pos = bisect.bisect_left(self._list, value)
        if pos != len(self._list) and self._list[pos] == value:
            return
        self._list.insert(pos, value)

    def find_element(self, value: int) -> bool:
        """Check if a value exists in the list."""
        pos = bisect.bisect_left(self._list, value)
        return pos != len(self._list) and self._list[pos] == value

    def closest_left_match(self, value: int) -> Optional[int]:
        """Find the largest element smaller than the given value."""
        pos = bisect.bisect_left(self._list, value)
        if pos == 0:
            return None

        return self._list[pos - 1]
