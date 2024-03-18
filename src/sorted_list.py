from typing import List, Optional
import bisect

# We use this to find the previous instruction.
class SortedList:
    def __init__(self) -> None:
        self._list: List[int] = []

    def __len__(self) -> int:
        return len(self._list)

    def insert_sorted(self, value: int) -> None:
        if self.find_element(value):
            return
        bisect.insort(self._list, value)

    def find_element(self, value: int) -> bool:
        pos = bisect.bisect_left(self._list, value)
        return pos != len(self._list) and self._list[pos] == value

    def closest_left_match(self, value: int) -> Optional[int]:
        pos = bisect.bisect_left(self._list, value)
        if pos == 0:
            return None
        else:
            return self._list[pos - 1]
