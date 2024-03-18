from .sorted_list import SortedList


def test_sorted_list() -> None:
    def test_sl(sl: SortedList) -> None:
        assert len(sl) == 3

        assert not sl.find_element(0)
        assert sl.find_element(10)
        assert sl.find_element(20)
        assert sl.find_element(30)
        assert not sl.find_element(100)

        assert sl.closest_left_match(0) is None
        assert sl.closest_left_match(10) is None
        assert sl.closest_left_match(11) == 10
        assert sl.closest_left_match(19) == 10
        assert sl.closest_left_match(20) == 10
        assert sl.closest_left_match(21) == 20

    sl = SortedList()
    sl.insert_sorted(10)
    sl.insert_sorted(20)
    sl.insert_sorted(30)
    test_sl(sl)

    sl = SortedList()
    sl.insert_sorted(30)
    sl.insert_sorted(20)
    sl.insert_sorted(10)
    test_sl(sl)
