from app.checkout import total_cents


def test_total_without_discount():
    assert total_cents([(1250, 2), (500, 1)]) == 3000


def test_percentage_discount_reduces_total():
    assert total_cents([(1000, 2)], discount_percent=10) == 1800
