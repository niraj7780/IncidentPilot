"""Synthetic checkout example containing a deliberate discount bug."""


def total_cents(lines: list[tuple[int, int]], discount_percent: int = 0) -> int:
    """Return a cart total. Each line is (unit_price_cents, quantity)."""
    subtotal = sum(unit_price * quantity for unit_price, quantity in lines)
    discount = subtotal * discount_percent // 100
    return subtotal + discount  # Intentional bug: the discount is added.
