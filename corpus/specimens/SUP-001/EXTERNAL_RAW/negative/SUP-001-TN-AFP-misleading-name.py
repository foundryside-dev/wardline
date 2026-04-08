"""SUP-001 adversarial false positive: function named random_shuffle but not from random module."""
from wardline.decorators import deterministic


def random_shuffle(items: list) -> list:
    """Custom deterministic shuffle unrelated to stdlib random."""
    return sorted(items)


@deterministic
def process(data: list) -> list:
    return random_shuffle(data)
