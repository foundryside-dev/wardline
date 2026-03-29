"""WardlineBase — cooperative base class for wardline-managed user code.

WardlineBase provides ``__init_subclass__`` integration for checking
wardline decorator usage on subclass methods. It cooperates with
``ABCMeta`` and other ``__init_subclass__`` hooks via cooperative
``super()`` calls (called BEFORE wardline checks, per MRO convention).
"""

from __future__ import annotations

from wardline.core.registry import REGISTRY


class WardlineBase:
    """Base class for wardline-managed services and components.

    Subclasses get their methods checked for wardline decorator
    annotations at class definition time. This enables early detection
    of missing or incorrect decorator usage without running a scan.

    When runtime enforcement is enabled (``wardline.runtime.enforcement.enable()``
    or ``WARDLINE_ENFORCE=1``), instances are also checked at construction
    time for tier consistency across decorated methods.

    Cooperative ``__init_subclass__``: calls ``super()`` BEFORE
    wardline checks to ensure other ``__init_subclass__`` hooks in
    the MRO chain fire correctly.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Cooperative super() BEFORE our checks — required for MRO
        super().__init_subclass__(**kwargs)

        # Check subclass methods for wardline decorators
        _check_decorated_methods(cls)

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        from wardline.runtime.enforcement import enforce_construction

        enforce_construction(self)


def _check_decorated_methods(cls: type) -> None:
    """Check methods of a class for wardline decorator annotations.

    Walks the class's own ``__dict__`` (not inherited methods) and
    looks for ``_wardline_groups`` on each callable — the attribute
    set by the wardline decorator factory.
    """
    # Snapshot dict items — cls.__dict__ is only mutated at class
    # definition time so this is safe, but a list() copy is cheap
    # insurance against future metaclass surprises.
    for name, value in list(cls.__dict__.items()):
        # Skip single-underscore private names but NOT dunders —
        # __init__, __call__, etc. can legitimately carry decorators.
        if name.startswith("_") and not name.startswith("__"):
            continue

        # Unwrap staticmethod/classmethod descriptors to access the
        # inner decorated function — _wardline_* attrs live there.
        unwrapped = value
        if isinstance(value, (staticmethod, classmethod)):
            unwrapped = value.__func__
        elif not callable(value):
            continue

        # Check for wardline decorator attributes
        try:
            _groups = unwrapped._wardline_groups
        except AttributeError:
            _groups = None  # not a wardline-decorated callable — skip
            continue

        # Verify decorated methods use registered decorators
        for attr_name in dir(unwrapped):
            if not attr_name.startswith("_wardline_"):
                continue
            if attr_name == "_wardline_groups":
                continue

            # The canonical name can be found by looking up which
            # registry entry has this attr in its contract
            _validate_decorator_attr(cls, name, attr_name)


def _validate_decorator_attr(
    cls: type, method_name: str, attr_name: str
) -> None:
    """Validate a wardline attribute is from a registered decorator.

    Checks that the attribute name appears in at least one registry
    entry's attrs contract. Raises ValueError if unrecognised so
    manually spoofed ``_wardline_*`` attributes are not silently accepted.
    """
    for entry in REGISTRY.values():
        try:
            entry.attrs[attr_name]
        except KeyError:
            _attr_val = None  # attr_name absent from this registry entry — try next
            continue
        return
    raise ValueError(
        f"{cls.__name__}.{method_name} has unrecognized wardline attribute "
        f"{attr_name!r}"
    )
