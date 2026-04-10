class Value:
    def __eq__(self, other):
        if not isinstance(other, Value):
            return NotImplemented
        return self.x == other.x
