#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This module implements an union find or disjoint set data structure.

An union find data structure can keep track of a set of elements into a number
of disjoint (nonoverlapping) subsets. That is why it is also known as the
disjoint set data structure. Mainly two useful operations on such a data
structure can be performed. A *find* operation determines which subset a
particular element is in. This can be used for determining if two
elements are in the same subset. An *union* Join two subsets into a
single subset.

The complexity of these two operations depend on the particular implementation.
It is possible to achieve constant time (O(1)) for any one of those operations
while the operation is penalized. A balance between the complexities of these
two operations is desirable and achievable following two enhancements:

1.  Using union by rank -- always attach the smaller tree to the root of the
    larger tree.
2.  Using path compression -- flattening the structure of the tree whenever
    find is used on it.

complexity:
    * find -- :math:`O(\\alpha(N))` where :math:`\\alpha(n)` is
      `inverse ackerman function
      <http://en.wikipedia.org/wiki/Ackermann_function#Inverse>`_.
    * union -- :math:`O(\\alpha(N))` where :math:`\\alpha(n)` is
      `inverse ackerman function
      <http://en.wikipedia.org/wiki/Ackermann_function#Inverse>`_.

"""

from collections import defaultdict


class UF:
    """An implementation of union find data structure.
    It uses weighted quick union by rank with path compression.
    """

    def __init__(self, N):
        """Initialize an empty union find object with N items.

        Args:
            N: Number of items in the union find object.
        """

        self._id = list(range(N))
        self._count = N
        self._rank = [0] * N
        self._N = N
        self._symbol_to_index = {}
        self._index_to_symbol = {}

    def find(self, p):
        """Find the set identifier for the item p."""

        # For integer items, try to preserve natural 0--N order if
        # possible, even if the successive calls to find are not in
        # that order
        if isinstance(p, int) and p < self._N and \
           p not in self._index_to_symbol:
            self._symbol_to_index[p] = p
            self._index_to_symbol[p] = p
        else:
            # Non-integer items (e.g. string)
            self._symbol_to_index.setdefault(p, len(self._symbol_to_index))
            self._index_to_symbol.setdefault(self._symbol_to_index[p], p)
        i = self._symbol_to_index[p]
        if i >= self._N:
            raise IndexError('You have been exceeding the UF capacity')

        id = self._id
        while i != id[i]:
            id[i] = id[id[i]]   # Path compression using halving.
            i = id[i]
        return i

    def count(self):
        """Return the number of items."""

        return self._count

    def connected(self, p, q):
        """Check if the items p and q are on the same set or not."""

        return self.find(p) == self.find(q)

    def union(self, p, q):
        """Combine sets containing p and q into a single set."""

        id = self._id
        rank = self._rank

        i = self.find(p)
        j = self.find(q)
        if i == j:
            return

        self._count -= 1
        if rank[i] < rank[j]:
            id[i] = j
        elif rank[i] > rank[j]:
            id[j] = i
        else:
            id[j] = i
            rank[i] += 1

    def get_components(self):
        """List of symbol components (as sets)"""
        d = defaultdict(set)
        for i, j in enumerate(self._id):
            d[self.find(self._index_to_symbol.get(j, j))].add(
                self._index_to_symbol.get(i, i)
            )
        return list(d.values())

    def __str__(self):
        """String representation of the union find object."""
        return " ".join([str(x) for x in self._id])

    def __repr__(self):
        """Representation of the union find object."""
        return "UF(" + str(self) + ")"

if __name__ == "__main__":
    print("Union find data structure.")
    N = int(raw_input("Enter number of items: "))
    uf = UF(N)
    print("Enter a sequence of space separated pairs of integers: ")
    while True:
        try:
            p, q = [int(x) for x in raw_input().split()]
            uf.union(p, q)
        except:
            break

    print(str(uf.count()) + " components: " + str(uf))
