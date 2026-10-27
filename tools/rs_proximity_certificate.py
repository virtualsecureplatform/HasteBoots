#!/usr/bin/env python3
"""Small-field audit of a proposed RS random-linear proximity argument.

The symbolic implementation is deliberately limited to tiny matrices. It is a
proof-audit aid, not a production extractor, Fiat-Shamir theorem or certificate
of complete-PBS security. No third-party symbolic algebra package is needed.
"""
from itertools import combinations, permutations, product


class Polynomial:
    """Sparse multivariate polynomial over a prime field (no function reduction)."""
    def __init__(self, p, variables, terms):
        self.p, self.variables = p, variables
        self.terms = {tuple(e): c % p for e, c in terms.items() if c % p}

    @classmethod
    def constant(cls, p, variables, value):
        return cls(p, variables, {(0,)*variables: value})

    @classmethod
    def variable(cls, p, variables, index):
        exponent = [0]*variables
        exponent[index] = 1
        return cls(p, variables, {tuple(exponent): 1})

    def _coerce(self, other):
        if isinstance(other, int):
            return self.constant(self.p, self.variables, other)
        if (self.p, self.variables) != (other.p, other.variables):
            raise ValueError("different polynomial rings")
        return other

    def __bool__(self):
        return bool(self.terms)

    def __add__(self, other):
        other = self._coerce(other)
        out = dict(self.terms)
        for exponent, coefficient in other.terms.items():
            out[exponent] = out.get(exponent, 0)+coefficient
        return Polynomial(self.p, self.variables, out)

    __radd__ = __add__

    def __neg__(self):
        return Polynomial(self.p, self.variables, {e: -c for e, c in self.terms.items()})

    def __sub__(self, other):
        return self + -self._coerce(other)

    def __rsub__(self, other):
        return self._coerce(other) + -self

    def __mul__(self, other):
        other = self._coerce(other)
        out = {}
        for a, x in self.terms.items():
            for b, y in other.terms.items():
                exponent = tuple(i+j for i, j in zip(a, b))
                out[exponent] = out.get(exponent, 0)+x*y
        return Polynomial(self.p, self.variables, out)

    __rmul__ = __mul__

    def __eq__(self, other):
        other = self._coerce(other)
        return self.terms == other.terms

    def degree(self):
        return max((sum(e) for e in self.terms), default=-1)

    def evaluate(self, values):
        if len(values) != self.variables:
            raise ValueError("wrong evaluation dimension")
        return sum(c * self._monomial(e, values) for e, c in self.terms.items()) % self.p

    def _monomial(self, exponent, values):
        out = 1
        for e, value in zip(exponent, values):
            out = out * pow(value, e, self.p) % self.p
        return out


def determinant(matrix, zero):
    """Leibniz expansion, used only for tiny audit matrices."""
    size = len(matrix)
    if size == 0:
        return zero+1
    out = zero
    for perm in permutations(range(size)):
        term = zero+1
        for i, j in enumerate(perm):
            term *= matrix[i][j]
        inversions = sum(perm[i] > perm[j] for i in range(size) for j in range(i+1, size))
        out += -term if inversions & 1 else term
    return out


def interpolate(points, values, p):
    """Independent Lagrange interpolation of a scalar polynomial."""
    out = [0]*len(points)
    for i, (x, value) in enumerate(zip(points, values)):
        basis, denominator = [1], 1
        for j, other in enumerate(points):
            if j == i:
                continue
            nxt = [0]*(len(basis)+1)
            for k, coefficient in enumerate(basis):
                nxt[k] = (nxt[k]-other*coefficient) % p
                nxt[k+1] = (nxt[k+1]+coefficient) % p
            basis = nxt
            denominator = denominator*(x-other) % p
        scale = value*pow(denominator, p-2, p) % p
        for j, coefficient in enumerate(basis):
            out[j] = (out[j]+scale*coefficient) % p
    return out


def evaluate(coefficients, point, p):
    out = 0
    for coefficient in reversed(coefficients):
        out = (out*point+coefficient) % p
    return out


def common_source(rows, points, message, radius, p):
    """Exhaustively find a common <=radius column-error set, if one exists."""
    for errors in combinations(range(len(points)), radius):
        good = [j for j in range(len(points)) if j not in errors]
        chosen = good[:message]
        decoded = [interpolate([points[j] for j in chosen], [row[j] for j in chosen], p) for row in rows]
        if all(evaluate(poly, points[j], p) == row[j] % p
               for row, poly in zip(rows, decoded) for j in good):
            return decoded, errors
    return None


def near_word(word, points, message, radius, p):
    return common_source([word], points, message, radius, p) is not None


def _trim(coefficients):
    while coefficients and not coefficients[-1]:
        coefficients.pop()
    return coefficients


def certificate(rows, points, message, radius, p):
    """Construct a nonzero exceptional-challenge polynomial for a far matrix.

    On every challenge whose linear combination is radius-close to RS, the
    polynomial vanishes. Dimensions are bounded so the audit cannot be mistaken
    for an efficient native-size implementation.
    """
    n, variables = len(points), len(rows)
    if (not 1 <= variables <= 3 or any(len(row) != n for row in rows) or n > 7 or
            any(type(x) is not int for x in (p, message, radius)) or
            not 3 <= p <= 257 or any(p % d == 0 for d in range(2, int(p**.5)+1)) or
            len(set(x % p for x in points)) != n or not 1 <= message <= n or
            not 0 <= radius or n < message+2*radius):
        raise ValueError("unsupported audit field, dimensions or decoding radius")
    zero = Polynomial.constant(p, variables, 0)
    if common_source(rows, points, message, radius, p) is not None:
        return None
    indeterminates = [Polynomial.variable(p, variables, i) for i in range(variables)]
    words = [sum((indeterminates[i]*rows[i][j] for i in range(variables)), zero) for j in range(n)]
    # Unknowns are E_0..E_radius and Q_0..Q_(message+radius-1).
    matrix = [[-word*pow(point, j, p) for j in range(radius+1)] +
              [zero+pow(point, j, p) for j in range(message+radius)]
              for point, word in zip(points, words)]
    columns = message+2*radius+1
    pivot = None
    for rank in range(min(n, columns), 0, -1):
        for rr in combinations(range(n), rank):
            for cc in combinations(range(columns), rank):
                minor = determinant([[matrix[i][j] for j in cc] for i in rr], zero)
                if minor:
                    pivot = rank, rr, cc, minor
                    break
            if pivot:
                break
        if pivot:
            break
    rank, rr, cc, minor = pivot
    if rank == columns:
        return dict(kind="rank", polynomial=minor, bound=n*(n+1), rank=rank)
    free = next(j for j in range(columns) if j not in cc)
    selected = list(cc)+[free]
    kernel = [zero]*columns
    for j, column in enumerate(selected):
        remaining = selected[:j]+selected[j+1:]
        coefficient = determinant([[matrix[i][c] for c in remaining] for i in rr], zero)
        kernel[column] = -coefficient if j & 1 else coefficient
    assert any(kernel)
    assert all(not sum((a*b for a, b in zip(row, kernel)), zero) for row in matrix)
    locator = _trim(kernel[:radius+1])
    numerator = _trim(kernel[radius+1:])
    assert locator and numerator, "a far matrix cannot have a zero E or Q kernel component"
    de, dq = len(locator)-1, len(numerator)-1
    if dq < de or dq-de >= message:
        exceptional = locator[-1]*numerator[-1]
        kind = "quotient-degree"
    else:
        # Pseudo-division avoids rational functions and degree-unstable divisions.
        remainder = numerator[:]
        while remainder and len(remainder) >= len(locator):
            shift, leading = len(remainder)-len(locator), remainder[-1]
            remainder = [locator[-1]*c for c in remainder]
            for i, coefficient in enumerate(locator):
                remainder[shift+i] -= leading*coefficient
            _trim(remainder)
        assert remainder, "generic divisibility would yield a common decoded source"
        exceptional = locator[-1]*next(c for c in remainder if c)
        kind = "division-remainder"
    assert exceptional and exceptional.degree() <= n*(n+1)
    return dict(kind=kind, polynomial=exceptional, bound=n*(n+1), rank=rank)


def exhaustive_check(rows, points, message, radius, p):
    """Enumerate a tiny challenge space and check the certificate pointwise."""
    if p**len(rows) > 1000000:
        raise ValueError("audit challenge space too large")
    cert = certificate(rows, points, message, radius, p)
    if cert is None:
        return dict(common_source=True)
    near = 0
    for alpha in product(range(p), repeat=len(rows)):
        word = [sum(a*row[j] for a, row in zip(alpha, rows)) % p for j in range(len(points))]
        if near_word(word, points, message, radius, p):
            near += 1
            if cert["polynomial"].evaluate(alpha) != 0:
                raise AssertionError(("certificate misses a close combination", alpha))
    total = p**len(rows)
    degree = cert["polynomial"].degree()
    assert near*p <= degree*total
    return dict(common_source=False, kind=cert["kind"], degree=degree,
                degree_bound=cert["bound"], near=near, challenges=total)
