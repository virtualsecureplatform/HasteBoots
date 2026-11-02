#!/usr/bin/env python3
"""Conservative *interactive algebraic* budget for a packed vector relation.

This is not a Fiat-Shamir, knowledge-soundness, hiding, or complete-PBS analysis.
Bounds follow local 2025/719 Theorems 1 and 3, with union bounds over rounds.
The row-code PCS adaptation remains experimental and needs independent review.
"""
import argparse
import json
from fractions import Fraction
from pathlib import Path

BABYBEAR = 2**31 - 2**27 + 1


def fixed_table_equality_bound(prime, width, variables):
    """Ideal-coin error for equality of two fixed packed base-field tables.

    Uses challenge_pair's k independent evaluations of a degree <=2k-1
    polynomial per fold. Conditional on a nonzero difference surviving the
    preceding folds, a fixed nonzero block vanishes with probability at most
    ((2k-1)/p)^k. Union over the possible first vanishing fold. PCS binding,
    word availability and Fiat-Shamir compilation are separate obligations.
    The caller must establish that prime is the field characteristic.
    """
    if any(type(x) is not int for x in (prime, width, variables)) or not (
            prime >= 3 and width >= 1 and variables >= 0 and 2*width <= prime):
        raise ValueError("invalid packed equality geometry")
    return min(Fraction(1), variables * Fraction(2*width-1, prime)**width)


def canonical_ntt_algebraic_bounds(prime, width, variables, polynomial_size, links=1):
    """Non-PCS ideal-interactive terms for packed_ntt::verify_canonical.

    Source tables are fixed before the k independent tensor row points;
    the 2k claimed folded polynomials are fixed before coefficient compression.
    Hash availability, PCS errors and adaptive Fiat-Shamir are not included.
    """
    fixed_table_equality_bound(prime, width, variables)
    if (type(polynomial_size) is not int or type(links) is not int or links < 1
            or width & (width-1) or polynomial_size < width
            or polynomial_size & (polynomial_size-1)):
        raise ValueError("invalid canonical NTT geometry")
    coefficient = (polynomial_size // width).bit_length()-1
    row = variables-coefficient
    if row < 0:
        raise ValueError("NTT polynomial exceeds the source table")
    return {
        "row_identity": links * min(Fraction(1), Fraction(row, prime)**width),
        "coefficient_compression": links * 2*width
            * fixed_table_equality_bound(prime, width, coefficient),
    }


def lookup_first_retry_bound(prime, degree, table_rows, pairs):
    """Analysis-only stop at the first rejected reciprocal challenge.

    Each compressed public table is fixed before its fresh uniform draw.
    Zero and the negatives of at most table_rows values are excluded. On
    paths without a rejection, each pair uses exactly two scalar phases
    (compression and reciprocal). This does not bound consumed sampler bytes
    or change the production retry loop. Callers must charge this event over
    all adversarial queries and verifier submissions, including false inputs.
    """
    if any(type(x) is not int for x in (prime, degree, table_rows, pairs)) or not (
            prime >= 3 and degree >= 1 and table_rows >= 1 and pairs >= 0):
        raise ValueError('invalid lookup retry geometry')
    q = prime**degree
    if table_rows + 1 >= q:
        raise ValueError('reciprocal domain must be nonempty')
    return dict(per_fresh_reciprocal=Fraction(table_rows+1, q),
                first_retry_union=min(Fraction(1), Fraction(pairs*(table_rows+1), q)),
                scalar_phases_without_retry=2*pairs)


def extension_lookup_algebraic_bounds(p, degree, variables, logical, table,
                                      columns, count, repetitions):
    """Conditional full-extension tuple lookup terms, excluding all PCS errors.

    Fixed sources and multiplicities precede tuple/reciprocal challenges;
    fixed helpers precede independent equality points. The extension must be
    a field of size p**degree. Multiplicities cannot wrap the characteristic.
    Shared sumcheck points leave all equations separate; union needs no
    independence between equations or requests.
    """
    dimensions=(p,degree,variables,logical,table,columns,count,repetitions)
    if any(type(x) is not int or x < 1 for x in dimensions) or not (
            p >= 3 and logical <= 1 << variables and logical+table-1 < p):
        raise ValueError('invalid extension lookup dimensions or characteristic')
    q=p**degree
    if table+1 >= q:
        raise ValueError('empty reciprocal challenge domain')
    pair=Fraction(table*(columns-1),q)+Fraction(logical+table-1,q-table-1)
    identity_degree=3 if logical == 1 << variables else 4
    return {
        'rational_identity': count*pair**repetitions,
        'sumcheck': count*repetitions*Fraction(variables,q),
        'identity_equality_reduction': count*repetitions*Fraction(variables,q),
        'identity_sumcheck': count*repetitions*Fraction(identity_degree*variables,q),
    }


def zerocheck_algebraic_bound(p, width, degree, variables):
    """Theorem 3 round union, independent of the commitment's row code.

    Conditional on the paper's packed ZeroCheck reduction and authenticated
    terminal factors; this does not include PCS or Fiat-Shamir errors.
    A union bound may exceed one, as in the legacy component calculator.
    """
    if any(type(x) is not int for x in (p, width, degree, variables)) or not (
            p >= 3 and width >= 1 and degree >= 1 and variables >= 1):
        raise ValueError("invalid packed ZeroCheck geometry")
    nodes = 2 * width - 1
    if nodes*(degree+1)+1 >= p:
        raise ValueError("field too small for packed ZeroCheck")
    zero = Fraction(max(variables, degree * nodes + 1, nodes * (degree + 1)), p) ** width
    # Theorem 3 is round-by-round; include every interaction conservatively.
    return (variables + 2) * zero


def atomic_zerocheck_phase_bounds(p, width, degree, variables, *, schedule_version):
    """Conditional fixed-table bad-transition terms for trusted schedules four/five.

    Requires one complete equality-point block, then one complete mixing/row
    block. Versions 1--3 do not have those phases. This supplies neither the
    source/Fiat-Shamir coupling nor a whole-protocol work or knowledge bound.
    """
    if type(schedule_version) is not int or schedule_version not in (4, 5):
        raise ValueError('atomic packed ZeroCheck phase bounds require schedule four or five')
    zerocheck_algebraic_bound(p, width, degree, variables)  # Shared geometry checks.
    nodes = 2*width-1
    return {
        'initial_equality': min(Fraction(1), Fraction(variables-1, p)**width),
        'first_mixed_challenge': Fraction(nodes*degree+1, p)**width,
        'remaining_round': Fraction(nodes*(degree+1), p)**width if variables > 1 else Fraction(),
    }


def bounds(p, width, degree, variables, factors, message_len, encoded_len, queries):
    """Return exact rational union-bound contributions for one ZeroCheck relation."""
    zero = zerocheck_algebraic_bound(p, width, degree, variables)
    distance = Fraction(encoded_len - message_len + 1, encoded_len)
    # Brakedown's conservative proximity gap, not RS unique-decoding radius.
    proximity = 2 * factors * (1 - distance / 3) ** queries
    random_test = factors * Fraction(encoded_len, p) ** width
    return {"zerocheck": zero, "proximity": proximity, "random_linear_test": random_test}


def choose(p, degree, variables, factors, message_len, encoded_len, target):
    threshold = Fraction(1, 2**target)
    for width in range(5, 33):
        if (2 * width - 1) * (degree + 1) + 1 >= p:
            continue
        # First require non-query errors to use less than half the budget.
        fixed = bounds(p, width, degree, variables, factors, message_len, encoded_len, 1)
        if fixed["zerocheck"] + fixed["random_linear_test"] >= threshold / 2:
            continue
        queries = 1
        while True:
            errors = bounds(p, width, degree, variables, factors, message_len, encoded_len, queries)
            if sum(errors.values()) <= threshold:
                return width, queries, errors
            queries += 1
    raise ValueError("no packing width <= 32 fits the algebraic budget")


def component_bounds(component):
    """Budget the actual block-symbol dimensions emitted by the Rust component."""
    names = ["prime", "width", "degree", "variables", "factors", "row_message_scalars",
             "row_message_blocks", "row_encoded_blocks", "block_width", "queries"]
    if any(type(component.get(name)) is not int or component[name] < 1 for name in names):
        raise ValueError("missing or nonpositive component dimensions")
    p = component["prime"]
    message = component["row_message_blocks"]
    length = component["row_encoded_blocks"]
    coefficient_blocks = (component["row_message_scalars"] + component["block_width"] - 1) // component["block_width"]
    expected = 1 << (coefficient_blocks - 1).bit_length()
    if message != expected or length <= message or length & (length - 1) or (p - 1) % (2 * length):
        raise ValueError("inconsistent block RS padding, rate, or NTT domain")
    if (2 * component["width"] - 1) * (component["degree"] + 1) + 1 >= p:
        raise ValueError("field too small for packed ZeroCheck")
    return bounds(p, component["width"], component["degree"], component["variables"],
                  component["factors"], message, length, component["queries"])


def lookup_component_bounds(component):
    """Conservative conditional-domain budget for small scalar-table lookups.

    At most two distinct helper prefixes and s source prefixes are opened.
    Shared columns are one proximity test per response, not independent draws.
    Tuple hashing uses independent (Y,r) pairs; a fixed bad row collides with
    some public tuple with probability <= M*(columns-1)/p.
    """
    component_bounds(component)  # Validate the actual common block-RS dimensions.
    names = ["logical_len", "public_table_len", "excluded_challenges", "repetitions"]
    if any(type(component.get(n)) is not int or component[n] < 1 for n in names):
        raise ValueError("missing or nonpositive lookup dimensions")
    p, k, n, count = (component[x] for x in ("prime", "width", "variables", "factors"))
    logical, table, excluded, reps = (component[x] for x in names)
    if component["degree"] != 3 or excluded not in (table, table+1) or excluded >= p or logical+table-1 >= p or logical > (1 << n)*k:
        raise ValueError("invalid lookup degree, characteristic, mask or challenge domain")
    columns = component.get("tuple_columns", 1)
    if type(columns) is not int or columns < 1:
        raise ValueError("positive tuple column count required")
    nodes = 2*k-1
    length = component["row_encoded_blocks"]
    message = component["row_message_blocks"]
    distance = Fraction(length-message+1, length)
    zero = bounds(p,k,3,n,1,message,length,component["queries"])["zerocheck"]
    return {
        "rational_identity": count * (Fraction(table*(columns-1),p) + Fraction(logical+table-1, p-excluded))**reps,
        "sumcheck": count * reps * n * Fraction(nodes,p)**k,
        "zerocheck": count * reps * zero,
        # s helper roots, at most 2 W responses plus one V each; each of
        # the original source columns has at most s W responses plus one V.
        "proximity": count * ((3+columns)*reps+columns) * (1-distance/3)**component["queries"],
        "random_linear_test": count * (reps+columns) * Fraction(length,p)**k,
    }


def decomposition_component_bounds(component):
    """Tuple comparisons plus canonical reconstruction/borrow endpoint checks."""
    if component.get("tuple_columns") != 3 or component.get("linear_checks") != 2:
        raise ValueError("expected two native input halves and three-column transitions")
    count = component["factors"]
    if count % 2 or component.get("linear_sources") != 2*(count+2):
        raise ValueError("inconsistent digit/source counts")
    errors = lookup_component_bounds(component)
    p, k, n = (component[x] for x in ("prime", "width", "variables"))
    length, message = (component[x] for x in ("row_encoded_blocks", "row_message_blocks"))
    roots = component["linear_sources"]
    gap = Fraction(length-message+1, 3*length)
    errors["linear_identity"] = 2*n*Fraction(2*k-1,p)**k
    errors["linear_proximity"] = 2*roots*(1-gap)**component["queries"]
    errors["linear_random_test"] = roots*Fraction(length,p)**k
    return errors


def lane_decomposition_component_bounds(component):
    """Separate helper/source block-RS budgets for lane-batched comparisons."""
    component_bounds(component)
    count, k, n = (component[x] for x in ("factors", "width", "variables"))
    checks = component.get("linear_checks")
    if type(checks) is not int or checks < 1 or k & (k-1) or count % checks or component.get("tuple_columns") != 3 or component.get("linear_sources") != 2*(count+checks):
        raise ValueError("invalid canonical lane component dimensions")
    helper = dict(component)
    for name in ["row_message_scalars", "row_message_blocks", "row_encoded_blocks", "block_width", "queries", "variables"]:
        helper[name] = component.get("helper_"+name)
    component_bounds(helper)
    reps = component.get("repetitions")
    if type(reps) is not int or reps < 1:
        raise ValueError("positive requested repetitions required")
    groups = (reps+k-1)//k
    actual = groups*k
    logical, table, excluded = (component.get(x) for x in ["logical_len","public_table_len","excluded_challenges"])
    if any(type(x) is not int or x<1 for x in [logical,table,excluded]):
        raise ValueError("missing tuple dimensions")
    p = component["prime"]
    degree = 3 if logical == (1 << n)*k else 4
    if component["degree"] != degree or logical > (1 << n)*k or excluded != table+1 or logical+table-1 >= p or excluded >= p:
        raise ValueError("invalid lane mask, degree or conditional challenge domain")
    if component.get("lookup_groups") != groups or component.get("effective_repetitions") != actual or helper["variables"] != n+k.bit_length()-1:
        raise ValueError("inconsistent lane grouping or helper variable count")
    nodes = 2*k-1
    def proximity(c):
        gap = Fraction(c["row_encoded_blocks"]-c["row_message_blocks"]+1,3*c["row_encoded_blocks"])
        return (1-gap)**c["queries"]
    root_count = component["linear_sources"]
    return {
        "rational_identity": count*(Fraction(2*table,p)+Fraction(logical+table-1,p-excluded))**actual,
        "sumcheck": count*groups*helper["variables"]*Fraction(nodes,p)**k,
        "zerocheck": count*groups*bounds(p,k,degree,helper["variables"],1,helper["row_message_blocks"],helper["row_encoded_blocks"],helper["queries"])["zerocheck"],
        "helper_proximity": count*groups*3*proximity(helper),
        "source_proximity": count*3*(groups+1)*proximity(component),
        "helper_random_linear_test": count*groups*Fraction(helper["row_encoded_blocks"],p)**k,
        "source_random_linear_test": count*3*Fraction(component["row_encoded_blocks"],p)**k,
        "linear_identity": checks*n*Fraction(nodes,p)**k,
        "linear_proximity": 2*root_count*proximity(component),
        "linear_random_test": root_count*Fraction(component["row_encoded_blocks"],p)**k,
    }


def extension_decomposition_component_bounds(component):
    """Interactive algebra/PCS inventory for coefficient-packed GF lookups.

    Does not analyze Fiat-Shamir, the seeded child/parent transcript composition,
    or establish the matrix-weighted row-code adaptation's soundness.
    """
    component_bounds(component)
    p,k,mu,count = (component[x] for x in ("prime","width","variables","factors"))
    degree = component.get("lookup_field_degree")
    supported = {(BABYBEAR,4),(BABYBEAR,5),(BABYBEAR,6),(BABYBEAR,8),
                 (2**64-2**32+1,2),(2**64-2**32+1,3),(2**64-2**32+1,4),(2**64-2**32+1,5)}
    if type(degree) is not int or (p,degree) not in supported or k < degree or k & (k-1):
        raise ValueError("unsupported verified extension field or packing width")
    checks = component.get("linear_checks")
    reps = component.get("repetitions")
    if any(type(x) is not int or x < 1 for x in (checks,reps)) or count % checks or component.get("tuple_columns") != 3 or component.get("linear_sources") != 2*(count+checks):
        raise ValueError("invalid canonical extension component inventory")
    helper = dict(component)
    for name in ["row_message_scalars","row_message_blocks","row_encoded_blocks","block_width","queries","variables"]:
        helper[name] = component.get("helper_"+name)
    component_bounds(helper)
    n = mu+k.bit_length()-1
    logical,table,excluded = (component.get(x) for x in ["logical_len","public_table_len","excluded_challenges"])
    if any(type(x) is not int or x < 1 for x in (logical,table,excluded)):
        raise ValueError("missing extension lookup dimensions")
    identity_degree = 3 if logical == (1<<mu)*k else 4
    if helper["variables"] != n or component["degree"] != identity_degree or logical > (1<<mu)*k or logical+table-1 >= p or excluded != table+1:
        raise ValueError("invalid helper, mask, or base-characteristic multiplicity bound")
    q = p**degree
    def proximity(c):
        return (1-Fraction(c["row_encoded_blocks"]-c["row_message_blocks"]+1,
                           3*c["row_encoded_blocks"]))**c["queries"]
    # Root/multiplicity commitments precede every pair. A bad rational identity
    # survives each independent full-GF pair with the following union bound.
    pair = Fraction(2*table,q)+Fraction(logical+table-1,q-excluded)
    return {
        "rational_identity": count*pair**reps,
        "sumcheck": count*reps*Fraction(n,q),
        "identity_equality_reduction": count*reps*Fraction(n,q),
        "identity_sumcheck": count*reps*Fraction(identity_degree*n,q),
        "helper_proximity": count*reps*3*proximity(helper),
        "source_proximity": count*3*(reps+1)*proximity(component),
        "helper_random_linear_test": count*reps*Fraction(helper["row_encoded_blocks"],p)**k,
        "source_random_linear_test": count*3*Fraction(component["row_encoded_blocks"],p)**k,
        "linear_identity": checks*mu*Fraction(2*k-1,p)**k,
        "linear_proximity": 2*component["linear_sources"]*proximity(component),
        "linear_random_test": component["linear_sources"]*Fraction(component["row_encoded_blocks"],p)**k,
    }


def accumulator_component_bounds(component):
    """Arithmetic, duplicated-half, endpoint and cyclic carry-partition checks."""
    component_bounds(component)
    p,k,n = (component[x] for x in ("prime","width","variables"))
    names = ["polynomial_size","rounds","padded_rounds","coefficient_variables","left_vars","source_queries","response_groups"]
    if any(type(component.get(x)) is not int or component[x]<0 for x in names):
        raise ValueError("missing or invalid accumulator dimensions")
    size,rounds,padded,coefficient,left,queries,responses = (component[x] for x in names)
    if component["degree"]!=1 or component["factors"]!=7 or component.get("linear_relations")!=7 or k&(k-1) or size<k or size&(size-1) or rounds<1 or padded!=1<<(rounds-1).bit_length():
        raise ValueError("invalid accumulator shape or relation count")
    row_variables=padded.bit_length()-1
    if coefficient!=(size//k).bit_length()-1 or n!=coefficient+row_variables+1 or not 0<=left<=n or component["row_message_scalars"]!=1<<(n-left) or queries!=row_variables+12:
        raise ValueError("inconsistent accumulator layout/query count")
    maximum_responses=14 if left<=coefficient else queries+7
    if not 14<=responses<=maximum_responses or (left<=coefficient and responses!=14):
        raise ValueError("invalid shared response count")
    length=component["row_encoded_blocks"]
    gap=Fraction(length-component["row_message_blocks"]+1,3*length)
    return {
        "linear_identities": 7*n*Fraction(2*k-1,p)**k,
        "proximity": maximum_responses*(1-gap)**component["queries"],
        "random_linear_test": 7*Fraction(length,p)**k,
    }


def monomial_component_bounds(component):
    """Two canonical NTT links, public-factor product, six PCS openings.

    Count every opening's random test even when its root repeats. Batched NTT
    queries share a W response only when its coefficient prefix fits on the left.
    """
    component_bounds(dict(component, degree=2, factors=2))
    p,k,n = (component[x] for x in ("prime","width","variables"))
    names = ["polynomial_size","rounds","padded_rounds","left_vars"]
    if any(type(component.get(x)) is not int or component[x]<0 for x in names):
        raise ValueError("missing or invalid monomial dimensions")
    size,rounds,padded,left = (component[x] for x in names)
    if k&(k-1) or size<k or size&(size-1) or rounds<1 or padded!=1<<(rounds-1).bit_length():
        raise ValueError("invalid monomial shape")
    coefficient=(size//k).bit_length()-1
    rows=padded.bit_length()  # Includes the two RLWE halves.
    if n!=coefficient+rows or not 0<=left<=n or component["row_message_scalars"]!=1<<(n-left):
        raise ValueError("inconsistent monomial layout")
    length,message=(component[x] for x in ("row_encoded_blocks","row_message_blocks"))
    responses=12 if left<=coefficient else 4*(k+1)+4
    return {
        "ntt_row_identity": 2*Fraction(rows,p)**k,
        "ntt_coefficient_compression": 4*k*coefficient*Fraction(2*k-1,p)**k,
        "zerocheck": bounds(p,k,2,n,2,message,length,component["queries"])["zerocheck"],
        "proximity": responses*(1-Fraction(length-message+1,3*length))**component["queries"],
        "random_linear_test": 6*Fraction(length,p)**k,
    }


def key_switch_component_bounds(component, decomposition_bound=lane_decomposition_component_bounds):
    """Original-dimension final stage: NTT links, key products, canonical
    negative-a decomposition and masked signed/truncated output extraction.
    """
    names = ["polynomial_size","output_dimension","basis_bits","digits","repetitions"]
    if any(type(component.get(x)) is not int or component[x]<1 for x in names):
        raise ValueError("missing key switching dimensions")
    size,lwe,bits,d,reps = (component[x] for x in names)
    p,k,n = (component[x] for x in ("prime","width","variables"))
    left=component.get("left_vars")
    if type(left) is not int or not 0<=left<=n or size!=1<<(lwe-1).bit_length() or k&(k-1) or k>size or bits>=p.bit_length() or d!=((p-1).bit_length()+bits-1)//bits:
        raise ValueError("unsupported key switching dimensions or canonical radix")
    coefficient=(size//k).bit_length()-1
    if n!=coefficient+1 or component["row_message_scalars"]!=1<<(n-left):
        raise ValueError("inconsistent key switching layout")
    radix=1<<bits
    lane=dict(component,degree=3,factors=d,logical_len=2*size,public_table_len=2*radix,
              excluded_challenges=2*radix+1,tuple_columns=3,linear_checks=1,
              linear_sources=2*(d+1),effective_repetitions=((reps+k-1)//k)*k,
              lookup_groups=(reps+k-1)//k)
    errors={"decomposition_"+name:value for name,value in decomposition_bound(lane).items()}
    length,message = (component[x] for x in ("row_encoded_blocks","row_message_blocks"))
    ntt_responses=4*(d+1) if left<=coefficient else 2*(d+1)*(k+1)
    errors.update({
        "ntt_row_identity": (d+1)*Fraction(1,p)**k,
        "ntt_coefficient_compression": (d+1)*2*k*coefficient*Fraction(2*k-1,p)**k,
        "product_and_extraction_zerocheck": 2*bounds(p,k,2,n,1,message,length,component["queries"])["zerocheck"],
        "ntt_product_extraction_proximity": (ntt_responses+2*(2*d+1)+2)*(1-Fraction(length-message+1,3*length))**component["queries"],
        "ntt_product_extraction_random_test": (4*d+4)*Fraction(length,p)**k,
    })
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prime", type=int, default=BABYBEAR)
    parser.add_argument("--degree", type=int, default=2)
    parser.add_argument("--variables", type=int, default=18)
    parser.add_argument("--factors", type=int, default=3)
    parser.add_argument("--message-len", type=int, default=512)
    parser.add_argument("--encoded-len", type=int, default=1024)
    parser.add_argument("--target", type=int, default=128)
    parser.add_argument("--component", type=Path, help="Rust HB_COMPONENT log or JSON record; check its actual fixed parameters")
    parser.add_argument("--lookup-component", type=Path, help="Rust HB_LOOKUP log or JSON record; scalar-table lookup-only budget")
    parser.add_argument("--decomposition-component", type=Path, help="Rust HB_DECOMPOSITION log; canonical native digit component")
    parser.add_argument("--lane-decomposition-component", type=Path, help="Rust HB_LANE_DECOMPOSITION log; lane-batched canonical component")
    parser.add_argument("--accumulator-component", type=Path, help="Rust HB_ACCUMULATOR log; arithmetic/continuity component budget")
    parser.add_argument("--monomial-component", type=Path, help="Rust HB_MONOMIAL log; public rotation product component budget")
    parser.add_argument("--key-switch-component", type=Path, help="Rust HB_KEY_SWITCH log; final RLWE key switching and extraction component")
    args = parser.parse_args()
    if sum(x is not None for x in [args.component,args.lookup_component,args.decomposition_component,args.lane_decomposition_component,args.accumulator_component,args.monomial_component,args.key_switch_component]) > 1:
        parser.error("select one component type")
    if args.component or args.lookup_component or args.decomposition_component or args.lane_decomposition_component or args.accumulator_component or args.monomial_component or args.key_switch_component:
        key_switch = args.key_switch_component is not None
        monomial = args.monomial_component is not None
        accumulator = args.accumulator_component is not None
        lookup = args.lookup_component is not None
        lane = args.lane_decomposition_component is not None
        decomposition = args.decomposition_component is not None
        content = (args.key_switch_component or args.monomial_component or args.accumulator_component or args.lane_decomposition_component or args.decomposition_component or args.lookup_component or args.component).read_text()
        prefix = "HB_KEY_SWITCH " if key_switch else "HB_MONOMIAL " if monomial else "HB_ACCUMULATOR " if accumulator else ("HB_LANE_DECOMPOSITION " if lane else ("HB_DECOMPOSITION " if decomposition else ("HB_LOOKUP " if lookup else "HB_COMPONENT ")))
        records = [line[len(prefix):] for line in content.splitlines() if line.startswith(prefix)]
        component = json.loads(records[-1] if records else content)
        errors = key_switch_component_bounds(component) if key_switch else monomial_component_bounds(component) if monomial else accumulator_component_bounds(component) if accumulator else (lane_decomposition_component_bounds(component) if lane else (decomposition_component_bounds(component) if decomposition else (lookup_component_bounds(component) if lookup else component_bounds(component))))
        if args.target < 1:
            parser.error("positive target required")
        total = sum(errors.values())
        print(json.dumps({
            "analysis": "component-only experimental interactive algebraic bound; not whole-proof security",
            "kind": component.get("kind"), "width": component["width"], "queries": component["queries"],
            **({"helper_message_symbols": component["helper_row_message_blocks"],
                "helper_encoded_symbols": component["helper_row_encoded_blocks"],
                "helper_variables": component["helper_variables"],
                "effective_repetitions": component["effective_repetitions"],
                "lookup_groups": component["lookup_groups"]} if lane else {}),
            "message_symbols": component["row_message_blocks"], "encoded_symbols": component["row_encoded_blocks"],
            "target_bits": args.target, "error_below_target": total <= Fraction(1, 2**args.target),
            "contributions": {name: float(value) for name, value in errors.items()}, "total": float(total),
        }, indent=2))
        return
    if min(args.prime, args.degree, args.variables, args.factors, args.message_len, args.encoded_len, args.target) <= 0 or args.encoded_len <= args.message_len:
        parser.error("positive parameters and encoded_len > message_len are required")
    k, q, errors = choose(args.prime, args.degree, args.variables, args.factors, args.message_len, args.encoded_len, args.target)
    total = sum(errors.values())
    print(json.dumps({
        "analysis": "experimental interactive algebraic bound; not whole-proof security",
        "width": k, "queries": q, "target_bits": args.target,
        "error_below_target": total <= Fraction(1, 2**args.target),
        "contributions": {name: float(value) for name, value in errors.items()},
        "total": float(total),
    }, indent=2))


if __name__ == "__main__":
    main()
