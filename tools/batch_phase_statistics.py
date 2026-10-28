"""Check digest-linked measured PBS phases; these are not security certificates."""
import re

OUTER = {"members_total_ns", "binding_ns", "hadamard_ns", "release_evaluations_ns",
         "blind_rotation_total_ns", "key_switch_total_ns"}
MEMBERS = {"preparation_ns", "hadamard_ns", "ntt_ns", "decomposition_ns",
           "accumulator_ns", "monomial_ns", "key_switch_ns"}
LOOKUP = {"preparation_ns", "commitment_ns", "sumcheck_ns", "zero_check_ns",
          "terminal_evaluation_ns", "openings_ns"}


def validate(packet, phases):
    version = packet.get("protocol_version")
    if type(version) is not int or version not in (5, 9):
        raise ValueError("unsupported measured protocol")
    if type(packet.get("batch_size")) is not int or packet["batch_size"]<1 or not isinstance(packet.get("proof_sha256"),str) or not re.fullmatch("[a-f0-9]{64}",packet["proof_sha256"]):
        raise ValueError("invalid phase packet identity")
    expected = dict(scope="complete-prover-wall-clock-phases", protocol_version=version,
                    proof_sha256=packet.get("proof_sha256"), batch_size=packet.get("batch_size"),
                    prove_ns=packet.get("prove_ns"))
    if any(type(phases.get(k)) is not type(v) or phases[k] != v for k, v in expected.items()):
        raise ValueError("unlinked phase record")
    if type(packet.get("prove_ns")) is not int or packet["prove_ns"] <= 0:
        raise ValueError("invalid prover duration")
    for role, names in (("outer", OUTER), ("members", MEMBERS), ("blind_rotation", LOOKUP), ("key_switch", LOOKUP)):
        data = phases.get(role)
        if not isinstance(data, dict) or set(data) != names or any(type(v) is not int or v < 0 for v in data.values()):
            raise ValueError("invalid measured phase fields")
    outer, members = phases["outer"], phases["members"]
    if sum(outer.values()) > packet["prove_ns"] or sum(members.values()) > outer["members_total_ns"]:
        raise ValueError("measured phases exceed their parent duration")
    if version == 5:
        if outer["members_total_ns"] != packet["prove_ns"] or any(v for k, v in outer.items() if k != "members_total_ns") or any(phases[r][k] for r in ("blind_rotation", "key_switch") for k in LOOKUP):
            raise ValueError("standalone phases mislabel joint work")
    else:
        if not outer["hadamard_ns"] or not outer["members_total_ns"]:
            raise ValueError("missing complete joint phases")
        for role in ("blind_rotation", "key_switch"):
            data = phases[role]
            if not data["sumcheck_ns"] or not data["openings_ns"] or data["zero_check_ns"] or sum(data.values()) > outer[role + "_total_ns"]:
                raise ValueError("joint comparison phase accounting mismatch")
    return dict(unattributed_prover_ns=packet["prove_ns"] - sum(outer.values()),
                member_overhead_ns=outer["members_total_ns"] - sum(members.values()))
