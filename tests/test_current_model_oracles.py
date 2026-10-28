"""Independent retained MODEL artifact and quantization boundary oracles.

MODEL names the model reproducibility namespace kind. Verifier Standard
(VSTD) certificates retain exact bytes; these tests do not execute a model.
Integer scale ratios and storage bit counts are dimensionless.
"""
from __future__ import annotations

import pytest
from test_current_model_artifact_bytes import selected
from verifier.domains.contracts import model_artifact_bytes as mechanism

@pytest.mark.parametrize("which",["architecture","weights"])
@pytest.mark.parametrize("bit",range(8*8))
def test_every_single_bit_substitution_refutes_selected_original_bytes(which: str, bit: int) -> None:
    architecture=b"arch\x00abc";weights=b"weight00"
    original=architecture if which=="architecture" else weights
    changed=bytearray(original);changed[bit//8]^=1<<(bit%8)
    args=dict(architecture=architecture,weights=weights,subject_architecture=architecture,subject_weights=weights)
    request,policy,evidence=selected(**args)
    positive=mechanism.build_model_artifact_bytes_certificate(request,evidence,policy=policy)
    assert mechanism.recheck_model_artifact_bytes_certificate(positive,expected_request=request,policy=policy)["status"]=="PASS"
    args[which]=bytes(changed)
    request,policy,evidence=selected(**args)
    negative=mechanism.build_model_artifact_bytes_certificate(request,evidence,policy=policy)
    assert mechanism.recheck_model_artifact_bytes_certificate(negative,expected_request=request,policy=policy)["status"]=="FAIL"


from test_current_model_quantization import specification, selected as quant_selected, replay as quant_replay


@pytest.mark.parametrize("bits", range(2, 17))
@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("edge", ["below", "low", "high", "above"])
def test_every_supported_storage_width_preserves_exact_integer_endpoints(
    bits: int, signed: bool, edge: str,
) -> None:
    # Independent enumeration of the declared integer storage domain.
    half = 2 ** (bits - 1)
    low, high = (-half, half - 1) if signed else (0, 2 ** bits - 1)
    zero = {"below": low - 1, "low": low, "high": high, "above": high + 1}[edge]
    spec = specification()
    spec["configuration"].update(storage_bits=bits, signed=signed, zero_point=zero)
    _, result = quant_replay(*quant_selected(spec=spec))
    assert result["status"] == ("PASS" if edge in ("low", "high") else "FAIL")
    assert result["model_3_1_prerequisite"] == "NOT_ESTABLISHED"
    assert result["quantized_execution"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("numerator,denominator,status", [
    (1, 1, "PASS"), (2**31, 1, "PASS"), (1, 2**31, "PASS"),
    (2**31 + 1, 1, "FAIL"), (1, 2**31 + 1, "FAIL"),
    (2, 2, "FAIL"), (0, 1, "FAIL"), (1, 0, "FAIL"),
    (-1, 1, "FAIL"), (1, -1, "FAIL"), (True, 1, "FAIL"),
    (1, True, "FAIL"), (1.0, 1, "FAIL"), (1, 1.0, "FAIL"),
])
def test_selected_scale_has_bounded_exact_reduced_rational_semantics(
    numerator: object, denominator: object, status: str,
) -> None:
    spec = specification()
    spec["configuration"].update(scale_numerator=numerator, scale_denominator=denominator)
    assert quant_replay(*quant_selected(spec=spec))[1]["status"] == status
