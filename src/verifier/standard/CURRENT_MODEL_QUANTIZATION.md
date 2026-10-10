# Current MODEL-3.3: retained quantization specification

Verifier Standard (VSTD) semantic family
`verifier-current-object-obligations-1` admits one bounded
`MODEL-3.3` quantization-specification proposition. MODEL is the model
reproducibility namespace kind. This route does not reinterpret historical
MODEL certificates or establish the whole statics tier.

The externally selected exact MODEL record must occur once in a finite typed
collection. Its payload selects `quantization_spec_sha256` and
`quantization_spec_byte_length`; these commit to canonical JavaScript Object
Notation (JSON) bytes retained in evidence as canonical base64. Secure Hash
Algorithm 256-bit (SHA-256) names the commitment. The specification contains exactly
`schema_version`, `weight_artifact_sha256`, `scheme`, and
`configuration`. Its weight digest must equal the selected MODEL
`weights_bytes_sha256` commitment. Selection and replay bind these bytes;
they do not establish that the weight artifact has the declared encoding.

This version recognizes `affine-per-tensor-v1` with exactly seven
configuration entries: `storage_bits` (integer 2 through 16), `signed`
(Boolean), positive reduced rational `scale_numerator` and
`scale_denominator` (each at most 2³¹), an integer `zero_point` in the
selected signed or unsigned storage range, `rounding=ties-to-even` and
`saturation=clamp`. Scale is
dimensionless; counts and bit widths are dimensionless integers. These names
identify the configuration to be tested by a future execution mechanism.
This route does not execute the quantizer, parse weight tensors, compare
dequantized values, or measure prediction quality.

Canonical byte mismatch, an invalid recognized configuration, a changed
weight-artifact selection, a malformed base64 transport, or substituted
certificate result fails. An absent retained specification, exceeded finite
bound, unsupported schema version or unknown scheme remains `UNKNOWN`.
The selected evidence limit is at most 4 MiB, the specification at most
1 MiB, and the certificate at most 8 MiB (MiB means 1,048,576 bytes).

`MODEL-3.1` is the governing prerequisite for the full `MODEL-3.3`
obligation. This certificate binds the quantization configuration to the
selected weight digest but does not carry or verify a `MODEL-3.1`
certificate. It therefore reports `model_3_1_prerequisite=NOT_ESTABLISHED`.
It makes no claim about raw weight conformance, actual quantized execution,
hardware requirements, training, provenance, disclosure authority or full
MODEL object conformance. In particular, a digest or declaration does not
establish a real quantized model or permission to publish private weights.

The separately registered public route, when integrated, must call
`recheck_model_quantization_certificate` with exact selected request and
policy. It must retain all evidence bytes; a redacted canonical certificate
is uncheckable. Until the route and canonical disclosure guard are integrated
and independently retested, this native module alone does not make the
objective publicly replayable.
