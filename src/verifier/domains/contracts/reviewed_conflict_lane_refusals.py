"""Exact reviewed refusals closing the bounded 140-row conflict lane.

Terminology: directed acyclic graph (DAG).
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping


SCHEMA_VERSION = "verifier-reviewed-conflict-lane-refusals-3"
BASE_SOURCE_COORDINATE_SHA256 = "e15e805f8212570695754ceba8716691f31ed6253f77536ffbfc3ff5b6962994"
R12_RECONCILIATION_INPUT_SHA256 = "1e9fc66aead230640084a4400c7c0e9baa2459fe0a89ba6b07c4dda8496171af"
R12_MEMBER_ID_SET_SHA256 = "566030c39bd6768d3c39c86402fdc166ad2635513849090086d8d2f27d702fc2"
BATCH07_PACKET_SHA256 = "d0d0cea2b7eaf2bd0c7b91ddfa4ef4e03db28d7d44e889c405a047538f4aaa9f"
BATCH07_REVIEW_SHA256 = "d7844503774dd7973fc906ce7dbc2f40fbf8931a55b06fd9c49c084bd932d22a"
BATCH08_PACKET_SHA256 = "5f99b9171e5e919604f6c9fa18d6b0010ed8c6885673f730b32b779fd8a32e39"
BATCH08_REVIEW_SHA256 = "372c32b5d81070b4232574ceb218bd613ef8a5860bb56b9836f55a5353553cff"
TOTAL_CONFLICT_LANE_ROWS = 140

# Counts are bound to exact registry symbols. Static validation verifies each
# named symbol's literal cardinality from successor source without imports.
ACCEPTED_MAPPING_REGISTRIES = (
    ("src/verifier/domains/contracts/independence_projection.py", "_ACCEPTED", 15),
    ("src/verifier/domains/contracts/typed_facets_projection.py", "_ACCEPTED", 16),
    ("src/verifier/domains/contracts/data_checks_projection.py", "_ACCEPTED", 5),
    ("src/verifier/domains/contracts/env_checks_projection.py", "_ACCEPTED", 4),
    ("src/verifier/domains/contracts/bench_checks_projection.py", "_ACCEPTED", 4),
    ("src/verifier/domains/contracts/token_checks_projection.py", "_ACCEPTED", 3),
    ("src/verifier/domains/contracts/reviewed_singleton_projections.py", "_ROWS", 30),
    ("src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py", "_ROWS", 20),
)
EXPECTED_R12_ACCEPTED_MEMBER_IDS = (
    "DATA-4.1", "ACTOR-5.1", "GRAPH-4.1", "TIME-5.1", "IDENTITY-4.1", "RECEIPT-4.1",
    "ARCH-3.1", "OBJECT-2.1", "RECEIPT-3.1", "HUMAN-3.6", "IDENTITY-3.1", "SIM-1.1",
    "GRAPH-2.1", "TIME-4.1", "TOKEN-2.1", "COLLECTIVE-1.1", "IDENTITY-2.1", "OBJECT-5.1",
    "BENCH-1.4", "ENV-1.2", "RECEIPT-2.1", "ENV-2.3", "GRAPH-1.1", "DATA-3.4",
    "SIM-4.1", "ACTOR-2.7", "DATA-1.1", "HARDWARE-2.1", "ROLE-5.1", "ROLE-3.1",
    "ENV-4.1", "DATA-5.1", "ARCH-1.1", "HARDWARE-2.2", "TOKEN-1.1", "DATA-1.4",
    "ACTOR-4.6", "DATA-1.2", "IDENTITY-5.1", "SIM-2.2", "SIM-4.4", "ENV-5.1",
    "SIM-4.3", "HUMAN-4.3", "ENV-1.5", "RECEIPT-1.1", "ARCH-4.1", "TOKEN-5.1",
    "BENCH-4.4", "ROLE-4.1", "HUMAN-2.5", "HARDWARE-3.1", "ACTOR-3.3", "ENV-1.4",
    "BENCH-5.1", "TIME-2.1", "TIME-1.1", "OBJECT-1.2", "ROLE-2.1", "RECEIPT-5.1",
    "BENCH-1.1", "SIM-2.5", "ARCH-5.1", "GRAPH-5.1", "ENV-3.3", "DATA-2.1",
    "ENV-1.3", "IDENTITY-1.1", "HARDWARE-1.1", "ACTOR-1.1", "BENCH-1.2", "HARDWARE-4.1",
    "SIM-3.4", "OBJECT-4.2", "SIM-2.3", "BENCH-2.1", "TIME-3.1", "HARDWARE-1.2",
    "GRAPH-3.1", "HUMAN-5.1", "ENV-1.1", "COLLECTIVE-2.1", "ARCH-2.1", "DATA-4.4",
    "COLLECTIVE-4.1", "TOKEN-3.1", "HARDWARE-1.3", "SIM-2.1", "TOKEN-4.1", "ROLE-1.1",
    "OBJECT-3.1", "HUMAN-1.1", "COLLECTIVE-5.1", "COLLECTIVE-3.1", "BENCH-3.6",
    "HARDWARE-5.1", "SIM-4.2",
)
REGISTRY_ACCEPTED_MEMBER_IDS = EXPECTED_R12_ACCEPTED_MEMBER_IDS
INHERITED_INDEPENDENCE_REFUSALS = (
    "AGENT-5.1", "BOT-5.1", "EVENT-5.1", "HYPER-5.1", "OWNER-5.1", "SPACE-5.1", "VERIFIER-5.1",
)
FOREIGN_REJECTED_KINDS_OUTSIDE_R12_DENOMINATOR = ("MODEL-5.1", "TRAIN-5.1")
INHERITED_BATCH04_06_REFUSALS = (
    "OBJECT-1.1", "SIM-5.1", "EVENT-2.1", "EVENT-3.1", "EVENT-4.1",
    "OWNER-2.6", "OWNER-4.3", "SPACE-2.1", "SPACE-3.1", "SPACE-4.1",
)
INHERITED_EXPLICIT_REFUSALS = INHERITED_INDEPENDENCE_REFUSALS + INHERITED_BATCH04_06_REFUSALS

REFUSAL_ROWS = ({'member_id': 'HYPER-2.3',
  'object_kind': 'HYPER',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/hyper_unknown_absorption.py',
  'module_binding': None,
  'module_sha256': '7fcadd2d7ddc563c983918e4a910d3d2ca4645920b384d396987772bbcffb8d5',
  'module_bytes': 25514,
  'mechanism': 'HYPER-2.3|verifier-current-hyper-unknown-absorption-certificate-1',
  'certificate_schema': 'verifier-current-hyper-unknown-absorption-certificate-1',
  'scope': 'selected_direct_operand_verdict_composition',
  'route_instance_id': 'route-instance:311ac1adb0f6556bc7d4619882bd7f8c437690f59a8a7c03309709096b9f8e53',
  'route_registration_digest': 'sha256:cee7255cd4aebae2af17ae0ca9b246ffd008033ba02145e7cd84e14bb793885c',
  'union_ref': 'union-candidate:8d1ac9cc0f77c9904b401edaa756881d9f29060fc22fe206c1ce74afefae825a',
  'union_claim_digest': 'sha256:775054b12e9f196b8167590450d3a73373c50d54568a0075385681871d8d71e0',
  'native_proposition_text': 'For one exact HYPER record in an exact retained typed collection, each selected child '
                             'certificate is bound to one distinct direct operand record and replayed through the '
                             'registered current-object route; a direct operand with no selected child, or whose '
                             'child replays UNKNOWN or unavailable, is UNKNOWN, and one UNKNOWN direct operand makes '
                             'the composed verdict UNKNOWN; otherwise any FAIL operand makes it FAIL and all PASS '
                             'operands make it PASS.',
  'native_proposition_text_sha256': 'sha256:02af393dd51cc6d7769e7e141e71fe25142b3deb74dccf41192042f42668f084',
  'union_claim_text': 'Direct-operand verdict composition with UNKNOWN absorption.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_HYPER_UNKNOWN_ABSORPTION.md',
  'union_source_sha256': 'sha256:b95e98ed4d25608a83ae411c75ea9040d59f2f6e5459e94d617e0b2ba6a89189',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:2c74548f604c281056e1a6b64913d1c1cb26097b89bd3dfaee414b6572162c3a',
  'union_contribution_index_zero_based': 17,
  'union_row_index_zero_based': 1,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact HYPER record and complete retained typed collection',
                   'at most one exact child request, policy and certificate per direct operand',
                   'registered child routes and finite checker limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'HYPER-3.1',
  'object_kind': 'HYPER',
  'tier': 3,
  'module_path': 'src/verifier/domains/contracts/hyper_composed_ceiling.py',
  'module_binding': None,
  'module_sha256': '3001f4576c0f4a0aa0d51fcaa9c2c19c68dc3c490feb124415e5237d91470efb',
  'module_bytes': 16763,
  'mechanism': 'HYPER-3.1|verifier-current-hyper-composed-ceiling-certificate-1',
  'certificate_schema': 'verifier-current-hyper-composed-ceiling-certificate-1',
  'scope': 'selected_direct_operand_tier_prefix_ceiling',
  'route_instance_id': 'route-instance:71d3786f0c67538d7bac5b824aada86e87a9b4cc3a401bdd8147506e3117bf79',
  'route_registration_digest': 'sha256:fadc35965a30542ecb344e913f144f7049eafc87e84b49ed5f62ee35296f5d9b',
  'union_ref': 'union-candidate:199fb44beadf6baff8d7064f5e42eb0534570af49316469a6c5dde049eaf1c28',
  'union_claim_digest': 'sha256:1909d2b6c4d1bcbe22c2a44d23cc64cdb4f395e20df22b0174f6f3866be42b6e',
  'native_proposition_text': 'For one exact HYPER record in an exact retained typed collection, every selected child '
                             "certificate is bound to one distinct direct operand record on that operand's own kind "
                             'ladder and replays PASS through the registered current-object route; each direct '
                             "operand's bound is the largest k such that selected children at meta-tiers 1 through k "
                             'all replay PASS (zero when tier 1 is unselected); the composed ceiling is the minimum '
                             "of those bounds whatever the HYPER payload declares, and the payload's declared_depth "
                             'is a nonnegative integer not above that ceiling.',
  'native_proposition_text_sha256': 'sha256:6cdd8e311a0cd5356f52202f1bb67229bc40a0be3408e4a339f272c357a078e1',
  'union_claim_text': 'A composed tier-prefix ceiling over the directly selected operands.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_HYPER_COMPOSED_CEILING.md',
  'union_source_sha256': 'sha256:21fb5d8de0375ae5042043f8dff0608f4241564c288ed8f64ca6e4e2f6e8ab48',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:2c74548f604c281056e1a6b64913d1c1cb26097b89bd3dfaee414b6572162c3a',
  'union_contribution_index_zero_based': 17,
  'union_row_index_zero_based': 2,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact HYPER record and complete retained typed collection',
                   'at most one exact child request, policy and certificate per direct operand and meta-tier',
                   'hyper_unknown_absorption module bytes enter the mechanism digest'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'HYPER-4.1',
  'object_kind': 'HYPER',
  'tier': 4,
  'module_path': 'src/verifier/domains/contracts/hyper_closure.py',
  'module_binding': None,
  'module_sha256': '90dd531363322e219ca087998c6dac75a5f9793ed87902b66fa2719fba023053',
  'module_bytes': 26675,
  'mechanism': 'HYPER-4.1|verifier-current-hyper-closure-certificate-1',
  'certificate_schema': 'verifier-current-hyper-closure-certificate-1',
  'scope': 'finite_declared_hyper_operand_closure',
  'route_instance_id': 'route-instance:f54bf2bfa1abc4b76d1fa7210b7a6abd9a733b452e5a80eae235ef05c10ca1a6',
  'route_registration_digest': 'sha256:4c69898af741d5ed9abf37c8be6c412579649f62873ad71c96901f101d901afd',
  'union_ref': 'union-candidate:4510cffa96d4cb3515ee8b8764df9df0c8866de4623fdc8d6799012c0a3fd4bb',
  'union_claim_digest': 'sha256:8370a3b187a493b17809847ca4fffaf6827e863530e3a8d50b856e8b1f498d12',
  'native_proposition_text': 'For the independently selected HYPER object and expected finite collection commitment, '
                             'the retained canonical namespace records are exactly the transitive closure of its '
                             'declared named operand references, including the HYPER root: each referenced object '
                             'occurs once with its exact bytes and admitted kind, each declared edge resolves inside '
                             'that collection, no composition dependency cycle occurs, no unrelated record is '
                             'included, and the recomputed canonical closure-member commitment equals the externally '
                             'selected expected commitment.',
  'native_proposition_text_sha256': 'sha256:df8d90e435554dd144199ef6bbfdb396b5292c086f036be1dc3b1082127b4412',
  'union_claim_text': 'Closure over the finite declared direct-operand set.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_HYPER_CLOSURE.md',
  'union_source_sha256': 'sha256:7f5d987c2fa38ab67d9ad394169e21b50977382f7cc771174edd3ecaf751dcf9',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:2c74548f604c281056e1a6b64913d1c1cb26097b89bd3dfaee414b6572162c3a',
  'union_contribution_index_zero_based': 17,
  'union_row_index_zero_based': 3,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact finite typed composition', 'independently selected HYPER and closure commitments'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'OWNER-3.1',
  'object_kind': 'OWNER',
  'tier': 3,
  'module_path': 'src/verifier/domains/contracts/owner_eligibility.py',
  'module_binding': None,
  'module_sha256': '6d84fe13dd2957be14b9ed1065c36d762479d81bd74f0a976abfdda16401d8c9',
  'module_bytes': 18416,
  'mechanism': 'OWNER-3.1|verifier-current-owner-eligibility-certificate-1',
  'certificate_schema': 'verifier-current-owner-eligibility-certificate-1',
  'scope': 'declared_hardware_ownership_eligibility',
  'route_instance_id': 'route-instance:7659eddb57b3e6a872927a9627437a1609d3aa85907777e67d69f49760cb2e6f',
  'route_registration_digest': 'sha256:ad0a3a8ac1951d5d05fc889bec67615d7434fea41dd0ab0a6d0a5f3dac57e3a5',
  'union_ref': 'union-candidate:6d8e6192bdb5a4b023045761c366c9cfc8a8c3bbb25b09367db02c9afdd1dd40',
  'union_claim_digest': 'sha256:65a84d3933421e1852c1e1f1080e866c4fbc081775dee1b43fd37f0c089f14f7',
  'native_proposition_text': 'For the externally selected exact OWNER record and finite typed collection, freshly '
                             'replay the declared hardware-ownership eligibility contract: a HUMAN may own declared '
                             'physical or virtual HARDWARE; an AGENT may not own HARDWARE; a BOT may own only '
                             'virtual HARDWARE inside its own freshly replayed finite isolated SIM, with exact SIM, '
                             'evidence, object inventory and virtual resource identifier and kind bindings.',
  'native_proposition_text_sha256': 'sha256:4f27ee958e0256c98a9254f788a860b5fb026486983e7b14757c6f52d6835acf',
  'union_claim_text': 'Declared hardware ownership eligibility for the selected OWNER relation.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_OWNER_HARDWARE_ELIGIBILITY.md',
  'union_source_sha256': 'sha256:73b80ba36d4e30b623fc8212b9b11501a3047b1a1523637155b107fcf19bf244',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:8e169443b9f0d45031b8a772472209a39caf9ef2317bdf9c57d9d18b8bacbac3',
  'union_contribution_index_zero_based': 18,
  'union_row_index_zero_based': 2,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact OWNER record and complete typed collection',
                   'BOT virtual-hardware branch requires retained isolation evidence and an exact finite isolation '
                   'binding'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-3.1',
  'object_kind': 'AGENT',
  'tier': 3,
  'module_path': 'src/verifier/domains/contracts/agent_ceiling_fixity.py',
  'module_binding': None,
  'module_sha256': '7b107e458dd8a947d365089b1aacaef46f2408e61270f9645a289e62c03453cc',
  'module_bytes': 17917,
  'mechanism': 'AGENT-3.1|verifier-current-agent-ceiling-fixity-certificate-1',
  'certificate_schema': 'verifier-current-agent-ceiling-fixity-certificate-1',
  'scope': 'exact_agent_record_bound_harness_ceiling',
  'route_instance_id': 'route-instance:7756cab6577a0b726c3ead60d788f7d60f7aa022c32807e473b90571be6e1f4c',
  'route_registration_digest': 'sha256:79509a1adf9139a5e7690b6e3b7ccddb256adea5a05678f196cf6cc81d0cde7f',
  'union_ref': 'union-candidate:8a69753a9eb0a256119d7f2976e65f3fbb58379b78dead48e5a926708bd548b9',
  'union_claim_digest': 'sha256:df6bd44fe94c23d159f4848ef1aebc68b96f7908071f88b07c0025054c3c00a5',
  'native_proposition_text': 'The externally selected exact AGENT record occurs once in the selected finite typed '
                             'collection; its harness operand binds exactly one HARNESS record of that collection; '
                             "that HARNESS record states an observation ceiling; and the AGENT record's declared "
                             "observation ceiling equals the bound HARNESS record's ceiling under statics:ceiling, "
                             "so the only ceiling reported is the harness's.",
  'native_proposition_text_sha256': 'sha256:266d0d90acdac5a2b3511392205c21223eaf4bd4332a090968401775541feac4',
  'union_claim_text': 'The AGENT declared observation ceiling equals the ceiling in its bound HARNESS record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_AGENT_CEILING_FIXITY.md',
  'union_source_sha256': 'sha256:9ef697df41bbc1460072fd1f908fb2de1853f85f54c9c8af1184138b0428d727',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 4,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact AGENT record and finite collection',
                   'exact bound HARNESS record and retained evidence bytes',
                   'installed policy and finite checker limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-3.1',
  'object_kind': 'BOT',
  'tier': 3,
  'module_path': 'src/verifier/domains/contracts/bot_inherited_ceiling.py',
  'module_binding': None,
  'module_sha256': '29477927b30750028f6201cf67948695b74bbf15db2f7ec0f8203c490e27d6e3',
  'module_bytes': 18963,
  'mechanism': 'BOT-3.1|verifier-current-bot-inherited-ceiling-certificate-1',
  'certificate_schema': 'verifier-current-bot-inherited-ceiling-certificate-1',
  'scope': 'exact_bot_record_inherited_harness_ceiling',
  'route_instance_id': 'route-instance:7a5840d0672226e620401a64195d86b45e8e5a35adbeae39c3f0859cacf2d72b',
  'route_registration_digest': 'sha256:b4cfda94296d3b37ce97dd18730e4f62849a0f2ad333e0832847e713abc29b64',
  'union_ref': 'union-candidate:0767c7cd6b2f557b6c3e2bfa18eb75ad86461b5adab144f2e020004e61c2995e',
  'union_claim_digest': 'sha256:91462d2d744d1225dae5c278051fad5958ed34869bfae5b061263c7068aea94e',
  'native_proposition_text': 'The externally selected exact BOT record occurs once in the selected finite typed '
                             "collection. Its agent operand binds exactly one AGENT record, and that record's "
                             'harness operand binds exactly one HARNESS record. That HARNESS record states an '
                             'integer observation ceiling. The ceiling is reported from that record, whether the bot '
                             'or the agent claims a ceiling, claims none, or claims a different one. A present claim '
                             'that exceeds it is refuted under statics:inherited.',
  'native_proposition_text_sha256': 'sha256:905c2a52890406a5555387baf27cf1070eef19013a4a5ff0f3be57f805abb663',
  'union_claim_text': 'The observation ceiling is inherited through the bound AGENT to its bound HARNESS; a claim '
                      'above it fails.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_BOT_INHERITED_CEILING.md',
  'union_source_sha256': 'sha256:1c09a63b456230f05a2045d019e3013845a2a22d8133c2372d80d3cbbfba60e8',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 5,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact BOT record and finite collection',
                   'exact bound AGENT and HARNESS records',
                   'retained evidence bytes, installed policy and finite checker limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'VERIFIER-2.1',
  'object_kind': 'VERIFIER',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/sim_checker.py',
  'module_binding': None,
  'module_sha256': '8500764157b9af0ebf2643a09a41f0a2755fcb91a30fb525ad6724fefc7da2aa',
  'module_bytes': 22229,
  'mechanism': 'VERIFIER-2.1|verifier-current-sim-checker-certificate-1',
  'certificate_schema': 'verifier-current-sim-checker-certificate-1',
  'scope': 'finite_native_sim_checker_outcome_correspondence',
  'route_instance_id': 'route-instance:b2e9135c81c917a00fd3b32a613af1bfdb13f7b3bea34503562755e27e35a532',
  'route_registration_digest': 'sha256:b40771519ad725c845b96bdcf4a11dc8798c3e9ca6791dfda06cb5825427cae4',
  'union_ref': 'union-candidate:79429db16f2856443916cc77c721584c89b9171d9cc040a1b68c3c5413dea6c5',
  'union_claim_digest': 'sha256:f1f64f1416981c0ccc05349b5cabfaff26ffad4c63d8c1d2ae1c6d9949aa95eb',
  'native_proposition_text': 'For the independently selected installed native simulation checker, exact finite input '
                             'cases, check names, expected outcomes and resource bounds, every selected invocation '
                             'reproduces its selected positive result or explicit refutation.',
  'native_proposition_text_sha256': 'sha256:44c2625e8317f48db8203f376c540744e6fc93adb6db12a068b52c3d0ffce3df',
  'union_claim_text': 'Finite native SIM-checker correspondence to independently selected expected outcomes.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_SIM_CHECKER.md',
  'union_source_sha256': 'sha256:6237a92b99cf1a48f787dfacc32546874ccc41e6b8ad3938ea596398a9258982',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:5f2a9b26ee03a3f14f8097ef02a9d599f723fc08109663c1b6e3cc09bdef1210',
  'union_contribution_index_zero_based': 20,
  'union_row_index_zero_based': 1,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['independently selected exact inputs and expected outcomes',
                   'admitted installed checker and runtime'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'VERIFIER-3.1',
  'object_kind': 'VERIFIER',
  'tier': 3,
  'module_path': 'src/verifier/domains/contracts/verifier_run_constraints.py',
  'module_binding': None,
  'module_sha256': '09343c6daecabb55e728076c7b42cdc38b87479117d8fa824c605debfa175592',
  'module_bytes': 29497,
  'mechanism': 'VERIFIER-3.1|verifier-current-verifier-run-constraints-certificate-1',
  'certificate_schema': 'verifier-current-verifier-run-constraints-certificate-1',
  'scope': 'selected_run_bound_constraint_observations',
  'route_instance_id': 'route-instance:d9ffa76fbd80b459a8bb7c3148559f9e5a891016510269f16905ec8934075839',
  'route_registration_digest': 'sha256:06fd7fc585f965e673747c73f3b4056d598134a6ac7de90f687b5c4ce462692c',
  'union_ref': 'union-candidate:bb79db570cec5181f6a35dbeb9bf14ecafc2342edb4657ec6af295fcd0ba72ed',
  'union_claim_digest': 'sha256:db3579818b76850a3a083cb57fc202f9591d0ffafae68c751b0de2d595d9d3f5',
  'native_proposition_text': 'Every declared constraint on the selected VERIFIER run is matched by an observation '
                             'that this checker produced during that run, bound to the run digest, and within the '
                             'declared maximum; the run is two traced in-process replays of one exact separately '
                             'selected registered child certificate that reproduce identical canonical reports and a '
                             'child PASS.',
  'native_proposition_text_sha256': 'sha256:3ccb4c7fdc254adaea92fc4cca42b897b101cdcef0b8ade1e75c7c982809524e',
  'union_claim_text': 'Checker-produced observations of selected constraints, bound to two replays of the actual '
                      'route run.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_VERIFIER_RUN_CONSTRAINTS.md',
  'union_source_sha256': 'sha256:e31ffd3995417d4cc328b50fcf088fb690b8b7c25875e9a58cb82e9e5d74460a',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:5f2a9b26ee03a3f14f8097ef02a9d599f723fc08109663c1b6e3cc09bdef1210',
  'union_contribution_index_zero_based': 20,
  'union_row_index_zero_based': 2,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact VERIFIER record naming the child route',
                   'exact child request, policy and certificate',
                   'installed interpreter and route dispatcher',
                   'finite constraint maxima and checker limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'VERIFIER-4.1',
  'object_kind': 'VERIFIER',
  'tier': 4,
  'module_path': 'src/verifier/domains/contracts/verifier_coverage_closure.py',
  'module_binding': None,
  'module_sha256': '046666618f9c0278fc1981d265a6a0e55ffba1af1926a2743365afd7f4b43fe9',
  'module_bytes': 29909,
  'mechanism': 'VERIFIER-4.1|verifier-current-verifier-coverage-closure-certificate-1',
  'certificate_schema': 'verifier-current-verifier-coverage-closure-certificate-1',
  'scope': 'selected_finite_claim_class_coverage_and_counterexample_boundaries',
  'route_instance_id': 'route-instance:c42a6ad441859517158a687f888bb2564792de7347e9a0140dfdf58e5e404b7c',
  'route_registration_digest': 'sha256:f30989ce7832ccb08371b9401833f97a86f89055c5ee7b80c6e3805ba407ee07',
  'union_ref': 'union-candidate:751f9d77b48cda757db2b0d1da49ab6d329728b5f302c9ba3f2c338008f4a5ef',
  'union_claim_digest': 'sha256:af96a702ba9e431255f980de008d6a697b0012835a82fe896f391bfe2b88e4c5',
  'native_proposition_text': 'The declared finite claim class equals the class enumerated from the retained '
                             'independently selected DAG profiles; every member has a retained native decision that '
                             'replays PASS with qualified PASS prerequisites; at least one declared '
                             'counterexample-boundary case per class objective exists; and every boundary case '
                             'replays to its declared FAIL or UNKNOWN through its registered route.',
  'native_proposition_text_sha256': 'sha256:ffe00ec3b007e7801f1a0c3896cba20513d5fa2efff2443daacada459fba5d04',
  'union_claim_text': 'Coverage and replayed counterexample boundaries for a selected finite declared claim class.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_VERIFIER_COVERAGE_CLOSURE.md',
  'union_source_sha256': 'sha256:d07b3bbb0b8440807bccff9181d4d377cd223ec12e1741f4f016aa6e1160276a',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:5f2a9b26ee03a3f14f8097ef02a9d599f723fc08109663c1b6e3cc09bdef1210',
  'union_contribution_index_zero_based': 20,
  'union_row_index_zero_based': 3,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native and union claim text/digests differ and no named source declares their relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['exact VERIFIER record naming class objectives',
                   'exact DAG bundle, policy and artifact file set',
                   'exact boundary requests, policies and certificates',
                   'installed route dispatcher and finite checker limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'EVENT-1.1',
  'object_kind': 'EVENT',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': None,
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'EVENT-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:a1e78fc5dca218aba0a32f66d045e63e3a8680f9d1a9a9f602a322e027702a01',
  'route_registration_digest': 'sha256:f5c0a66064463c618e531c7e5dd194d8bfd858279e9d28c38fd07af31fd80844',
  'union_ref': 'union-candidate:a4174e7901fd943a6143f20e308ff60b05d9167bf7aa045d328a167bb9bcdbe1',
  'union_claim_digest': 'sha256:f0f2be3496930bf30d18ba95791429248054d5a0a712202379ef8e81f28a29a5',
  'native_proposition_text': 'The externally selected exact EVENT record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. Nonempty time, space and meaning operands resolving respectively to TIME, '
                             'SPACE and any admitted kind.',
  'native_proposition_text_sha256': 'sha256:267bd606ae6af3e441c2f196591c2c6984e9b8bbabf16857b6bafc66eb41c843',
  'union_claim_text': 'Declared TIME/SPACE/meaning operand facets for the exact EVENT record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:824231beddb6272e94d4608160b90a89658f19f57149bd647ed70b9623b4dfd3',
  'union_contribution_index_zero_based': 16,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_EXACT_TEXT_MAPPING_PREREQUISITES_PRESERVED',
  'refusal_reason': 'Native registration includes collection reconstruction, reference resolution, acyclicity and '
                    'the EVENT operand contract, while the union claim is a terse operand-facet summary; no named '
                    'source declares an exact projection relation.',
  'credit': 0,
  'batch': '07',
  'requirements': ['externally selected EVENT subject',
                   'complete collection commitment, evidence and installed policy',
                   'nonempty time, space and meaning operands resolving to TIME, SPACE and an admitted kind'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-1.1',
  'object_kind': 'AGENT',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'AGENT-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:9e7673c8909748eff1719f89148ad8b7a36ce69336a7fe2642ab4fedd26500ae',
  'route_registration_digest': 'sha256:fd8efa11b96905db3262809705181be9897e7ba17304e383098f4de98e52c308',
  'union_ref': 'union-candidate:577d9fa2696a29cbc932ef4ac92ab609d794f0f4dd502f8fef7a8c76cab8929b',
  'union_claim_digest': 'sha256:7a0fa31f88f82eb435d202074d1abf8e360a31bb8a183fb44b8cbe750b8407a5',
  'native_proposition_text': 'The externally selected exact AGENT record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. Nonempty model, harness and env operands resolving respectively to MODEL, '
                             'HARNESS and ENV.',
  'native_proposition_text_sha256': 'sha256:a1ce9fa0f82b57e9a69b73bed162f347ffbc8ace759e3906f820e4a381b4a217',
  'union_claim_text': 'Declared MODEL/HARNESS/ENV operand facets plus retained bound-HARNESS replay.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union text adds retained bound-HARNESS replay while the typed-facets route establishes '
                    'collection/reference/acyclicity and operand facets only; neither named source declares this '
                    'combined projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact AGENT subject',
                   'complete finite collection commitment, evidence and installed policy',
                   'MODEL, HARNESS and ENV operands resolving to the declared kinds'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-1.8',
  'object_kind': 'AGENT',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/agent_checks.py',
  'module_binding': 'agent_checks',
  'module_sha256': '3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708',
  'module_bytes': 22025,
  'mechanism': 'AGENT-1.8|verifier-current-agent-checks-certificate-1',
  'certificate_schema': 'verifier-current-agent-checks-certificate-1',
  'scope': 'finite_retained_agent_harness',
  'route_instance_id': 'route-instance:383590421f5d8334d05d76810b73666350318d27246470aee2f2c4c2a901328d',
  'route_registration_digest': 'sha256:828ef7d8d07f97888109d12c9f79178c80514abffbdcc61e56bb81a61fe61ed5',
  'union_ref': 'union-candidate:3fc2a57b565b079d91b1115a6b00618dd90ac03d07026bef76c5b68081c2e99c',
  'union_claim_digest': 'sha256:7a0fa31f88f82eb435d202074d1abf8e360a31bb8a183fb44b8cbe750b8407a5',
  'native_proposition_text': 'The exact selected retained harness certificate is semantically replayed under the '
                             'current external policy; required channels are inside its instrumented observation '
                             'surface.',
  'native_proposition_text_sha256': 'sha256:dffa5507a0b84d76c6c52079814893f0842c24033fb8e0a7e683f63a71422437',
  'union_claim_text': 'Declared MODEL/HARNESS/ENV operand facets plus retained bound-HARNESS replay.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 1,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native check covers bound-HARNESS replay and required channels but does not establish the '
                    "union row's MODEL/HARNESS/ENV operand-facet conjunction; no named source declares that "
                    'projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact AGENT record, collection and evidence',
                   'exact selected HARNESS certificate and native check',
                   'installed current external policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-2.1',
  'object_kind': 'AGENT',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/agent_checks.py',
  'module_binding': 'agent_checks',
  'module_sha256': '3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708',
  'module_bytes': 22025,
  'mechanism': 'AGENT-2.1|verifier-current-agent-checks-certificate-1',
  'certificate_schema': 'verifier-current-agent-checks-certificate-1',
  'scope': 'finite_retained_agent_trajectory',
  'route_instance_id': 'route-instance:2ff48db84f267b33f17a1f325eac8e1600af0ec2504b82989f7ed9e51f0d3cae',
  'route_registration_digest': 'sha256:6fe7fc860e3f91989373a96807013f5111e59d529117273267d2125e0f040c42',
  'union_ref': 'union-candidate:2fc64c0cf442516aeee2bba8b77be9f8b87164e8288bfa5d611fb4a7e0c50c2e',
  'union_claim_digest': 'sha256:754b028c4776ba929e5cd48df1767564e42f891c95f3db521fee0f6aa27d95fc',
  'native_proposition_text': 'Every retained declared decision has its exact contiguous integer position and '
                             'references a record inside the bound observation ceiling.',
  'native_proposition_text_sha256': 'sha256:0ab9da10ccef255965363882748880e098e92e4f7708752ef37685fd0718dcb1',
  'union_claim_text': 'Contiguous retained decision trajectory and exact declared-action/tool-invocation '
                      'correspondence.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_AGENT_CHECKS.md',
  'union_source_sha256': 'sha256:7b17f2c42e16a22b2eead25fbe29a88387d9d9e46be2e920a1962b94fcfbab9d',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 2,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins trajectory and action/tool correspondence, while this route declares '
                    'trajectory only; no exact source-declared projection permits the conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact AGENT record, collection, evidence and native trajectory check',
                   'bound observation ceiling',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-2.3',
  'object_kind': 'AGENT',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/agent_checks.py',
  'module_binding': 'agent_checks',
  'module_sha256': '3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708',
  'module_bytes': 22025,
  'mechanism': 'AGENT-2.3|verifier-current-agent-checks-certificate-1',
  'certificate_schema': 'verifier-current-agent-checks-certificate-1',
  'scope': 'finite_retained_agent_actions',
  'route_instance_id': 'route-instance:2f9d8c2a0c81a5a3655e3770b7752dc69b737e05002938cb16b125d99283eaa6',
  'route_registration_digest': 'sha256:1ef64e8c05b1e465a94b2fcfc699334c039b76779a238c998e3944e991be9457',
  'union_ref': 'union-candidate:0dc300ae1257212391e2010f81325fbe9381816b89a83fc8a81fe02595fe62c1',
  'union_claim_digest': 'sha256:754b028c4776ba929e5cd48df1767564e42f891c95f3db521fee0f6aa27d95fc',
  'native_proposition_text': 'Every distinct declared action references exactly one matching retained tool '
                             'invocation inside the observation ceiling.',
  'native_proposition_text_sha256': 'sha256:c57a944caac9cfbcff82d06ee1fa306bd304e489d16c1b9b044039a74987aa26',
  'union_claim_text': 'Contiguous retained decision trajectory and exact declared-action/tool-invocation '
                      'correspondence.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_AGENT_CHECKS.md',
  'union_source_sha256': 'sha256:7b17f2c42e16a22b2eead25fbe29a88387d9d9e46be2e920a1962b94fcfbab9d',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 3,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins trajectory and action/tool correspondence, while this route declares '
                    'action/tool correspondence only; no exact source-declared projection permits the conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact AGENT record, collection, evidence and native action check',
                   'matching retained tool invocation inside the observation ceiling',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-4.1',
  'object_kind': 'AGENT',
  'tier': 4,
  'module_path': 'src/verifier/domains/contracts/agent_checks.py',
  'module_binding': 'agent_checks',
  'module_sha256': '3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708',
  'module_bytes': 22025,
  'mechanism': 'AGENT-4.1|verifier-current-agent-checks-certificate-1',
  'certificate_schema': 'verifier-current-agent-checks-certificate-1',
  'scope': 'finite_retained_agent_outcomes',
  'route_instance_id': 'route-instance:8bf9e91918910bf63ffa630513ab3166d67e935f3500bed87ed195281113d1de',
  'route_registration_digest': 'sha256:599ecd72c6aff9e35726869d4224913e0a5404ff7ae757c62c4d686a7ac8b9a4',
  'union_ref': 'union-candidate:aaa061d8159705e3cb7ed775c5186cd5beef1d68e370c84973198f5f96045038',
  'union_claim_digest': 'sha256:1bc82cfd9a8712949efa7bba2a0cd320dcfc5cf11771e6b8f500b6bc84b2a6e9',
  'native_proposition_text': 'The complete retained outcome inventory equals the selected declared outcome contract, '
                             'preserving canonical value types.',
  'native_proposition_text_sha256': 'sha256:2ce99e84dc204c83394f702c9e3034fc6de1f18371ce7425f710f6d34bd46456',
  'union_claim_text': 'Exact retained outcome inventory and unique claim/support-channel correspondence.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_AGENT_CHECKS.md',
  'union_source_sha256': 'sha256:7b17f2c42e16a22b2eead25fbe29a88387d9d9e46be2e920a1962b94fcfbab9d',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 5,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins outcome inventory and claim/support-channel correspondence, while this '
                    'route declares outcome inventory only; no exact source-declared projection permits the '
                    'conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact AGENT record, collection, evidence and native outcome check',
                   'selected declared outcome contract',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'AGENT-4.3',
  'object_kind': 'AGENT',
  'tier': 4,
  'module_path': 'src/verifier/domains/contracts/agent_checks.py',
  'module_binding': 'agent_checks',
  'module_sha256': '3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708',
  'module_bytes': 22025,
  'mechanism': 'AGENT-4.3|verifier-current-agent-checks-certificate-1',
  'certificate_schema': 'verifier-current-agent-checks-certificate-1',
  'scope': 'finite_retained_agent_claims',
  'route_instance_id': 'route-instance:0394d246104db3127051af4b27d843ce267eed53800ff97214a2deecc66defd0',
  'route_registration_digest': 'sha256:19c8b9e739719a1d42d76717b46cfbf95d5a4cdb1c1a87b3dd57d9d7970ee986',
  'union_ref': 'union-candidate:fe04a4765b8067d7dff4489152e9a0fe271eb9c2130391240a3901e3d79401aa',
  'union_claim_digest': 'sha256:1bc82cfd9a8712949efa7bba2a0cd320dcfc5cf11771e6b8f500b6bc84b2a6e9',
  'native_proposition_text': 'Every uniquely identified declared claim references distinct records inside the '
                             'observation ceiling, and its distinct declared channels equal the channels of those '
                             'supporting records.',
  'native_proposition_text_sha256': 'sha256:72e8c8a906435c35d88f36ee87c058eaad738515f2095f2a3c90347bba608274',
  'union_claim_text': 'Exact retained outcome inventory and unique claim/support-channel correspondence.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_AGENT_CHECKS.md',
  'union_source_sha256': 'sha256:7b17f2c42e16a22b2eead25fbe29a88387d9d9e46be2e920a1962b94fcfbab9d',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:e81fc5102dbaa508cf6466ca7a9062f5e6b37a12d460592a13c752490ebdf153',
  'union_contribution_index_zero_based': 14,
  'union_row_index_zero_based': 6,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins outcome inventory and claim/support-channel correspondence, while this '
                    'route declares the latter only; no exact source-declared projection permits the conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact AGENT record, collection, evidence and native claim check',
                   'distinct supporting records and declared channels inside the observation ceiling',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-1.1',
  'object_kind': 'BOT',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'BOT-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:11caa1fe3329aa7c48756f5c040929844f5fc5c27050cc747aab3cff2c0ed749',
  'route_registration_digest': 'sha256:689461b77defa9f529908528417dcb1e7dca71837d91daa6bb90400374f7c858',
  'union_ref': 'union-candidate:659335a261fa1cc84c9d5b24387f9f97a08b01b9a83f3c21a43068210f3197bc',
  'union_claim_digest': 'sha256:783d69980b9959b21c51b41ba2be9c71c8ff46ada6dfff6a700cb63159fc08d1',
  'native_proposition_text': 'The externally selected exact BOT record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. Nonempty agent, sim and env operands resolving respectively to AGENT, SIM '
                             'and ENV.',
  'native_proposition_text_sha256': 'sha256:b72222a98442c2482d0447c5859d0b065c632a0483d2c852aa977d33eda31e65',
  'union_claim_text': 'Declared AGENT/SIM/ENV operands plus exact nested child bindings and native child replay.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim adds exact nested child bindings and native child replay while typed facets '
                    'establishes structural operand facets only; neither named source declares the combined '
                    'projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact BOT subject',
                   'complete collection commitment, evidence and installed policy',
                   'AGENT, SIM and ENV operands resolving to the declared kinds'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-1.6',
  'object_kind': 'BOT',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/bot_checks.py',
  'module_binding': 'bot_checks',
  'module_sha256': '3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661',
  'module_bytes': 21591,
  'mechanism': 'BOT-1.6|verifier-current-bot-checks-certificate-1',
  'certificate_schema': 'verifier-current-bot-checks-certificate-1',
  'scope': 'finite_retained_bot_binding',
  'route_instance_id': 'route-instance:22a4e7c071117242f5a85c32fe84563b46d899256396dca251e1be708c83093c',
  'route_registration_digest': 'sha256:6fe25c07551eb88e7d984637c986d1c4bc01282e41ae324af476b1fa2e99f811',
  'union_ref': 'union-candidate:f9f36f652395a60a339f0e3fbe18961c7d1d9ea7517de825b7bc839d3261f1d1',
  'union_claim_digest': 'sha256:783d69980b9959b21c51b41ba2be9c71c8ff46ada6dfff6a700cb63159fc08d1',
  'native_proposition_text': 'The selected retained agent, simulation, harness and environment records match their '
                             'actual namespace operands and their native child certificates replay under current '
                             'external policy.',
  'native_proposition_text_sha256': 'sha256:c481bfed114e21d1b529e73d4647470479a7b95f46a9c8c509324c09cf2e244d',
  'union_claim_text': 'Declared AGENT/SIM/ENV operands plus exact nested child bindings and native child replay.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 1,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native check includes HARNESS and current-policy replay but does not itself establish the '
                    "union row's declared operand-facet conjunction; no named source declares the claimed "
                    'projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact BOT record, collection, evidence and native binding check',
                   'selected AGENT, SIM, HARNESS and ENV records and native child certificates',
                   'installed current external policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-2.1',
  'object_kind': 'BOT',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/bot_checks.py',
  'module_binding': 'bot_checks',
  'module_sha256': '3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661',
  'module_bytes': 21591,
  'mechanism': 'BOT-2.1|verifier-current-bot-checks-certificate-1',
  'certificate_schema': 'verifier-current-bot-checks-certificate-1',
  'scope': 'finite_retained_bot_alignment',
  'route_instance_id': 'route-instance:d1ae3efa0e03d7c73653f5689d9265d4feebe384f83ed07d7714b76d1d569145',
  'route_registration_digest': 'sha256:4cfe6fcfc835988a4bef1e86324e8fb3b2d6481816dbe256fbcdcd05da309620',
  'union_ref': 'union-candidate:026e9ad723842f5ee1a9bb289acffc41aaa34f98b41b02df2018d67f21b00708',
  'union_claim_digest': 'sha256:e763457eb088184b606d38ed2f73e197c401ae8a77737abbf6ff58f7bea61bf7',
  'native_proposition_text': 'Every retained simulation transition attributed to the selected agent maps to one '
                             'strictly ordered retained record inside its observation ceiling; exogenous transitions '
                             'are explicit.',
  'native_proposition_text_sha256': 'sha256:ed0bddd7055cb34d877598763a95d1edbff4de208e4abf91d7ff607a1a9eebcd',
  'union_claim_text': 'Ordered retained transition coverage, projected observations within the agent ceiling, and '
                      'action/tool-input alignment.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_BOT_CHECKS.md',
  'union_source_sha256': 'sha256:c01dca475c4dd42a956f608d1c579d8501f7690085571e716c819630b48156ce',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 2,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins alignment, observation and actuation checks, while this route declares '
                    'transition alignment only; no exact source-declared projection permits the conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact BOT record, collection, evidence and native alignment check',
                   'ordered retained transitions inside the observation ceiling',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-2.2',
  'object_kind': 'BOT',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/bot_checks.py',
  'module_binding': 'bot_checks',
  'module_sha256': '3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661',
  'module_bytes': 21591,
  'mechanism': 'BOT-2.2|verifier-current-bot-checks-certificate-1',
  'certificate_schema': 'verifier-current-bot-checks-certificate-1',
  'scope': 'finite_retained_bot_observation',
  'route_instance_id': 'route-instance:31214f7ce56d975892b046e27250f40cc384f85d9b598b27e5018b203269fc42',
  'route_registration_digest': 'sha256:e3417dc452bee7b5fdd8cae1d9b758e57e171a40095b77baa2a12a4089cd7842',
  'union_ref': 'union-candidate:6d80c44d449277d0cc43970dbba6f63b4b63f132373b2c30e3518726076c31cf',
  'union_claim_digest': 'sha256:e763457eb088184b606d38ed2f73e197c401ae8a77737abbf6ff58f7bea61bf7',
  'native_proposition_text': 'The retained initial observation and each attributed tool observation equal the '
                             'selected simulation projections and remain inside the selected agent observation '
                             'ceiling.',
  'native_proposition_text_sha256': 'sha256:038c5fd25b2a347cb54c29e30f1c0bab52c2cc0bcb90762c4ee9c7b3b3e127b5',
  'union_claim_text': 'Ordered retained transition coverage, projected observations within the agent ceiling, and '
                      'action/tool-input alignment.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_BOT_CHECKS.md',
  'union_source_sha256': 'sha256:c01dca475c4dd42a956f608d1c579d8501f7690085571e716c819630b48156ce',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 3,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins alignment, observation and actuation checks, while this route declares '
                    'projected observation correspondence only; no exact source-declared projection permits the '
                    'conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact BOT record, collection, evidence and native observation check',
                   'selected simulation projections and AGENT observation ceiling',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-2.3',
  'object_kind': 'BOT',
  'tier': 2,
  'module_path': 'src/verifier/domains/contracts/bot_checks.py',
  'module_binding': 'bot_checks',
  'module_sha256': '3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661',
  'module_bytes': 21591,
  'mechanism': 'BOT-2.3|verifier-current-bot-checks-certificate-1',
  'certificate_schema': 'verifier-current-bot-checks-certificate-1',
  'scope': 'finite_retained_bot_actuation',
  'route_instance_id': 'route-instance:1283bbc8888a5d7e161f1413048a051d8076d62679939e63992d972c63fa27f0',
  'route_registration_digest': 'sha256:e4ea46c4306339cb9d81d1478b8b83e664f0310ab76fc781701d75d983a60e3e',
  'union_ref': 'union-candidate:2f8c0c5ef9f0dd3437680b54321bd1e1c047924df24505f0a252fa7ccd968ccb',
  'union_claim_digest': 'sha256:e763457eb088184b606d38ed2f73e197c401ae8a77737abbf6ff58f7bea61bf7',
  'native_proposition_text': 'Every attributed retained simulation action equals the input of its aligned retained '
                             'agent tool invocation.',
  'native_proposition_text_sha256': 'sha256:35355b24b781a1923d2f9dee3089a7c3ec50075d977c3b050f83aaafbe8e1ee8',
  'union_claim_text': 'Ordered retained transition coverage, projected observations within the agent ceiling, and '
                      'action/tool-input alignment.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_BOT_CHECKS.md',
  'union_source_sha256': 'sha256:c01dca475c4dd42a956f608d1c579d8501f7690085571e716c819630b48156ce',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 4,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The union claim conjoins alignment, observation and actuation checks, while this route declares '
                    'action/tool-input equality only; no exact source-declared projection permits the conjunction.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact BOT record, collection, evidence and native actuation check',
                   'aligned retained AGENT tool invocation',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'BOT-4.1',
  'object_kind': 'BOT',
  'tier': 4,
  'module_path': 'src/verifier/domains/contracts/bot_checks.py',
  'module_binding': 'bot_checks',
  'module_sha256': '3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661',
  'module_bytes': 21591,
  'mechanism': 'BOT-4.1|verifier-current-bot-checks-certificate-1',
  'certificate_schema': 'verifier-current-bot-checks-certificate-1',
  'scope': 'finite_retained_bot_containment',
  'route_instance_id': 'route-instance:0550de73a237bdcb5f39686d041a39c06bc0dba8dfd77659e218a906747f6252',
  'route_registration_digest': 'sha256:2403e386090b7b0d2896399ca80ce4ef052626a3eb1521d0e54a3426a4d6a5f9',
  'union_ref': 'union-candidate:9c970af195fc57dd4e06e5937bc9ceac2fa311a4aa9f80c686e515b5653c5261',
  'union_claim_digest': 'sha256:f45bc0d8cc25564fae41159432b99baae60c0bbc654512f442d48e477d84d4f0',
  'native_proposition_text': 'The selected agent and simulator environments are declared distinct and retain '
                             'distinct subjects, software inventories and execution identifiers; a fused declaration '
                             'remains unestablished.',
  'native_proposition_text_sha256': 'sha256:4dbb74ac36b5c2645f688dbdbbfd45d223b355eefd9fd2f9316b3f5cd9f749f5',
  'union_claim_text': 'Declared containment by distinct retained environment subjects, software inventories, and '
                      'execution identifiers.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_BOT_CHECKS.md',
  'union_source_sha256': 'sha256:c01dca475c4dd42a956f608d1c579d8501f7690085571e716c819630b48156ce',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:a52c69a28e1e60ce78f1d39f10ed147f88277d712e3e24eb6ab56ed5e6d8a8a0',
  'union_contribution_index_zero_based': 15,
  'union_row_index_zero_based': 6,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native proposition includes a fused-declaration UNKNOWN boundary and differs from the terse '
                    'union summary; no named source declares an exact projection relation.',
  'credit': 0,
  'batch': '08',
  'requirements': ['exact BOT record, collection, evidence and native containment check',
                   'distinct selected AGENT and simulator environment records',
                   'installed policy and finite limits'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'HYPER-1.1',
  'object_kind': 'HYPER',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'HYPER-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:2baeb89f53922ec00ddafc31837f37ea55a7a8a803d884441e42753d977b797f',
  'route_registration_digest': 'sha256:a8cafe46b301993a5f9be36141a96952db2f9fe7502372b212c16c5ec39a23b2',
  'union_ref': 'union-candidate:597c5d3aae7cdaf8808c405dfe072b8ae09f0e32f233b73f2ebb3b469208de24',
  'union_claim_digest': 'sha256:5c3ae1c3c61733abae16f965f4bda44ea41e27306d6c9eddb0fbdecb88841e70',
  'native_proposition_text': 'The externally selected exact HYPER record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. Named nonempty relational operands resolving to admitted records.',
  'native_proposition_text_sha256': 'sha256:efaa6fc08d356dab516410fb478813388615a871157caaa883e27b5d8e40e89c',
  'union_claim_text': 'Declared typed facets for the exact HYPER record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:2c74548f604c281056e1a6b64913d1c1cb26097b89bd3dfaee414b6572162c3a',
  'union_contribution_index_zero_based': 17,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native proposition specifies exact collection reconstruction, reference resolution, '
                    'acyclicity and operand constraints, while the union claim is only a terse label; no named '
                    'source declares the projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact HYPER subject',
                   'complete collection commitment, evidence and installed policy',
                   'named nonempty relational operands resolving to admitted records'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'OWNER-1.1',
  'object_kind': 'OWNER',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'OWNER-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:0e61f876d5715ccf8dc2fb2c955c0f58066d414f1313b368c05d5fc3bca5cae6',
  'route_registration_digest': 'sha256:2083ce97688eee56d9dff227ea9d2dad5fb9d7fe85b9113cfe79d1c378b4f22e',
  'union_ref': 'union-candidate:77886138c36114f88afae3b11e558887c0f175b7fc84da063c1c6dd3a8e7d3d9',
  'union_claim_digest': 'sha256:09d98d9d47b7c0cbf18f272b12255709fe5c7a3deda04eb5d0a3570a0aeab79d',
  'native_proposition_text': 'The externally selected exact OWNER record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. Nonempty actor resolving to ACTOR and object resolving to any admitted kind; '
                             'ownership eligibility and title are separate.',
  'native_proposition_text_sha256': 'sha256:4db1ac165eb22bf93b470c16c5f28669037306e07fac72d644099cc4169249d0',
  'union_claim_text': 'Declared ACTOR and owned-object operand facets for the exact OWNER record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:8e169443b9f0d45031b8a772472209a39caf9ef2317bdf9c57d9d18b8bacbac3',
  'union_contribution_index_zero_based': 18,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native proposition is a larger structural and operand contract and explicitly excludes '
                    'eligibility/title; the terse union claim has no declared exact projection relation.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact OWNER subject',
                   'complete collection commitment, evidence and installed policy',
                   'ACTOR and owned-object operands resolving to declared kinds'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'SPACE-1.1',
  'object_kind': 'SPACE',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'SPACE-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:77902b744c3eb7e05a0b093099b1c4fc3127b324bf7723232e9feef59dacf598',
  'route_registration_digest': 'sha256:70c09b6c4daf9f70d2363ecffda58f2c151b4fbeeb2ccadf08f8ec2e943191fb',
  'union_ref': 'union-candidate:cb634bac56b1ba7a42c08adcabb561c53b1533891f558b1d438cd1fd484fb30a',
  'union_claim_digest': 'sha256:d402409ee42cec527ccc7c5dd2fe81265e47d44316ead60e49e39d9cc6a27329',
  'native_proposition_text': 'The externally selected exact SPACE record occurs in the selected finite collection, '
                             'every retained namespace record reconstructs exactly, all declared references resolve, '
                             "composition is acyclic, and each record satisfies its declared kind's operand "
                             'contract. No composition operands; kind-specific payload meaning is not checked.',
  'native_proposition_text_sha256': 'sha256:eade3cd9f0904c7d2d706d38d7a3d8d1a7ed0b4c05ad53a5229f8678ff415d32',
  'union_claim_text': 'Declared typed facets for the exact SPACE record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:f4ff32a484c91daca726d9831daf9203a60ed40e742ebb1cf64a1d04e792c20e',
  'union_contribution_index_zero_based': 19,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native proposition defines structural reconstruction and explicitly leaves payload meaning '
                    'unchecked, while the union claim is only a terse typed-facet label; no named source declares '
                    'the projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact SPACE subject',
                   'complete collection commitment, evidence and installed policy',
                   'no composition operands; payload meaning remains unchecked'],
  'requirements_preserved': True,
  'requirements_discharged': False},
 {'member_id': 'VERIFIER-1.1',
  'object_kind': 'VERIFIER',
  'tier': 1,
  'module_path': 'src/verifier/domains/contracts/typed_facets.py',
  'module_binding': 'typed_facets',
  'module_sha256': 'ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df',
  'module_bytes': 18261,
  'mechanism': 'VERIFIER-1.1|verifier-current-typed-facets-certificate-1',
  'certificate_schema': 'verifier-current-typed-facets-certificate-1',
  'scope': 'finite_kind_specific_declared_operand_facets',
  'route_instance_id': 'route-instance:ca39f1c8be169f5ba5c61b622623b1d92de29755fe995868565238cf885946fa',
  'route_registration_digest': 'sha256:468ad92aaad9e871a4ba85cc4c31354cb3041797c378643799b75b54355a1de0',
  'union_ref': 'union-candidate:848c7d1ab8b1e0beb1ee008c91786217af52c61ed9b0914d68ee34dc5933e257',
  'union_claim_digest': 'sha256:a61d7f2e0544cee1d3bd11679d2a8bcaf16ff1b5053a298e9ad677c1acc14721',
  'native_proposition_text': 'The externally selected exact VERIFIER record occurs in the selected finite '
                             'collection, every retained namespace record reconstructs exactly, all declared '
                             'references resolve, composition is acyclic, and each record satisfies its declared '
                             "kind's operand contract. No composition operands; kind-specific payload meaning is not "
                             'checked.',
  'native_proposition_text_sha256': 'sha256:ba391774cddc3b5ff6de01617e7cae6ce6a1b35dca2336ec465a7f323a5437d7',
  'union_claim_text': 'Declared typed facets for the exact VERIFIER record.',
  'union_source_uri': 'producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md',
  'union_source_sha256': 'sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd',
  'producer_source_coordinate_digest': 'sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95',
  'ancestor_consumer_source_coordinate_digest': 'sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763',
  'candidate_input_digest': 'sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5',
  'source_map_digest': 'sha256:5f2a9b26ee03a3f14f8097ef02a9d599f723fc08109663c1b6e3cc09bdef1210',
  'union_contribution_index_zero_based': 20,
  'union_row_index_zero_based': 0,
  'direction': None,
  'unavailable_selector': None,
  'dependency_binding_status': 'UNKNOWN',
  'disposition': 'REFUSED_NO_DECLARED_EXACT_PROJECTION',
  'refusal_reason': 'The native proposition defines structural reconstruction and explicitly leaves payload meaning '
                    'unchecked, while the union claim is only a terse typed-facet label; no named source declares '
                    'the projection.',
  'credit': 0,
  'batch': '08',
  'requirements': ['externally selected exact VERIFIER subject',
                   'complete collection commitment, evidence and installed policy',
                   'no composition operands; payload meaning remains unchecked'],
  'requirements_preserved': True,
  'requirements_discharged': False})
REFUSED_MEMBERS = tuple(row["member_id"] for row in REFUSAL_ROWS)
EXPECTED_R12_REFUSED_MEMBER_IDS = (
    "AGENT-5.1", "BOT-5.1", "EVENT-5.1", "HYPER-5.1", "OWNER-5.1", "SPACE-5.1", "VERIFIER-5.1",
    "OBJECT-1.1", "SIM-5.1", "EVENT-2.1", "EVENT-3.1", "EVENT-4.1",
    "OWNER-2.6", "OWNER-4.3", "SPACE-2.1", "SPACE-3.1", "SPACE-4.1",
    "HYPER-2.3", "HYPER-3.1", "HYPER-4.1", "OWNER-3.1", "AGENT-3.1",
    "BOT-3.1", "VERIFIER-2.1", "VERIFIER-3.1", "VERIFIER-4.1", "EVENT-1.1",
    "AGENT-1.1", "AGENT-1.8", "AGENT-2.1", "AGENT-2.3", "AGENT-4.1",
    "AGENT-4.3", "BOT-1.1", "BOT-1.6", "BOT-2.1", "BOT-2.2", "BOT-2.3",
    "BOT-4.1", "HYPER-1.1", "OWNER-1.1", "SPACE-1.1", "VERIFIER-1.1",
)
EXPECTED_R12_MEMBER_IDS = EXPECTED_R12_ACCEPTED_MEMBER_IDS + EXPECTED_R12_REFUSED_MEMBER_IDS
_ROWS_BY_MEMBER = {row["member_id"]: row for row in REFUSAL_ROWS}


class ReviewedConflictLaneRefusal(ValueError):
    """The requested mapping is refused or is not an exact reviewed row."""


def _member_id_set_digest(member_ids: tuple[str, ...]) -> str:
    return hashlib.sha256(("\n".join(sorted(member_ids)) + "\n").encode()).hexdigest()


def validate_exact_r12_partition(
    accepted_member_ids: tuple[str, ...], refusal_member_ids: tuple[str, ...]
) -> dict[str, Any]:
    """Validate exact R12 identities, not merely the 97 + 43 arithmetic."""
    if type(accepted_member_ids) is not tuple or type(refusal_member_ids) is not tuple:
        raise ReviewedConflictLaneRefusal("exact tuple partitions required")
    if any(type(member_id) is not str for member_id in accepted_member_ids + refusal_member_ids):
        raise ReviewedConflictLaneRefusal("exact string member identities required")
    if len(accepted_member_ids) != len(set(accepted_member_ids)):
        raise ReviewedConflictLaneRefusal("duplicate accepted member identity")
    if len(refusal_member_ids) != len(set(refusal_member_ids)):
        raise ReviewedConflictLaneRefusal("duplicate refusal member identity")
    accepted = set(accepted_member_ids)
    refused = set(refusal_member_ids)
    expected_accepted = set(EXPECTED_R12_ACCEPTED_MEMBER_IDS)
    expected_refused = set(EXPECTED_R12_REFUSED_MEMBER_IDS)
    overlap = accepted & refused
    combined = accepted_member_ids + refusal_member_ids
    if overlap:
        raise ReviewedConflictLaneRefusal("overlapping R12 partition identities: " + ",".join(sorted(overlap)))
    missing_accepted = expected_accepted - accepted
    foreign_accepted = accepted - expected_accepted
    if missing_accepted or foreign_accepted:
        raise ReviewedConflictLaneRefusal(
            "accepted R12 identity mismatch: missing=" + ",".join(sorted(missing_accepted))
            + "; foreign=" + ",".join(sorted(foreign_accepted))
        )
    missing_refused = expected_refused - refused
    foreign_refused = refused - expected_refused
    if missing_refused or foreign_refused:
        raise ReviewedConflictLaneRefusal(
            "refused R12 identity mismatch: missing=" + ",".join(sorted(missing_refused))
            + "; foreign=" + ",".join(sorted(foreign_refused))
        )
    if len(combined) != TOTAL_CONFLICT_LANE_ROWS:
        raise ReviewedConflictLaneRefusal("incomplete R12 partition cardinality")
    digest = _member_id_set_digest(combined)
    if digest != R12_MEMBER_ID_SET_SHA256:
        raise ReviewedConflictLaneRefusal("R12 member identity digest mismatch")
    return {
        "denominator": TOTAL_CONFLICT_LANE_ROWS,
        "accepted_member_ids": len(accepted),
        "refused_member_ids": len(refused),
        "overlap": 0,
        "foreign": 0,
        "missing": 0,
        "r12_member_id_set_sha256": digest,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def _exact_recursive(expected: Any, observed: Any) -> bool:
    """Compare recursively without Python's bool/int/float value coercions."""
    if type(expected) is not type(observed):
        return False
    if type(expected) is dict:
        if any(type(key) is not str for key in expected):
            return False
        if any(type(key) is not str for key in observed):
            return False
        if expected.keys() != observed.keys():
            return False
        return all(_exact_recursive(value, observed[key]) for key, value in expected.items())
    if type(expected) in (list, tuple):
        return len(expected) == len(observed) and all(
            _exact_recursive(expected_value, observed_value)
            for expected_value, observed_value in zip(expected, observed)
        )
    return expected == observed


def reviewed_refusal(member_id: str) -> dict[str, Any]:
    if type(member_id) is not str or member_id not in _ROWS_BY_MEMBER:
        raise ReviewedConflictLaneRefusal("member is outside the exact reviewed refusal set")
    row = _ROWS_BY_MEMBER[member_id]
    return {**row, "requirements": tuple(row["requirements"])}


def classify_exact_refusal(member_id: str, candidate: Mapping[str, Any]) -> dict[str, Any]:
    row = reviewed_refusal(member_id)
    if type(candidate) is not dict:
        raise ReviewedConflictLaneRefusal("exact refusal coordinate mapping required")
    required = {key: value for key, value in row.items() if key != "requirements"}
    required["requirements"] = tuple(row["requirements"])
    observed = candidate
    if not _exact_recursive(required, observed):
        raise ReviewedConflictLaneRefusal("substituted or aliased refusal coordinate")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "EXPLICIT_REVIEWED_REFUSAL",
        "member_id": member_id,
        "direction": None,
        "unavailable_selector": None,
        "dependency_binding_status": "UNKNOWN",
        "requirements_preserved": True,
        "requirements_discharged": False,
        "credit": {"evidence": 0, "authority": 0, "package": 0, "runtime": 0,
                   "profile": 0, "completeness": 0, "release": 0},
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def conflict_lane_accounting() -> dict[str, Any]:
    partition = validate_exact_r12_partition(
        REGISTRY_ACCEPTED_MEMBER_IDS,
        INHERITED_EXPLICIT_REFUSALS + REFUSED_MEMBERS,
    )
    accepted = partition["accepted_member_ids"]
    inherited_refusals = len(INHERITED_EXPLICIT_REFUSALS)
    explicit_refusals = partition["refused_member_ids"]
    uninspected = partition["denominator"] - accepted - explicit_refusals
    return {
        "denominator": partition["denominator"],
        "accepted_one_way_mappings": accepted,
        "inherited_explicit_refusals": inherited_refusals,
        "new_explicit_refusals": len(REFUSAL_ROWS),
        "explicit_refusals": explicit_refusals,
        "uninspected": uninspected,
        "source_inspection_closed": (
            partition["overlap"] == partition["foreign"] == partition["missing"] == uninspected == 0
        ),
        "r12_member_id_set_sha256": partition["r12_member_id_set_sha256"],
        "runtime_qualified": False,
        "full_suite_qualified": False,
        "package_qualified": False,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }
