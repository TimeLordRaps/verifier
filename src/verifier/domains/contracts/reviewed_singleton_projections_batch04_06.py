"""Twenty exact accepted singleton projections from reviewed batches 04--06.

Terminology: uniform resource identifier (URI).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest


SCHEMA_VERSION = "verifier-reviewed-singleton-projections-batch04-06-1"
BASE_SOURCE_COORDINATE_SHA256 = "5bcd1cdce34ffbcf641350e0f5d24c2239264c0febc7e90f8a7506f7a4580a50"

# member, kind, tier, module path/hash, mechanism, scope, route id/digest,
# union id/claim digest/source URI/source hash, producer coordinate,
# candidate input, source-map digest, contribution index, row index.
_ROWS = (
    ("OBJECT-2.1", "OBJECT", 2, "src/verifier/domains/contracts/object_lineage.py", "c94158b34a751a8e6702cd455d4906651efac2657fad8436238b6a3566d9d5a3", "verifier.domains.contracts.object_lineage.recheck_object_lineage_certificate", "selected_linear_version_lineage", "route-instance:141a7ba79956fba2affcdcc7d9ceec0acc578004a946259f85e9eeb0f9e6c321", "sha256:a92f80d95ca8a82ead7482afac58b03d6120ffaa1f6cc318bb2bf468a75f4b35", "union-candidate:d067c071c6af69e3b5e7dcae875537c724b087101c880b098edbb7b801925390", "sha256:8750987ada92407430be767596d1817857b2ccf143fb093aac93de9d35182c27", "producer-source://src/verifier/standard/CURRENT_OBJECT_LINEAGE.md", "sha256:ada6e4474b85d7902a9fd0e2ab371a6a36afd99320bcc66c3213a184c3889f1f", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:971820b536a77ab51150e112d3c8aecbdb75c5c8f52aac3644d971e103b274aa", 11, 2),
    ("RECEIPT-2.1", "RECEIPT", 2, "src/verifier/domains/contracts/receipt_validation_replay.py", "e9fbff52f11102ede40f71cfbc4150d77127c167d3bace263e8c8207388feb25", "verifier.domains.contracts.receipt_validation_replay.recheck_receipt_validation_replay_certificate", "selected_vstd1_receipt_audit_replay", "route-instance:30896169222bd30b3dcd8bc60945e38d2476ea7bb11e941e96ffc22b4de3f5fc", "sha256:5625888306bfd79a43c0649b7dc79c54fe18efb56e4765b0abadb1edc678f2d5", "union-candidate:5297532de658df289b8baf3c5ed64460e20827d72279557d82d4268987d8f2ec", "sha256:445bc761d0a3bdb01ece55c6d89c6f4d8a246564e25db0bd2813517baffd4a6d", "producer-source://src/verifier/standard/CURRENT_RECEIPT_VALIDATION_REPLAY.md", "sha256:9336934176742f5c8f453a4c7ec04e3dce6a7e6759166b9a34d7235a2bda7277", "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1", "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", "sha256:05025e0e90ba4308c00787421a4ce17ac2fffa65d4e19341d11858325375ba09", 22, 1),
    ("RECEIPT-3.1", "RECEIPT", 3, "src/verifier/domains/contracts/receipt_statics.py", "f14ea956678b061ba5f80c683b361820da0821adb9571f56455c0e6717869b98", "verifier.domains.contracts.receipt_statics.recheck_receipt_statics_certificate", "selected_vstd1_receipt_canonical_statics", "route-instance:15d9ab3eb7ed58bd60b03af1fba04583927f0bc1d79893a44f87807fd41e665c", "sha256:44ca3c34c5c01bbcf160cd224b7f30f5ac3da32e0979e9ffc38ac04b55f727f1", "union-candidate:2bea67334221f748ff6c822d7579a2ae96950d741af074f3d49249380125fb7a", "sha256:e78ecfc0a1d0e9a83b1d09e62484970d2403774db95e2a4027c3f683aab9067e", "producer-source://src/verifier/standard/CURRENT_RECEIPT_STATICS.md", "sha256:97351628e6fe6b2afff23af890a5ecf88e886137d18645de4c7151805b303f87", "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1", "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", "sha256:05025e0e90ba4308c00787421a4ce17ac2fffa65d4e19341d11858325375ba09", 22, 2),
    ("RECEIPT-4.1", "RECEIPT", 4, "src/verifier/domains/contracts/receipt_prerequisite_closure.py", "6c7179476d37091a936e2f824e560905d1d1123073b0ee73d0d6c3b5a396f175", "verifier.domains.contracts.receipt_prerequisite_closure.recheck_receipt_prerequisite_closure_certificate", "selected_declared_receipt_prerequisite_cone", "route-instance:0dc34da8c1045a0d565bcbaf13e342380b928f89d519c112cdd5b9713a3a4aab", "sha256:c17f1375dd605331bbfe0547b919ad682ebee11320ca380e22e3a5dcd1c70f93", "union-candidate:f96776601e13ba69f028bc032afe09f225228b42eda377a8d2fdd677396dad7c", "sha256:925f51f1c1fb9b7dbba0b31089f542b498cc3861e026f8f92a2faa65ec309536", "producer-source://src/verifier/standard/CURRENT_RECEIPT_PREREQUISITE_CLOSURE.md", "sha256:96628dc554ed7d48e568d4d5af6386a93b9fc7a8eb2914b0dbd57a51c2e0b731", "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1", "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", "sha256:05025e0e90ba4308c00787421a4ce17ac2fffa65d4e19341d11858325375ba09", 22, 3),
    ("SIM-2.2", "SIM", 2, "src/verifier/domains/contracts/sim_response.py", "0d9afe7a445286a7a2fe116cdbaeb59ccf7a957c14e5ecb168e521e4c998a4cf", "verifier.domains.contracts.sim_response.recheck_sim_response_certificate", "finite_model_relative_action_response", "route-instance:5f6ede4fda68baded9feed2f552c95bbf145b1121b9420c8ceb59cb29cc1d3be", "sha256:ef943acd93f49ea9bac3d21551609b28fd24832667bb7bffb02915e53b792883", "union-candidate:1b7cd9dcba8ac6eca3028631be14220e6746c00566c949bce873dda42b8f1a4b", "sha256:b9eca922b48b1e29d7012dc784d0f46c44452e272781124deee7d1a03babbfeb", "producer-source://src/verifier/standard/CURRENT_SIM_DYNAMICS.md", "sha256:32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 2),
    ("SIM-4.1", "SIM", 4, "src/verifier/domains/contracts/sim_shard_coverage.py", "5cb8239f19186181e95a7feaba4aa86a2f69c6459f8e6a24e9689928955c9395", "verifier.domains.contracts.sim_shard_coverage.recheck_sim_shard_coverage_certificate", "finite_selected_retained_shard_time_coverage", "route-instance:3798b687b6fcc7cafa5500d39a6d9200c5ffdc56a87ebdf9b4d5471326efa572", "sha256:d62848114f803d22f8e4dc05da2fa4a03d286a71c0420d895953fd94ba475090", "union-candidate:c70c9acf5abfdff437263d4ae6c2653a770ee4921a78aa9ba2c7662c7e682da9", "sha256:5c2436f86c9a41c0c43662f2e1d4b4fd02ac90e4b8fb8d2522d06dea0db3c7fa", "producer-source://src/verifier/standard/CURRENT_SIM_DYNAMICS.md", "sha256:32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 6),
    ("SIM-4.3", "SIM", 4, "src/verifier/domains/contracts/sim_shard_signatures.py", "81ece70f90346273c9cacbad1e36a8e30d6d732c770684c7ccd0d24bd3dfabc4", "verifier.domains.contracts.sim_shard_signatures.recheck_sim_shard_signatures_certificate", "finite_selected_key_bound_shard_row_signatures", "route-instance:6365d04f25994c61af790e4bc955e6403790810cbbadf86fd934d782044ab5d7", "sha256:6718d9679a32e743bfa23b53cb5b06a4d0413a9ae88093bda05fb2f5ceb47cb0", "union-candidate:006392d65622e912a2865379d890caac0197857627a30b48cf5ff7791ec58495", "sha256:d28a989bc2e7406bb6b767d4f91c9b3120bc0944d237e7899692949d8ca44f34", "producer-source://src/verifier/standard/CURRENT_SIM_SHARD_RELATIONS.md", "sha256:34deb4bae1fdc571f62eaf74c4d944691961c30f270833a15652021ea02b557a", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 8),
    ("SIM-4.4", "SIM", 4, "src/verifier/domains/contracts/sim_surface_partition.py", "d17e50068b7b0960346b270d6c02c79694a851ad2c491bcf8a758d4bb444af9a", "verifier.domains.contracts.sim_surface_partition.recheck_sim_surface_partition_certificate", "finite_declared_state_partition_accounting", "route-instance:6184c4dce381e5171cc805613ef1079949a414898aee5360cced3e487ff03e9c", "sha256:3860cf0f33546be2bbb6d9da212726a52040e55590d30e795954194a32fdeb1e", "union-candidate:2406ca0946505f9260bf572d7fdc3c25b5248a7c771707f8b00db8a9264774d9", "sha256:a950fcdf16899835d6c341a32b061a23346301a13d72332d02c53a2b28710c77", "producer-source://src/verifier/standard/CURRENT_SIM_DYNAMICS.md", "sha256:32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 9),
    ("TIME-2.1", "TIME", 2, "src/verifier/domains/contracts/time_order.py", "8f9260a61954a4b3c56fff5e9a1a87ad4a6db767bdf1db85b26fc327d5476441", "verifier.domains.contracts.time_order.recheck_time_order_certificate", "finite_retained_declared_clock_order", "route-instance:9852345662a2527951223f270b5f9ca6a7a0a5f08cbcf02815ad4eeba8b1fa71", "sha256:a8c8a9a1cd19dad918cefa4eec9b18117f761daadc4531e62f925e8a6f9dd075", "union-candidate:59d003c1193d6f94d3fad13d623fc59813011e35bc77dc43ac45238dd234cae0", "sha256:f31bfcc249c7c657cd7f76ed94bfc24a6824ce83c585527e16520159dd2206c3", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:440efbe03d1c313e47adb016adeb8cc84d6bc161f09d701b94ae8e047f296c39", 6, 1),
    ("TIME-4.1", "TIME", 4, "src/verifier/domains/contracts/time_closure.py", "cf0292125c35306864f529e2c9a86b126efd8aab1516ede64d661c70e023084a", "verifier.domains.contracts.time_closure.recheck_time_closure_certificate", "selected_declared_clock_inventory_closure", "route-instance:1f99f78ab1c33f24b4f8e96a4730b8b5c408fdc4410c8d63b89354319bde7c9b", "sha256:2976bbaa85edfa6d232a462a5b5a10a83cb4fd5f2a619bbd501bc4b6f3df4aee", "union-candidate:f86cba061b1ea0a6f55382ebec2834d93fa325d1f0ab002ee47e9cfd3fa71ca7", "sha256:705d0f5be92334e994f19c72753314209ecb60c444c0e571e50aa33f2fa50a07", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:440efbe03d1c313e47adb016adeb8cc84d6bc161f09d701b94ae8e047f296c39", 6, 3),
    ("ROLE-2.1", "ROLE", 2, "src/verifier/domains/contracts/role_lifecycle.py", "10ea426c28e841431f5ff195afa9a9d806e955d89ca2977e57f350c214897921", "verifier.domains.contracts.role_lifecycle.recheck_role_lifecycle_certificate", "finite_selected_role_lifecycle_occupancy_replay", "route-instance:9b7b6de727c1ed2ad61d4ef00a7b863d6b9a9b0c38db66afd824c69e6ebeddca", "sha256:a4e396185957a2c00189933ee439bebafc9914c24c52b85017349faf247c8f25", "union-candidate:3c220f508c3e7dd72d10c097d339345e921b2b5a0c1bd90dc3cad38b1716cf91", "sha256:bcd5c1936ea6a569c509436917047f4770cc2f5be4b34b11948a95beaee9467f", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:05fe711441e82a53f0392fed6722acc6d8a938fc2d2fbf1affc4dbf5cd74d024", 5, 1),
    ("ROLE-3.1", "ROLE", 3, "src/verifier/domains/contracts/role_constraints.py", "0ac9f2a90e671b27742b68e2c2a850c27b618c6eead37c3071c1c19dd2ae77af", "verifier.domains.contracts.role_constraints.recheck_role_constraints_certificate", "finite_declared_role_occupancy_permission_constraints", "route-instance:428da1260c2c2633f5d69e3f3b450a0494d128bdf134848bf38dbe77d5092979", "sha256:761bd2bbbf0acf0c1919a66bcd7d5dbd63345a2a31f7cd10d3f90966fb7c41a5", "union-candidate:51b5ea59733f97178bf3e74dd542fda012cbe5256bf2139840b53c0eba9282ec", "sha256:8bf6dc066e80b30892b0a142920cb0b8a3e654cbc8c40db9fbc2dbc11aa71fbd", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:05fe711441e82a53f0392fed6722acc6d8a938fc2d2fbf1affc4dbf5cd74d024", 5, 2),
    ("ROLE-4.1", "ROLE", 4, "src/verifier/domains/contracts/role_closure.py", "4bfda2338fee3651b38a4816bfd902733caa2ff3d9d25a630ecf3792872ce8e3", "verifier.domains.contracts.role_closure.recheck_role_closure_certificate", "finite_selected_role_point_decision_occupancy_closure", "route-instance:860433caf74cc36125432a4aee2589ad99e79a45756c0fed45df2131fdf12825", "sha256:468d2f00620adb78724a6b08c9ed7a3f53b427cec256f54615f107aad8a12108", "union-candidate:04d0c4d219ce1e2dd263af4f02e18e128cf8c9995e2d18567197692130e641a9", "sha256:4d14e02521f7951fde6017dbc2953ba7b54b036c48fcb88551b3e1be4e391e6e", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:05fe711441e82a53f0392fed6722acc6d8a938fc2d2fbf1affc4dbf5cd74d024", 5, 3),
    ("SIM-2.1", "SIM", 2, "src/verifier/domains/contracts/sim_dynamics.py", "72c786f691d39658c464c59da94b6f6e1e2d601543340d4bdb0e53c99c9c256e", "verifier.domains.contracts.sim_dynamics.recheck_sim_dynamics_certificate", "finite_selected_native_transition_replay", "route-instance:e7e05e6c462677e2b7f09b1ba1a6e260ffd5dc0099fa675630bfbb98d60412c1", "sha256:335e0a24e23faa2f32240bc2f61d5d8159c3491053f679ccfcc18195d964060c", "union-candidate:c614041b0557197f5980de9dc2daa70a03e0476b54228342d67e546519ad896e", "sha256:f8f8693295fa1c8031cda386cc55b0ae24daba1cdc766134af60fd70c7b67c09", "producer-source://src/verifier/standard/CURRENT_SIM_DYNAMICS.md", "sha256:32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 1),
    ("SIM-2.3", "SIM", 2, "src/verifier/domains/contracts/sim_internal_state.py", "967163ac95db3df7c2421682e95a4d8938b5e46ce7e870e1a9fdbde707633791", "verifier.domains.contracts.sim_internal_state.recheck_sim_internal_state_certificate", "finite_model_relative_internal_state", "route-instance:d1a7d6e05b7c9aa75c65e29c40a6f58498c72e158a6d9d8ea38cf4bfed67c484", "sha256:7ad184034756939600c8f40aeb64d102c731610a80dd70282de1168ca55df1d4", "union-candidate:778e35e945fdf20511e8def8eeeb316b8b8fc0924860d151ae9b360412e9b645", "sha256:1ea319e6b9d3a624323432e98838e6216e5f9ce69751a0ad81cd6d3357fe6de0", "producer-source://src/verifier/standard/CURRENT_SIM_DYNAMICS.md", "sha256:32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 3),
    ("SIM-2.5", "SIM", 2, "src/verifier/domains/contracts/sim_perspective.py", "adcd447253f6cd6c53a01043539347635ab45a1be33e1443cd76bf67ce4827ad", "verifier.domains.contracts.sim_perspective.recheck_sim_perspective_certificate", "finite_selected_macro_projection_alignment", "route-instance:abb350d22faf2e9a149a74882fbaaae649bff9f16fc48b521435cc6f07c69581", "sha256:45d73e7c94c75c3c879943cf155e74ba60ac0f9c7c580ff81b12be0ff9a5a6c6", "union-candidate:ad996ea61d191c53b60b146a1e03a5499a19908520e3005bdc76805f66e5dbbc", "sha256:3819bfd1156554cd9b416d9231f188b0441cbf214262fe20c94e4010dbf7d5db", "producer-source://src/verifier/standard/CURRENT_SIM_PERSPECTIVE.md", "sha256:49e5eed5a4b750ea04d139d71e42b2e3a719e4f5339052a74f07878552248842", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 4),
    ("SIM-3.4", "SIM", 3, "src/verifier/domains/contracts/sim_external_law.py", "1ae09656fdf1405d025145bc79ac7cca30a9f5af67249820b0fbfa7399b90ca5", "verifier.domains.contracts.sim_external_law.recheck_sim_external_law_certificate", "selected_distinct_external_law_statement", "route-instance:c7d5b0dba68296466418fb5a1c94fbd2459f166840acbcdc26bbf3a1cc9e82dc", "sha256:9416e5863b70071270c03881ec7fd78517784a82c21a4ba556237fad57c35880", "union-candidate:a7fe110cc5bc4a88e6473c338ff2cf4ce37c5c5f70ff4aec0830ba709e10e905", "sha256:5f7e5007aab4206e5490c1332d2e463c21d1c63ba30b7087312a15350244ede3", "producer-source://src/verifier/standard/CURRENT_SIM_EXTERNAL_LAW.md", "sha256:c7d4b64a27c83b44b4631982644fb7f043d5eb61d7f39a6b0d1ced05eece04e8", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 5),
    ("TIME-3.1", "TIME", 3, "src/verifier/domains/contracts/time_strict.py", "557a7e3af5b4c3dba6d64036159e0de528d06ec648c6542359cd39b75d63d205", "verifier.domains.contracts.time_strict.recheck_time_strict_certificate", "selected_strict_declared_clock_order", "route-instance:d87ac5f65050e2c740eef6565376186331412928b154926a6a60181cd525fc36", "sha256:8fd73a86b2b16a558fe093acd0791371c5f62fccc8a31e72f74ee49809e6621a", "union-candidate:8c0dd9f2295b3c29ee987cc0cceddf3ddb4b7c28fc753de946eede7d9e11674e", "sha256:aa12896dee78f955e3f698beafd307f271e043193761b41d0aa847e495dffe8a", "producer-source://src/verifier/standard/META_TIERS.md", "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c", "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1", "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", "sha256:440efbe03d1c313e47adb016adeb8cc84d6bc161f09d701b94ae8e047f296c39", 6, 2),
    ("OBJECT-3.1", "OBJECT", 3, "src/verifier/domains/contracts/object_statics.py", "86ec11b2c52c059bb499e6363e9d1e85e302c2a69a2548c39942c2f01afb295b", "verifier.domains.contracts.object_statics.recheck_object_statics_certificate", "selected_canonical_collection_statics", "route-instance:f47ac8e9397f23ee796267fe35efc9a186d979f2f853a200e4456351414d8724", "sha256:e18bd42c4727016caa49d4f53bf848687b70f3a2786f81692ccbf262a22da3f6", "union-candidate:1e46e39001d4ed5b9d0d6662673bdb1e9cdee18164bfe0ffdaf62d35b2fae262", "sha256:867832438e4568b70dbd0cd4318f5e6332e9f8a14a45f0666d4cd3d4bb1b9eea", "producer-source://src/verifier/standard/CURRENT_OBJECT_STATICS.md", "sha256:fc9e6acddbcdeb9c896ffd3e34a1827601fa5d5224d32d274188169e1f595a00", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:971820b536a77ab51150e112d3c8aecbdb75c5c8f52aac3644d971e103b274aa", 11, 3),
    ("SIM-4.2", "SIM", 4, "src/verifier/domains/contracts/sim_shard_relations.py", "47d095097d19584652f8d641596e4294b10774aaba722d19887aaecd34c63cfc", "verifier.domains.contracts.sim_shard_relations.recheck_sim_shard_relations_certificate", "finite_selected_retained_cross_shard_relations", "route-instance:fd4b0a1b108f55e7e2d77fd9e32551df387a5dc9ac129b3dc14f19c2c1ab889a", "sha256:33a8f0505c78353f4c07cd7697904efd22c4fb6240247b1af94aa8bc41b07631", "union-candidate:cc53885c53a898caab4c14eea81cd751eef9c62855849abbda305a64f206fbd6", "sha256:5600420d6a7d33ad61d02925228617715d0f1e8a4593c8b1ea97044b2e4b2110", "producer-source://src/verifier/standard/CURRENT_SIM_SHARD_COVERAGE.md", "sha256:3fde3dcf19cd58dac207ca6c22904bc9c1d7e6357fb7351d53b65a4f3a8e820d", "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462", "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", "sha256:f4effd0f63c9fe23740be428fabdb347453517eb9ddb34b93c6dd9f3fd7e9954", 12, 7),
)

_FIELDS = (
    "member_id", "object_kind", "tier", "module_path", "module_sha256", "mechanism",
    "scope", "route_instance_id", "route_registration_digest", "union_ref_id",
    "union_claim_digest", "source_uri", "source_sha256", "producer_source_coordinate_digest",
    "candidate_input_digest", "source_map_digest", "contribution_index", "row_index",
)
_PINS = {row[0]: dict(zip(_FIELDS, row)) for row in _ROWS}
MAPPED_MEMBERS = tuple(_PINS)
EXCLUDED_MEMBERS = (
    "OBJECT-1.1", "SIM-5.1", "EVENT-2.1", "EVENT-3.1", "EVENT-4.1",
    "OWNER-2.6", "OWNER-4.3", "SPACE-2.1", "SPACE-3.1", "SPACE-4.1",
)
DECLARED_DEPENDENCY_EDGES = (
    ("EVENT-4.1", "EVENT-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("OWNER-2.6", "OWNER-2.1", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("OWNER-2.6", "OWNER-2.2", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("OWNER-2.6", "OWNER-2.3", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("OWNER-2.6", "OWNER-2.4", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("OWNER-2.6", "OWNER-2.5", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("OWNER-4.3", "OWNER-4.1", "SOURCE_DECLARED_TRANSITIVE_REPRESENTED_PREREQUISITE"),
    ("OWNER-4.3", "OWNER-4.2", "SOURCE_DECLARED_REPRESENTED_PREREQUISITE"),
    ("RECEIPT-2.1", "RECEIPT-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("RECEIPT-4.1", "RECEIPT-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("ROLE-2.1", "ROLE-3.1", "HIGHER_TIER_PREREQUISITE_WITHIN_TRANCHE"),
    ("ROLE-2.1", "ROLE-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("ROLE-4.1", "ROLE-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("ROLE-4.1", "ROLE-3.1", "SOURCE_DECLARED_INLINE_ENDPOINT_WITNESS"),
    ("SIM-2.2", "SIM-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-2.3", "SIM-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-2.5", "SIM-2.1", "SOURCE_DECLARED_EMBEDDED_TRAJECTORY"),
    ("SIM-2.5", "SIM-2.3", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-4.1", "SIM-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-4.2", "SIM-4.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-4.3", "SIM-4.2", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SIM-4.4", "SIM-4.3", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SPACE-2.1", "SPACE-3.1", "HIGHER_TIER_PREREQUISITE_WITHIN_TRANCHE"),
    ("SPACE-2.1", "SPACE-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("SPACE-4.1", "SPACE-3.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("TIME-3.1", "TIME-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
    ("TIME-4.1", "TIME-2.1", "SOURCE_DECLARED_REQUIRED_CHILD"),
)


class ReviewedSingletonBatch0406Refusal(ValueError):
    """The input is not one of the exact accepted batch-04--06 mappings."""


def accepted_projection(member_id: str) -> dict[str, Any]:
    if type(member_id) is not str or member_id not in _PINS:
        raise ReviewedSingletonBatch0406Refusal("member is outside the fixed accepted batch set")
    return dict(_PINS[member_id])


def installed_source_binding(member_id: str) -> dict[str, str]:
    pin = accepted_projection(member_id)
    path = Path(__file__).resolve().parents[4] / pin["module_path"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != pin["module_sha256"]:
        raise ReviewedSingletonBatch0406Refusal("native source differs from reviewed bytes")
    return {"path": pin["module_path"], "sha256": actual}


def project_registration(member_id: str, native_registration: Mapping[str, Any],
                         union_candidate: Mapping[str, Any], *,
                         direction: str = "ROUTE_TO_UNION") -> dict[str, Any]:
    pin = accepted_projection(member_id)
    if direction != "ROUTE_TO_UNION":
        raise ReviewedSingletonBatch0406Refusal("only ROUTE_TO_UNION narrowing is admitted")
    if type(native_registration) is not dict:
        raise ReviewedSingletonBatch0406Refusal("exact native registration mapping required")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise ReviewedSingletonBatch0406Refusal("native registration digest differs")
    required = {
        "member_id": pin["member_id"], "object_kind": pin["object_kind"], "tier": pin["tier"],
        "scope": pin["scope"], "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"], "claim_sha256": pin["union_claim_digest"],
        "source": {"uri": pin["source_uri"], "sha256": pin["source_sha256"]},
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"], "row_index": pin["row_index"],
    }
    for field, expected in required.items():
        if union_candidate.get(field) != expected:
            raise ReviewedSingletonBatch0406Refusal("union candidate has substituted " + field)
    text = native_registration.get("proposition")
    if type(text) is not str or union_candidate.get("claim_text") != text:
        raise ReviewedSingletonBatch0406Refusal("exact proposition text was not preserved")
    if "sha256:" + hashlib.sha256(text.encode()).hexdigest() != pin["union_claim_digest"]:
        raise ReviewedSingletonBatch0406Refusal("proposition text digest differs")
    return {
        "schema_version": SCHEMA_VERSION, "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "member_id": member_id, "object_kind": pin["object_kind"], "tier": pin["tier"],
        "relation": {"direction": "ROUTE_TO_UNION",
                     "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
                     "information_relation": "NARROWING_NON_REVERSIBLE",
                     "semantic_equivalence_claimed": False, "digest_alias_claimed": False},
        "acceptance_mechanism": {"kind": "REGISTERED", "identifier": pin["mechanism"]},
        "installed_source": installed_source_binding(member_id),
        "dependency_binding_status": "UNKNOWN", "dependency_discharged_by_mapping": False,
        "excluded_members": list(EXCLUDED_MEMBERS),
        "host_selections": {"package_digest": None, "installed_mechanism_digest": None,
                            "authority_digest": None, "cli_module_origins": None},
        "current_evidence_status": "UNKNOWN", "evidence_credit": "NONE",
        "authority_credit": "NONE", "package_credit": "NONE",
        "installed_mechanism_credit": "NONE", "test_credit": "NONE",
        "semantic_completeness": "UNKNOWN", "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    return {"uninspected_before": 56, "processed": 30, "mapped": len(MAPPED_MEMBERS),
            "reviewed_refusals": len(EXCLUDED_MEMBERS), "uninspected_after": 26,
            "mapped_credit": 0, "dependency_edges_unresolved": len(DECLARED_DEPENDENCY_EDGES),
            "semantic_completeness": "UNKNOWN", "release_admissible": False}
