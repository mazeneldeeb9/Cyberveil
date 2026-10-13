# CYBERVEIL isolated malware test result

On 2026-10-05, CYBERVEIL observed a real, repository-labelled Linux.Wirenet specimen inside a disposable offline Ubuntu VM. **It generated no alerts for the specimen. This is a detection miss in this constrained experiment, not proof of protection.** The model was not changed or tuned to make the test pass.

## Environment and isolation

The test used QEMU 11.1.2, a fresh Ubuntu 24.04 x86_64 guest with Linux 6.8.0-142, two emulated CPUs, and 3 GB RAM. The VM files were created in a new folder on the user's external SSD. The official Ubuntu cloud image SHA-256 was verified against its published checksum before provisioning:

`6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`

Dependencies and encrypted research archives were downloaded only before specimen execution. The provisioning guest was shut down, and a fresh execution overlay was booted with `-nodefaults -nic none`, no host filesystem shares, no clipboard, no guest-agent channel, and a private local serial socket. Both the host launch arguments and guest-side checks were inspected. Inside the guest, the only interface was `lo`, the route table was empty, and no 9p, virtiofs, NFS, or CIFS shares were mounted.

The specimen ran as the dedicated non-sudo account `specimen`, UID 1001, with CPU, memory, process-count, file-size, and descriptor limits. The monitoring harness ran separately with access to guest telemetry. It refused execution unless QEMU identity, network isolation, filesystem isolation, and both archive/sample checksums matched. No VM is an absolute security boundary; these were containment controls for this specific experiment.

## Specimen provenance

The specimen came from the [theZoo Linux.Wirenet research directory](https://github.com/ytisf/theZoo/tree/48515e492013bc5bb2769249ea539436bb3e733f/malware/Binaries/Linux.Wirenet), pinned to revision `48515e492013bc5bb2769249ea539436bb3e733f`.

| Item | Verified value |
| --- | --- |
| Archive SHA-256 | `e0de34fa6e920cedb6f8280700ba076a64a0995efc896bfe33bea7991ced3e86` |
| Specimen SHA-256 | `35ff79dd456fe3054a60fe0a16f38bf5fc3928e1e8439ca4d945573f8c48c0b8` |
| Specimen MD5 identifier | `9a0e765eecc5433af3dc726206ecc56e` |
| Format | Original ELF32 x86, 64,400 bytes; no binary modifications |

An ARM-only Linux.Mirai.B archive was inspected for compatibility but never executed. No specimen was extracted into the host filesystem or included in CYBERVEIL's package, source distribution, or video. The separate lab harness is not a product feature.

## Observations

The monitoring session ran from 16:45:31 to 16:46:41 UTC, approximately 70 seconds: 20 seconds of baseline, followed by 50 seconds after launching the specimen. CYBERVEIL used the same `sklearn-logistic-regression-a92ef585` model and normal thresholds, with no automatic process actions.

| Measurement | Result |
| --- | ---: |
| Total process telemetry samples | 7,589 |
| Records associated with the specimen account | 99 across two PIDs |
| Original launcher PID 900 | 50 records; launcher exit code 0 before cleanup |
| Descendant `WIFIADAPT`, PID 902 | 49 records; approximately 2.59 MB RSS |
| Recorded model scores across those PIDs | 28 |
| Highest specimen-linked score | 0.00013265, approximately 0.0133% |
| Medium/high alert thresholds | 65% / 85% |
| Detections, specimen or otherwise | 0 |
| CYBERVEIL remediation actions | 0 |

The launcher records include its post-exit presence before reaping; they are not 50 seconds of continuing launcher execution. The separate descendant remained observable. The highest score was far below the alert threshold. Telemetry collection succeeding does not mean malware detection succeeded.

Raw structured observations, scores, and the incident record are preserved in [the JSON evidence](evidence/vm-result-20261005.json). The SSD's `offline-console.log` also records the live test and shutdown. The full demo video contains the live serial-console chapter and explicitly shows the zero-alert outcome.

## Interpretation and cleanup

This experiment demonstrates a limitation of the synthetic behavior model against one quiet historical specimen in a constrained environment. It does not measure sensitivity across malware families. The guest had no command-server connectivity, browser credentials, or interactive desktop, and the specimen was unprivileged. It was disk-backed malware, not a fileless attack. Those constraints limit the behavior observed and do not justify lowering thresholds or claiming general accuracy.

The lab harness stopped processes belonging to its dedicated guest UID after observation; this was test cleanup, not a CYBERVEIL containment success. A subsequent guest process check showed no remaining processes for that account, then the VM was powered off. The disposable execution and preparation disks were removed after preserving text/JSON evidence. The clean official Ubuntu base image remains for rebuilding a future lab; the removed working disks are not recoverable through the application.

Next detection work requires independent, labelled benign and malicious behavior data, representative workloads, held-out family evaluation, and explicit false-positive analysis. This single sample must not be added to training and then reused as purported held-out proof.
