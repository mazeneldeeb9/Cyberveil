# CYBERVEIL real-malware VM test — 13 October 2026

**The real Linux.Wirenet specimen ran, but CYBERVEIL generated zero alerts. This is a detection miss in this constrained experiment, not a successful protection demonstration.**

The completed monitoring session ran from **15:20:46 to 15:23:16 UTC**, using the live Linux collector and the existing monitoring engine. This tested the headless detection backend inside the guest, not the macOS desktop UI. No product code, model parameters, or detection thresholds were changed to obtain the result.

## Measured result

| Measurement | Observed result |
| --- | --- |
| Baseline before launch | 30 seconds |
| Observation after launch | 120 seconds |
| Total session duration | 150.12 seconds |
| Total process telemetry records | 16,380 |
| Specimen-account records | 239 across two PIDs |
| Specimen-linked model scores | 81 |
| Highest specimen-linked model score | 0.0001331561, approximately 0.0133% |
| Medium / high alert thresholds | 65% / 85%, unchanged |
| Alerts across the session | 0 |
| CYBERVEIL process actions | 0 |
| Session status | Completed, no reported scan error |

The original launcher, PID 768, exited with code 0 and was retained as a zombie until cleanup. Its 120 telemetry records must not be interpreted as 120 seconds of continuing execution. Its descendant, **WIFIADAPT, PID 770**, produced 119 records, with a maximum recorded RSS of 2,105,344 bytes. Both PIDs had zero recorded network connections. The model score is an experimental score, not a calibrated probability that a process is malicious.

The collector reported a permission limitation for `command_hint`. Other listed collection capabilities were available; a completed collection session does not establish successful detection.

## Lab and containment

The host is an Apple Silicon Mac. The test therefore used a hardware-virtualized ARM Linux guest as an outer boundary, with the x86 Ubuntu test guest emulated **inside that ARM guest**:

- Host: QEMU 11.1.2, `virt`, HVF hardware virtualization, 4 virtual CPUs and 6 GiB RAM. No TCG fallback on the host.
- Inner guest: Ubuntu 24.04, x86_64, Linux 6.8.0-142-generic, 2 virtual CPUs and 2 GiB RAM. Its emulator ran under the outer guest's unprivileged `ubuntu` account.
- Both execution guests: no network adapter, only `lo`, no routes, no host filesystem shares, no clipboard, and no guest-agent channel.
- Host execution process: additional macOS sandbox restrictions. Seven preflight checks passed, including denied reads of personal files and unrelated SSD files, denied writes outside the lab, denied network connection creation, guest-harness rejection on macOS, and HVF initialization under the sandbox.
- The running host VM command line was checked, and no open network sockets were found for that process.
- Specimen: dedicated guest UID 1900, no sudo privileges, with CPU, address-space, process-count, descriptor, file-size, and core-dump limits. CYBERVEIL observed the guest separately; automatic process remediation was not enabled.

Provisioning and archive acquisition finished before the offline execution boot. The original prepared disk was preserved read-only, and execution used a fresh copy-on-write disk.

This configuration differs from the earlier host-side TCG experiment. QEMU explicitly excludes TCG-only emulation from its guest-isolation security guarantees; the physical host here used HVF. These controls still do **not** make malware execution risk-free. See [QEMU security guidance](https://www.qemu.org/docs/master/system/security.html).

## Specimen and model identity

The specimen was the same repository-labelled Linux.Wirenet sample used on 5 October, from theZoo revision `48515e492013bc5bb2769249ea539436bb3e733f`. It was acquired as an encrypted archive inside the preparation guest, then checksum-verified and extracted only inside the offline test guest. The original ELF bytes were not modified.

| Item | Identity |
| --- | --- |
| Specimen SHA-256 | `35ff79dd456fe3054a60fe0a16f38bf5fc3928e1e8439ca4d945573f8c48c0b8` |
| Encrypted archive SHA-256 | `e0de34fa6e920cedb6f8280700ba076a64a0995efc896bfe33bea7991ced3e86` |
| CYBERVEIL model | `sklearn-logistic-regression-a92ef585` |
| Product source archive SHA-256 | `f7f7fc154979848fd2c3dc856ad8422f70dcf74b8b15020306b4ff2006c79a14` |

All 40 archived product files matched their current workspace contents at verification time; macOS AppleDouble metadata entries were excluded from that comparison. The separate lab wrapper recorded scores returned by the existing classifier without changing scoring behavior.

## Setup attempts and cleanup

An earlier offline attempt stopped during guest startup, before specimen launch. Its logs were preserved separately. Subsequent offline maintenance corrected guest console/startup configuration; those maintenance boots were not malware tests and are not counted in the result above.

After observation, the lab harness cleaned up the dedicated specimen account's processes. This was **lab cleanup, not CYBERVEIL remediation**. Both test guests powered off, the host QEMU process exited with code 0, and no QEMU test process remained running.

The final disposable execution disk, `outer-execution.qcow2`, was deleted after evidence was copied and verified. It is not recoverable through CYBERVEIL. The read-only prepared snapshots remain on the SSD and contain an encrypted research archive; treat them as restricted lab material, not ordinary application deliverables. No standalone specimen was extracted onto the Mac or added to the repository.

## Evidence and interpretation

- [Structured monitoring result](evidence/vm-result-20261013.json)
- [Host containment preflight](evidence/vm-preflight-20261013.json)
- [Host execution configuration](evidence/vm-host-manifest-20261013.json)
- Complete lab logs and snapshots: `/Volumes/External/CYBERVEIL-Lab-20261013-Nv9Qh8/`
- Result JSON SHA-256: `ccdb09bed5d05cf9f0abaaccf3a1814faa74e78e90db05953f347f51fe13b2d7`

This repeat confirms that telemetry was collected for this specimen while the current model did not alert. It does not establish detection accuracy across malware families. It reused a historical, disk-backed sample in an offline, unprivileged, headless environment with no command-server access or personal browser data. It is neither an independent held-out benchmark nor a fileless-malware validation.

Further detection work should use representative, independently labelled malicious and benign workloads, held-out evaluation, and explicit false-positive measurement. This result must not be converted into a claimed success by lowering thresholds or training on this specimen and then retesting the same sample as if it were unseen.
