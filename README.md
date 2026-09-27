# Mail attachment security test corpus

Generated on: 2026-09-27T17:15:26Z

This corpus contains only benign content and the standard EICAR antivirus test string.
It is intended for authorized mail-security, SEG, sandbox, AV, DLP, and attachment-policy testing.

## Scope of EICAR-based results

EICAR only exercises the detection *plumbing* and unpacking depth of the pipeline.
A "blocked" result on a nested, encoded, or renamed EICAR sample proves that the
gateway's unpacker reached that layer and matched a known signature. It does NOT
demonstrate detection of real, novel malware. Treat these results as coverage and
behaviour tests of the pipeline (how deep it unpacks, how it resolves MIME/filename
ambiguity, how it handles parser edge cases), not as an efficacy test of the AV engine.

## Archive password

Password used by encrypted archive samples:

    Test123

## Safety limits

- Maximum generated nested ZIP depth: 10 (hard cap: 20)
- Number of files in file-count sample: 250 (hard cap: 2000)
- Uncompressed size for high-compression sample: 20 MB (hard cap: 100 MB)

These caps are intentional. The generator does not create true ZIP bombs or other resource-exhaustion payloads.

## Important limitations

1. 05-office/extension-only/*.docm|xlsm|pptm test extension policy only; these are DOCX bytes without VBA.
2. 05-office/container-tests/*.docx contain unreferenced objects in the OOXML ZIP; they are NOT user-clickable embedded OLE objects.
3. F14-CPL is a DLL with a .cpl extension, not a functional Control Panel applet. F13 is a valid JAR container without executable Java classes. F64 is ISO9660 renamed .img, not a distinct raw disk image.
4. Genuine VBA Office, XLSB, XLL, old binary Office/OLE, Outlook MSG, OneNote and real encoded JSE/VBE need separate validated generators or Office/Windows. CHM, MSI, RAR, PDF with active JavaScript and real OLE embeddings are not generated.
5. 04-shortcuts/benign-notepad.lnk is a native Shell Link pointing to the local Notepad program without arguments. Test client behavior on Windows before treating it as evidence of sandbox execution.
6. PNG/PDF/GIF/JPEG plus ZIP are concatenation/parser-differential samples, not universal polyglots. Unicode filename edge cases on Linux may be normalized or rejected by Windows/Outlook.
7. QR samples require Python qrcode and Pillow. JPEG+ZIP and JPEG QR require Pillow. A Windows PE, DLL, EXE-in-ZIP and PE MIME mismatches require MinGW.
8. 7z samples require 7z; encrypted ZIP requires zip. ISO9660 requires genisoimage/mkisofs, CAB requires gcab, encrypted PDF requires qpdf. Missing utilities skip cases and their manifest rows.
9. MIME .eml files are generated for offline inspection or later SMTP transmission. This script does not send mail. Some raw MIME cases intentionally use duplicate or nonstandard headers.
10. EICAR is exactly 68 bytes (no final newline); your local AV/EDR may quarantine samples immediately. Archive passwords are stored in this README and EML subject/body test cases.
11. Re-runs: the generator refuses to write into a non-empty output directory. Pass FRESH=1 to wipe and regenerate it, or choose a new output path as the first argument.
12. The 7-Zip binary is detected as either `7z` or `7zz` (both exist across Kali versions).

## Suggested Kali packages

Optional packages that increase coverage:

    sudo apt update
    sudo apt install -y gcc gcc-mingw-w64-x86-64 zip 7zip file genisoimage gcab qpdf

Optional QR support:

    sudo apt install -y python3-qrcode python3-pil

## Manifest

See manifest.csv for every generated sample. Columns:

    id, category, path, sha256, size_bytes, expected, purpose

The `expected` value is a per-category heuristic (block / pass / policy-dependent)
meant as a starting point. Review and adjust it to match your organization's
attachment policy before scoring a run. `sha256`/`size_bytes` let you correlate
what the gateway actually delivered or stripped with the original sample.
