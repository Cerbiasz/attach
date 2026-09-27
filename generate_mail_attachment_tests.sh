#!/usr/bin/env bash
set -Eeuo pipefail

# Safe mail-attachment test corpus generator for Kali Linux.
# Generates only benign files and the standard EICAR test string.
# It does NOT generate real malware, exploits, weaponized macros, or destructive archive bombs.

ROOT="${1:-mail-attachment-tests}"
PASSWORD="${ARCHIVE_PASSWORD:-Test123}"
NEST_DEPTH="${NEST_DEPTH:-10}"
MANY_FILES="${MANY_FILES:-250}"
COMPRESS_MB="${COMPRESS_MB:-20}"

# Safety caps: deliberately prevent accidental resource-exhaustion samples.
(( NEST_DEPTH > 20 )) && NEST_DEPTH=20
(( MANY_FILES > 2000 )) && MANY_FILES=2000
(( COMPRESS_MB > 100 )) && COMPRESS_MB=100

log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# On current Kali the 7-Zip binary may be named 7z or 7zz; detect either.
SEVENZIP="$(command -v 7z || command -v 7zz || true)"
have_7z() { [[ -n "$SEVENZIP" ]]; }

# Idempotency: refuse to write into a non-empty output directory so stale
# samples from a previous run never mix with the new manifest. FRESH=1 wipes it.
if [[ -e "$ROOT" && -n "$(ls -A "$ROOT" 2>/dev/null)" ]]; then
  if [[ "${FRESH:-0}" == "1" ]]; then
    warn "FRESH=1: removing existing output directory $ROOT"
    rm -rf "$ROOT"
  else
    warn "Output directory '$ROOT' exists and is not empty."
    warn "Re-run with FRESH=1 to wipe it, or pass a new output path as the first argument."
    exit 1
  fi
fi

mkdir -p "$ROOT"/{00-baseline,01-antivirus,02-executable,03-scripts,04-shortcuts,05-office/{plain,extension-only,container-tests},06-archives,07-encrypted,08-nested,09-web,10-pdf,11-mime,12-filename,13-parser,14-resource-limits}

MANIFEST="$ROOT/manifest.csv"
printf 'id,category,path,purpose\n' > "$MANIFEST"

csv_field() {
  local s="$1"
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

csv_add() {
  local id="$1" cat="$2" path="$3" purpose="$4"
  {
    csv_field "$id"; printf ','
    csv_field "$cat"; printf ','
    csv_field "$path"; printf ','
    csv_field "$purpose"; printf '\n'
  } >> "$MANIFEST"
}

# -----------------------------
# 00 - Baseline / control files
# -----------------------------
log "Creating baseline/control files"
printf 'MAIL-GATEWAY-BENIGN-TEST\n' > "$ROOT/00-baseline/test.txt"
printf 'id,value\n1,MAIL-GATEWAY-BENIGN-TEST\n' > "$ROOT/00-baseline/test.csv"
cat > "$ROOT/00-baseline/test.html" <<'EOF'
<!doctype html><html><body><h1>MAIL-GATEWAY-BENIGN-TEST</h1></body></html>
EOF
cat > "$ROOT/00-baseline/test.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="640" height="120">
  <text x="20" y="60">MAIL-GATEWAY-BENIGN-TEST</text>
</svg>
EOF

# 1x1 PNG, generated from a tiny known-good base64 literal.
base64 -d > "$ROOT/00-baseline/test.png" <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=
EOF

i=0
for f in test.txt test.csv test.html test.svg test.png; do
  i=$((i+1))
  csv_add "$(printf 'BASE-%03d' "$i")" "baseline" "00-baseline/$f" "Benign control file expected to pass ordinary attachment controls"
done

# -----------------------------
# 01 - EICAR AV controls
# -----------------------------
log "Creating EICAR controls"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$ROOT/01-antivirus/eicar.com"
cp "$ROOT/01-antivirus/eicar.com" "$ROOT/01-antivirus/eicar.txt"
cp "$ROOT/01-antivirus/eicar.com" "$ROOT/01-antivirus/invoice.pdf"
cp "$ROOT/01-antivirus/eicar.com" "$ROOT/01-antivirus/image.jpg"

csv_add "AV-001" "antivirus" "01-antivirus/eicar.com" "Standard EICAR antivirus test string"
csv_add "AV-002" "antivirus" "01-antivirus/eicar.txt" "EICAR content with benign-looking text extension"
csv_add "AV-003" "antivirus" "01-antivirus/invoice.pdf" "EICAR content with misleading PDF extension"
csv_add "AV-004" "antivirus" "01-antivirus/image.jpg" "EICAR content with misleading JPEG extension"

# -----------------------------
# 02 - Benign executable formats
# -----------------------------
log "Creating benign executable source files"
cat > "$ROOT/02-executable/benign.c" <<'EOF'
#include <stdio.h>
int main(void) {
    puts("MAIL-GATEWAY-BENIGN-TEST");
    return 0;
}
EOF
csv_add "EXE-SRC" "executable" "02-executable/benign.c" "Source used to build benign executable samples"

if have gcc; then
  gcc "$ROOT/02-executable/benign.c" -O2 -s -o "$ROOT/02-executable/benign-linux-elf" || true
  [[ -f "$ROOT/02-executable/benign-linux-elf" ]] && csv_add "EXE-001" "executable" "02-executable/benign-linux-elf" "Benign Linux ELF executable"
else
  warn "gcc not found: skipping benign ELF compilation"
fi

if have x86_64-w64-mingw32-gcc; then
  if x86_64-w64-mingw32-gcc "$ROOT/02-executable/benign.c" -O2 -s -o "$ROOT/02-executable/benign.exe"; then
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/invoice.pdf"
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/image.jpg"
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/invoice.pdf.exe"
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/INVOICE.EXE"
    csv_add "EXE-002" "executable" "02-executable/benign.exe" "Benign Windows PE executable"
    csv_add "EXE-003" "executable" "02-executable/invoice.pdf" "Windows PE renamed to PDF"
    csv_add "EXE-004" "executable" "02-executable/image.jpg" "Windows PE renamed to JPEG"
    csv_add "EXE-005" "executable" "02-executable/invoice.pdf.exe" "Double-extension Windows PE"
    csv_add "EXE-006" "executable" "02-executable/INVOICE.EXE" "Upper-case executable extension"
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/benign.scr"
    cp "$ROOT/02-executable/benign.exe" "$ROOT/02-executable/no-extension"
    csv_add "F02" "executable" "02-executable/benign.scr" "Real benign PE with Windows screensaver extension; tests type and extension policy"
    csv_add "F33" "executable" "02-executable/no-extension" "Real benign PE without extension"
  else
    warn "mingw benign.exe build failed: skipping PE-derived samples"
  fi
  cat > "$ROOT/02-executable/benign-dll.c" <<'EOF'
__declspec(dllexport) int MailGatewayTest(void) { return 0; }
EOF
  if x86_64-w64-mingw32-gcc -shared "$ROOT/02-executable/benign-dll.c" -O2 -s -o "$ROOT/02-executable/benign.dll"; then
    cp "$ROOT/02-executable/benign.dll" "$ROOT/02-executable/benign.cpl"
    csv_add "F03" "executable" "02-executable/benign.dll" "Benign native Windows PE DLL with exported function"
    csv_add "F14-CPL" "executable" "02-executable/benign.cpl" "PE DLL bytes with CPL extension; tests extension and PE detection, not functioning Control Panel applet"
  fi
else
  warn "mingw-w64 compiler not found: Windows PE samples will be skipped"
fi

# -----------------------------
# 03 - Benign scripts
# -----------------------------
log "Creating benign script files"
cat > "$ROOT/03-scripts/test.ps1" <<'EOF'
Write-Output "MAIL-GATEWAY-BENIGN-TEST"
EOF
cat > "$ROOT/03-scripts/test.bat" <<'EOF'
@echo off
echo MAIL-GATEWAY-BENIGN-TEST
EOF
cp "$ROOT/03-scripts/test.bat" "$ROOT/03-scripts/test.cmd"
cat > "$ROOT/03-scripts/test.js" <<'EOF'
WScript.Echo("MAIL-GATEWAY-BENIGN-TEST");
EOF
cat > "$ROOT/03-scripts/test.vbs" <<'EOF'
WScript.Echo "MAIL-GATEWAY-BENIGN-TEST"
EOF
cat > "$ROOT/03-scripts/test.hta" <<'EOF'
<html><head><title>MAIL-GATEWAY-BENIGN-TEST</title><hta:application /></head>
<body>MAIL-GATEWAY-BENIGN-TEST</body></html>
EOF
cat > "$ROOT/03-scripts/test.sh" <<'EOF'
#!/bin/sh
printf '%s\n' 'MAIL-GATEWAY-BENIGN-TEST'
EOF
chmod +x "$ROOT/03-scripts/test.sh"
cat > "$ROOT/03-scripts/test.py" <<'EOF'
print("MAIL-GATEWAY-BENIGN-TEST")
EOF
cat > "$ROOT/03-scripts/test.wsf" <<'EOF'
<?xml version="1.0"?><job id="benign"><script language="JScript"><![CDATA[WScript.Echo("MAIL-GATEWAY-BENIGN-TEST");]]></script></job>
EOF
printf 'WEB\n1\nhttps://example.invalid/\n' > "$ROOT/03-scripts/test.iqy"

i=0
for f in test.ps1 test.bat test.cmd test.js test.vbs test.hta test.sh test.py test.wsf test.iqy; do
  i=$((i+1))
  csv_add "$(printf 'SCRIPT-%03d' "$i")" "scripts" "03-scripts/$f" "Benign script used to test attachment policy and active-content handling"
done

# -----------------------------
# 04 - Shortcut-like formats
# -----------------------------
log "Creating shortcut-like files"
cat > "$ROOT/04-shortcuts/test.url" <<'EOF'
[InternetShortcut]
URL=https://example.invalid/
EOF
csv_add "SHORT-001" "shortcuts" "04-shortcuts/test.url" "Benign Windows Internet Shortcut to reserved example.invalid domain"
cat > "$ROOT/04-shortcuts/benign.scf" <<'EOF'
[Shell]
Command=2
IconFile=explorer.exe,3
[Taskbar]
Command=ToggleDesktop
EOF
csv_add "F14-SCF" "shortcuts" "04-shortcuts/benign.scf" "Benign Shell Command File invoking Show Desktop"

# -----------------------------
# 05 - Office / OOXML
# -----------------------------
log "Creating basic Office/OOXML samples"
python3 - "$ROOT" <<'PY'
import os, sys, zipfile
root = sys.argv[1]

def make_docx(path, extra=None):
    files = {
        '[Content_Types].xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="txt" ContentType="text/plain"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>''',
        '_rels/.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''',
        'word/document.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>MAIL-GATEWAY-BENIGN-TEST</w:t></w:r></w:p></w:body></w:document>'''
    }
    if extra:
        files.update(extra)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            if isinstance(data, str): data = data.encode()
            z.writestr(name, data)

plain = os.path.join(root, '05-office/plain/test.docx')
make_docx(plain)
with open(os.path.join(root, '01-antivirus/eicar.com'), 'rb') as f:
    eicar = f.read()
make_docx(os.path.join(root, '05-office/container-tests/docx-container-with-eicar.docx'), {
    'word/embeddings/eicar.txt': eicar
})
PY

csv_add "OFF-001" "office" "05-office/plain/test.docx" "Minimal benign OOXML Word document"
csv_add "OFF-002" "office" "05-office/container-tests/docx-container-with-eicar.docx" "Valid OOXML container with unreferenced EICAR file under word/embeddings; tests recursive container inspection only"

# Extension-policy samples only: valid benign DOCX bytes with macro-capable extensions.
cp "$ROOT/05-office/plain/test.docx" "$ROOT/05-office/extension-only/test.docm"
cp "$ROOT/05-office/plain/test.docx" "$ROOT/05-office/extension-only/test.xlsm"
cp "$ROOT/05-office/plain/test.docx" "$ROOT/05-office/extension-only/test.pptm"
i=0
for f in test.docm test.xlsm test.pptm; do
  i=$((i+1))
  csv_add "$(printf 'OFF-EXT-%03d' "$i")" "office-extension-only" "05-office/extension-only/$f" "Extension-policy test only; this file does NOT contain VBA and is not a genuine macro-enabled Office document"
done

# -----------------------------
# 06 - Archives
# -----------------------------
log "Creating archive samples"
python3 - "$ROOT" <<'PY'
import os, sys, zipfile, tarfile
root = sys.argv[1]
src = os.path.join(root, '01-antivirus/eicar.com')
with zipfile.ZipFile(os.path.join(root, '06-archives/eicar.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    z.write(src, 'eicar.com')
with tarfile.open(os.path.join(root, '06-archives/eicar.tar'), 'w') as t:
    t.add(src, arcname='eicar.com')
with tarfile.open(os.path.join(root, '06-archives/eicar.tar.gz'), 'w:gz') as t:
    t.add(src, arcname='eicar.com')
PY
csv_add "ARC-001" "archives" "06-archives/eicar.zip" "ZIP containing EICAR"
csv_add "ARC-002" "archives" "06-archives/eicar.tar" "TAR containing EICAR"
csv_add "ARC-003" "archives" "06-archives/eicar.tar.gz" "TAR.GZ containing EICAR"

if have_7z; then
  (cd "$ROOT/06-archives" && "$SEVENZIP" a -y eicar.7z ../01-antivirus/eicar.com >/dev/null)
  csv_add "ARC-004" "archives" "06-archives/eicar.7z" "7z archive containing EICAR"
else
  warn "7z/7zz not found: skipping .7z archive"
fi

# -----------------------------
# 07 - Encrypted archives
# -----------------------------
log "Creating encrypted archive samples where supported"
if have zip; then
  (cd "$ROOT/01-antivirus" && zip -j -P "$PASSWORD" ../07-encrypted/eicar-password.zip eicar.com >/dev/null)
  csv_add "ENC-001" "encrypted" "07-encrypted/eicar-password.zip" "Password-protected ZIP containing EICAR; password is documented in README"
else
  warn "zip utility not found: skipping password-protected ZIP"
fi

if have_7z; then
  (cd "$ROOT/07-encrypted" && "$SEVENZIP" a -y -p"$PASSWORD" -mhe=on eicar-password.7z ../01-antivirus/eicar.com >/dev/null)
  csv_add "ENC-002" "encrypted" "07-encrypted/eicar-password.7z" "Password-protected 7z containing EICAR; password is documented in README"
fi

# -----------------------------
# 08 - Nested archives and nested mail
# -----------------------------
log "Creating nested archive samples (depth $NEST_DEPTH)"
python3 - "$ROOT" "$NEST_DEPTH" <<'PY'
import os, sys, zipfile, shutil, tempfile
root, depth = sys.argv[1], int(sys.argv[2])
out = os.path.join(root, '08-nested')
src = os.path.join(root, '01-antivirus/eicar.com')
prev = src
for i in range(1, depth + 1):
    dst = os.path.join(out, f'level-{i:02d}.zip')
    with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(prev, os.path.basename(prev))
    prev = dst
PY
for i in $(seq 1 "$NEST_DEPTH"); do
  csv_add "NEST-$(printf '%02d' "$i")" "nested" "08-nested/level-$(printf '%02d' "$i").zip" "Nested ZIP chain ending in EICAR; depth $i"
done

# -----------------------------
# 09 - HTML / SVG active content (benign)
# -----------------------------
log "Creating HTML/SVG samples"
cat > "$ROOT/09-web/link.html" <<'EOF'
<!doctype html><html><body>
<h1>MAIL-GATEWAY-BENIGN-TEST</h1>
<a href="https://example.invalid/">Open benign test URL</a>
</body></html>
EOF
cat > "$ROOT/09-web/blob-download.html" <<'EOF'
<!doctype html><html><body>
<script>
const blob = new Blob(["MAIL-GATEWAY-BENIGN-TEST\n"], {type: "text/plain"});
const a = document.createElement("a");
a.href = URL.createObjectURL(blob);
a.download = "mail-gateway-test.txt";
a.textContent = "Download benign test file";
document.body.appendChild(a);
</script>
</body></html>
EOF
cat > "$ROOT/09-web/link.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="640" height="180">
  <text x="20" y="50">MAIL-GATEWAY-BENIGN-TEST</text>
  <a href="https://example.invalid/"><text x="20" y="100">Open benign test URL</text></a>
</svg>
EOF
cat > "$ROOT/09-web/script.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="640" height="180">
  <text id="msg" x="20" y="60">MAIL-GATEWAY-BENIGN-TEST</text>
  <script><![CDATA[
    document.getElementById('msg').textContent = 'MAIL-GATEWAY-BENIGN-ACTIVE-CONTENT-TEST';
  ]]></script>
</svg>
EOF
csv_add "WEB-001" "web" "09-web/link.html" "HTML attachment with benign reserved-domain hyperlink"
csv_add "WEB-002" "web" "09-web/blob-download.html" "Benign HTML/JavaScript Blob download of a text file; tests HTML-smuggling-style detection without executable payload"
csv_add "WEB-003" "web" "09-web/link.svg" "SVG with benign hyperlink"
csv_add "WEB-004" "web" "09-web/script.svg" "SVG with benign JavaScript modifying local text only"

# -----------------------------
# 10 - PDF samples
# -----------------------------
log "Creating minimal PDFs"
python3 - "$ROOT" <<'PY'
import os, sys
root=sys.argv[1]

def pdf_with_link(path, url='https://example.invalid/'):
    objs=[]
    def add(s):
        objs.append(s.encode('latin-1'))
        return len(objs)
    catalog=add('<< /Type /Catalog /Pages 2 0 R >>')
    pages=add('<< /Type /Pages /Kids [3 0 R] /Count 1 >>')
    page=add('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R /Annots [6 0 R] >>')
    stream='BT /F1 16 Tf 72 720 Td (MAIL-GATEWAY-BENIGN-TEST) Tj 0 -40 Td (Open benign test URL) Tj ET'
    content=add(f'<< /Length {len(stream)} >>\nstream\n{stream}\nendstream')
    font=add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
    annot=add(f'<< /Type /Annot /Subtype /Link /Rect [72 660 260 690] /Border [0 0 0] /A << /S /URI /URI ({url}) >> >>')
    out=bytearray(b'%PDF-1.4\n')
    offsets=[0]
    for i,obj in enumerate(objs,1):
        offsets.append(len(out))
        out += f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n'
    xref=len(out)
    out += f'xref\n0 {len(objs)+1}\n'.encode()
    out += b'0000000000 65535 f \n'
    for off in offsets[1:]: out += f'{off:010d} 00000 n \n'.encode()
    out += f'trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    open(path,'wb').write(out)

pdf_with_link(os.path.join(root,'10-pdf/pdf-with-url.pdf'))
PY
csv_add "PDF-001" "pdf" "10-pdf/pdf-with-url.pdf" "Minimal valid PDF with benign URI annotation"

# Optional QR samples if qrcode/Pillow are installed.
python3 - "$ROOT" >/dev/null 2>&1 <<'PY' && QR_OK=1 || QR_OK=0
import os, sys
import qrcode
root=sys.argv[1]
img=qrcode.make('https://example.invalid/')
img.save(os.path.join(root,'10-pdf/qr-benign.png'))
try:
    img.convert('RGB').save(os.path.join(root,'10-pdf/pdf-with-qr.pdf'),'PDF')
except Exception:
    pass
PY
if [[ "${QR_OK:-0}" == "1" && -f "$ROOT/10-pdf/qr-benign.png" ]]; then
  csv_add "PDF-002" "pdf" "10-pdf/qr-benign.png" "QR code resolving to reserved example.invalid domain"
  [[ -f "$ROOT/10-pdf/pdf-with-qr.pdf" ]] && csv_add "PDF-003" "pdf" "10-pdf/pdf-with-qr.pdf" "PDF containing benign QR code"
else
  warn "Python qrcode/Pillow not installed: skipping QR samples"
fi

# -----------------------------
# 11 - Raw MIME / EML samples
# -----------------------------
log "Creating raw MIME/EML parser-differential samples"
python3 - "$ROOT" <<'PY'
import os, sys, base64, email.policy
from email.message import EmailMessage
from email.generator import BytesGenerator
from io import BytesIO
root=sys.argv[1]
out=os.path.join(root,'11-mime')

def save(msg, name):
    with open(os.path.join(out,name),'wb') as f:
        BytesGenerator(f, policy=email.policy.SMTP).flatten(msg)

def base(subject):
    m=EmailMessage()
    m['From']='sender@example.invalid'
    m['To']='recipient@example.invalid'
    m['Subject']=subject
    m.set_content('MAIL-GATEWAY-BENIGN-TEST')
    return m

with open(os.path.join(root,'09-web/link.svg'),'rb') as f: svg=f.read()
with open(os.path.join(root,'01-antivirus/eicar.com'),'rb') as f: eicar=f.read()

m=base('TEST SVG declared as text/plain')
m.add_attachment(svg, maintype='text', subtype='plain', filename='voicemail.svg')
save(m,'svg-as-text-plain.eml')

m=base('TEST EICAR declared as PDF')
m.add_attachment(eicar, maintype='application', subtype='pdf', filename='invoice.pdf')
save(m,'eicar-as-pdf.eml')

m=base('TEST duplicate attachment filename')
m.add_attachment(b'MAIL-GATEWAY-BENIGN-TEST\n', maintype='application', subtype='pdf', filename='invoice.pdf')
m.add_attachment(eicar, maintype='application', subtype='pdf', filename='invoice.pdf')
save(m,'duplicate-filename.eml')

m=base('TEST attachment with no filename')
m.add_attachment(eicar, maintype='application', subtype='octet-stream')
save(m,'eicar-no-filename.eml')

inner=base('INNER EICAR TEST')
inner.add_attachment(eicar, maintype='application', subtype='octet-stream', filename='eicar.com')
inner_bytes=inner.as_bytes(policy=email.policy.SMTP)
outer=base('OUTER message/rfc822 TEST')
outer.add_attachment(inner_bytes, maintype='message', subtype='rfc822', filename='attached-message.eml')
save(outer,'outer-with-attached-eml.eml')
PY
csv_add "MIME-001" "mime" "11-mime/svg-as-text-plain.eml" "SVG attachment declared as text/plain"
csv_add "MIME-002" "mime" "11-mime/eicar-as-pdf.eml" "EICAR attachment declared as application/pdf and named invoice.pdf"
csv_add "MIME-003" "mime" "11-mime/duplicate-filename.eml" "Two attachments share the same filename but contain different content"
csv_add "MIME-004" "mime" "11-mime/eicar-no-filename.eml" "EICAR attachment without a filename parameter"
csv_add "MIME-005" "mime" "11-mime/outer-with-attached-eml.eml" "Nested message/rfc822 containing EICAR"

# -----------------------------
# 12 - Filename normalization
# -----------------------------
log "Creating filename-normalization samples"
python3 - "$ROOT" <<'PY'
import os, sys, shutil
root=sys.argv[1]
out=os.path.join(root,'12-filename')
src=os.path.join(root,'00-baseline/test.txt')
names=[
    'invoice.pdf.exe',
    'invoice.pdf........exe',
    'INVOICE.EXE',
    'Invoice.ExE',
    'invoice .exe',
    'invoice...exe',
    ('A'*180)+'.exe',
    'invoice．exe',       # U+FF0E fullwidth full stop
    'invoice․exe',       # U+2024 one dot leader
    'invoice‐2026.pdf',  # U+2010 hyphen
]
for n in names:
    shutil.copyfile(src, os.path.join(out,n))
PY
i=0
while IFS= read -r -d '' f; do
  i=$((i+1))
  rel="${f#"$ROOT/"}"
  csv_add "$(printf 'NAME-%03d' "$i")" "filename" "$rel" "Benign content with suspicious or normalization-sensitive filename"
done < <(find "$ROOT/12-filename" -maxdepth 1 -type f -print0)

# -----------------------------
# 13 - Parser differential / concatenation samples
# -----------------------------
log "Creating parser-differential samples"
cp "$ROOT/06-archives/eicar.zip" "$ROOT/13-parser/zip-with-trailing-junk.zip"
printf '\nMAIL-GATEWAY-TRAILING-DATA\n' >> "$ROOT/13-parser/zip-with-trailing-junk.zip"
cat "$ROOT/00-baseline/test.png" "$ROOT/06-archives/eicar.zip" > "$ROOT/13-parser/png-plus-zip.png"
cp "$ROOT/13-parser/png-plus-zip.png" "$ROOT/13-parser/png-plus-zip.zip"

python3 - "$ROOT" <<'PY'
import os, sys
root=sys.argv[1]
src=os.path.join(root,'06-archives/eicar.zip')
dst=os.path.join(root,'13-parser/truncated-eicar.zip')
data=open(src,'rb').read()
open(dst,'wb').write(data[:-8] if len(data)>8 else data)
PY
csv_add "PARSE-001" "parser" "13-parser/zip-with-trailing-junk.zip" "Valid ZIP followed by extra trailing bytes"
csv_add "PARSE-002" "parser" "13-parser/png-plus-zip.png" "PNG concatenated with ZIP; parser-dependent dual-format/leading-data test"
csv_add "PARSE-003" "parser" "13-parser/png-plus-zip.zip" "Same concatenated PNG+ZIP bytes with ZIP extension"
csv_add "PARSE-004" "parser" "13-parser/truncated-eicar.zip" "Deliberately truncated ZIP for parser-error handling; not guaranteed to open"

# -----------------------------
# 14 - Resource-limit tests (bounded)
# -----------------------------
log "Creating bounded resource-limit samples"
python3 - "$ROOT" "$MANY_FILES" "$COMPRESS_MB" <<'PY'
import os, sys, zipfile
root, count, mb = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
out=os.path.join(root,'14-resource-limits')
with zipfile.ZipFile(os.path.join(out,f'many-files-{count}.zip'),'w',zipfile.ZIP_DEFLATED) as z:
    for i in range(count):
        z.writestr(f'files/test-{i:05d}.txt', 'MAIL-GATEWAY-BENIGN-TEST\n')
zero=os.path.join(out,f'zeros-{mb}MB.bin')
chunk=b'\x00'*(1024*1024)
with open(zero,'wb') as f:
    for _ in range(mb): f.write(chunk)
with zipfile.ZipFile(os.path.join(out,f'high-compression-{mb}MB.zip'),'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    z.write(zero,os.path.basename(zero))
os.remove(zero)
PY
csv_add "LIMIT-001" "resource-limits" "14-resource-limits/many-files-${MANY_FILES}.zip" "ZIP with many benign small files; bounded file-count limit test"
csv_add "LIMIT-002" "resource-limits" "14-resource-limits/high-compression-${COMPRESS_MB}MB.zip" "Bounded high-compression-ratio ZIP; not a decompression bomb"

# -----------------------------
# 15 - Additional Kali-native samples
# -----------------------------
log "Creating additional native container, MIME, web, and filename samples"
python3 - "$ROOT" "$MANIFEST" "$COMPRESS_MB" <<'PY'
import base64, csv, gzip, io, os, pathlib, shutil, sys, urllib.parse, warnings, zipfile
from email import policy
from email.message import EmailMessage

root, manifest, mb = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
eicar = (root / '01-antivirus/eicar.com').read_bytes()
marker = b'MAIL-GATEWAY-BENIGN-TEST\n'
pe_path = root / '02-executable/benign.exe'
pe = pe_path.read_bytes() if pe_path.exists() else None

with open(manifest, 'a', newline='', encoding='utf-8') as mf:
    rows = csv.writer(mf)
    def put(check, group, path, purpose):
        rows.writerow([check, group, str(path.relative_to(root)), purpose])
    def archive(path, entries):
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in entries.items(): z.writestr(name, data)
    def mail(subject, attachments):
        msg = EmailMessage(policy=policy.SMTP)
        msg['From'] = 'sender@example.invalid'
        msg['To'] = 'recipient@example.invalid'
        msg['Subject'] = subject
        msg.set_content('MAIL-GATEWAY-BENIGN-TEST')
        for name, data, mime in attachments:
            major, minor = mime.split('/', 1)
            msg.add_attachment(data, maintype=major, subtype=minor, filename=name)
        return msg.as_bytes(policy=policy.SMTP)
    def raw_mail(path, part_headers, data, cte='base64'):
        if cte == 'base64': payload = base64.encodebytes(data)
        elif cte == 'quoted-printable':
            import quopri
            payload = quopri.encodestring(data)
        else: payload = data
        headers = [b'From: sender@example.invalid', b'To: recipient@example.invalid',
                   b'Subject: MAIL-GATEWAY-BENIGN-TEST', b'MIME-Version: 1.0',
                   b'Content-Type: multipart/mixed; boundary="TESTBOUNDARY"']
        content = (b'\r\n'.join(headers) + b'\r\n\r\n--TESTBOUNDARY\r\n'
                   b'Content-Type: text/plain\r\n\r\nMAIL-GATEWAY-BENIGN-TEST\r\n'
                   b'--TESTBOUNDARY\r\n' + part_headers + b'\r\n'
                   + b'Content-Transfer-Encoding: ' + cte.encode('ascii') + b'\r\n\r\n'
                   + payload.rstrip(b'\r\n') + b'\r\n--TESTBOUNDARY--\r\n')
        path.write_bytes(content)

    arc = root / '06-archives'
    nested = root / '08-nested'
    mime = root / '11-mime'
    parser = root / '13-parser'
    web = root / '09-web'
    names = root / '12-filename'
    off = root / '05-office'
    pdf = root / '10-pdf'
    limits = root / '14-resource-limits'

    gz = arc / 'eicar.com.gz'
    with gzip.open(gz, 'wb') as f: f.write(eicar)
    put('F61', 'archives', gz, 'Standalone GZIP stream containing EICAR')
    for script in ('test.ps1', 'test.js', 'test.vbs'):
        dst = arc / ('script-' + script + '.zip')
        archive(dst, {script: (root / '03-scripts' / script).read_bytes()})
        put('F55-' + script, 'archives', dst, 'ZIP with benign script ' + script)
    dst = arc / 'pdf-and-eicar.zip'
    archive(dst, {'invoice.pdf': (pdf / 'pdf-with-url.pdf').read_bytes(), 'eicar.com': eicar})
    put('F69', 'archives', dst, 'ZIP with valid PDF and EICAR in separate entries')
    dst = arc / 'deep-tree.zip'
    archive(dst, {'/'.join(['d'] * 24) + '/eicar.com': eicar})
    put('F70', 'archives', dst, 'ZIP with 24 nested directories ending in EICAR')
    if pe:
        dst = arc / 'benign-pe.zip'
        archive(dst, {'benign.exe': pe})
        put('F53', 'archives', dst, 'ZIP with real benign Windows PE')
        dst = nested / 'zip-zip-benign-pe.zip'
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('benign.exe', pe)
        archive(dst, {'inner.zip': inner.getvalue()})
        put('F65', 'nested', dst, 'ZIP containing ZIP containing benign Windows PE')

    inner = mail('INNER ZIP EICAR', [('eicar.zip', (arc / 'eicar.zip').read_bytes(), 'application/zip')])
    dst = nested / 'eml-zip-eicar.eml'
    dst.write_bytes(inner)
    put('F102', 'nested', dst, 'EML with ZIP attachment containing EICAR')
    dst = nested / 'zip-eml-eicar.zip'
    archive(dst, {'attached-message.eml': mail('INNER EICAR', [('eicar.com', eicar, 'application/octet-stream')])})
    put('F108', 'nested', dst, 'ZIP with EML containing EICAR')
    dst = nested / 'zip-eml-zip-eicar.zip'
    archive(dst, {'attached-message.eml': inner})
    put('F108-ZEZ', 'nested', dst, 'ZIP with EML with ZIP containing EICAR')
    if pe:
        dst = nested / 'eml-benign-pe.eml'
        dst.write_bytes(mail('BENIGN PE', [('benign.exe', pe, 'application/octet-stream')]))
        put('F101', 'nested', dst, 'EML with benign Windows PE attachment')

    rtf = off / 'plain/test.rtf'
    rtf.write_text(r'{\rtf1\ansi MAIL-GATEWAY-BENIGN-TEST}', encoding='ascii')
    put('F22', 'office', rtf, 'Valid minimal benign RTF')
    jar = arc / 'benign.jar'
    archive(jar, {'META-INF/MANIFEST.MF': b'Manifest-Version: 1.0\r\nCreated-By: Mail Gateway Test\r\n\r\n',
                  'MAIL-GATEWAY-TEST.txt': marker})
    put('F13', 'archives', jar, 'Valid JAR archive structure with manifest and benign text; no Java executable class')
    src = pdf / 'pdf-with-url.pdf'
    dst = off / 'container-tests/docx-container-with-zip.docx'
    with zipfile.ZipFile(off / 'plain/test.docx') as original, zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as z:
        for info in original.infolist(): z.writestr(info.filename, original.read(info.filename))
        z.writestr('word/embeddings/archive.zip', (arc / 'eicar.zip').read_bytes())
    put('F106', 'office', dst, 'OOXML ZIP with unreferenced embedded ZIP; recursive inspection only, not clickable OLE object')
    dst = off / 'container-tests/docx-with-external-link.docx'
    with zipfile.ZipFile(off / 'plain/test.docx') as original, zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as z:
        for info in original.infolist():
            data = original.read(info.filename)
            if info.filename == 'word/document.xml':
                data = data.replace(b'</w:body>', b'<w:p><w:hyperlink xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="rId1"><w:r><w:t>Reserved test URL</w:t></w:r></w:hyperlink></w:p></w:body>')
            z.writestr(info.filename, data)
        z.writestr('word/_rels/document.xml.rels', '''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/" TargetMode="External"/>
</Relationships>''')
    put('F25', 'office', dst, 'Valid DOCX with an external hyperlink relationship to a reserved domain; not an auto-fetching object')
    dst = off / 'container-tests/pdf-named-docx.docx'
    shutil.copyfile(src, dst)
    put('F32', 'office', dst, 'Actual PDF bytes with DOCX extension; file-type detection test')

    dst = web / 'redirect.html'
    dst.write_text('<!doctype html><meta http-equiv="refresh" content="0;url=https://example.invalid/">', encoding='utf-8')
    put('F88', 'web', dst, 'HTML meta refresh to reserved example.invalid domain')
    dst = web / 'base64-blob.html'
    dst.write_text('''<!doctype html><script>
const b = atob("TUFJTC1HQVRFV0FZLUJFTklHTi1URVNU");
const a = document.createElement("a");
a.href = URL.createObjectURL(new Blob([b], {type:"text/plain"}));
a.download = "benign.txt"; a.textContent = "Download benign text";
document.body.appendChild(a);
</script>''', encoding='utf-8')
    put('F95', 'web', dst, 'Base64 plus Blob creates only benign TXT')
    dst = web / 'base64-link.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70">
<a href="data:text/plain;base64,TUFJTC1HQVRFV0FZLUJFTklHTi1URVNU"><text x="8" y="40">Open benign text</text></a></svg>''', encoding='utf-8')
    put('F91', 'web', dst, 'SVG with inline Base64 benign text data URI')
    dst = web / 'external-resource.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70"><image href="https://example.invalid/test.png" width="10" height="10"/></svg>''', encoding='utf-8')
    put('F100', 'web', dst, 'SVG with external image reference to reserved domain; no callback expected')
    dst = web / 'foreign-object.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70"><foreignObject width="400" height="70"><div xmlns="http://www.w3.org/1999/xhtml">MAIL-GATEWAY-BENIGN-TEST</div></foreignObject></svg>''', encoding='utf-8')
    put('F99', 'web', dst, 'SVG foreignObject with harmless HTML fragment')
    dst = web / 'js-navigation.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70"><script><![CDATA[
function go() { window.location.href = "https://example.invalid/"; }
]]></script><text x="8" y="40" onclick="go()">Open reserved URL</text></svg>''', encoding='utf-8')
    put('F131', 'web', dst, 'SVG click handler navigating only to reserved domain')
    dst = web / 'link-to-html.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70"><a href="https://example.invalid/test.html"><text x="8" y="40">Open reserved HTML URL</text></a></svg>''', encoding='utf-8')
    put('F97', 'web', dst, 'SVG hyperlink to reserved HTML URL')
    dst = web / 'encoded-text-js.svg'
    dst.write_text('''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="70"><text id="t" x="8" y="40">Test</text><script><![CDATA[
document.getElementById('t').textContent=String.fromCharCode(79,75);
]]></script></svg>''', encoding='utf-8')
    put('F98', 'web', dst, 'SVG with benign numeric encoded JavaScript text assignment')

    # Raw RFC messages allow exact control of MIME headers independently of MIME library normalization.
    samples = [
        ('pe-as-jpeg.eml', b'Content-Type: image/jpeg; name="invoice.jpg"\r\nContent-Disposition: attachment; filename="invoice.jpg"', pe, 'F41', 'PE bytes declared JPEG'),
        ('pe-as-octet-stream.eml', b'Content-Type: application/octet-stream; name="invoice.bin"\r\nContent-Disposition: attachment; filename="invoice.bin"', pe, 'F43', 'PE bytes declared octet-stream'),
        ('different-name-and-filename.eml', b'Content-Type: application/octet-stream; name="safe.txt"\r\nContent-Disposition: attachment; filename="danger.exe"', pe or marker, 'F44', 'Contradictory name and filename parameters'),
        ('filename-rfc2047.eml', b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="=?UTF-8?B?Y2hlY2sucHMx?="', marker, 'F45', 'Encoded-word filename in quoted parameter; nonstandard parser differential'),
        ('filename-rfc2231.eml', b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=UTF-8''check%2Eps1", marker, 'F46', 'RFC2231 extended filename parameter'),
        ('quoted-printable.eml', b'Content-Type: text/plain; name="sample.txt"\r\nContent-Disposition: attachment; filename="sample.txt"', eicar, 'F49', 'Quoted-printable transfer encoding of EICAR bytes'),
        ('duplicate-content-type.eml', b'Content-Type: text/plain; name="safe.txt"\r\nContent-Type: application/octet-stream; name="check.exe"\r\nContent-Disposition: attachment; filename="check.exe"', marker, 'F52', 'Duplicate conflicting Content-Type headers in one part'),
    ]
    for filename, headers, content, check, purpose in samples:
        if content is None: continue
        dst = mime / filename
        raw_mail(dst, headers, content, 'quoted-printable' if check == 'F49' else 'base64')
        put(check, 'mime', dst, purpose)
    hdr = b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="eicar.txt"'
    dst = mime / 'folded-base64.eml'
    raw_mail(dst, hdr, eicar)
    put('F47', 'mime', dst, 'EICAR Base64 attachment with standard folded lines')
    dst = mime / 'nonstandard-base64-whitespace.eml'
    raw_mail(dst, hdr, eicar)
    dst.write_bytes(dst.read_bytes().replace(base64.encodebytes(eicar).rstrip(b'\n'),
                                     b'  ' + base64.b64encode(eicar[:24]) + b'\r\n\t' + base64.b64encode(eicar[24:])))
    put('F48', 'mime', dst, 'Base64 split at byte boundary with whitespace; deliberately nonstandard parser differential')
    dst = mime / 'pe-as-pdf.eml'
    if pe:
        raw_mail(dst, b'Content-Type: application/pdf; name="invoice.pdf"\r\nContent-Disposition: attachment; filename="invoice.pdf"', pe)
        put('F42', 'mime', dst, 'Real PE declared PDF and named invoice.pdf')
    dst = mime / 'nested-multipart.eml'
    nested_msg = EmailMessage(policy=policy.SMTP)
    nested_msg['From'] = 'sender@example.invalid'; nested_msg['To'] = 'recipient@example.invalid'
    nested_msg['Subject'] = 'Nested multipart'
    nested_msg.set_content('MAIL-GATEWAY-BENIGN-TEST')
    nested_msg.add_alternative('<p>MAIL-GATEWAY-BENIGN-TEST</p>', subtype='html')
    nested_msg.add_attachment(eicar, maintype='application', subtype='octet-stream', filename='eicar.com')
    dst.write_bytes(nested_msg.as_bytes())
    put('F50', 'mime', dst, 'multipart/mixed containing multipart/alternative and EICAR attachment')
    dst = mime / 'password-in-subject.eml'
    password = os.environ.get('ARCHIVE_PASSWORD', 'Test123')
    b = mail('Password: ' + password, [('archive.zip', (root / '07-encrypted/eicar-password.zip').read_bytes(), 'application/zip')]) if (root / '07-encrypted/eicar-password.zip').exists() else None
    if b:
        dst.write_bytes(b); put('F78', 'mime', dst, 'Password protected ZIP, password in subject')
        msg = EmailMessage(policy=policy.SMTP)
        msg['From'] = 'sender@example.invalid'; msg['To'] = 'recipient@example.invalid'
        msg['Subject'] = 'Password in message body'
        msg.set_content('Password: ' + password)
        msg.add_attachment((root / '07-encrypted/eicar-password.zip').read_bytes(), maintype='application', subtype='zip', filename='archive.zip')
        dst = mime / 'password-in-body.eml'; dst.write_bytes(msg.as_bytes())
        put('F79', 'mime', dst, 'Password protected ZIP, password in body')
        try:
            from PIL import Image, ImageDraw
            image = Image.new('RGB', (650, 80), 'white')
            ImageDraw.Draw(image).text((12, 24), 'Password: ' + password, fill='black')
            dst = root / '07-encrypted/password-in-image.png'
            image.save(dst)
            put('F80', 'encrypted', dst, 'PNG containing visible password text; use with the encrypted ZIP')
        except (ImportError, UnicodeEncodeError):
            pass

    for filename, content in [('right-to-left-override-\u202eexe.pdf', marker),
                              ('ending-dot.exe.', marker), ('ending-space.exe ', marker)]:
        dst = names / filename; dst.write_bytes(content)
        put('F38/39', 'filename', dst, 'Filename normalization on Unix; Windows/Outlook may change or reject name')
    if pe:
        for filename in ('faktura.pdf.docx.exe', 'long-' + 'a'*180 + '.exe'):
            dst = names / filename; dst.write_bytes(pe)
            put('F29/35', 'filename', dst, 'Benign Windows PE with deceptive/long filename')
        dst = mime / 'combined-filename-mime.eml'
        raw_mail(dst, b'Content-Type: image/jpeg; name="safe.jpg"\r\nContent-Disposition: attachment; filename="invoice\xef\xbc\x8epdf.exe"', pe)
        put('F138', 'mime', dst, 'Combined PE, MIME mismatch, Unicode fullwidth dot, double extension, conflicting name')

    dst = parser / 'duplicate-zip-entry.zip'
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(dst, 'w') as z:
            z.writestr('same.txt', marker); z.writestr('same.txt', eicar)
    put('F116', 'parser', dst, 'Two ZIP entries with identical names and different content')
    dst = parser / 'case-differing-zip-entry.zip'
    archive(dst, {'CHECK.TXT': marker, 'check.txt': eicar})
    put('F117', 'parser', dst, 'ZIP with case variant filenames')
    dst = parser / 'unicode-zip-entry.zip'
    archive(dst, {'faktura．exe': eicar})
    put('F118', 'parser', dst, 'Unicode fullwidth dot in ZIP entry filename')
    dst = parser / 'zip-local-central-name-disagreement.zip'
    archive(dst, {'safe.txt': eicar})
    zipbytes = bytearray(dst.read_bytes())
    # Rename the name in the LOCAL file header only (its first occurrence),
    # leaving the central directory entry as 'safe.txt'. Do not assume a fixed
    # offset: locate the name relative to the local-file-header signature so an
    # extra field or a different zipfile layout cannot break the run. Both names
    # are 8 bytes, so byte offsets stay valid.
    lfh = zipbytes.find(b'PK\x03\x04')
    name_pos = zipbytes.find(b'safe.txt', lfh) if lfh != -1 else -1
    if name_pos != -1:
        zipbytes[name_pos:name_pos + 8] = b'evil.exe'
        dst.write_bytes(zipbytes)
        put('F115', 'parser', dst, 'ZIP with local header name evil.exe but central directory name safe.txt; intentionally inconsistent')
    else:
        warn_msg = 'F115 skipped: unexpected ZIP layout, local header name not found'
        sys.stderr.write('[!] ' + warn_msg + '\n')
    # These are concatenation differentials, not universally valid polyglots.
    for name, source in [('pdf-plus-zip.pdf', src), ('gif-plus-zip.gif', root / '13-parser/one-pixel.gif')]:
        if name.endswith('.gif'):
            source.write_bytes(base64.b64decode('R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='))
        dst = parser / name
        dst.write_bytes(source.read_bytes() + (arc / 'eicar.zip').read_bytes())
        put('F109' if name.endswith('.pdf') else 'F111', 'parser', dst, 'Valid leading format plus ZIP bytes; ZIP recognition is parser-dependent')
    try:
        from PIL import Image
        img = Image.new('RGB', (1, 1), 'white')
        source = io.BytesIO(); img.save(source, 'JPEG')
        dst = parser / 'jpeg-plus-zip.jpg'
        dst.write_bytes(source.getvalue() + (arc / 'eicar.zip').read_bytes())
        put('F110', 'parser', dst, 'Valid JPEG bytes plus ZIP bytes; ZIP recognition is parser-dependent')
        qr = pdf / 'qr-benign.png'
        if qr.exists():
            img = Image.open(qr).convert('RGB'); dst = pdf / 'qr-benign.jpg'
            img.save(dst, 'JPEG'); put('F93', 'pdf', dst, 'JPEG with benign QR code')
    except ImportError:
        pass

    dst = limits / ('standalone-' + str(mb) + 'MB.bin')
    with dst.open('wb') as f:
        for _ in range(mb): f.write(marker + bytes(1024*1024-len(marker)))
    put('F122', 'resource-limits', dst, 'Bounded standalone attachment, size controlled by COMPRESS_MB')
PY

# A self-contained Shell Link and two small PDF structures; all targets are benign.
python3 - "$ROOT" "$MANIFEST" <<'PY'
import csv, pathlib, struct, sys
root, manifest = pathlib.Path(sys.argv[1]), sys.argv[2]
with open(manifest, 'a', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    def record(check, kind, path, purpose):
        writer.writerow([check, kind, str(path.relative_to(root)), purpose])

    # MS-SHLLINK header and LinkInfo referencing the Windows Notepad executable.
    path = root / '04-shortcuts/benign-notepad.lnk'
    target = b'C:\\Windows\\System32\\notepad.exe\x00'
    volume = struct.pack('<IIII', 17, 3, 0, 16) + b'\x00'
    suffix = b'notepad.exe\x00'
    base_offset = 28 + len(volume)
    suffix_offset = base_offset + len(target)
    linkinfo = struct.pack('<IIIIIII', suffix_offset + len(suffix), 28, 1, 28,
                           base_offset, 0, suffix_offset) + volume + target + suffix
    header = (struct.pack('<I', 76) + bytes.fromhex('0114020000000000c000000000000046')
              + struct.pack('<II', 0x82, 0x20) + bytes(24)
              + struct.pack('<IIiHHII', 0, 0, 1, 0, 0, 0, 0))
    assert len(header) == 76
    path.write_bytes(header + linkinfo + bytes(4))
    record('F10', 'shortcuts', path, 'Native Shell Link with LinkInfo pointing to Windows Notepad; no arguments or network destination')

    def make_pdf(path, extra=False, attachment_name='benign.txt', attachment=None):
        objects = []
        def add(data):
            objects.append(data if isinstance(data, bytes) else data.encode('ascii'))
            return len(objects)
        if extra:
            add('<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(' + attachment_name + ') 5 0 R] >> >> >>')
        else:
            add('<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /NeedAppearances true >> >>')
        add('<< /Type /Pages /Kids [3 0 R] /Count 1 >>')
        add('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]' +
            (' >>' if extra else ' /Annots [5 0 R] >>'))
        stream = b'MAIL-GATEWAY-BENIGN-TEST\n' if attachment is None else attachment
        add(b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'endstream')
        if extra:
            add('<< /Type /Filespec /F (' + attachment_name + ') /UF (' + attachment_name + ') /EF << /F 6 0 R >> >>')
            add(b'<< /Type /EmbeddedFile /Length %d >>\nstream\n' % len(stream) + stream + b'endstream')
        else:
            add('<< /Type /Annot /Subtype /Widget /FT /Tx /T (benign-field) /V (MAIL-GATEWAY-BENIGN-TEST) /Rect [72 680 290 705] /P 3 0 R /F 4 >>')
        data = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        offsets = [0]
        for n, obj in enumerate(objects, 1):
            offsets.append(len(data))
            data += ('%d 0 obj\n' % n).encode() + obj + b'\nendobj\n'
        xref = len(data)
        data += ('xref\n0 %d\n' % (len(objects) + 1)).encode() + b'0000000000 65535 f \n'
        for offset in offsets[1:]: data += ('%010d 00000 n \n' % offset).encode()
        data += ('trailer\n<< /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)).encode()
        path.write_bytes(data)
    path = root / '10-pdf/embedded-benign.txt.pdf'
    make_pdf(path, extra=True)
    record('F84', 'pdf', path, 'PDF with actual EmbeddedFiles name tree and a benign TXT attachment')
    path = root / '10-pdf/acroform.pdf'
    make_pdf(path)
    record('F85', 'pdf', path, 'PDF with a benign AcroForm text field')
    path = root / '10-pdf/embedded-eicar.zip.pdf'
    make_pdf(path, extra=True, attachment_name='archive.zip', attachment=(root / '06-archives/eicar.zip').read_bytes())
    record('F105', 'pdf', path, 'PDF with real EmbeddedFiles ZIP attachment containing EICAR')
PY

# Optional native tools on Kali: each output is checked before adding it to the manifest.
if have genisoimage || have mkisofs; then
  ISO_TOOL="$(command -v genisoimage || command -v mkisofs)"
  if "$ISO_TOOL" -quiet -o "$ROOT/06-archives/eicar.iso" "$ROOT/01-antivirus/eicar.com" 2>/dev/null; then
    csv_add "F63" "archives" "06-archives/eicar.iso" "ISO9660 filesystem with EICAR"
    cp "$ROOT/06-archives/eicar.iso" "$ROOT/06-archives/eicar.img"
    csv_add "F64" "archives" "06-archives/eicar.img" "ISO9660 image bytes with IMG extension; not a separate raw disk image format"
  fi
fi
if have gcab; then
  if (cd "$ROOT/01-antivirus" && gcab -c ../06-archives/eicar.cab eicar.com >/dev/null 2>&1); then
    csv_add "F62" "archives" "06-archives/eicar.cab" "Genuine Microsoft CAB containing EICAR"
  fi
fi
if have qpdf; then
  if qpdf --encrypt "$PASSWORD" "$PASSWORD" 256 -- "$ROOT/10-pdf/pdf-with-url.pdf" "$ROOT/07-encrypted/pdf-password.pdf"; then
    csv_add "F77" "encrypted" "07-encrypted/pdf-password.pdf" "Password-encrypted valid PDF containing a benign link"
  fi
fi
if have_7z; then
  (cd "$ROOT/08-nested" && "$SEVENZIP" a -y zip-in-7z.7z ../06-archives/eicar.zip >/dev/null)
  csv_add "F68-PART" "nested" "08-nested/zip-in-7z.7z" "7z containing ZIP containing EICAR; no RAR layer"
fi
if have zip && [[ -f "$ROOT/08-nested/level-02.zip" ]]; then
  (cd "$ROOT/08-nested" && zip -j -P "$PASSWORD" encrypted-outer.zip level-02.zip >/dev/null)
  csv_add "F137-PART" "nested" "08-nested/encrypted-outer.zip" "Encrypted ZIP containing unencrypted nested ZIP ending in EICAR"
  if (cd "$ROOT/08-nested" && zip -j -P "$PASSWORD" encrypted-in-encrypted.zip ../07-encrypted/eicar-password.zip >/dev/null 2>&1); then
    csv_add "F75" "nested" "08-nested/encrypted-in-encrypted.zip" "Encrypted ZIP containing encrypted ZIP containing EICAR"
  fi
fi
if have zip; then
  (cd "$ROOT/06-archives" && zip -j -q zip-with-lnk.zip ../04-shortcuts/benign-notepad.lnk)
  csv_add "F54" "archives" "06-archives/zip-with-lnk.zip" "ZIP containing a benign Notepad Shell Link"
  (cd "$ROOT/08-nested" && zip -j -q -P "$PASSWORD" encrypted-zip-with-lnk.zip ../04-shortcuts/benign-notepad.lnk)
  csv_add "F127" "nested" "08-nested/encrypted-zip-with-lnk.zip" "Encrypted ZIP containing a benign Notepad Shell Link"
  python3 - "$ROOT" "$MANIFEST" <<'PY'
import csv, pathlib, sys
from email.message import EmailMessage
from email import policy
root=pathlib.Path(sys.argv[1]); path=root/'08-nested/eml-zip-lnk.eml'
msg=EmailMessage(policy=policy.SMTP)
msg['From']='sender@example.invalid'; msg['To']='recipient@example.invalid'; msg['Subject']='Benign ZIP LNK test'
msg.set_content('MAIL-GATEWAY-BENIGN-TEST')
msg.add_attachment((root/'06-archives/zip-with-lnk.zip').read_bytes(), maintype='application', subtype='zip', filename='zip-with-lnk.zip')
path.write_bytes(msg.as_bytes())
with open(sys.argv[2], 'a', newline='', encoding='utf-8') as f:
 csv.writer(f).writerow(['F133','nested','08-nested/eml-zip-lnk.eml','EML containing ZIP containing a benign Notepad Shell Link'])
PY
fi

# -----------------------------
# Manifest enrichment: add sha256, size and an expected-verdict column.
# -----------------------------
log "Enriching manifest with sha256, size and expected-verdict columns"
python3 - "$ROOT" "$MANIFEST" <<'PY'
import csv, hashlib, pathlib, sys
root, manifest = pathlib.Path(sys.argv[1]), sys.argv[2]

# Per-category default expectation. This is a STARTING HEURISTIC, not policy:
#   block           - a correctly configured gateway is expected to detect/strip it
#                     (these samples carry the EICAR signature)
#   pass            - benign control content expected to be delivered
#   policy-dependent - outcome depends on the organization's attachment policy
# Review and adjust per sample before scoring a real run.
EXPECTED = {
    'baseline': 'pass',
    'antivirus': 'block',
    'archives': 'block',
    'nested': 'block',
    'parser': 'block',
    'encrypted': 'policy-dependent',
    'executable': 'policy-dependent',
    'scripts': 'policy-dependent',
    'shortcuts': 'policy-dependent',
    'office': 'policy-dependent',
    'office-extension-only': 'policy-dependent',
    'web': 'policy-dependent',
    'pdf': 'policy-dependent',
    'mime': 'policy-dependent',
    'filename': 'policy-dependent',
    'resource-limits': 'policy-dependent',
}

with open(manifest, newline='', encoding='utf-8') as f:
    rows = list(csv.reader(f))
if not rows:
    sys.exit(0)

out = [['id', 'category', 'path', 'sha256', 'size_bytes', 'expected', 'purpose']]
for r in rows[1:]:
    if len(r) < 4:
        continue
    cid, category, rel, purpose = r[0], r[1], r[2], r[3]
    f = root / rel
    if f.is_file():
        data = f.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        size = str(len(data))
    else:
        sha256, size = '', ''
    out.append([cid, category, rel, sha256, size, EXPECTED.get(category, 'policy-dependent'), purpose])

with open(manifest, 'w', newline='', encoding='utf-8') as f:
    csv.writer(f).writerows(out)
PY

# -----------------------------
# README / limitations
# -----------------------------
cat > "$ROOT/README.md" <<EOF
# Mail attachment security test corpus

Generated on: $(date -u +'%Y-%m-%dT%H:%M:%SZ')

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

    $PASSWORD

## Safety limits

- Maximum generated nested ZIP depth: $NEST_DEPTH (hard cap: 20)
- Number of files in file-count sample: $MANY_FILES (hard cap: 2000)
- Uncompressed size for high-compression sample: ${COMPRESS_MB} MB (hard cap: 100 MB)

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
12. The 7-Zip binary is detected as either \`7z\` or \`7zz\` (both exist across Kali versions).

## Suggested Kali packages

Optional packages that increase coverage:

    sudo apt update
    sudo apt install -y gcc gcc-mingw-w64-x86-64 zip 7zip file genisoimage gcab qpdf

Optional QR support:

    sudo apt install -y python3-qrcode python3-pil

## Manifest

See manifest.csv for every generated sample. Columns:

    id, category, path, sha256, size_bytes, expected, purpose

The \`expected\` value is a per-category heuristic (block / pass / policy-dependent)
meant as a starting point. Review and adjust it to match your organization's
attachment policy before scoring a run. \`sha256\`/\`size_bytes\` let you correlate
what the gateway actually delivered or stripped with the original sample.
EOF

# Basic validation report
log "Validating generated corpus"
{
  echo "Mail attachment corpus validation"
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  if have file; then
    find "$ROOT" -type f ! -name 'manifest.csv' ! -name 'README.md' -print0 | sort -z | xargs -0 file
  else
    echo "'file' command is not installed; MIME/magic validation skipped."
  fi
} > "$ROOT/file-identification.txt"

log "Done"
log "Corpus: $ROOT"
log "Manifest: $MANIFEST"
log "Limitations: $ROOT/README.md"
log "Magic/file report: $ROOT/file-identification.txt"
