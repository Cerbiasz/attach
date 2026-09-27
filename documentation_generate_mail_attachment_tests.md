# Dokumentacja `generate_mail_attachment_tests.sh`

Generator bezpiecznych próbek do testowania załączników pocztowych na Kali Linux. Tworzy zwykłe pliki testowe oraz standardowy ciąg EICAR; nie wysyła wiadomości i nie zawiera prawdziwego malware. Pliki `.eml` są przygotowanymi wiadomościami do inspekcji lub późniejszej wysyłki. Zawartość i nazwy plików należy oceniać na podstawie `manifest.csv`, ponieważ część próbek ma *celowo* niezgodne rozszerzenie lub nagłówki.

> **Zakres wyników opartych na EICAR.** EICAR sprawdza wyłącznie *instalację hydrauliczną* wykrywania i głębokość rozpakowywania. Wynik „zablokowano" dla zagnieżdżonej, zakodowanej czy przemianowanej próbki EICAR dowodzi, że unpacker bramy sięgnął danej warstwy i dopasował znaną sygnaturę — **nie** dowodzi wykrywania prawdziwego, nowego malware. Traktuj te wyniki jako test pokrycia i zachowania potoku (jak głęboko rozpakowuje, jak rozstrzyga niejednoznaczność MIME/nazwy, jak radzi sobie z anomaliami parsera), a nie jako test skuteczności silnika AV.

> **Schemat identyfikatorów.** Kolumna `id` w manifeście używa jednej z dwóch spójnych postaci: kody `Fnn` mapują na zewnętrzną taksonomię technik załączników (obejmuje też próbki tworzone ręcznie z sekcji 4), a identyfikatory `PREFIKS-NNN` (np. `BASE-003`, `SCRIPT-007`, `NAME-011`) oznaczają natywne przypadki generatora. Identyfikatory nie zawierają już nazw plików, więc nietypowe znaki Unicode w nazwie próbki nie psują manifestu.

## 1. Przygotowanie Kali Linux

Zainstaluj narzędzia używane do pełnego dostępnego zakresu generatora:

```bash
sudo apt update
sudo apt install -y \
  bash python3 coreutils findutils \
  gcc gcc-mingw-w64-x86-64 \
  zip unzip 7zip file \
  genisoimage gcab qpdf \
  python3-qrcode python3-pil
```

`bash`, `python3` i podstawowe narzędzia systemowe są potrzebne do uruchomienia. Reszta zwiększa zakres:

| Narzędzie | Próbki, które umożliwia |
|---|---|
| `gcc` | Nieszkodliwy ELF do testu polityki plików wykonywalnych. |
| `gcc-mingw-w64-x86-64` | Prawdziwe pliki PE: EXE, DLL i warianty PE o innych nazwach; kolejne przypadki ZIP/EML/MIME oparte na PE. |
| `zip` | Archiwa z hasłem i łańcuchy z szyfrowaną warstwą ZIP. |
| `7zip` (`7z`/`7zz`) | 7z, zaszyfrowane 7z i mieszany łańcuch 7z → ZIP. W aktualnym Kali pakietem jest `7zip`; skrypt wykrywa binarkę pod nazwą `7z` lub `7zz`. |
| `genisoimage` lub `mkisofs` | ISO9660 i identyczne bajty z rozszerzeniem `.img`. |
| `gcab` | Poprawne archiwum CAB. |
| `qpdf` | Szyfrowany PDF. |
| `python3-qrcode` + `python3-pil` | QR w PNG/PDF; Pillow także JPEG, obraz z hasłem oraz próbkę JPEG + ZIP. |
| `file` | Raport `file-identification.txt`. |

Pakiety opcjonalne nie są instalowane przez skrypt. Gdy brak danego programu, jego próbki są pomijane i **nie pojawiają się w manifeście**. Pełny `README.md` generowany w katalogu wynikowym zapisuje ograniczenia danego przebiegu.

## 2. Uruchomienie

```bash
chmod +x generate_mail_attachment_tests.sh
./generate_mail_attachment_tests.sh
```

Wynik domyślnie trafia do `mail-attachment-tests/`. Możesz podać inną ścieżkę jako pierwszy argument:

```bash
ARCHIVE_PASSWORD='HasloTestowe123!' \
NEST_DEPTH=15 MANY_FILES=1000 COMPRESS_MB=50 \
./generate_mail_attachment_tests.sh ./moje-probki-mailowe
```

| Ustawienie | Domyślnie | Maksimum wymuszone przez skrypt | Znaczenie |
|---|---:|---:|---|
| `ARCHIVE_PASSWORD` | `Test123` | brak osobnego limitu | Hasło ZIP/7z/PDF; trafia też do wygenerowanego `README.md` oraz testowych wiadomości z hasłem w temacie/treści. Użyj wyłącznie hasła testowego. |
| `NEST_DEPTH` | `10` | `20` | Liczba kolejnych archiwów `level-NN.zip`. |
| `MANY_FILES` | `250` | `2000` | Liczba plików TXT w archiwum testującym limit wpisów. |
| `COMPRESS_MB` | `20` | `100` | Rozmiar rozpakowanych zer w teście kompresji oraz wielkość samodzielnego `.bin`. |
| `FRESH` | `0` | — | `FRESH=1` czyści istniejący katalog wynikowy przed przebiegiem. |

Skrypt **odmawia** zapisu do niepustego katalogu wynikowego, aby stare próbki z poprzedniego uruchomienia nie mieszały się z nowym manifestem. Aby powtórzyć przebieg w tym samym miejscu, uruchom z `FRESH=1` (czyści katalog), albo podaj nową ścieżkę jako pierwszy argument.

### Pliki w katalogu głównym wyniku

| Plik | Znaczenie |
|---|---|
| `manifest.csv` | Faktycznie wygenerowane przypadki. Kolumny: `id,category,path,sha256,size_bytes,expected,purpose`. `sha256`/`size_bytes` pozwalają zestawić to, co brama faktycznie dostarczyła lub okroiła, z próbką wejściową. `expected` (block / pass / policy-dependent) to **heurystyka per-kategoria** i punkt wyjścia — przejrzyj i dostosuj do polityki organizacji przed punktowaniem przebiegu. To podstawowe źródło listy próbek. |
| `README.md` | Parametry przebiegu, hasło testowe, ograniczenia i pakiety. |
| `file-identification.txt` | Wynik `file` dla próbek, pomocny przy zestawieniu rozszerzenia z rzeczywistą zawartością. |

## 3. Co znajduje się w każdym katalogu

Poniższe ścieżki są względem katalogu wyniku. **[O]** oznacza wariant opcjonalny; bez wskazanego narzędzia nie zostanie utworzony. W pozostałych przypadkach skrypt tworzy plik standardowo.

### `00-baseline/` — pliki kontrolne

`test.txt`, `test.csv`, `test.html`, `test.svg`, `test.png` — zwykłe, nieszkodliwe załączniki. Najpierw sprawdź, czy polityka pozwala je dostarczyć; w przeciwnym razie późniejsze wyniki mogą być mylące. Obraz PNG ma rozmiar 1 × 1.

### `01-antivirus/` — rozpoznanie EICAR

`eicar.com` — standardowy 68-bajtowy ciąg testowy bez końcowego znaku nowej linii. `eicar.txt`, `invoice.pdf`, `image.jpg` zawierają **te same bajty EICAR**. Dwa ostatnie pliki nie są prawdziwym PDF ani JPEG: badają rozpoznawanie treści mimo mylącego rozszerzenia. Lokalne AV/EDR może usunąć pliki już podczas generowania.

### `02-executable/` — pliki wykonywalne

`benign.c` — źródło programu wypisującego znacznik testowy; `benign-linux-elf` **[O: `gcc`]**. `benign.exe`, `invoice.pdf`, `image.jpg`, `invoice.pdf.exe`, `INVOICE.EXE`, `benign.scr`, `no-extension` **[O: MinGW]** zawierają rzeczywisty, nieszkodliwy Windows PE. `benign-dll.c`, `benign.dll`, `benign.cpl` **[O: MinGW]**: DLL eksportuje funkcję zwracającą zero; `.cpl` ma bajty DLL i sprawdza rozszerzenie/typ PE, ale **nie jest działającym apletem Panelu sterowania**.

### `03-scripts/` — skrypty i zapytanie sieciowe

`test.ps1`, `test.bat`, `test.cmd`, `test.js`, `test.vbs`, `test.hta`, `test.sh`, `test.py`, `test.wsf` — prosta, nieszkodliwa treść lub wypisanie znacznika. `test.iqy` zawiera adres w zarezerwowanej domenie `example.invalid`. Skrypt **nie** tworzy zakodowanych JSE/VBE; zmiana samego rozszerzenia dawałaby fałszywy test.

### `04-shortcuts/` — skróty

`test.url` — Internet Shortcut do `example.invalid`; `benign.scf` — polecenie „Pokaż pulpit”; `benign-notepad.lnk` — binarny Windows Shell Link do lokalnego Notatnika bez argumentów. Działanie LNK w kliencie pocztowym sprawdzaj na testowym Windows.

### `05-office/` — dokumenty i kontener OOXML

| Podkatalog / plik | Co rzeczywiście zawiera |
|---|---|
| `plain/test.docx` | Minimalny poprawny DOCX z tekstem. |
| `plain/test.rtf` | Poprawny, prosty RTF. |
| `container-tests/docx-container-with-eicar.docx` | EICAR zapisany w OOXML jako **niepowiązany** plik `word/embeddings/eicar.txt`. |
| `container-tests/docx-container-with-zip.docx` | ZIP z EICAR zapisany jako **niepowiązany** `word/embeddings/archive.zip`. |
| `container-tests/docx-with-external-link.docx` | Prawdziwa relacja hiperłącza do `example.invalid`; nie jest to obiekt pobierany automatycznie. |
| `container-tests/pdf-named-docx.docx` | Rzeczywisty PDF pod nazwą `.docx`; wyłącznie test rozpoznania formatu. |
| `extension-only/test.docm`, `test.xlsm`, `test.pptm` | **Bajty DOCX** z innym rozszerzeniem; wyłącznie test polityki nazwy, bez VBA i bez prawidłowej struktury XLSM/PPTM. |

Żadnego z plików `container-tests` nie traktuj jako testu prawdziwego klikalnego obiektu OLE osadzonego przez Worda.

### `06-archives/` — archiwa

`eicar.zip`, `eicar.tar`, `eicar.tar.gz`, `eicar.com.gz`, `eicar.7z` **[O: 7z]**, `eicar.cab` **[O: gcab]**, `eicar.iso` i `eicar.img` **[O: genisoimage/mkisofs]**. Plik `.img` ma identyczną zawartość ISO9660, nie osobny format surowego obrazu dysku.

`benign.jar` to poprawny kontener JAR z manifestem i plikiem TXT, **bez uruchamialnej klasy Java**. `deep-tree.zip` ma EICAR w 24 zagnieżdżonych katalogach. `pdf-and-eicar.zip` zawiera oddzielnie PDF i EICAR. `script-test.ps1.zip`, `script-test.js.zip`, `script-test.vbs.zip` zawierają skrypty z `03-scripts/`. `zip-with-lnk.zip` **[O: `zip`]** zawiera skrót LNK. `benign-pe.zip` **[O: MinGW]** zawiera rzeczywisty benign PE.

### `07-encrypted/` — pliki chronione hasłem

`eicar-password.zip` **[O: `zip`]**, `eicar-password.7z` **[O: 7z]**, `pdf-password.pdf` **[O: `qpdf`]**, `password-in-image.png` **[O: `zip` i Pillow]**. Obraz pokazuje hasło jako tekst i należy go zestawić z zaszyfrowanym archiwum. Hasło konkretnego przebiegu jest zapisane w `README.md`.

### `08-nested/` — łańcuchy formatów

`level-01.zip` … `level-NN.zip` — każdy kolejny ZIP zawiera poprzedni; na końcu jest EICAR. `zip-zip-benign-pe.zip` **[O: MinGW]** kończy się benign PE. `eml-benign-pe.eml` **[O: MinGW]** zawiera ten PE jako załącznik.

`eml-zip-eicar.eml` (EML → ZIP → EICAR), `zip-eml-eicar.zip` (ZIP → EML → EICAR), `zip-eml-zip-eicar.zip` (ZIP → EML → ZIP → EICAR). `zip-in-7z.7z` **[O: 7z]** daje 7z → ZIP → EICAR i **nie zawiera warstwy RAR**.

`encrypted-outer.zip` **[O: `zip`, co najmniej 2 poziomy]** to zaszyfrowany ZIP → zwykły ZIP → EICAR; `encrypted-in-encrypted.zip` **[O: `zip`]** to zaszyfrowany ZIP → zaszyfrowany ZIP → EICAR. `encrypted-zip-with-lnk.zip` i `eml-zip-lnk.eml` **[O: `zip`]** zawierają odpowiednio zaszyfrowany ZIP → LNK i EML → ZIP → LNK.

### `09-web/` — HTML i SVG

`link.html`, `redirect.html`, `blob-download.html`, `base64-blob.html`; `link.svg`, `script.svg`, `base64-link.svg`, `external-resource.svg`, `foreign-object.svg`, `js-navigation.svg`, `link-to-html.svg`, `encoded-text-js.svg`.

Pliki sprawdzają link, przekierowanie HTML, utworzenie **wyłącznie pliku TXT** przez Blob, Base64, JavaScript w SVG, zasób zewnętrzny oraz HTML wewnątrz SVG. Adresy sieciowe są w zarezerwowanej domenie `example.invalid`; nie oczekuj potwierdzenia połączenia zwrotnego. `js-navigation.svg` wymaga kliknięcia, nie przekierowuje samoistnie.

### `10-pdf/` — cechy PDF i kod QR

`pdf-with-url.pdf` — adnotacja URI; `acroform.pdf` — pole tekstowe formularza; `embedded-benign.txt.pdf` — poprawna struktura EmbeddedFiles z TXT; `embedded-eicar.zip.pdf` — poprawna struktura EmbeddedFiles z ZIP zawierającym EICAR. `qr-benign.png`, `pdf-with-qr.pdf` **[O: qrcode i Pillow]**; `qr-benign.jpg` **[O: dodatkowo Pillow]**.

### `11-mime/` — kompletne wiadomości `.eml`

| Próbki | Sprawdzany wariant |
|---|---|
| `svg-as-text-plain.eml`, `eicar-as-pdf.eml`, `pe-as-jpeg.eml` **[O: MinGW]**, `pe-as-pdf.eml` **[O: MinGW]**, `pe-as-octet-stream.eml` **[O: MinGW]** | Rozbieżność deklarowanego MIME, nazwy i rzeczywistych bajtów. |
| `duplicate-filename.eml`, `eicar-no-filename.eml`, `different-name-and-filename.eml`, `combined-filename-mime.eml` **[O: MinGW]** | Duplikat nazwy, brak nazwy, konflikt `name=`/`filename=` i połączone cechy nazwy/MIME. |
| `filename-rfc2047.eml`, `filename-rfc2231.eml` | Dwa sposoby kodowania nazwy; wariant RFC 2047 w parametrze jest **celowo niestandardowy**. |
| `folded-base64.eml`, `nonstandard-base64-whitespace.eml`, `quoted-printable.eml` | Kodowanie treści; drugi przypadek jest celową anomalią parsera. |
| `nested-multipart.eml`, `duplicate-content-type.eml`, `outer-with-attached-eml.eml` | Zagnieżdżenie `multipart`, sprzeczne nagłówki części, załączona wiadomość `message/rfc822`. |
| `password-in-subject.eml`, `password-in-body.eml` **[O: `zip`]** | Zaszyfrowany ZIP oraz hasło odpowiednio w temacie lub treści. |

Wysyłka surowego `.eml` jako załącznika bada również obsługę załączonych wiadomości; wczytanie jego bajtów jako *całej wysyłanej wiadomości* bada pokazane w nim nagłówki MIME. To dwa różne testy.

### `12-filename/` — interpretacja nazwy

`invoice.pdf.exe`, `invoice.pdf........exe`, `INVOICE.EXE`, `Invoice.ExE`, `invoice .exe`, `invoice...exe`, nazwa z 180 znakami `A` i `.exe`, `invoice．exe` (pełnoszeroka kropka), `invoice․exe` (one dot leader), `invoice‐2026.pdf` (nietypowy łącznik), `ending-dot.exe.`, `ending-space.exe `, `right-to-left-override-…` (znak U+202E). Pierwsze próbki mają zwykły tekst w środku. `faktura.pdf.docx.exe` oraz `long-…exe` **[O: MinGW]** mają rzeczywiste bajty PE. Nazwy kończące się spacją lub kropką mogą zostać zmienione przez Windows/Outlook.

### `13-parser/` — różnice między parserami

`zip-with-trailing-junk.zip`, `truncated-eicar.zip`, `zip-local-central-name-disagreement.zip` — odpowiednio dane po ZIP, obcięte archiwum i **celowo sprzeczne** nazwy w nagłówku lokalnym/centralnym ZIP. `duplicate-zip-entry.zip`, `case-differing-zip-entry.zip`, `unicode-zip-entry.zip` — zduplikowane, różniące się wielkością liter i Unicode nazwy wpisów.

`png-plus-zip.png`, `png-plus-zip.zip`, `pdf-plus-zip.pdf`, `gif-plus-zip.gif`, `jpeg-plus-zip.jpg` **[O: Pillow]** — konkatenacja formatu obrazu/PDF z ZIP zawierającym EICAR; wykrycie ZIP zależy od parsera. `one-pixel.gif` jest pomocniczym benign obrazem. Nie zakładaj, że konkatenacje są poprawnym poliglotem we wszystkich programach.

### `14-resource-limits/` — ograniczone testy limitów

`many-files-N.zip` — domyślnie 250 niewielkich TXT; `high-compression-NMB.zip` — mocno skompresowane zera; `standalone-NMB.bin` — samodzielny plik o zadanym rozmiarze. Skrypt nie tworzy bomby dekompresyjnej; obowiązują limity opisane w sekcji 2.

## 4. Czego generator nie tworzy i jak przygotować próbki ręcznie

Przechowuj własne przypadki poza katalogiem automatycznym, np. `manual/`, a ich identyfikator i prawdziwy format dopisz do **osobnego** rejestru testów. Kopiowanie pliku pod nową nazwą nie zastępuje wygenerowania właściwego formatu.

### A. Makra Office, XLAM, XLSB i dawne formaty — F15–F21, F76, F135

1. Na testowym komputerze z **desktopowym Microsoft Office** otwórz Word, Excel lub PowerPoint. W edytorze VBA (`Alt+F11`) dodaj nieszkodliwą procedurę, np. `Sub MailGatewayTest(): MsgBox "MAIL-GATEWAY-BENIGN-TEST": End Sub`.
2. Zapisz odpowiednio jako **Word Macro-Enabled Document (`.docm`)**, **Excel Macro-Enabled Workbook (`.xlsm`)** lub **PowerPoint Macro-Enabled Presentation (`.pptm`)**. Weryfikacja: plik otwiera się w swojej aplikacji i rzeczywiście zawiera projekt VBA. Samo przemianowanie DOCX nie wystarczy.
3. W Excelu użyj „Zapisz jako”, aby osobno utworzyć `.xlsb` oraz dodatek **Excel Add-In (`.xlam`)** z nieszkodliwą makroprocedurą. W Wordzie/Excelu zapisz osobne dokumenty w starszych formatach `.doc`/`.xls`.
4. W celu sprawdzenia szyfrowania utwórz oddzielny DOCX/XLSX i w aplikacji wybierz **Plik → Informacje → Chroń → Szyfruj hasłem**. Potwierdź, że otwarcie wymaga hasła. Dla F135 zapakuj **prawdziwy** DOCM w ZIP: `zip -j manual/zip-docm.zip manual/test.docm`.

Formaty makr `.docm/.xlsm/.pptm` i dodatek `.xlam` są opisane przez Microsoft; hasło zapisywane w dokumencie to odrębny przypadek od hasła do ZIP. [Formaty Office](https://support.microsoft.com/en-us/office/vba/open-xml-formats-and-file-name-extensions), [dodatek XLAM](https://support.microsoft.com/en-US/Excel/create-custom-functions-in-excel), [szyfrowanie Word](https://support.microsoft.com/en-us/office/protect-a-word-document-with-a-password-05084cc3-300d-4c1a-8416-38d3e37d6826).

**XLL (F19):** to dodatek natywny, nie zwykła DLL podmieniona nazwą. Zbuduj minimalny, nieszkodliwy projekt na podstawie [Excel XLL SDK](https://learn.microsoft.com/en-us/office/client-developer/excel/getting-started-with-the-excel-xll-sdk), a następnie sprawdź ładowanie w testowym Excelu. Nie używaj kodu uruchamiającego procesy lub sieć.

### B. Faktyczne obiekty osadzone w Office — F23–F24, F126

W Wordzie wybierz **Wstaw → Obiekt → Utwórz z pliku**, wskaż zwykły `test.txt` i pozostaw opcję łączenia z plikiem wyłączoną. Zapisz DOCX i sprawdź, że obiekt jest widoczny oraz otwiera się z dokumentu. Dopiero w odrębnym przebiegu użyj próbki EICAR lub benign EXE, jeżeli aplikacja i lokalne AV pozwalają ją osadzić. Dla F126 przygotuj wiele **rzeczywistych** obiektów w kontrolowanym zakresie — generatorowe wpisy `word/embeddings/` nie są ekwiwalentem OLE. [Instrukcja Microsoft](https://support.microsoft.com/en-us/word/insert-an-object-in-word-or-outlook).

### C. Outlook MSG i OneNote — F27, F103–F104, F107, F128, F134

W klasycznym Outlooku na testowym Windows utwórz wiadomość z załącznikiem `test.txt`, PDF albo EICAR, następnie użyj **Plik → Zapisz jako → Outlook Message Format (`.msg`)**. Dla MSG → MSG dołącz zapisany `.msg` do drugiej wiadomości i zapisz ją jako MSG. Wariant MSG → PDF → ZIP wymaga prawdziwego `10-pdf/embedded-eicar.zip.pdf`. Sprawdź, czy Outlook pokazuje wszystkie poziomy załączników. [Zapisywanie wiadomości Outlook](https://support.microsoft.com/en-us/outlook/mail/save-an-outlook-message-as-a-eml-file-a-pdf-file-or-as-a-draft).

W desktopowym OneNote na Windows utwórz stronę, użyj **Wstaw → Załącznik pliku** i dołącz benign TXT lub skrypt testowy, następnie wyeksportuj odpowiednią sekcję w natywnym formacie OneNote dostępnym w danej wersji. Zweryfikuj ponownym otwarciem oraz widocznością załącznika; eksport do PDF nie bada formatu OneNote. [Załączniki w OneNote](https://support.microsoft.com/pl-pl/onenote/onenote-help-and-learning/insert-or-attach-files-to-notes).

### D. RAR, CHM i MSI/MSP — F09, F12, F57, F68, F73

* **RAR:** użyj narzędzia RAR/WinRAR od producenta. Na Kali można pobrać jego wariant CLI dla Linux x64, zgodnie z dostępną licencją. Utwórz osobno RAR z `01-antivirus/eicar.com`, RAR chroniony hasłem i łańcuch ZIP → 7z → RAR → EICAR; po utworzeniu użyj funkcji testowania archiwum i sprawdź zawartość. Sam `7z` w Kali nie tworzy RAR. [RARLAB — wersja dla Linux](https://www.rarlab.com/download.htm).
* **CHM:** w Windows HTML Help Workshop przygotuj stronę HTML ze znacznikiem testowym, dodaj ją do projektu `.hhp`, skompiluj do `.chm` i otwórz wynik w testowym czytniku. [Kompilowanie projektu HTML Help](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/compile-a-help-project).
* **MSI/MSP:** zbuduj minimalny MSI instalujący tylko nieszkodliwy TXT, korzystając z WiX Toolset i jego samouczka. MSP wymaga osobnego projektu aktualizacyjnego i bazowego MSI; nie uznawaj MSI przemianowanego na `.msp` za poprawną próbkę. Potwierdź identyfikację formatu narzędziem Windows Installer na testowej maszynie. [WiX Toolset](https://wixtoolset.org/documentation/tutorial).

### E. JSE/VBE, PIF i wiarygodna ikona skrótu — F02, F06–F07, F40

`test.js` i `test.vbs` są dostępne w `03-scripts/`, ale **nie są zakodowanymi** `.jse`/`.vbe`. Takie pliki przygotuj tylko za pomocą sprawdzonego kodera zgodnego z Windows Script Host i przetestuj dekodowanie/wykonanie nieszkodliwego `WScript.Echo` na izolowanym Windows. Jeśli brak zgodnego kodera, oznacz przypadek jako niewykonany. Analogicznie `.pif` przygotuj z rzeczywistego środowiska obsługującego ten stary format; nie zmieniaj nazwy LNK na PIF. Dla F40 ustaw ikonę PDF w **oddzielnym** testowym LNK wskazującym wyłącznie Notatnik i sprawdź, jak ikonę oraz pełną nazwę przedstawia klient pocztowy Windows.

### F. Funkcjonalne CPL/JAR i odrębny obraz IMG — F13–F14, F64

`02-executable/benign.cpl` bada typ PE oraz rozszerzenie, ale nie obsługuje interfejsu apletu. Jeżeli potrzebny jest **działający** CPL, zbuduj w testowym projekcie Windows SDK DLL z eksportowaną funkcją `CPlApplet`, która obsługuje podstawowe komunikaty Panelu sterowania bez działań ubocznych. Potwierdź format PE oraz zachowanie w odizolowanym Windows. `benign.jar` ma prawidłową strukturę archiwum, lecz nie zawiera klasy; aby sprawdzić wykonywalny JAR, skompiluj minimalną klasę Java wypisującą znacznik, dodaj `Main-Class` do manifestu i zweryfikuj uruchomienie na testowym JRE.

`06-archives/eicar.img` zawiera ISO9660 pod inną nazwą. Jeżeli F64 ma oznaczać **odrębny obraz surowego dysku**, przygotuj osobny niewielki obraz FAT na Kali (`dosfstools` i `mtools`), dodaj do niego benign TXT lub EICAR i sprawdź odczyt katalogu w narzędziu rozumiejącym FAT. Tego obrazu nie zastępuje zmiana rozszerzenia ISO.

### G. Duże dokumenty i pozostałe różnice parserów — F121, F124–F125, część F37/F50/F97/F136

Przy testach powyżej limitów generatora utwórz osobny, uzgodniony zestaw z większą liczbą plików lub większymi **poprawnymi** dokumentami PDF/Office; stopniuj rozmiary i weryfikuj otwieranie w docelowej aplikacji. F37 wymaga macierzy Unicode dopasowanej do badanego klienta, F50 dodatkowych układów `multipart`, F97 rzeczywistego wariantu przekierowania SVG zgodnego z wybranym klientem, a F136 poliglotu zweryfikowanego w **obu** parserach. Generator daje dla tych tematów przykłady lub przybliżenia, nie pełne pokrycie.

## 5. Szybka kontrola wyników

```bash
file mail-attachment-tests/04-shortcuts/benign-notepad.lnk
file mail-attachment-tests/05-office/container-tests/pdf-named-docx.docx
unzip -l mail-attachment-tests/05-office/container-tests/docx-container-with-zip.docx
qpdf --check mail-attachment-tests/10-pdf/embedded-eicar.zip.pdf
wc -c mail-attachment-tests/01-antivirus/eicar.com
head -n 5 mail-attachment-tests/manifest.csv
```

Osadzony ZIP z `embedded-eicar.zip.pdf` jest załącznikiem w strukturze PDF, a nie ZIP-em doklejonym do końca pliku. Odczytaj go parserem PDF obsługującym EmbeddedFiles. `wc -c` dla EICAR powinno zwrócić `68`; `file` dla `pdf-named-docx.docx` powinno wskazać PDF.

Nie uznawaj samego „wiadomość dotarła” za pozytywny lub negatywny wynik wszystkich warstw. Zapisuj osobno: etap SMTP, zachowanie SEG, skanera AV, sandboxa i klienta pocztowego oraz to, co użytkownik faktycznie otrzymał.

## 6. Luki metodyczne i braki pokrycia — jak domknąć samodzielnie

Ten generator to **bezpieczny baseline**. Zanim uznasz ocenę za kompletną, zrozum, co on faktycznie mierzy, i uzupełnij poniższe braki. Wszystko poniżej da się przygotować z treścią **nieszkodliwą** (EICAR, benign marker, oficjalne ciągi testowe).

### 6.0. Co ten korpus mierzy (i czego nie)

- EICAR jest wykrywany **wyłącznie sygnaturowo**. Cały zestaw testuje **zasięg potoku**: czy skaner rozpakuje do danej warstwy, znormalizuje nazwę, sparsuje MIME — **nie** skuteczność silnika, heurystyki, ML ani sandboxa.
- EICAR jest **inertny**, więc **nie uruchomi detonacji w sandboxie**. Nie wpisuj „sandbox” do zakresu wyników opartych wyłącznie na EICAR.
- Wynik „block” to nie to samo co „neutralizacja” — patrz 6.4 (CDR).

Pierwsze zdanie raportu powinno brzmieć: *„Testowaliśmy zasięg i logikę potoku bezpiecznym korpusem, nie skuteczność detekcji ani sandbox”.*

### 6.1. Werdykt per-próbka + harness korelacji po `sha256` (priorytet 1)

Kolumna `expected` w manifeście jest **heurystyką per-kategoria**, nie prawdą per-próbka.

1. Dodaj własny plik `expected_override.csv` (`id,expected`) i nadpisz nim wartości dla konkretnych próbek zgodnie z Twoją polityką.
2. Zbuduj prosty harness dostarczania: **jedna próbka = jedna wiadomość**, wysyłka na dedykowaną skrzynkę testową. W temacie umieść **`path`** próbki (a nie `id`) — kilka ID nie jest unikalnych (np. `F38/39`, `F29/35` mapują na >1 plik), więc `path`/`sha256` to jedyny jednoznaczny klucz korelacji.
3. Po stronie odbioru policz `sha256` każdego dostarczonego załącznika i zestaw z manifestem po `path`/`sha256`. Klasyfikuj wynik jako jeden z: `delivered-unchanged` (hash zgodny), `delivered-modified` (hash inny → prawdopodobne CDR), `stripped` (załącznik usunięty, wiadomość dostarczona), `blocked-at-smtp`, `quarantined`.

Bez tego kroku nie udowodnisz, **co** brama zrobiła — a to jest sedno profesjonalnej oceny.

### 6.2. Łańcuchy „post-makro”: ISO/IMG/VHD → LNK → skrypt oraz obejście MOTW (priorytet 1)

Generator daje ISO i LNK **osobno**. Realny wektor to złożony łańcuch i obejście Mark-of-the-Web:

- **ISO z LNK + skryptem (Kali):**
  ```bash
  mkdir chain && cp mail-attachment-tests/04-shortcuts/benign-notepad.lnk chain/
  cp mail-attachment-tests/03-scripts/test.ps1 chain/
  genisoimage -quiet -o manual/chain-iso-lnk.iso -J -r chain
  ```
- **VHD/VHDX (na testowym Windows, PowerShell):**
  ```powershell
  New-VHD -Path C:\test\benign.vhdx -SizeBytes 16MB -Fixed
  Mount-VHD C:\test\benign.vhdx ; # sformatuj, skopiuj benign TXT/LNK ; Dismount-VHD
  ```
- **Co dowodzisz:** czy brama zagląda do ISO/IMG/VHD (rozpakowanie) oraz — na **endpoincie** — czy pliki wypakowane/zamontowane z tych kontenerów dostają `Zone.Identifier` (MOTW). Historycznie ZIP propaguje MOTW, ISO/IMG/VHD nie. To rozdziel: rozpakowanie = test bramy, propagacja MOTW = test klienta/endpointa.

### 6.3. OneNote, prawdziwe makra VBA, XLL, MSG, RAR, CHM, MSI

To najważniejsze realne wektory, a generator ich nie tworzy. Instrukcje krok po kroku są już w **sekcji 4** (A–G). Traktuj sekcję 4 jako obowiązkową część „kompletnej” oceny, nie dodatek. Priorytetowo: prawdziwe makro `.docm/.xlsm` (4A), OneNote `.one` (4C), RAR i łańcuch z RAR (4D).

### 6.4. Weryfikacja neutralizacji (CDR) — nie tylko blokada (priorytet 2)

Nowoczesne bramy nie blokują, tylko **rozbrajają i dostarczają** (Content Disarm & Reconstruction). Dla bram z CDR właściwe pytanie to „czy aktywny element zniknął?”. Dla każdej benign-active próbki pobierz **dostarczony** plik i sprawdź:

```bash
# makro w Office?
unzip -l delivered.docm | grep -i vbaProject.bin
# JavaScript / akcje w PDF?
grep -aE '/JavaScript|/OpenAction|/AA|/Launch|/EmbeddedFile' delivered.pdf
# skrypt / zdarzenia w SVG?
grep -aiE '<script|onload=|onclick=' delivered.svg
```

Zapisz `delivered-neutralized` jako **osobny** wynik od `delivered-unchanged` i od `blocked`.

### 6.5. DLP-kanarki (jeśli DLP jest w zakresie)

W README zakres wspomina DLP, ale żadna próbka go nie pokrywa. Analogiem EICAR dla DLP są **testowe** wzorce, które Twój DLP ma łapać — nigdy prawdziwe dane osobowe:

- Testowy numer karty (Luhn-poprawny, przeznaczony do testów): `4111 1111 1111 1111`.
- Testowe wzorce oznaczone jawnie jako `TEST-DLP-CANARY`, w formacie zgodnym z regułą DLP (np. atrapa IBAN/SSN w formacie, ale bez realnej osoby).

Umieść je w TXT/DOCX/PDF/XLSX i sprawdź, czy DLP je oznacza. Jeśli nie testujesz DLP — usuń „DLP” z zakresu w README, żeby nie obiecywać pokrycia bez próbek.

### 6.6. Treść szyfrowana end-to-end (S/MIME, PGP)

Zaszyfruj benign TXT **kluczem testowym** i wyślij jako S/MIME lub PGP. Cel: udowodnić świadomy blind spot — brama zwykle **nie przeskanuje** zaszyfrowanej treści. Wynik informuje politykę: albo wymuszona deszyfracja na bramie, albo blokada/kwarantanna wiadomości szyfrowanych spoza zaufanych nadawców.

### 6.7. Rules of Engagement (higiena zaangażowania)

- **Powiadom SOC / blue team przed wysyłką** — inaczej wygenerujesz prawdziwy incydent.
- Autoryzacja **na piśmie**, dedykowane skrzynki testowe, wyznaczone okno czasowe.
- Zapisuj wynik **per warstwa**: SMTP → SEG → AV → sandbox → CDR → klient — i co użytkownik faktycznie dostał.

---

## 7. Pełny katalog wygenerowanych plików

Ścieżki względem katalogu wyniku. Kolumna „Jak utworzony” podaje mechanizm; **[O: narzędzie]** = wariant opcjonalny (bez narzędzia plik nie powstaje i nie ma go w manifeście). „Oczekiwane” to heurystyka z kolumny `expected` manifestu (w tabelach skrócona: `policy` = `policy-dependent`). Łącznie **122 wiersze manifestu / 120 unikalnych ID** przy domyślnym zestawie narzędzi (na środowisku z pełnym zestawem liczba rośnie o próbki opcjonalne poniżej). Dwa ID nie są unikalne, bo mapują na zewnętrzną taksonomię technik: `F38/39` odpowiada 3 plikom (`12-filename/`), a `F29/35` — 2 plikom (gdy jest MinGW). Dlatego jednoznacznym kluczem próbki jest `path` (lub `sha256`), nie `id`.

**Legenda dwóch kolumn oceny (do raportu):**

- **Rola** — `Główny` = próbka reprezentuje wektor zagrożenia (surogat złośliwej treści); `Baza` = kontrola/benchmark (nieszkodliwa, ma przejść — kalibruje fałszywe pozytywy). Dla wierszy `Baza` niepokojące jest **zablokowanie** (nadmierne filtrowanie), nie przejście.
- **Jeśli przejdzie → ryzyko** — jak zinterpretować w raporcie fakt, że próbka **została dostarczona** do skrzynki: jaki atak to umożliwia i jaka waga (Krytyczne / Wysokie / Średnie / Niskie). Ocena zakłada, że „przejście” realnej próbki oznacza, iż analogiczna **złośliwa** treść w tym samym opakowaniu też przejdzie. Wagę dostrój do profilu odbiorców (np. ELF istotny dla serwerów Linux, PE dla stacji Windows).

### `00-baseline/` — pliki kontrolne (dowodzą: benign przechodzi ordynarne kontrole)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `test.txt`, `test.csv`, `test.html`, `test.svg` | BASE-001..004 | Baza | pass | `printf`/here-doc z markerem | Oczekiwane. Zablokowanie = nadmierne filtrowanie (FP) → utrata legalnej poczty |
| `test.png` | BASE-005 | Baza | pass | dekodowany z literału base64 (PNG 1×1) | Oczekiwane. Zablokowanie = FP na zwykłym obrazie |

### `01-antivirus/` — rozpoznanie EICAR (dowodzą: dopasowanie sygnatury niezależnie od rozszerzenia)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `eicar.com` | AV-001 | Główny | block | `printf` 68-bajtowego ciągu EICAR | **Krytyczne** — bazowa detekcja sygnaturowa nie działa; dowolny znany malware przejdzie |
| `eicar.txt`, `invoice.pdf`, `image.jpg` | AV-002..004 | Główny | block | `cp` tych samych bajtów EICAR pod mylącą nazwą | **Wysokie** — brak inspekcji treści wg zawartości; znany malware pod zmienioną nazwą przejdzie |

### `02-executable/` — pliki wykonywalne (dowodzą: polityka typu/rozszerzenia i detekcja PE)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `benign.c` | EXE-SRC | Baza | policy | źródło C wypisujące marker | Niskie — źródło tekstowe; przejście zwykle akceptowalne |
| `benign-linux-elf` | EXE-001 | Główny | policy | `gcc` **[O: gcc]** | Średnie — natywny ELF; istotne gdy odbiorcy to Linux/serwery |
| `benign.exe` | EXE-002 | Główny | policy | `x86_64-w64-mingw32-gcc` **[O: MinGW]** | **Wysokie** — natywny PE; wykonanie kodu po uruchomieniu przez użytkownika |
| `invoice.pdf`, `image.jpg` | EXE-003/004 | Główny | policy | `cp` bajtów PE pod mylącą nazwą **[O: MinGW]** | **Wysokie** — PE udający dokument/obraz (masquerade); użytkownik oszukany |
| `invoice.pdf.exe`, `INVOICE.EXE` | EXE-005/006 | Główny | policy | `cp` PE, podwójne/wielkie rozszerzenie **[O: MinGW]** | **Wysokie** — double-extension/wielkość liter; klasyczny dropper |
| `benign.scr`, `no-extension` | F02, F33 | Główny | policy | `cp` PE, rozszerzenie SCR / brak **[O: MinGW]** | **Wysokie** — alternatywne/brak rozszerzenia wykonywalnego omija filtr po nazwie |
| `benign.dll` | F03 | Główny | policy | `mingw -shared`, eksport funkcji **[O: MinGW]** | Średnie — DLL wymaga nośnika uruchamiającego (rundll32 / DLL sideloading) |
| `benign.cpl` | F14-CPL | Główny | policy | `cp` bajtów DLL jako `.cpl` (nie działający applet) **[O: MinGW]** | **Wysokie** — `.cpl` uruchamiane dwuklikiem przez `control.exe` |

### `03-scripts/` — skrypty i zapytanie sieciowe (dowodzą: polityka aktywnej treści)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `test.ps1/.bat/.cmd/.js/.vbs/.hta/.sh/.py/.wsf` | SCRIPT-001..009 | Główny | policy | here-doc z markerem (`.cmd` = `cp .bat`) | **Wysokie** dla WSH/HTA/PS (`.js/.vbs/.hta/.wsf/.ps1` — klasyczne droppery); Niższe dla `.sh/.py` na Windows |
| `test.iqy` | SCRIPT-010 | Główny | policy | `printf` zapytania Web Query do `example.invalid` | Średnie — Excel Web Query pobiera zdalne dane/formuły |

### `04-shortcuts/` — skróty (dowodzą: obsługa formatów skrótów przez klienta)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `test.url` | SHORT-001 | Główny | policy | here-doc INI, URL do `example.invalid` | Średnie — Internet Shortcut → phishing / uruchomienie handlera URL |
| `benign.scf` | F14-SCF | Główny | policy | here-doc Shell Command File („Pokaż pulpit”) | Średnie — SCF może wywołać żądanie SMB → wyciek NetNTLM |
| `benign-notepad.lnk` | F10 | Główny | policy | binarny MS-SHLLINK złożony w Pythonie (`struct`), cel = lokalny Notatnik, bez argumentów | **Wysokie** — LNK to główny wektor droppera po blokadzie makr (2022+) |

### `05-office/` — dokumenty i kontenery OOXML (dowodzą: rekurencyjna inspekcja kontenera, rozpoznanie formatu, polityka nazwy)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `plain/test.docx` | OFF-001 | Baza | policy | Python `zipfile` buduje minimalny OOXML | Oczekiwane. Zablokowanie zwykłego DOCX = nadmierne filtrowanie |
| `plain/test.rtf` | F22 | Baza | policy | zapis minimalnego RTF | Oczekiwane (ten RTF jest pusty). Uwaga: RTF bywa nośnikiem exploitów — realny wariant zrób osobno |
| `container-tests/docx-container-with-eicar.docx` | OFF-002 | Główny | policy | OOXML z **niepowiązanym** `word/embeddings/eicar.txt` | **Wysokie** — brak rekurencyjnej inspekcji OOXML; makro/obiekt w Office przejdzie |
| `container-tests/docx-container-with-zip.docx` | F106 | Główny | policy | OOXML z niepowiązanym `word/embeddings/archive.zip` (ZIP+EICAR) | **Wysokie** — zagnieżdżony kontener w Office nieinspekcjonowany |
| `container-tests/docx-with-external-link.docx` | F25 | Główny | policy | DOCX z relacją hiperłącza do `example.invalid` | Średnie — zdalne pobranie / template injection / phishing z dokumentu |
| `container-tests/pdf-named-docx.docx` | F32 | Główny | policy | `cp` bajtów PDF pod nazwą `.docx` | Średnie — rozpoznanie typu po nazwie zamiast treści; obejście reguł typu |
| `extension-only/test.docm/.xlsm/.pptm` | OFF-EXT-001..003 | Główny | policy | `cp` DOCX pod rozszerzeniem makro (bez VBA) | **Wysokie** — polityka nie blokuje rozszerzeń makro (zweryfikuj prawdziwym makrem, sekcja 4A) |

### `06-archives/` — archiwa (dowodzą: rozpakowanie i inspekcja różnych kontenerów)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `eicar.zip`, `eicar.tar`, `eicar.tar.gz` | ARC-001..003 | Główny | block | Python `zipfile`/`tarfile` z EICAR | **Wysokie** — brak rozpakowania danego kontenera; malware w tym formacie przejdzie |
| `eicar.com.gz` | F61 | Główny | block | `gzip` strumienia EICAR | **Wysokie** — jw. (gzip) |
| `script-test.ps1/.js/.vbs.zip` | F55-* | Główny | block | `zipfile` z benign skryptem | **Wysokie** — spakowany skrypt-dropper przejdzie |
| `pdf-and-eicar.zip` | F69 | Główny | block | `zipfile`: PDF + EICAR w osobnych wpisach | **Wysokie** — malware obok benign wabika w jednym archiwum |
| `deep-tree.zip` | F70 | Główny | block | `zipfile`, EICAR w 24 zagnieżdżonych katalogach | Średnie — test odporności na głębokie drzewo katalogów |
| `benign.jar` | F13 | Główny | block | `zipfile` z `MANIFEST.MF` (bez klasy Java) | Średnie — JAR wymaga JRE u odbiorcy |
| `zip-with-lnk.zip` | F54 | Główny | block | `zip` z benign LNK **[O: zip]** | **Wysokie** — dostawa LNK-droppera w archiwum (bardzo popularny łańcuch) |
| `eicar.7z` | ARC-004 | Główny | block | `7z`/`7zz` **[O: 7z]** | **Wysokie** — brak wsparcia 7z w skanerze |
| `eicar.iso`, `eicar.img` | F63, F64 | Główny | block | `genisoimage`; `.img` = `cp` bajtów ISO **[O: genisoimage/mkisofs]** | **Wysokie** — ISO/IMG omija Mark-of-the-Web; popularny kontener 2021+ |
| `eicar.cab` | F62 | Główny | block | `gcab` **[O: gcab]** | Średnie — CAB rzadszy, ale wykonalny wektor |
| `benign-pe.zip` | F53 | Główny | block | `zipfile` z realnym benign PE **[O: MinGW]** | **Wysokie** — natywny PE spakowany w archiwum |

### `07-encrypted/` — chronione hasłem (dowodzą: obsługa treści zaszyfrowanej i pozyskania hasła)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `eicar-password.zip` | ENC-001 | Główny | policy | `zip -P` **[O: zip]** | **Wysokie** — zaszyfrowane archiwum + hasło w treści = klasyczny bypass skanera |
| `eicar-password.7z` | ENC-002 | Główny | policy | `7z -p -mhe=on` **[O: 7z]** | **Wysokie** — jw.; `-mhe` szyfruje też nazwy plików |
| `pdf-password.pdf` | F77 | Główny | policy | `qpdf --encrypt` **[O: qpdf]** | Średnie — zaszyfrowany PDF nieinspekcjonowany |
| `password-in-image.png` | F80 | Główny | policy | PIL rysuje hasło jako tekst na obrazie **[O: Pillow + zip]** | Średnie — hasło w obrazie; jeśli brama nie OCR-uje, nie powiąże go z archiwum |

### `08-nested/` — łańcuchy formatów (dowodzą: głębokość rozpakowywania i zagnieżdżenie wiadomości)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `level-01.zip` … `level-NN.zip` | NEST-01..NN | Główny | block | pętla `zipfile`: każdy ZIP pakuje poprzedni, na końcu EICAR (domyślnie 10) | **Wysokie** — zanotuj graniczną głębokość: unpacker nie sięga poziomu N → malware głębiej przejdzie |
| `eml-zip-eicar.eml` | F102 | Główny | block | `EmailMessage` z załącznikiem ZIP(EICAR) | **Wysokie** — brama nie inspekcjonuje załączonych wiadomości |
| `zip-eml-eicar.zip` | F108 | Główny | block | `zipfile` z `.eml` zawierającym EICAR | **Wysokie** — jw. (kolejność odwrócona) |
| `zip-eml-zip-eicar.zip` | F108-ZEZ | Główny | block | ZIP → EML → ZIP → EICAR | **Wysokie** — wielowarstwowe zagnieżdżenie mieszane |
| `encrypted-outer.zip` | F137-PART | Główny | block | `zip -P` wokół zwykłego ZIP(EICAR) **[O: zip]** | **Wysokie** — szyfrowana warstwa zewnętrzna blokuje inspekcję wnętrza |
| `encrypted-in-encrypted.zip` | F75 | Główny | block | `zip -P` wokół zaszyfrowanego ZIP **[O: zip]** | **Wysokie** — podwójne szyfrowanie |
| `encrypted-zip-with-lnk.zip` | F127 | Główny | block | `zip -P` z benign LNK **[O: zip]** | **Wysokie** — szyfrowany łańcuch dostawy LNK |
| `eml-zip-lnk.eml` | F133 | Główny | block | `EmailMessage` z ZIP(LNK) **[O: zip]** | **Wysokie** — LNK w załączonej wiadomości w ZIP |
| `zip-zip-benign-pe.zip` | F65 | Główny | block | ZIP → ZIP → benign PE **[O: MinGW]** | **Wysokie** — zagnieżdżony natywny PE |
| `eml-benign-pe.eml` | F101 | Główny | block | `EmailMessage` z benign PE **[O: MinGW]** | **Wysokie** — PE w załączonej wiadomości |
| `zip-in-7z.7z` | F68-PART | Główny | block | `7z` wokół ZIP(EICAR), bez warstwy RAR **[O: 7z]** | **Wysokie** — mieszany łańcuch kontenerów (7z→zip) |

### `09-web/` — HTML i SVG (dowodzą: detekcja aktywnej treści i „HTML-smuggling-style” bez ładunku)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `link.html`, `redirect.html` | WEB-001, F88 | Główny | policy | here-doc: hiperłącze / meta-refresh do `example.invalid` | Średnie — HTML phishing / przekierowanie do złośliwej strony |
| `blob-download.html`, `base64-blob.html` | WEB-002, F95 | Główny | policy | JS tworzy Blob → **tylko** plik TXT | **Wysokie** — HTML smuggling: plik budowany po stronie klienta, omija skanowanie transferu |
| `link.svg`, `link-to-html.svg` | WEB-003, F97 | Główny | policy | SVG z hiperłączem | Średnie — SVG-phishing |
| `script.svg`, `encoded-text-js.svg` | WEB-004, F98 | Główny | policy | SVG z JS modyfikującym **tylko** lokalny tekst | **Wysokie** — aktywny JS w SVG renderowanym w przeglądarce; wektor XSS/smuggling |
| `base64-link.svg` | F91 | Główny | policy | SVG z data-URI (benign tekst) | Średnie — data-URI ukrywa treść przed skanerem URL |
| `external-resource.svg` | F100 | Główny | policy | SVG z `<image href>` do `example.invalid` | Średnie — zdalne pobranie / tracker / callback z SVG |
| `foreign-object.svg` | F99 | Główny | policy | SVG `foreignObject` z nieszkodliwym HTML | Średnie — osadzony HTML w SVG |
| `js-navigation.svg` | F131 | Główny | policy | SVG z `onclick` nawigującym do `example.invalid` | Średnie — nawigacja po kliknięciu (phishing) |

### `10-pdf/` — cechy PDF i QR (dowodzą: inspekcja adnotacji, formularzy, plików osadzonych, QR)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `pdf-with-url.pdf` | PDF-001 | Baza | policy | ręcznie budowany PDF z adnotacją URI | Średnie — PDF z URI → phishing; głównie kalibracja cechy |
| `acroform.pdf` | F85 | Baza | policy | PDF z polem formularza AcroForm | Niskie — formularz PDF; zwykle akceptowalny |
| `embedded-benign.txt.pdf` | F84 | Główny | policy | PDF ze strukturą EmbeddedFiles (benign TXT) | Średnie — mechanizm dostawy pliku osadzonego w PDF |
| `embedded-eicar.zip.pdf` | F105 | Główny | block | PDF z EmbeddedFiles = ZIP(EICAR) | **Wysokie** — PDF-dropper z osadzonym archiwum; brak inspekcji EmbeddedFiles |
| `qr-benign.png`, `pdf-with-qr.pdf`, `qr-benign.jpg` | PDF-002/003, F93 | Główny | policy | `qrcode` + PIL **[O: qrcode/Pillow]** | Średnie — quishing: QR → złośliwy URL omija skanery URL w treści |

### `11-mime/` — kompletne wiadomości `.eml` (dowodzą: rozbieżności parsera MIME, nazwy vs typ vs bajty)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `svg-as-text-plain.eml`, `eicar-as-pdf.eml` | MIME-001/002 | Główny | policy | `EmailMessage`: zadeklarowany MIME ≠ zawartość | **Wysokie** — brama ufa nagłówkowi, klient renderuje realny typ (parser differential) |
| `duplicate-filename.eml`, `eicar-no-filename.eml` | MIME-003/004 | Główny | policy | `EmailMessage`: duplikat nazwy / brak nazwy | Średnie — obsługa brzegowa nazw; różna decyzja bramy vs klienta |
| `outer-with-attached-eml.eml`, `nested-multipart.eml` | MIME-005, F50 | Główny | policy | zagnieżdżenie `message/rfc822` / `multipart` | **Wysokie** — zagnieżdżone wiadomości/parts nieinspekcjonowane |
| `different-name-and-filename.eml` | F44 | Główny | policy | surowy RFC: konflikt `name=`/`filename=` | **Wysokie** — rozbieżna decyzja o typie: brama patrzy na jeden parametr, klient na drugi |
| `filename-rfc2047.eml`, `filename-rfc2231.eml` | F45/F46 | Główny | policy | surowy RFC: dwa kodowania nazwy (2047 celowo niestandardowy) | Średnie — kodowana nazwa myli reguły rozszerzeń |
| `folded-base64.eml`, `nonstandard-base64-whitespace.eml`, `quoted-printable.eml` | F47/F48/F49 | Główny | policy | surowy RFC: warianty kodowania treści (F48 = celowa anomalia) | Średnie — anomalia kodowania: brama nie zdekoduje, klient tak |
| `duplicate-content-type.eml` | F52 | Główny | policy | surowy RFC: sprzeczne nagłówki `Content-Type` | **Wysokie** — parser differential na sprzecznych nagłówkach |
| `password-in-subject.eml`, `password-in-body.eml` | F78/F79 | Główny | policy | `EmailMessage` z ZIP-hasło + hasło w temacie/treści **[O: zip]** | **Wysokie** — bypass szyfrowaniem + socjotechnika podania hasła |
| `pe-as-jpeg.eml`, `pe-as-octet-stream.eml`, `pe-as-pdf.eml`, `combined-filename-mime.eml` | F41/F43/F42/F138 | Główny | policy | surowy RFC z bajtami PE i mylącym MIME/nazwą **[O: MinGW]** | **Wysokie** — realny PE ukryty za deklarowanym typem/nazwą |

### `12-filename/` — interpretacja nazwy (dowodzą: normalizacja nazwy po stronie klienta/bramy)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `invoice.pdf.exe`, `invoice.pdf........exe`, `invoice...exe`, `invoice .exe`, `INVOICE.EXE`, `Invoice.ExE`, `<180×A>.exe` | NAME-003..010 | Główny | policy | `cp` benign tekstu pod nazwą wrażliwą na normalizację | Średnie — masquerade typu; słabe reguły i użytkownik oszukani co do rozszerzenia |
| `invoice․exe` (U+2024), `invoice．exe` (U+FF0E), `invoice‐2026.pdf` (U+2010) | NAME-001/004/002 | Główny | policy | jw., znaki Unicode podobne do kropki/łącznika | Średnie — homoglify obchodzą dopasowanie rozszerzeń po literalnej kropce |
| `right-to-left-override-<U+202E>exe.pdf`, `ending-dot.exe.`, `ending-space.exe ` | F38/39 | Główny | policy | `write` benign bajtów pod nazwą z RTL-override / kończącą się kropką/spacją | **Wysokie** — RTL-override odwraca widoczne rozszerzenie (klasyczny trik); trailing dot/space omija reguły Windows |
| `faktura.pdf.docx.exe`, `long-<180×a>.exe` | F29/35 | Główny | policy | benign **PE** pod zwodniczą/długą nazwą **[O: MinGW]** | **Wysokie** — realny PE pod zwodniczą nazwą; dostarczenie = wykonanie po dwukliku |

### `13-parser/` — różnice między parserami (dowodzą: rozbieżna interpretacja tych samych bajtów)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `zip-with-trailing-junk.zip` | PARSE-001 | Główny | block | `cp eicar.zip` + doklejone bajty | Średnie — dane po ZIP; parser różnie interpretuje strukturę |
| `png-plus-zip.png`, `png-plus-zip.zip` | PARSE-002/003 | Główny | block | konkatenacja PNG + ZIP(EICAR) | **Wysokie** — polyglot: skaner widzi obraz, narzędzie odbiorcy wypakowuje ZIP |
| `truncated-eicar.zip` | PARSE-004 | Główny | block | `eicar.zip` obcięty o 8 bajtów | Niskie — test obsługi błędu parsera (nie gwarantuje otwarcia) |
| `duplicate-zip-entry.zip` | F116 | Główny | block | `zipfile`: dwa wpisy o tej samej nazwie, różna treść | **Wysokie** — skaner sprawdza jeden wpis, wypakowywacz wybiera drugi |
| `case-differing-zip-entry.zip` | F117 | Główny | block | `zipfile`: `CHECK.TXT` vs `check.txt` | Średnie — kolizja wielkości liter między systemami plików |
| `unicode-zip-entry.zip` | F118 | Główny | block | `zipfile`: nazwa wpisu z pełnoszeroką kropką | Średnie — homoglif w nazwie wpisu obchodzi reguły |
| `zip-local-central-name-disagreement.zip` | F115 | Główny | block | `zipfile`, potem nadpisanie **tylko** nazwy w local header (`evil.exe`) vs central (`safe.txt`) | **Wysokie** — skaner czyta central (`safe.txt`), wypakowywacz local (`evil.exe`); realny bypass |
| `pdf-plus-zip.pdf`, `gif-plus-zip.gif` | F109/F111 | Główny | block | konkatenacja PDF/GIF + ZIP(EICAR) | **Wysokie** — polyglot dwuformatowy |
| `jpeg-plus-zip.jpg` | F110 | Główny | block | konkatenacja JPEG (PIL) + ZIP(EICAR) **[O: Pillow]** | **Wysokie** — polyglot JPEG/ZIP |

Plik pomocniczy `one-pixel.gif` (benign obraz źródłowy dla `gif-plus-zip.gif`) **nie jest** przypadkiem testowym i nie ma go w manifeście.

### `14-resource-limits/` — ograniczone testy limitów (dowodzą: limity liczby wpisów/kompresji, nie DoS)

| Plik | ID | Rola | Oczekiwane | Jak utworzony | Jeśli przejdzie → ryzyko |
|---|---|---|---|---|---|
| `many-files-N.zip` | LIMIT-001 | Główny | policy | `zipfile` z N benign TXT (domyślnie 250) | Średnie — jeśli skaner pomija archiwa o dużej liczbie wpisów (limit), malware w takim archiwum przejdzie |
| `high-compression-NMB.zip` | LIMIT-002 | Główny | policy | `zipfile` mocno skompresowanych zer (nie bomba) | Średnie — pomijanie przy wysokim współczynniku kompresji (ochrona przed bombą) tworzy lukę skanowania |
| `standalone-NMB.bin` | F122 | Główny | policy | marker + zera, rozmiar wg `COMPRESS_MB` | Średnie — jeśli skaner pomija pliki powyżej limitu rozmiaru, duży malware przejdzie |

### Podsumowanie próbek opcjonalnych

Bez wskazanego narzędzia poniższe **nie powstają** i nie ma ich w manifeście:

| Narzędzie | Próbki |
|---|---|
| MinGW (`x86_64-w64-mingw32-gcc`) | wszystkie PE: EXE-002..006, F02, F33, F03, F14-CPL, F53, F65, F101, F41/F42/F43/F138, F29/35 |
| `7z`/`7zz` | ARC-004, ENC-002, F68-PART |
| `genisoimage`/`mkisofs` | F63, F64 |
| `gcab` | F62 |
| `qrcode` + Pillow | PDF-002, PDF-003, F93 |

---

## Źródła do konfiguracji narzędzi

- [Kali Linux: pakiet 7zip i polecenie `7z`](https://www.kali.org/tools/7zip/).
- [Microsoft: rozszerzenia i formaty dokumentów Office](https://support.microsoft.com/en-us/office/vba/open-xml-formats-and-file-name-extensions).
- [Microsoft: osadzanie obiektu w Wordzie](https://support.microsoft.com/en-us/word/insert-an-object-in-word-or-outlook).
- [Microsoft: format dodatku XLAM](https://support.microsoft.com/en-US/Excel/create-custom-functions-in-excel).
- [Microsoft: tworzenie XLL](https://learn.microsoft.com/en-us/office/client-developer/excel/getting-started-with-the-excel-xll-sdk).
- [RARLAB: archiwizator RAR dla Linux](https://www.rarlab.com/download.htm).
