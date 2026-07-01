# Einleitung

Die EU-Verordnung **eIDAS** (Verordnung (EU) Nr. 910/2014) unterscheidet drei
Stufen elektronischer Signaturen. Sie unterscheiden sich nicht in der
*Technik*, sondern vor allem in der **rechtlichen Wirkung** und der
**Beweiskraft** vor Gericht: Wer wurde identifiziert, wer stellt das
Zertifikat aus, und wie sicher ist ausgeschlossen, dass jemand anderes
unterschrieben hat?

Alle drei Stufen sind in der EU rechtsgültig -- aber nur die höchste Stufe,
die **qualifizierte elektronische Signatur (QES)**, ist einer
handschriftlichen Unterschrift gesetzlich gleichgestellt.

```{=latex}
\begin{figure}[H]
\centering
\begin{tikzpicture}[font=\small]
  \draw[-{Latex[length=2mm]}] (0,0) -- (0,6.4) node[above, align=center] {Rechtssicherheit\\\&\ Beweiskraft};
  \draw[-{Latex[length=2mm]}] (-0.3,0) -- (9.6,0);

  % Stufe 1: EES
  \fill[qesred!65] (0.5,0) rectangle (3,1.3);
  \node[white, font=\bfseries\small] at (1.75,0.65) {EES};
  \node[align=center, text width=2.6cm] at (1.75,-0.8) {\textbf{Einfach}};

  % Stufe 2: FES
  \fill[qesamber!85] (3.5,0) rectangle (6,3.3);
  \node[white, font=\bfseries\small] at (4.75,1.65) {FES};
  \node[align=center, text width=2.6cm] at (4.75,-0.8) {\textbf{Fortgeschritten}};

  % Stufe 3: QES
  \fill[qesgreen!85] (6.5,0) rectangle (9,5.9);
  \node[white, font=\bfseries\small] at (7.75,2.95) {QES};
  \node[align=center, text width=2.6cm] at (7.75,-0.8) {\textbf{Qualifiziert}};

  % Handschrift-Gleichstellung nur bei QES
  \draw[qesgreen, thick, -{Latex[length=1.5mm]}] (7.75,6.35) -- (7.75,6.0);
  \node[align=center, text width=3.4cm, font=\small\itshape] at (7.75,6.85)
    {$\triangleq$ handschriftliche\\Unterschrift};
\end{tikzpicture}
\caption{Je höher die Stufe, desto stärker die rechtliche Beweiskraft. Nur die
qualifizierte Signatur (QES) ist der eigenhändigen Unterschrift gleichgestellt.}
\end{figure}
```

# Einfache elektronische Signatur (EES)

**Definition (Art. 3 Nr. 10 eIDAS):** Daten in elektronischer Form, die
anderen elektronischen Daten beigefügt oder logisch mit ihnen verbunden
werden und die der Unterzeichner zur Unterzeichnung nutzt.

**Typische Beispiele:**

- Eingescannte oder eingefügte Bild-Unterschrift in einem PDF
- Eingetippter Name unter einer E-Mail
- Klick auf "Ich stimme zu" / "Bestellung abschicken"

**Rechtliche Wirkung:** Eine einfache elektronische Signatur darf vor
Gericht nicht *allein wegen ihrer elektronischen Form* als Beweismittel
abgelehnt werden (Art. 25 Abs. 1 eIDAS). Es gibt jedoch **keine gesetzliche
Vermutung der Echtheit** -- im Streitfall muss derjenige, der sich auf die
Signatur beruft, aktiv beweisen, dass sie tatsächlich von der genannten
Person stammt. Das ist in der Praxis schwierig, da die Signatur beliebig
kopierbar und ohne Identitätsprüfung erstellt ist.

**Technik:** Hier gibt es in der Regel **keine** kryptografische
Absicherung. Ein Bild der Unterschrift oder ein eingetippter Name ist
schlicht zusätzlicher Inhalt der Datei -- nichts hindert daran, den Text
danach zu ändern oder die "Unterschrift" zu kopieren und in ein anderes
Dokument einzufügen. Weder die Identität des Unterzeichners noch die
Unveränderbarkeit des Dokuments werden technisch sichergestellt.

**Sicherheitsniveau:** niedrig -- keine Identitätsprüfung, keine
Manipulationserkennung.

# Fortgeschrittene elektronische Signatur (FES)

**Definition (Art. 26 eIDAS):** Eine fortgeschrittene elektronische
Signatur muss vier Anforderungen gleichzeitig erfüllen:

1. Sie ist **eindeutig dem Unterzeichner zugeordnet**.
2. Sie ermöglicht die **Identifizierung des Unterzeichners**.
3. Sie wurde unter Verwendung von Signaturerstellungsdaten erzeugt, die der
   Unterzeichner mit einem **hohen Maß an Vertrauen unter seiner alleinigen
   Kontrolle** verwenden kann.
4. Sie ist so mit den unterzeichneten Daten verbunden, dass eine
   **nachträgliche Veränderung der Daten erkennbar** ist.

**Typische Beispiele:** Signaturdienste wie DocuSign oder Adobe Sign mit
E-Mail- und SMS-Verifizierung, Unterschrift mit Unterschriftendynamik
(Druck, Geschwindigkeit) auf einem Signatur-Pad, ein signiertes PDF mit
einem persönlichen (nicht-qualifizierten) Zertifikat.

**Rechtliche Wirkung:** Höhere Beweiskraft als die einfache Signatur, da
Identität und Unversehrtheit technisch nachvollziehbar sind. Ersetzt aber
weiterhin **nicht** die gesetzliche Schriftform (z. B. § 126 BGB) und ist
der handschriftlichen Unterschrift nicht automatisch gleichgestellt.

**Technik:** Die fortgeschrittene Signatur nutzt asymmetrische Kryptografie
(Public-Key-Verfahren): Über den Dokumentinhalt wird ein Hashwert gebildet
und mit dem **privaten Schlüssel** des Unterzeichners verschlüsselt
(digitale Signatur, z. B. RSA oder ECDSA). Jede nachträgliche Änderung am
Dokument verändert den Hashwert -- die Signatur wird dadurch ungültig, und
die Manipulation ist erkennbar. Die Identität ergibt sich aus dem zum
Schlüssel gehörenden Zertifikat; wie zuverlässig diese Zuordnung ist, hängt
davon ab, wie streng der Aussteller (z. B. Unternehmen, E-Mail-Provider)
die Identität vor Ausstellung geprüft hat.

**Mehrere Unterschriften:** Sollen mehrere Personen dasselbe PDF
unterschreiben, wird dafür keine bestehende Signatur aufgebrochen. Jede
weitere Unterschrift legt eine neue **Version** des Dokuments an
(inkrementelles Update) und deckt zusätzlich zum Inhalt auch alle bisher
vorhandenen Signaturen mit ab. Frühere Signaturen bleiben dabei unangetastet
und weiterhin gültig -- neue Signaturen kommen rein **additiv** hinzu,
Version für Version.

**Sicherheitsniveau:** mittel -- Manipulationserkennung vorhanden, aber die
Identität wird i. d. R. nicht durch eine unabhängige, vertrauenswürdige
Stelle geprüft.

# Qualifizierte elektronische Signatur (QES)

**Definition (Art. 3 Nr. 12 eIDAS):** Eine fortgeschrittene elektronische
Signatur, die zusätzlich

- mit einem **qualifizierten Zertifikat** erstellt wurde, ausgestellt von
  einem **qualifizierten Vertrauensdiensteanbieter (QTSP)**, der die
  Identität des Unterzeichners vorab zweifelsfrei geprüft hat (z. B. per
  Video-Ident oder Ausweisprüfung), und
- mit einer **qualifizierten elektronischen Signaturerstellungseinheit
  (QSCD)** erzeugt wurde -- einer besonders gesicherten Hardware wie einer
  Signaturkarte oder einem zertifizierten Fernsignatur-HSM.

**Rechtliche Wirkung (Art. 25 Abs. 2 eIDAS):** Die QES ist der
handschriftlichen Unterschrift **in allen EU-Mitgliedstaaten rechtlich
gleichgestellt**. Es gilt die **gesetzliche Vermutung der Echtheit**: Im
Streitfall muss nicht der Unterzeichnete die Echtheit beweisen, sondern die
Gegenseite müsste die Fälschung beweisen (Beweislastumkehr). Nur die QES
kann die gesetzliche Schriftform ersetzen.

**Typische Beispiele:** Qualifizierte Fernsignaturdienste wie D-Trust
sign-me, Swisscom All-in Signing Service, A-Trust oder die Bundesdruckerei
-- genau solche Dienste nutzt **PDF QES Signer**, um Dokumente zu
signieren.

**Technik:** Kryptografisch funktioniert die QES wie die FES (Hashwert +
digitale Signatur mit privatem Schlüssel), zusätzlich abgesichert durch
drei Punkte: Der private Schlüssel verlässt nie die zertifizierte Hardware
(QSCD) und kann nicht exportiert werden. Das zugehörige Zertifikat wird
erst nach zweifelsfreier Identitätsprüfung durch den QTSP ausgestellt. Bei
PDF-Dokumenten (Standard PAdES) wird die Signatur über einen genau
definierten Byte-Bereich der Datei gebildet und durch einen qualifizierten
Zeitstempel ergänzt -- so bleibt die Signatur auch nach Jahren
überprüfbar, selbst wenn das Signaturzertifikat inzwischen abgelaufen ist.

**Sicherheitsniveau:** hoch -- geprüfte Identität, gesicherte Hardware,
Manipulationserkennung, gesetzliche Vermutungswirkung.

# Vergleich auf einen Blick

```{=latex}
\begin{table}[H]
\centering
\small
\begin{tabular}{@{}p{3.6cm}ccc@{}}
\toprule
\textbf{Merkmal} & \textbf{Einfach (EES)} & \textbf{Fortgeschritten (FES)} & \textbf{Qualifiziert (QES)} \\
\midrule
Identitätsprüfung & {\color{qesred}$\times$} & (unternehmensintern) & {\color{qesgreen}$\checkmark$} durch QTSP \\
Manipulationserkennung & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} & {\color{qesgreen}$\checkmark$} \\
Qualifiziertes Zertifikat & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Sichere Hardware (QSCD) & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Gleichstellung mit Unterschrift & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Beweiskraft vor Gericht & gering & mittel & hoch (Vermutung) \\
Ersetzt gesetzl. Schriftform (§126 BGB) & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
\bottomrule
\end{tabular}
\caption{Vergleich der drei eIDAS-Signaturstufen.}
\end{table}
```

# Welche Signatur brauche ich?

```{=latex}
\begin{figure}[H]
\centering
\begin{tikzpicture}[
  node distance=8mm and 8mm,
  every node/.style={font=\footnotesize},
  decision/.style={diamond, draw, aspect=2.6, align=center, fill=qesbg,
    inner sep=2pt, text width=3.1cm},
  result/.style={rectangle, rounded corners, draw, align=center,
    minimum width=3.0cm, minimum height=1.1cm, inner sep=3pt},
  >=Latex, thick
]
\node[decision] (q1) {Muss die Signatur einer handschriftlichen
  Unterschrift rechtlich gleichgestellt sein (z.\,B.\ §126 BGB, notarielle
  oder behördliche Anforderung)?};
\node[decision, below=14mm of q1] (q2) {Besteht ein hohes Haftungs- oder
  Streitrisiko (z.\,B.\ Vertrag, Kündigung, HR-Dokument)?};
\node[result, fill=qesgreen!20, right=22mm of q1] (qes) {Qualifizierte\\Signatur (QES)};
\node[result, fill=qesamber!20, right=22mm of q2] (fes) {Fortgeschrittene\\Signatur (FES)};
\node[result, fill=qesred!12, below=10mm of q2] (ees) {Einfache\\Signatur (EES)};

\draw[->] (q1) -- node[above] {ja} (qes);
\draw[->] (q1) -- node[right] {nein} (q2);
\draw[->] (q2) -- node[above] {ja} (fes);
\draw[->] (q2) -- node[right] {nein} (ees);
\end{tikzpicture}
\caption{Vereinfachte Entscheidungshilfe. Im Zweifel bzw. bei rechtlicher
Unsicherheit empfiehlt sich die höhere Stufe.}
\end{figure}
```

# Bezug zu PDF QES Signer

**PDF QES Signer** erstellt qualifizierte elektronische Signaturen (PAdES,
inkl. Langzeitarchivierung nach PAdES-B-LTA) über qualifizierte
Fernsignaturdienste. Jede damit erzeugte Signatur erfüllt automatisch alle
Anforderungen der höchsten eIDAS-Stufe: geprüfte Identität durch den
Vertrauensdiensteanbieter, qualifiziertes Zertifikat und Erzeugung auf
zertifizierter Hardware (QSCD) beim Anbieter.

Quellcode, Downloads und weitere Dokumentation:
[codeberg.org/pitbo/pdf-qes-signer](https://codeberg.org/pitbo/pdf-qes-signer).

# Glossar

**eIDAS** -- *electronic IDentification, Authentication and trust
Services*; EU-Verordnung (EU) Nr. 910/2014 zur Regelung elektronischer
Identifizierung und Vertrauensdienste im Binnenmarkt.

**QTSP** -- *Qualified Trust Service Provider*; von einer nationalen
Aufsichtsstelle zugelassener und beaufsichtigter Vertrauensdiensteanbieter,
der qualifizierte Zertifikate ausstellen darf.

**QSCD** -- *Qualified electronic Signature Creation Device*; zertifizierte,
besonders abgesicherte Hardware (Chipkarte oder Fernsignatur-HSM) zur
Erzeugung qualifizierter Signaturen.

**PAdES** -- *PDF Advanced Electronic Signatures*; ETSI-Standard für
elektronische Signaturen in PDF-Dokumenten, auf dem PDF QES Signer
aufbaut.
