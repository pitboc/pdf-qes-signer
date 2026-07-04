# Introduction

The EU **eIDAS** Regulation (Regulation (EU) No. 910/2014) distinguishes
three levels of electronic signatures. They differ not in the underlying
*technology*, but above all in their **legal effect** and their
**evidentiary weight** in court: Who was identified, who issues the
certificate, and how reliably is it excluded that someone else signed?

All three levels are legally valid throughout the EU -- but only the
highest level, the **Qualified Electronic Signature (QES)**, is legally
equivalent to a handwritten signature.

```{=latex}
\begin{figure}[H]
\centering
\begin{tikzpicture}[font=\small]
  \draw[-{Latex[length=2mm]}] (0,0) -- (0,6.4) node[above, align=center] {Legal certainty\\\&\ evidentiary weight};
  \draw[-{Latex[length=2mm]}] (-0.3,0) -- (9.6,0);

  % Level 1: SES
  \fill[qesred!65] (0.5,0) rectangle (3,1.3);
  \node[white, font=\bfseries\small] at (1.75,0.65) {SES};
  \node[align=center, text width=2.6cm] at (1.75,-0.8) {\textbf{Simple}};

  % Level 2: AES
  \fill[qesamber!85] (3.5,0) rectangle (6,3.3);
  \node[white, font=\bfseries\small] at (4.75,1.65) {AES};
  \node[align=center, text width=2.6cm] at (4.75,-0.8) {\textbf{Advanced}};

  % Level 3: QES
  \fill[qesgreen!85] (6.5,0) rectangle (9,5.9);
  \node[white, font=\bfseries\small] at (7.75,2.95) {QES};
  \node[align=center, text width=2.6cm] at (7.75,-0.8) {\textbf{Qualified}};

  % Equivalence to handwritten signature only for QES
  \draw[qesgreen, thick, -{Latex[length=1.5mm]}] (7.75,6.35) -- (7.75,6.0);
  \node[align=center, text width=3.4cm, font=\small\itshape] at (7.75,6.85)
    {$\triangleq$ handwritten\\signature};
\end{tikzpicture}
\caption{The higher the level, the stronger the legal evidentiary weight.
Only the Qualified Electronic Signature (QES) is legally equivalent to a
handwritten signature.}
\end{figure}
```

# Simple Electronic Signature (SES)

**Definition (Art. 3(10) eIDAS):** Data in electronic form which is
attached to or logically associated with other data in electronic form
and which is used by the signatory to sign.

**Typical examples:**

- A scanned or inserted image of a signature in a PDF
- A typed name at the bottom of an email
- Clicking "I agree" / "Place order"

**Legal effect:** A simple electronic signature may not be denied legal
effect and admissibility as evidence in court solely on the grounds that
it is in electronic form (Art. 25(1) eIDAS). However, there is **no
statutory presumption of authenticity** -- in a dispute, whoever relies on
the signature must actively prove that it genuinely originates from the
named person. In practice this is difficult, since the signature can be
freely copied and was created without any identity verification.

**Technology:** As a rule, there is **no** cryptographic protection here.
An image of a signature or a typed name is simply additional content of
the file -- nothing prevents the text from being changed afterwards or the
"signature" from being copied into a different document. Neither the
identity of the signatory nor the integrity of the document is technically
guaranteed.

**Security level:** low -- no identity verification, no tamper detection.

# Advanced Electronic Signature (AES)

**Definition (Art. 26 eIDAS):** An advanced electronic signature must
simultaneously meet four requirements:

1. It is **uniquely linked to the signatory**.
2. It is **capable of identifying the signatory**.
3. It was created using electronic signature creation data that the
   signatory can, with a **high level of confidence, use under their sole
   control**.
4. It is **linked to the signed data** in such a way that any subsequent
   change to the data is **detectable**.

**Typical examples:** Signature services such as DocuSign or Adobe Sign
with email and SMS verification, a signature captured with signature
dynamics (pressure, speed) on a signature pad, or a signed PDF using a
personal (non-qualified) certificate.

**Legal effect:** Stronger evidentiary weight than a simple signature,
since identity and integrity are technically verifiable. However, it still
does **not** replace statutory written-form requirements (e.g. § 126 BGB in
Germany) and is not automatically equivalent to a handwritten signature.

**Technology:** The advanced signature uses asymmetric cryptography
(public-key methods): a hash value is computed over the document content
and encrypted with the signatory's **private key** (digital signature,
e.g. RSA or ECDSA). Any subsequent change to the document changes the hash
value -- the signature then becomes invalid, and the tampering is
detectable. Identity derives from the certificate associated with the key;
how reliable that association is depends on how rigorously the issuer
(e.g. a company or email provider) verified the identity before issuing
it.

**Multiple signatures:** If several people need to sign the same PDF, no
existing signature is broken to do so. Each additional signature creates a
new **revision** of the document (an incremental update) and additionally
covers all previously existing signatures as well as the content. Earlier
signatures remain untouched and stay valid -- new signatures are added
purely **additively**, revision by revision.

**Security level:** medium -- tamper detection is present, but identity is
typically not verified by an independent, trusted authority.

# Qualified Electronic Signature (QES)

**Definition (Art. 3(12) eIDAS):** An advanced electronic signature that
is additionally

- created using a **qualified certificate**, issued by a **qualified
  trust service provider (QTSP)** who has verified the signatory's
  identity beforehand beyond doubt (e.g. via video identification or an
  ID check), and
- created using a **qualified electronic signature creation device
  (QSCD)** -- specially secured hardware such as a signature card or a
  certified remote-signing HSM.

**Legal effect (Art. 25(2) eIDAS):** The QES is **legally equivalent to a
handwritten signature in all EU member states**. The **statutory
presumption of authenticity** applies: in a dispute, the signatory does
not have to prove authenticity -- rather, the other party would have to
prove forgery (reversal of the burden of proof). Only the QES can replace
the statutory written-form requirement.

**Typical examples:** Qualified remote signature services such as
D-Trust sign-me, Swisscom All-in Signing Service, A-Trust, or the German
Bundesdruckerei -- **PDF QES Signer** uses exactly this kind of service to
sign documents.

**Technology:** Cryptographically, the QES works like the AES (hash value
+ digital signature with a private key), additionally secured by three
factors: the private key never leaves the certified hardware (QSCD) and
cannot be exported. The associated certificate is issued only after the
QTSP has verified the identity beyond doubt. For PDF documents (PAdES
standard), the signature is computed over a precisely defined byte range
of the file and supplemented with a qualified timestamp -- so the
signature remains verifiable even years later, even if the signing
certificate has since expired.

**Security level:** high -- verified identity, secured hardware, tamper
detection, statutory presumption of validity.

# Comparison at a Glance

```{=latex}
\begin{table}[H]
\centering
\small
\begin{tabular}{@{}p{3.6cm}ccc@{}}
\toprule
\textbf{Feature} & \textbf{Simple (SES)} & \textbf{Advanced (AES)} & \textbf{Qualified (QES)} \\
\midrule
Identity verification & {\color{qesred}$\times$} & (internal to provider) & {\color{qesgreen}$\checkmark$} by QTSP \\
Tamper detection & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} & {\color{qesgreen}$\checkmark$} \\
Qualified certificate & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Secure hardware (QSCD) & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Equivalent to handwritten signature & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
Evidentiary weight in court & low & medium & high (presumption) \\
Replaces statutory written form (§126 BGB) & {\color{qesred}$\times$} & {\color{qesred}$\times$} & {\color{qesgreen}$\checkmark$} \\
\bottomrule
\end{tabular}
\caption{Comparison of the three eIDAS signature levels.}
\end{table}
```

# Which Signature Do I Need?

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
\node[decision] (q1) {Must the signature be legally equivalent to a
  handwritten signature (e.g.\ \S126 BGB, notarial or official
  requirement)?};
\node[decision, below=14mm of q1] (q2) {Is there a high liability or
  dispute risk (e.g.\ contract, termination, HR document)?};
\node[result, fill=qesgreen!20, right=22mm of q1] (qes) {Qualified\\Signature (QES)};
\node[result, fill=qesamber!20, right=22mm of q2] (fes) {Advanced\\Signature (AES)};
\node[result, fill=qesred!12, below=10mm of q2] (ees) {Simple\\Signature (SES)};

\draw[->] (q1) -- node[above] {yes} (qes);
\draw[->] (q1) -- node[right] {no} (q2);
\draw[->] (q2) -- node[above] {yes} (fes);
\draw[->] (q2) -- node[right] {no} (ees);
\end{tikzpicture}
\caption{Simplified decision guide. When in doubt, or where there is legal
uncertainty, the higher level is recommended.}
\end{figure}
```

# Relation to PDF QES Signer

**PDF QES Signer** creates qualified electronic signatures (PAdES,
including long-term archiving per PAdES-B-LTA) via qualified remote
signature services. Every signature it creates automatically satisfies all
requirements of the highest eIDAS level: identity verified by the trust
service provider, a qualified certificate, and creation on certified
hardware (QSCD) at the provider.

Source code, downloads, and further documentation:
[codeberg.org/pitbo/pdf-qes-signer](https://codeberg.org/pitbo/pdf-qes-signer).

# Glossary

**eIDAS** -- *electronic IDentification, Authentication and trust
Services*; EU Regulation (EU) No. 910/2014 governing electronic
identification and trust services in the internal market.

**QTSP** -- *Qualified Trust Service Provider*; a trust service provider
accredited and supervised by a national supervisory body, authorized to
issue qualified certificates.

**QSCD** -- *Qualified electronic Signature Creation Device*; certified,
specially secured hardware (a smart card or a remote-signing HSM) used to
create qualified signatures.

**PAdES** -- *PDF Advanced Electronic Signatures*; the ETSI standard for
electronic signatures in PDF documents, on which PDF QES Signer is built.
