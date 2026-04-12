# Open Issues

## 0. Crash on signature verification – `AttributeError: '_act_sign'`

```
pdf-signer Dokumente/01.08.2025\ OBV\ Dr.\ Muß_signed.pdf
Traceback (most recent call last):
  File ".../main_window.py", line 1888, in check_signatures
    self._set_modifying_actions_enabled(False)
  File ".../main_window.py", line 1708, in _set_modifying_actions_enabled
    for act in (self._act_sign, self._tb_sign,
                ^^^^^^^^^^^^^^
AttributeError: 'PDFSignerApp' object has no attribute '_act_sign'. Did you mean: '_act_open'?
```

## 1. "Restart" after update only closes, does not restart

After an update the "Restart" button closes the application but does not relaunch it.

## 2. Some strings not translated / missing i18n

- Comments in the openssl command template
- Placeholder texts in input fields (e.g. "Max Mustermann", "mein-schluessel.p12", etc.)

These should fall back to English if no translation exists.

## 3. Settings → General should be renamed to "Language"

As long as Settings → General only contains language settings, the tab should be
renamed accordingly (de: "Sprache", en: "Language", …).

## 4. No downgrade offered when switching from develop to stable channel

When switching from the develop channel to stable, no downgrade is triggered.
Workarounds:
- Manual install via wheel file (document in README)
- Add `--installversion vX.Y.Z` parameter to `setup_pdf_signer.bat` / `setup_pdf_signer.sh`
