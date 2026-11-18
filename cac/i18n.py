"""Titles of the artefacts the collector writes, in the subject's language (`subject.language`).

Only titles the collector composes are translated; names, issuers and tool output stay as given.
Complear renders the rest of each evidence item in its reader's locale. An unknown language falls
back to English.
"""

TITLES = {
    "en": {
        "tai_scan": "TAI Scan risk level: {level}",
        "sbom": "SBOM ({components} components, {models} models, {datasets} datasets)",
        "signature_verified": "Image signature verified",
        "signature_failed": "Image signature FAILED verification",
        "signature_unchecked": "Image signature not checked",
        "tests": "{name}: {passed} of {total} tests passed",
        "notified_body_certificate": "Notified body certificate ({issuer})",
        "declaration_of_conformity": "Declaration of conformity ({issuer})",
        "ce_marking": "CE marking ({issuer})",
        "eu_database_registration": "EU database registration ({issuer})",
    },
    "de": {
        "tai_scan": "TAI-Scan-Risikostufe: {level}",
        "sbom": "SBOM ({components} Komponenten, {models} Modelle, {datasets} Datensätze)",
        "signature_verified": "Image-Signatur verifiziert",
        "signature_failed": "Image-Signatur-Prüfung FEHLGESCHLAGEN",
        "signature_unchecked": "Image-Signatur nicht geprüft",
        "tests": "{name}: {passed} von {total} Tests bestanden",
        "notified_body_certificate": "Bescheinigung der benannten Stelle ({issuer})",
        "declaration_of_conformity": "Konformitätserklärung ({issuer})",
        "ce_marking": "CE-Kennzeichnung ({issuer})",
        "eu_database_registration": "Registrierung in der EU-Datenbank ({issuer})",
    },
    "fr": {
        "tai_scan": "Niveau de risque TAI Scan : {level}",
        "sbom": "SBOM ({components} composants, {models} modèles, {datasets} jeux de données)",
        "signature_verified": "Signature de l'image vérifiée",
        "signature_failed": "ÉCHEC de la vérification de la signature de l'image",
        "signature_unchecked": "Signature de l'image non vérifiée",
        "tests": "{name} : {passed} tests réussis sur {total}",
        "notified_body_certificate": "Certificat de l'organisme notifié ({issuer})",
        "declaration_of_conformity": "Déclaration de conformité ({issuer})",
        "ce_marking": "Marquage CE ({issuer})",
        "eu_database_registration": "Enregistrement dans la base de données de l'UE ({issuer})",
    },
    "es": {
        "tai_scan": "Nivel de riesgo de TAI Scan: {level}",
        "sbom": "SBOM ({components} componentes, {models} modelos, {datasets} conjuntos de datos)",
        "signature_verified": "Firma de la imagen verificada",
        "signature_failed": "Verificación de la firma de la imagen FALLIDA",
        "signature_unchecked": "Firma de la imagen no comprobada",
        "tests": "{name}: {passed} de {total} pruebas superadas",
        "notified_body_certificate": "Certificado del organismo notificado ({issuer})",
        "declaration_of_conformity": "Declaración de conformidad ({issuer})",
        "ce_marking": "Marcado CE ({issuer})",
        "eu_database_registration": "Registro en la base de datos de la UE ({issuer})",
    },
    "it": {
        "tai_scan": "Livello di rischio TAI Scan: {level}",
        "sbom": "SBOM ({components} componenti, {models} modelli, {datasets} set di dati)",
        "signature_verified": "Firma dell'immagine verificata",
        "signature_failed": "Verifica della firma dell'immagine NON RIUSCITA",
        "signature_unchecked": "Firma dell'immagine non controllata",
        "tests": "{name}: {passed} test superati su {total}",
        "notified_body_certificate": "Certificato dell'organismo notificato ({issuer})",
        "declaration_of_conformity": "Dichiarazione di conformità ({issuer})",
        "ce_marking": "Marcatura CE ({issuer})",
        "eu_database_registration": "Registrazione nella banca dati dell'UE ({issuer})",
    },
    "pt": {
        "tai_scan": "Nível de risco do TAI Scan: {level}",
        "sbom": "SBOM ({components} componentes, {models} modelos, {datasets} conjuntos de dados)",
        "signature_verified": "Assinatura da imagem verificada",
        "signature_failed": "Verificação da assinatura da imagem FALHOU",
        "signature_unchecked": "Assinatura da imagem não verificada",
        "tests": "{name}: {passed} de {total} testes aprovados",
        "notified_body_certificate": "Certificado do organismo notificado ({issuer})",
        "declaration_of_conformity": "Declaração de conformidade ({issuer})",
        "ce_marking": "Marcação CE ({issuer})",
        "eu_database_registration": "Registo na base de dados da UE ({issuer})",
    },
    "nl": {
        "tai_scan": "TAI Scan-risiconiveau: {level}",
        "sbom": "SBOM ({components} componenten, {models} modellen, {datasets} datasets)",
        "signature_verified": "Image-handtekening geverifieerd",
        "signature_failed": "Verificatie van image-handtekening MISLUKT",
        "signature_unchecked": "Image-handtekening niet gecontroleerd",
        "tests": "{name}: {passed} van {total} tests geslaagd",
        "notified_body_certificate": "Certificaat van de aangemelde instantie ({issuer})",
        "declaration_of_conformity": "Conformiteitsverklaring ({issuer})",
        "ce_marking": "CE-markering ({issuer})",
        "eu_database_registration": "Registratie in de EU-databank ({issuer})",
    },
    "pl": {
        "tai_scan": "Poziom ryzyka TAI Scan: {level}",
        "sbom": "SBOM ({components} komponentów, {models} modeli, {datasets} zbiorów danych)",
        "signature_verified": "Podpis obrazu zweryfikowany",
        "signature_failed": "Weryfikacja podpisu obrazu NIEUDANA",
        "signature_unchecked": "Podpis obrazu niesprawdzony",
        "tests": "{name}: zaliczono {passed} z {total} testów",
        "notified_body_certificate": "Certyfikat jednostki notyfikowanej ({issuer})",
        "declaration_of_conformity": "Deklaracja zgodności ({issuer})",
        "ce_marking": "Oznakowanie CE ({issuer})",
        "eu_database_registration": "Rejestracja w unijnej bazie danych ({issuer})",
    },
}

LANGUAGES = sorted(TITLES)


def title(lang, key, **values):
    """The title `key` in `lang` (a BCP 47 tag; only its language part is used), English otherwise."""
    base = (lang or "en").split("-")[0].lower()
    return TITLES.get(base, TITLES["en"])[key].format(**values)
