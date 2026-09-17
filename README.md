# kerbad — fork with a fix for the enctype fallback (KDC_ERR_ETYPE_NOTSUPP)

This is a fork of CravateRouge/kerbad, a pure-Python
Kerberos library. It carries one fix on top of upstream main; nothing else is changed, and the
upstream repository stays the authoritative source for the library, its API and its documentation.

Fork branch: main = upstream b5f2781 + 79cf629
("Fix enctype fallback picking the enctype the KDC just refused").

## The problem this fork fixes

When a KDC refuses the encryption type of the first AS-REQ, kerbad crashed instead of falling back to
another encryption type.

Observed symptom (reproduced through bloodyAD's add badSuccessor, but the same code path is used by
anything that authenticates with a password):

    [+] Creating DMSA danila$ in OU=...
    [+] Impersonating: CN=...
    [-] Failed to retrieve dMSA TGT
    ...
    kerbad.protocol.errors.KerberosError:  Error Name: KDC_ERR_ETYPE_NOTSUPP
    Detail: "KDC has no support for encryption type"

Root cause: for a password credential kerbad builds its enctype preference list starting with RC4
(ARCFOUR_HMAC_MD5). get_TGT() sends the first AS-REQ with that enctype; when the account cannot
use RC4 (for example on a Windows Server 2025 domain controller where RC4 is not available for that
account), the KDC answers KDC_ERR_ETYPE_NOTSUPP and attaches an ETYPE-INFO2 hint in the error's
e-data. kerbad parses that hint through select_preferred_encryption_method() and asks
get_preferred_enctype() which enctype to retry with — and that function returned the first enctype
of the client's list that also appears in the server hint. The hint may name the very enctype the
KDC has just refused (RC4 is listed with an empty salt), so the retry repeated the rejected request.
The retry lives outside the try/except that caught the first refusal (kerbad/client.py:323), so the
second refusal was never handled and the whole call died with KDC_ERR_ETYPE_NOTSUPP.

## The fix

One function, kerbad/common/creds.py — KerberosCredential.get_preferred_enctype().

Before:

    def get_preferred_enctype(self, server_enctypes:List[EncryptionType]) -> EncryptionType:
        client_enctypes = self.get_supported_enctypes(as_int=False)
        common_enctypes = self.get_common_enctypes(server_enctypes)

        for c_enctype in client_enctypes:
            if c_enctype in common_enctypes:
                return c_enctype

After:

    def get_preferred_enctype(self, server_enctypes:List[EncryptionType]) -> EncryptionType:
        common_enctypes = self.get_common_enctypes(server_enctypes)

        # server_enctypes is ordered by the server itself (ETYPE-INFO2 lists the enctypes
        # the KDC accepts, strongest first), so its order beats the local one: the local
        # order can start with an enctype the KDC just refused (e.g. RC4 first)
        for s_enctype in server_enctypes:
            if s_enctype in common_enctypes:
                return s_enctype

Why this shape:

- ETYPE-INFO2 lists the enctypes the KDC accepts, strongest first, so the server's order is the only
  order that reflects what the KDC will really accept; with it the retry goes out as AES256.
- The enctype and its salt are taken from the same ETYPE-INFO2 entry, so they cannot get out of sync
  (machine accounts have different AES128/AES256 salts, and a wrong salt turns the failure into
  PREAUTH_FAILED, which hides the enctype trail).
- No other caller changes behaviour: S4U2proxy and similar calls pass their own list, and its order
  is still honoured.

Scope: kerbad/common/creds.py only, 6 insertions / 5 deletions. No dependency, version, ASN.1 or
crypto changes.

## How it was verified

- Enctype probe against the DC, one AS-REQ per enctype, creating nothing in AD: the KDC refused etype
  23 (RC4) with KDC_ERR_ETYPE_NOTSUPP, while its ETYPE-INFO2 hint listed 18 (AES256), 17 (AES128)
  and 23 (RC4, no salt); etypes 18 and 17 returned AS_REP.
- Environment control with a second, independent client (impacket): an RC4-only request
  (getTGT.py -hashes :<ntlm>) is refused with KDC_ERR_ETYPE_NOSUPP, an AES256-only request
  (getTGT.py -aesKey <hex>) succeeds — the refusal is a property of the account/DC, not of kerbad.
  The defect is in how kerbad handles that refusal.
- Before/after with the same command against the same target: before the change the log reads
  Failed to get TGT with etype ARCFOUR_HMAC_MD5, then
  Trying with supported suggested etype ARCFOUR_HMAC_MD5 and the call dies; after the change it reads
  Trying with supported suggested etype AES256_CTS_HMAC_SHA1_96, then Got valid TGT, and the
  collection completes.
- Tested against a lab Windows Server 2025 domain controller where RC4 is not usable for the account
  (bloodyAD 2.5.5 + kerbad 0.5.11).

## Using this fork

Install the fork into the same Python environment (virtualenv) that runs your tool. Install it after
the tool itself, otherwise pip will pull the PyPI kerbad as a dependency and shadow this one:

    pip install "kerbad @ git+https://github.com/daniladomoroshchenov/kerbad.git"

Pin the exact commit for a reproducible install:

    pip install "kerbad @ git+https://github.com/daniladomoroshchenov/kerbad.git@79cf629"

Editable install from a clone (convenient while testing further changes):

    git clone https://github.com/daniladomoroshchenov/kerbad.git
    cd kerbad
    pip install -e . --no-deps --no-build-isolation

Check that the patched copy is the one being imported — run this with the same interpreter that runs
your tool:

    python -c "import kerbad, kerbad.common.creds as c; print(kerbad.file)"
    python -c "import inspect, kerbad.common.creds as c; print('s_enctype' in inspect.getsource(c.KerberosCredential.get_preferred_enctype))"

The first command must print a path inside the fork's copy (not site-packages/kerbad of the released
package), the second must print True.

Roll back to the released version:

    pip install kerbad==0.5.11

Keeping in sync with upstream

    git remote add upstream https://github.com/CravateRouge/kerbad.git
    git fetch upstream
    git rebase upstream/main
