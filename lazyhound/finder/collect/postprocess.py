"""Collection post-processing filters (applied after run/import/azure).

- ``drop_disabled`` prunes disabled principals (they can't authenticate).
- ``slim_objects`` trims object ``properties`` down to the fields any check,
  query, or display actually reads (the whitelist below is derived from the
  code's property accesses), dropping the long tail of BloodHound/LDAP
  attributes nothing uses. Both keep attack-path results identical while
  shrinking the collection.
"""
from __future__ import annotations

_UAC_ACCOUNTDISABLE = 0x0002

# Property keys (lower-cased) that the analyzer / scan / query / reports read,
# collected by grepping every props/properties access. Comparison is
# case-insensitive so BloodHound's lower-case keys and native LDAP's mixed-case
# keys both match. Anything NOT here is provably unread and safe to drop.
_KEEP_PROPS: frozenset = frozenset({
    # identity / naming
    "name", "samaccountname", "userprincipalname", "distinguishedname",
    "displayname", "objectcategory", "cn", "mail", "ad_name", "entra_name",
    "securityidentifier", "principalid", "identity",
    # account state / config
    "enabled", "accountenabled", "useraccountcontrol", "admincount",
    "accountexpires", "pwdlastset", "pwdneverexpires", "lastlogon",
    "lastlogontimestamp", "logoncount", "sensitive", "dontreqpreauth",
    "unconstraineddelegation", "usertype", "primarygroupid",
    # groups / membership / trusts
    "member", "grouptype", "grouptypes", "securityenabled", "membershiprule",
    "managedby", "manager", "department", "title", "description",
    "trustattributes", "trustdirection", "trusttype", "flatname",
    # delegation / gMSA / dMSA / encryption
    "allowedtodelegate", "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity", "msds-groupmsamembership",
    "msds-managedaccountprecededbylink", "msds-managedpasswordinterval",
    "msds-supportedencryptiontypes", "msds-oidtogrouplink",
    "serviceprincipalname", "serviceprincipalnames", "serviceprincipaltype",
    "sidhistory", "ms-ds-machineaccountquota", "machineaccountquota",
    # computers / OS
    "operatingsystem", "operatingsystemversion", "operatingsystemservicepack",
    "dnshostname",
    # ADCS (templates / CA)
    "mspki-certificate-name-flag", "mspki-enrollment-flag", "mspki-ra-signature",
    "pkiextendedkeyusage", "mspki-certificate-application-policy",
    "mspki-certificate-policy", "mspki-cert-template-oid",
    "mspki-template-schema-version", "mspki-enrollment-server",
    "mspki-enrollment-servers", "certificatetemplates", "hasenrollmentendpoint",
    "webenrollment", "flags", "gpcpath", "gpcfilesyspath", "gplink",
    # Entra roles / policies / config
    "rolename", "roletemplateid", "roledefinitionid", "approleid",
    "ishighvalue", "appid", "tenantid", "tenantname", "usertype",
    "authenticationtype", "verifieddomains", "state", "conditions",
    "grantcontrols", "identitysynchronization", "permissions",
    # hybrid-sync markers
    "onpremisessecurityidentifier", "onpremisessyncenabled", "on_prem_sid",
    "_onpremsid", "_onpremsyncenabled", "whencreated",
})


def _is_disabled(obj: dict) -> bool:
    cls = str(obj.get("object_class", "")).lower()
    props = obj.get("properties", {}) or {}
    if cls in ("user", "computer"):
        try:
            uac = int(props.get("userAccountControl", 0) or 0)
        except (ValueError, TypeError):
            uac = 0
        return bool(uac & _UAC_ACCOUNTDISABLE)
    if cls == "aad_user":
        # Entra: accountEnabled is False when disabled; absent/None => enabled.
        return props.get("accountEnabled") is False
    return False


def drop_disabled(data: dict) -> int:
    """Remove disabled AD (user/computer with UAC ACCOUNTDISABLE) and Entra
    (aad_user with accountEnabled=false) objects from ``data`` in place.

    Filters both the on-prem ``objects`` list and the ``azure_objects`` list (if
    present) and keeps ``meta.object_count`` honest. Returns the count removed.
    Dangling references (group members, ACE trustees) to removed principals are
    tolerated by the analyzer, which resolves missing SIDs to their raw value.
    """
    if not isinstance(data, dict):
        return 0
    removed = 0
    for key in ("objects", "azure_objects"):
        lst = data.get(key)
        if not isinstance(lst, list):
            continue
        kept = [o for o in lst if not _is_disabled(o)]
        removed += len(lst) - len(kept)
        data[key] = kept
    meta = data.get("meta")
    if isinstance(meta, dict) and "object_count" in meta:
        meta["object_count"] = len(data.get("objects", []))
    return removed


def slim_objects(data: dict) -> int:
    """Trim each object's ``properties`` to the keys any check/query/display
    reads (``_KEEP_PROPS``, case-insensitive), in place. Returns the number of
    property values dropped. Top-level fields (object_sid, object_class, name,
    dn, dacl, member lists, edges) are untouched, so attack-path results and
    ``info``/``search`` output are unchanged — only the unread long tail goes.
    """
    if not isinstance(data, dict):
        return 0
    removed = 0
    for key in ("objects", "azure_objects"):
        lst = data.get(key)
        if not isinstance(lst, list):
            continue
        for obj in lst:
            props = obj.get("properties")
            if not isinstance(props, dict):
                continue
            drop = [k for k in props if k.lower() not in _KEEP_PROPS]
            for k in drop:
                del props[k]
            removed += len(drop)
    return removed
