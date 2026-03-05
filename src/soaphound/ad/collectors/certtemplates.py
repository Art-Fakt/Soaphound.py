from uuid import UUID
import logging
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, dedupe_aces
from soaphound.ad.adws import WELL_KNOWN_SIDS
from soaphound.lib.utils import ADUtils

def collect_cert_templates(ip=None, domain=None, username=None, auth=None, base_dn_override=None):
    """
    Collecte tous les templates de certificats PKI (pKICertificateTemplate)
    """
    attributes = [
        "name", "objectGUID", "distinguishedName", "objectClass",
        "nTSecurityDescriptor", "whenCreated", "whenChanged",
        "displayName", "cn", "flags",
        "pKIExtendedKeyUsage", "pKICertificateNameFlag", "pKIEnrollmentFlag",
        "pKIPrivateKeyFlag", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
        "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size",
        "msPKI-Template-Schema-Version", "msPKI-Template-Minor-Revision",
        "msPKI-Cert-Template-OID", "msPKI-Certificate-Application-Policy",
        "msPKI-Certificate-Policy", "msPKI-RA-Signature",
        "pKIDefaultKeySpec", "pKIMaxIssuingDepth", "pKIExpirationPeriod",
        "pKIOverlapPeriod", "pKIKeyUsage", "revision"
    ]
    
    # Configuration naming context for certificate templates
    config_dn = f"CN=Configuration,{base_dn_override}" if base_dn_override else None
    
    query = "(objectClass=pKICertificateTemplate)"
    raw_objects = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query=query,
        attributes=attributes,
        base_dn_override=config_dn
    ).get("objects", [])

    # Normalization
    for obj in raw_objects:
        oc = ADUtils.get_entry_property(obj, "objectClass", default=[])
        if isinstance(oc, str):
            obj["objectClass"] = [oc]
        elif oc is None:
            obj["objectClass"] = []
        
        dn = ADUtils.get_entry_property(obj, "distinguishedName", default="")
        if isinstance(dn, list):
            obj["distinguishedName"] = dn[0] if dn else ""
        
        guid = ADUtils.get_entry_property(obj, "objectGUID")
        if isinstance(guid, bytes):
            try:
                obj["objectGUID"] = str(UUID(bytes_le=guid)).upper()
            except Exception:
                pass
    
    print(f"[INFO] Certificate Templates collected : {len(raw_objects)}")
    return raw_objects


def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid


def format_cert_templates(
    cert_templates,
    domain,
    domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    """
    Format certificate templates for BloodHound
    """
    formatted_templates = []
    domain_upper = domain.upper()

    for obj in cert_templates:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        
        cert_guid = obj.get("objectGUID")
        if isinstance(cert_guid, bytes):
            cert_guid = str(UUID(bytes_le=cert_guid)).upper()
        elif isinstance(cert_guid, str):
            cert_guid = cert_guid.upper()

        def _get(obj, key):
            v = obj.get(key)
            if isinstance(v, list):
                v = v[0] if v else None
            return v

        name = _get(obj, "name") or _get(obj, "cn") or ""
        displayname = _get(obj, "displayName") or name
        
        # Parse flags
        enrollment_flag = int(_get(obj, "msPKI-Enrollment-Flag") or _get(obj, "pKIEnrollmentFlag") or 0)
        certificate_name_flag = int(_get(obj, "msPKI-Certificate-Name-Flag") or _get(obj, "pKICertificateNameFlag") or 0)
        private_key_flag = int(_get(obj, "msPKI-Private-Key-Flag") or _get(obj, "pKIPrivateKeyFlag") or 0)
        
        # Important security flags
        requires_manager_approval = (enrollment_flag & 0x00000002) != 0  # CT_FLAG_PEND_ALL_REQUESTS
        client_auth = False
        
        eku = obj.get("pKIExtendedKeyUsage", [])
        if not isinstance(eku, list):
            eku = [eku] if eku else []
        
        # Check for client authentication EKU
        if "1.3.6.1.5.5.7.3.2" in eku:  # Client Authentication
            client_auth = True
        
        authorized_signatures = int(_get(obj, "msPKI-RA-Signature") or 0)
        schema_version = int(_get(obj, "msPKI-Template-Schema-Version") or 1)
        
        # Parse ACEs
        aces_cert, isaclprotected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            cert_guid,
            "CertTemplate",
            object_type_guid_map=objecttype_guid_map
        )
        aces_cert = dedupe_aces(aces_cert)
        for ace in aces_cert:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, domain_sid)

        whencreated = filetime_to_unix(obj.get("whenCreated"))

        props = {
            "name": f"{name.upper()}@{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": dn.upper() if dn else None,
            "displayname": displayname,
            "certificatenameflag": certificate_name_flag,
            "enrollmentflag": enrollment_flag,
            "requiresmanagerapproval": requires_manager_approval,
            "certificateapplicationpolicy": eku,
            "effectiveekus": eku,
            "authorizedsignatures": authorized_signatures,
            "schemaversion": schema_version,
            "validityperiod": _get(obj, "pKIExpirationPeriod"),
            "renewalperiod": _get(obj, "pKIOverlapPeriod"),
            "whencreated": whencreated,
        }

        cert_bh_entry = {
            "ObjectIdentifier": cert_guid,
            "Properties": props,
            "Aces": aces_cert,
            "IsDeleted": False,
            "IsACLProtected": isaclprotected,
        }
        formatted_templates.append(cert_bh_entry)

    return {
        "data": formatted_templates,
        "meta": {
            "type": "certtemplates",
            "count": len(formatted_templates),
            "version": 6
        }
    }
