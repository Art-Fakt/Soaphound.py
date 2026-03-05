from uuid import UUID
import logging
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects, _ldap_datetime_to_epoch, _parse_aces, dedupe_aces, filetime_to_unix, adws_objecttype_guid_map
from soaphound.ad.adws import WELL_KNOWN_SIDS
from soaphound.lib.utils import ADUtils

def parse_spn_targets(spn_list, value_to_id_cache, id_to_type_cache):
    """
    Parse SPN list to create SPNTargets with ObjectIdentifier and ObjectType.
    SPN format: service/hostname[:port][/servicename]
    """
    spn_targets = []
    if not spn_list:
        return spn_targets
    
    for spn in spn_list:
        try:
            parts = spn.split('/')
            if len(parts) < 2:
                continue
            
            # Extract hostname from SPN
            hostname_part = parts[1].split(':')[0]  # Remove port if present
            
            # Try to find the computer in cache by hostname
            # Look for the DN pattern with CN=hostname
            target_id = None
            target_type = "Computer"
            
            # Try variations of hostname lookups
            for dn_upper in value_to_id_cache.keys():
                if f"CN={hostname_part.upper()}," in dn_upper:
                    target_id = value_to_id_cache[dn_upper]
                    if target_id in id_to_type_cache:
                        type_int = id_to_type_cache[target_id]
                        type_map = {0: "User", 1: "Computer", 2: "Group"}
                        target_type = type_map.get(type_int, "Computer")
                    break
            
            if target_id:
                spn_targets.append({
                    "ObjectIdentifier": target_id,
                    "ObjectType": target_type
                })
        except Exception as e:
            logging.debug(f"Failed to parse SPN {spn}: {e}")
            continue
    
    return spn_targets

def parse_allowed_to_delegate(delegate_list, value_to_id_cache, id_to_type_cache):
    """
    Parse msDS-AllowedToDelegateTo to create AllowedToDelegate list.
    Format: service/hostname[:port]
    """
    allowed_to_delegate = []
    if not delegate_list:
        return allowed_to_delegate
    
    for target_spn in delegate_list:
        try:
            # Extract hostname from SPN
            parts = target_spn.split('/')
            if len(parts) < 2:
                continue
            
            hostname_part = parts[1].split(':')[0]  # Remove port if present
            
            # Try to find the computer in cache
            target_id = None
            target_type = "Computer"
            
            for dn_upper in value_to_id_cache.keys():
                if f"CN={hostname_part.upper()}," in dn_upper:
                    target_id = value_to_id_cache[dn_upper]
                    if target_id in id_to_type_cache:
                        type_int = id_to_type_cache[target_id]
                        type_map = {0: "User", 1: "Computer", 2: "Group"}
                        target_type = type_map.get(type_int, "Computer")
                    break
            
            if target_id:
                allowed_to_delegate.append({
                    "ObjectIdentifier": target_id,
                    "ObjectType": target_type
                })
        except Exception as e:
            logging.debug(f"Failed to parse delegation target {target_spn}: {e}")
            continue
    
    return allowed_to_delegate

def collect_users(ip=None, domain=None, username=None, auth=None, base_dn_override=None, adws_object_classes=None):
    """
    Collecte tous les objets utilisateurs (classiques, GMSA et SMSA selon support)
    """
    attributes = [
        "name", "objectGUID", "objectSid", "objectClass", "distinguishedName", "userAccountControl",
        "whenCreated", "description", "memberOf", "primaryGroupID", "sAMAccountName", "displayName", "mail",
        "title", "adminCount", "lastLogon", "lastLogonTimestamp", "pwdLastSet", "msDS-AllowedToDelegateTo",
        "servicePrincipalName", "sIDHistory", "whenChanged", "nTSecurityDescriptor",
        # Additional attributes for enhanced BloodHound analysis
        "userPassword", "homeDirectory", "logonScript", "profilePath", "scriptPath",
        "msDS-UserPasswordExpiryTimeComputed", "msDS-SupportedEncryptionTypes",
        "unicodePwd", "unixUserPassword", "msSFU30Password", "accountExpires"
    ]
    
    users = []

    # Classic users
    query_users = "(&(objectCategory=person)(objectClass=user))"
    users += pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query=query_users,
        attributes=attributes,
        base_dn_override=base_dn_override
    ).get("objects", [])

    #print("object_class" + str(adws_object_classes))
    # GMSA if supported and present in LDAP schema
    if adws_object_classes and "msDS-GroupManagedServiceAccount" in adws_object_classes:
        query_gmsa = "(objectClass=msDS-GroupManagedServiceAccount)"
        users += pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query_gmsa,
            attributes=attributes + ["msDS-GroupMSAMembership"],
            base_dn_override=base_dn_override
        ).get("objects", [])
    else:
        logging.debug("No support for GMSA, skipping GMSA query")
        
    # SMSA if supported and present in schema
    if adws_object_classes and "msDS-ManagedServiceAccount" in adws_object_classes:
        query_smsa = "(objectClass=msDS-ManagedServiceAccount)"
        users += pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query_smsa,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
    else:
        logging.debug("No support for SMSA, skipping SMSA query")
    
     # Normalization as in BloodHound.py

    for obj in users:

        # Check if objectClass is a string, convert it to a list
        oc = ADUtils.get_entry_property(obj, "objectClass", default=[])
        if isinstance(oc, str):
            obj["objectClass"] = [oc]
        elif oc is None:
            obj["objectClass"] = []
        # DN as a simple string
        dn = ADUtils.get_entry_property(obj, "distinguishedName", default="")
        if isinstance(dn, list):
            obj["distinguishedName"] = dn[0] if dn else ""
        # ID as upper-case GUID if objectGUID is present and of type bytes

        guid = ADUtils.get_entry_property(obj, "objectGUID")
        if isinstance(guid, bytes):
            try:
                from uuid import UUID
                obj["objectGUID"] = str(UUID(bytes_le=guid)).upper()
            except Exception:
                pass
    print(f"[INFO] Users collected : {len(users)}")
    return users




def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def append_bh_default_users(formatted_users, domain_name, domain_sid):
   
    
    formatted_users.append({
        "AllowedToDelegate": [],
        "ObjectIdentifier": f"{domain_name.upper()}-S-1-5-20",
        "PrimaryGroupSID": None,
        "ContainedBy": None,
        "Properties": {
            "domain": domain_name.upper(),
            "domainsid": domain_sid,
            "name": f"NT AUTHORITY@{domain_name.upper()}",
        },
        "Aces": [],
        "SPNTargets": [],
        "HasSIDHistory": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    })
    return formatted_users

def ensure_string(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except Exception:
            return None
    return str(val)

def format_users(
    users,
    domain,
    domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_users = []
    domain_upper = domain.upper()

    for obj in users:
        # Prepare the IDs
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        user_guid = obj.get("objectGUID")
        if isinstance(user_guid, bytes):
            user_guid = str(UUID(bytes_le=user_guid)).upper()
        elif isinstance(user_guid, str):
            user_guid = user_guid.upper()
        value_to_id_cache[dn.upper()] = user_guid

        sid_bytes = obj.get("objectSid")
        user_sid = None
        if isinstance(sid_bytes, bytes):
            user_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            user_sid = sid_bytes.upper()

        # Numeric properties and conversions
        def _get(obj, key):
            v = obj.get(key)
            if isinstance(v, list):
                v = v[0] if v else None
            return v

        user_account_control = int(_get(obj, "userAccountControl") or 0)
        admin_count = int(_get(obj, "adminCount") or 0)
        sAM = _get(obj, "sAMAccountName") or ""
        description = _get(obj, "description")
        displayname = _get(obj, "displayName")
        email = _get(obj, "mail")
        title = _get(obj, "title")
        homedirectory = _get(obj, "homeDirectory")
        logonscript = _get(obj, "logonScript")
        scriptpath = _get(obj, "scriptPath")
        profilepath = _get(obj, "profilePath")
        userpassword = _get(obj, "userPassword")
        unicodepassword = _get(obj, "unicodePwd")
        unixpassword = _get(obj, "unixUserPassword")
        sfupassword = _get(obj, "msSFU30Password")
        accountexpires = filetime_to_unix(obj.get("accountExpires"))
        msdsuserpasswordexpiry = filetime_to_unix(obj.get("msDS-UserPasswordExpiryTimeComputed"))
        supportedencryptiontypes = _get(obj, "msDS-SupportedEncryptionTypes")
        sidhistory = obj.get("sIDHistory", [])
        if not isinstance(sidhistory, list): sidhistory = []
        serviceprincipalnames = obj.get("servicePrincipalName", [])
        if not isinstance(serviceprincipalnames, list): serviceprincipalnames = []
        
        # Parse msDS-AllowedToDelegateTo for constrained delegation
        delegate_to = obj.get("msDS-AllowedToDelegateTo", [])
        if not isinstance(delegate_to, list):
            delegate_to = [delegate_to] if delegate_to else []
        
        isaclprotected = False  # Default value, updated if ACL is processed

        # ACEs on the user
        aces_user, isaclprotected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            user_sid,
            "User", object_type_guid_map=objecttype_guid_map
        )
        aces_user = dedupe_aces(aces_user)
        for ace in aces_user:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, domain_sid)

        # FILETIME -> Unix
        lastlogon = filetime_to_unix(obj.get("lastLogon"))
        lastlogontimestamp = filetime_to_unix(obj.get("lastLogonTimestamp"))
        if lastlogontimestamp == 0:
            lastlogontimestamp = -11644473600
        pwdlastset = filetime_to_unix(obj.get("pwdLastSet"))
        whencreated = filetime_to_unix(obj.get("whenCreated"))

        # Order and property names **exactly like BH**
        props = {
            "name": f"{sAM.upper()}@{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "highvalue": admin_count == 1,  
            "distinguishedname": dn.upper() if dn else None,
            "unconstraineddelegation": (user_account_control & 0x00080000) == 0x00080000,
            "trustedtoauth": (user_account_control & 0x01000000) == 0x01000000,
            "passwordnotreqd": (user_account_control & 0x00000020) == 0x00000020,
            "enabled": (user_account_control & 2) == 0,
            "lastlogon": lastlogon,
            "lastlogontimestamp": lastlogontimestamp,
            "pwdlastset": pwdlastset,
            "dontreqpreauth": (user_account_control & 0x00400000) == 0x00400000,
            "pwdneverexpires": (user_account_control & 0x00010000) == 0x00010000,
            "sensitive": (user_account_control & 0x00100000) == 0x00100000,
            "serviceprincipalnames": serviceprincipalnames,
            "hasspn": bool(serviceprincipalnames),
            "displayname": displayname if displayname else None,
            "email": email if email else None,
            "title": title if title else None,
            "homedirectory": homedirectory if homedirectory else None,
            "description": description if description else None,
            "userpassword": userpassword if userpassword else None,
            "admincount": admin_count == 1,
            "sidhistory": sidhistory,
            "whencreated": whencreated,
            "unixpassword": unixpassword if unixpassword else None,
            "unicodepassword": unicodepassword if unicodepassword else None,
            "logonscript": logonscript if logonscript else None,
            "scriptpath": scriptpath if scriptpath else None,
            "profilepath": profilepath if profilepath else None,
            "samaccountname": sAM,
            "sfupassword": sfupassword if sfupassword else None,
            "isaclprotected": isaclprotected,
            "accountexpires": accountexpires if accountexpires and accountexpires > 0 else None,
            "msdsuserpasswordexpiry": msdsuserpasswordexpiry if msdsuserpasswordexpiry and msdsuserpasswordexpiry > 0 else None,
            "supportedencryptiontypes": supportedencryptiontypes if supportedencryptiontypes else None,
        }

        # PRIMARY GROUP
        primary_group = obj.get("primaryGroupID")
        if isinstance(primary_group, list):
            primary_group = primary_group[0] if primary_group else None
        if primary_group:
            primary_sid = f"{domain_sid}-{primary_group}"
        else:
            primary_sid = None

        # Parse SPNs to create SPNTargets
        spn_targets = parse_spn_targets(serviceprincipalnames, value_to_id_cache, id_to_type_cache)
        
        # Parse AllowedToDelegateTo for constrained delegation
        allowed_to_delegate = parse_allowed_to_delegate(delegate_to, value_to_id_cache, id_to_type_cache)

        user_bh_entry = {
            "AllowedToDelegate": allowed_to_delegate,
            "ObjectIdentifier": user_sid,
            "PrimaryGroupSID": primary_sid,
            "ContainedBy": None,
            "Properties": props,
            "Aces": aces_user,
            "SPNTargets": spn_targets,
            "HasSIDHistory": [],
            "IsDeleted": False,
            "IsACLProtected": isaclprotected,
        }
        formatted_users.append(user_bh_entry)

    formatted_users = append_bh_default_users(formatted_users, domain, domain_sid)

    return {
        "data": formatted_users,
        "meta": {
            "type": "users",
            "count": len(formatted_users),
            "version": 6
        }
    }



