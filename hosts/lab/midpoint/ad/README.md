# winsvr01 AD resource (midPoint)

`01-ad-resource.xml` is the live "winsvr01 AD Resource"
(oid `caeced2c-a0bf-495b-9f46-69ba362ec7d6`) exported on 2026-11-24, **after**
adding an activation outbound to the default AD Account object type. Nothing in
the Nix config imports it; re-apply it the same way as `../agent/` and `../hr/`:

    curl -u administrator:<pw> -H 'Content-Type: application/xml' \
      -X PUT http://192.168.100.13:8080/midpoint/ws/rest/resources/caeced2c-a0bf-495b-9f46-69ba362ec7d6 \
      --data-binary @01-ad-resource.xml

## What was wrong

`schemaHandling` has two account object types:

  * intent `agent`   ("AI agent account")  - HAD an <activation> outbound
  * intent `default` ("AD Account")        - had NONE

So disabling an employee disabled the AI agents they sponsor, but left the
employee's own AD account fully enabled. For a leaver scenario that is exactly
backwards: the robots lose their access and the human keeps theirs.

Measured before the fix, after deactivating EMP0002 in HR:

    CN=Dingle Burg,OU=Lab Users   userAccountControl: 66048   <- still ENABLED
    CN=svc-agent-ops,OU=AI Agents userAccountControl: 514     <- disabled
    CN=svc-pam-review,OU=AI Agents userAccountControl: 514    <- disabled

## The fix

An activation outbound on the `default` object type that mirrors the focus's
effectiveStatus, so it covers administrative disable, expiry and archive alike:

    <activation>
      <administrativeStatus>
        <outbound>
          <name>user-lifecycle</name>
          <strength>strong</strength>
          <source><path>$focus/activation/effectiveStatus</path></source>
          <expression><script><code>
            import com.evolveum.midpoint.xml.ns._public.common.common_3.*
            effectiveStatus == ActivationStatusType.ENABLED
                ? ActivationStatusType.ENABLED
                : ActivationStatusType.DISABLED
          </code></script></expression>
        </outbound>
      </administrativeStatus>
    </activation>

## Verified 2026-11-24

Deactivate EMP0002 in the HR app, run HR CSV Reconciliation, then Recompute
AI Agents:

    CN=Dingle Burg                 userAccountControl: 66050  <- ACCOUNTDISABLE set
    CN=Solid Snake  (still active) userAccountControl: 512    <- untouched
    CN=svc-agent-ops               userAccountControl: 514
    CN=svc-pam-review              userAccountControl: 514

and an LDAP simple bind as dburg with the CORRECT password is refused with
AD's "account disabled" code rather than "bad password":

    ldap_bind: Invalid credentials (49)
      additional info: 80090308: LdapErr: DSID-0C090434,
      AcceptSecurityContext error, data 533      (533 = ACCOUNT_DISABLED)

Reactivating in HR reverses all of it: 66048 / 512 / 512, and the bind
succeeds again.

Depends on the HR activation inbound fix in `../hr/` - without it `active=false`
never reaches midPoint and this outbound has nothing to act on.
