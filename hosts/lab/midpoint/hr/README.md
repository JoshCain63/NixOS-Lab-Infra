# HR CSV resource (midPoint)

`01-hr-csv-resource.xml` is the live HR CSV Connector resource
(oid `6195997a-438c-4514-a166-c03a2e4a1a1d`) exported on 2026-11-24, **after**
fixing its activation mapping. It is kept here so the fix survives rebuilding
midPoint from scratch; nothing in the Nix config imports it, so apply it the
same way as the files in `../agent/`:

    curl -u administrator:<pw> -H 'Content-Type: application/xml' \
      -X PUT http://192.168.100.13:8080/midpoint/ws/rest/resources/6195997a-438c-4514-a166-c03a2e4a1a1d \
      --data-binary @01-hr-csv-resource.xml

## What was wrong

The HR `active` column never reached a user's activation. `pcheemster` had been
`active=false` in employees.csv since the lab was built and was still enabled in
midPoint, and deactivating an employee in the HR app did nothing - which made
scenario 6 ("sponsor leaves") untestable through its documented path.

The original mapping was:

    <activation><administrativeStatus>
      <inbound id="21"><expression><asIs/></expression></inbound>
      <inbound id="22">
        <name>DetermineIfEnabled</name>
        <condition><script><code>input == 'true' ? 'ENABLED' : 'DISABLED'</code></script></condition>
      </inbound>
    </administrativeStatus></activation>

Two faults:

1. The ENABLED/DISABLED logic is in a `<condition>`. A condition only decides
   whether a mapping applies; its return value is thrown away. So nothing was
   ever written to administrativeStatus.
2. Mapping 21's `<asIs/>` has no source. The CSV connector exposes `active` as
   an ordinary attribute and the resource declares no simulated-activation
   capability, so there is no native activation value to copy.

## The fix

A plain attribute inbound, which is the idiomatic form when the resource has no
simulated activation capability:

    <attribute>
      <ref>ri:active</ref>
      <inbound>
        <name>DetermineIfEnabled</name>
        <strength>strong</strength>
        <expression><script><code>input == 'true' ? 'enabled' : 'disabled'</code></script></expression>
        <target><path>activation/administrativeStatus</path></target>
      </inbound>
    </attribute>

The enum values must be **lowercase**. With 'ENABLED' every object fails with

    No enum value 'ENABLED' in class ...ActivationStatusType
      in expression in mapping 'DetermineIfEnabled' in inbound expression
      for attributes/active in resource:...(HR CSV Connector)

Verified 2026-11-24: deactivating EMP0002 in the HR app disables the user in
midPoint, which disables svc-agent-ops and svc-pam-review in AD
(userAccountControl 514) via the Recompute AI Agents task, and both agents then
fail closed at boundary_login. Reactivating restores all of it.
