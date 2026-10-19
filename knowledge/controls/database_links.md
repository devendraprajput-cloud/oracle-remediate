controls: ch4.no_public_db_links, ch6.no_access_link_dollar
# Public database links

A public database link is usable by every account in the database, so the
remote credentials it stores are effectively shared with all users.
Hardening guides recommend removing public links and using private links owned
by the schema that needs them.

## Why rollback is not exact

Link credentials are stored encrypted in SYS.LINK$ and cannot be read back.
A rollback that recreates the link must supply the password again, so an
automated rollback can only use a placeholder unless the credential is held in
a vault. Dropping a link also invalidates dependent views and PL/SQL; they
revalidate on next use only if a link with the same name resolves again.

## Private links

A private database link is created in the schema of the connected user; there
is no syntax for creating a private link directly in another schema, so
re-creating links for an application schema is normally done while connected
as (or proxied to) that schema during a change window.
