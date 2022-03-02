
package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

var apiAuthCmd = &cobra.Command{
  Use:   "ApiAuth",
  Short: "API Authentication",
  Long: "API Authentication",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ApiAuth called")
  },
}


var loginCmd = &cobra.Command{
  Use:   "login",
  Short: "Login",
  Long: `### Present client credentials to obtain an authorization token

Looker API implements the OAuth2 [Resource Owner Password Credentials Grant](https://looker.com/docs/r/api/outh2_resource_owner_pc) pattern.
The client credentials required for this login must be obtained by creating an API3 key on a user account
in the Looker Admin console. The API3 key consists of a public `client_id` and a private `client_secret`.

The access token returned by `login` must be used in the HTTP Authorization header of subsequent
API requests, like this:
```
Authorization: token 4QDkCyCtZzYgj4C2p2cj3csJH7zqS5RzKs2kTnG4
```
Replace "4QDkCy..." with the `access_token` value returned by `login`.
The word `token` is a string literal and must be included exactly as shown.

This function can accept `client_id` and `client_secret` parameters as URL query params or as www-form-urlencoded params in the body of the HTTP request. Since there is a small risk that URL parameters may be visible to intermediate nodes on the network route (proxies, routers, etc), passing credentials in the body of the request is considered more secure than URL params.

Example of passing credentials in the HTTP request body:
````
POST HTTP /login
Content-Type: application/x-www-form-urlencoded

client_id=CGc9B7v7J48dQSJvxxx&client_secret=nNVS9cSS3xNpSC9JdsBvvvvv
````

### Best Practice:
Always pass credentials in body params. Pass credentials in URL query params **only** when you cannot pass body params due to application, tool, or other limitations.

For more information and detailed examples of Looker API authorization, see [How to Authenticate to Looker API3](https://github.com/looker/looker-sdk-ruby/blob/master/authentication.md).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("login called")
  },
}


var login_userCmd = &cobra.Command{
  Use:   "login_user",
  Short: "Login user",
  Long: `### Create an access token that runs as a given user.

This can only be called by an authenticated admin user. It allows that admin to generate a new
authentication token for the user with the given user id. That token can then be used for subsequent
API calls - which are then performed *as* that target user.

The target user does *not* need to have a pre-existing API client_id/client_secret pair. And, no such
credentials are created by this call.

This allows for building systems where api user authentication for an arbitrary number of users is done
outside of Looker and funneled through a single 'service account' with admin permissions. Note that a
new access token is generated on each call. If target users are going to be making numerous API
calls in a short period then it is wise to cache this authentication token rather than call this before
each of those API calls.

See 'login' for more detail on the access token and how to use it.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("login_user called")
  },
}


var logoutCmd = &cobra.Command{
  Use:   "logout",
  Short: "Logout",
  Long: `### Logout of the API and invalidate the current access token.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("logout called")
  },
}




var authCmd = &cobra.Command{
  Use:   "Auth",
  Short: "Manage User Authentication Configuration",
  Long: "Manage User Authentication Configuration",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Auth called")
  },
}


var create_sso_embed_urlCmd = &cobra.Command{
  Use:   "create_sso_embed_url",
  Short: "Create SSO Embed Url",
  Long: `### Create SSO Embed URL

Creates an SSO embed URL and cryptographically signs it with an embed secret.
This signed URL can then be used to instantiate a Looker embed session in a PBL web application.
Do not make any modifications to this URL - any change may invalidate the signature and
cause the URL to fail to load a Looker embed session.

A signed SSO embed URL can only be used once. After it has been used to request a page from the
Looker server, the URL is invalid. Future requests using the same URL will fail. This is to prevent
'replay attacks'.

The `target_url` property must be a complete URL of a Looker UI page - scheme, hostname, path and query params.
To load a dashboard with id 56 and with a filter of `Date=1 years`, the looker URL would look like `https:/myname.looker.com/dashboards/56?Date=1%20years`.
The best way to obtain this target_url is to navigate to the desired Looker page in your web browser,
copy the URL shown in the browser address bar and paste it into the `target_url` property as a quoted string value in this API request.

Permissions for the embed user are defined by the groups in which the embed user is a member (group_ids property)
and the lists of models and permissions assigned to the embed user.
At a minimum, you must provide values for either the group_ids property, or both the models and permissions properties.
These properties are additive; an embed user can be a member of certain groups AND be granted access to models and permissions.

The embed user's access is the union of permissions granted by the group_ids, models, and permissions properties.

This function does not strictly require all group_ids, user attribute names, or model names to exist at the moment the
SSO embed url is created. Unknown group_id, user attribute names or model names will be passed through to the output URL.
To diagnose potential problems with an SSO embed URL, you can copy the signed URL into the Embed URI Validator text box in `<your looker instance>/admin/embed`.

The `secret_id` parameter is optional. If specified, its value must be the id of an active secret defined in the Looker instance.
if not specified, the URL will be signed using the newest active secret defined in the Looker instance.

#### Security Note
Protect this signed URL as you would an access token or password credentials - do not write
it to disk, do not pass it to a third party, and only pass it through a secure HTTPS
encrypted transport.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_sso_embed_url called")
  },
}


var ldap_configCmd = &cobra.Command{
  Use:   "ldap_config",
  Short: "Get LDAP Configuration",
  Long: `### Get the LDAP configuration.

Looker can be optionally configured to authenticate users against an Active Directory or other LDAP directory server.
LDAP setup requires coordination with an administrator of that directory server.

Only Looker administrators can read and update the LDAP configuration.

Configuring LDAP impacts authentication for all users. This configuration should be done carefully.

Looker maintains a single LDAP configuration. It can be read and updated.       Updates only succeed if the new state will be valid (in the sense that all required fields are populated);       it is up to you to ensure that the configuration is appropriate and correct).

LDAP is enabled or disabled for Looker using the **enabled** field.

Looker will never return an **auth_password** field. That value can be set, but never retrieved.

See the [Looker LDAP docs](https://www.looker.com/docs/r/api/ldap_setup) for additional information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ldap_config called")
  },
}


var update_ldap_configCmd = &cobra.Command{
  Use:   "update_ldap_config",
  Short: "Update LDAP Configuration",
  Long: `### Update the LDAP configuration.

Configuring LDAP impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the LDAP configuration.

LDAP is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any LDAP setting changes be tested using the APIs below before being set globally.

See the [Looker LDAP docs](https://www.looker.com/docs/r/api/ldap_setup) for additional information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_ldap_config called")
  },
}


var test_ldap_config_connectionCmd = &cobra.Command{
  Use:   "test_ldap_config_connection",
  Short: "Test LDAP Connection",
  Long: `### Test the connection settings for an LDAP configuration.

This tests that the connection is possible given a connection_host and connection_port.

**connection_host** and **connection_port** are required. **connection_tls** is optional.

Example:
```json
{
  "connection_host": "ldap.example.com",
  "connection_port": "636",
  "connection_tls": true
}
```

No authentication to the LDAP server is attempted.

The active LDAP settings are not modified.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ldap_config_connection called")
  },
}


var test_ldap_config_authCmd = &cobra.Command{
  Use:   "test_ldap_config_auth",
  Short: "Test LDAP Auth",
  Long: `### Test the connection authentication settings for an LDAP configuration.

This tests that the connection is possible and that a 'server' account to be used by Looker can       authenticate to the LDAP server given connection and authentication information.

**connection_host**, **connection_port**, and **auth_username**, are required.       **connection_tls** and **auth_password** are optional.

Example:
```json
{
  "connection_host": "ldap.example.com",
  "connection_port": "636",
  "connection_tls": true,
  "auth_username": "cn=looker,dc=example,dc=com",
  "auth_password": "secret"
}
```

Looker will never return an **auth_password**. If this request omits the **auth_password** field, then       the **auth_password** value from the active config (if present) will be used for the test.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ldap_config_auth called")
  },
}


var test_ldap_config_user_infoCmd = &cobra.Command{
  Use:   "test_ldap_config_user_info",
  Short: "Test LDAP User Info",
  Long: `### Test the user authentication settings for an LDAP configuration without authenticating the user.

This test will let you easily test the mapping for user properties and roles for any user without      needing to authenticate as that user.

This test accepts a full LDAP configuration along with a username and attempts to find the full info      for the user from the LDAP server without actually authenticating the user. So, user password is not      required.The configuration is validated before attempting to contact the server.

**test_ldap_user** is required.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ldap_config_user_info called")
  },
}


var test_ldap_config_user_authCmd = &cobra.Command{
  Use:   "test_ldap_config_user_auth",
  Short: "Test LDAP User Auth",
  Long: `### Test the user authentication settings for an LDAP configuration.

This test accepts a full LDAP configuration along with a username/password pair and attempts to       authenticate the user with the LDAP server. The configuration is validated before attempting the       authentication.

Looker will never return an **auth_password**. If this request omits the **auth_password** field, then       the **auth_password** value from the active config (if present) will be used for the test.

**test_ldap_user** and **test_ldap_password** are required.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ldap_config_user_auth called")
  },
}


var oidc_configCmd = &cobra.Command{
  Use:   "oidc_config",
  Short: "Get OIDC Configuration",
  Long: `### Get the OIDC configuration.

Looker can be optionally configured to authenticate users against an OpenID Connect (OIDC)
authentication server. OIDC setup requires coordination with an administrator of that server.

Only Looker administrators can read and update the OIDC configuration.

Configuring OIDC impacts authentication for all users. This configuration should be done carefully.

Looker maintains a single OIDC configuation. It can be read and updated.       Updates only succeed if the new state will be valid (in the sense that all required fields are populated);       it is up to you to ensure that the configuration is appropriate and correct).

OIDC is enabled or disabled for Looker using the **enabled** field.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oidc_config called")
  },
}


var update_oidc_configCmd = &cobra.Command{
  Use:   "update_oidc_config",
  Short: "Update OIDC Configuration",
  Long: `### Update the OIDC configuration.

Configuring OIDC impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the OIDC configuration.

OIDC is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any OIDC setting changes be tested using the APIs below before being set globally.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_oidc_config called")
  },
}


var oidc_test_configCmd = &cobra.Command{
  Use:   "oidc_test_config",
  Short: "Get OIDC Test Configuration",
  Long: `### Get a OIDC test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oidc_test_config called")
  },
}


var delete_oidc_test_configCmd = &cobra.Command{
  Use:   "delete_oidc_test_config",
  Short: "Delete OIDC Test Configuration",
  Long: `### Delete a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_oidc_test_config called")
  },
}


var create_oidc_test_configCmd = &cobra.Command{
  Use:   "create_oidc_test_config",
  Short: "Create OIDC Test Configuration",
  Long: `### Create a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_oidc_test_config called")
  },
}


var password_configCmd = &cobra.Command{
  Use:   "password_config",
  Short: "Get Password Config",
  Long: `### Get password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("password_config called")
  },
}


var update_password_configCmd = &cobra.Command{
  Use:   "update_password_config",
  Short: "Update Password Config",
  Long: `### Update password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_password_config called")
  },
}


var force_password_reset_at_next_login_for_all_usersCmd = &cobra.Command{
  Use:   "force_password_reset_at_next_login_for_all_users",
  Short: "Force password reset",
  Long: `### Force all credentials_email users to reset their login passwords upon their next login.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("force_password_reset_at_next_login_for_all_users called")
  },
}


var saml_configCmd = &cobra.Command{
  Use:   "saml_config",
  Short: "Get SAML Configuration",
  Long: `### Get the SAML configuration.

Looker can be optionally configured to authenticate users against a SAML authentication server.
SAML setup requires coordination with an administrator of that server.

Only Looker administrators can read and update the SAML configuration.

Configuring SAML impacts authentication for all users. This configuration should be done carefully.

Looker maintains a single SAML configuation. It can be read and updated.       Updates only succeed if the new state will be valid (in the sense that all required fields are populated);       it is up to you to ensure that the configuration is appropriate and correct).

SAML is enabled or disabled for Looker using the **enabled** field.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("saml_config called")
  },
}


var update_saml_configCmd = &cobra.Command{
  Use:   "update_saml_config",
  Short: "Update SAML Configuration",
  Long: `### Update the SAML configuration.

Configuring SAML impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the SAML configuration.

SAML is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any SAML setting changes be tested using the APIs below before being set globally.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_saml_config called")
  },
}


var saml_test_configCmd = &cobra.Command{
  Use:   "saml_test_config",
  Short: "Get SAML Test Configuration",
  Long: `### Get a SAML test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("saml_test_config called")
  },
}


var delete_saml_test_configCmd = &cobra.Command{
  Use:   "delete_saml_test_config",
  Short: "Delete SAML Test Configuration",
  Long: `### Delete a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_saml_test_config called")
  },
}


var create_saml_test_configCmd = &cobra.Command{
  Use:   "create_saml_test_config",
  Short: "Create SAML Test Configuration",
  Long: `### Create a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_saml_test_config called")
  },
}


var parse_saml_idp_metadataCmd = &cobra.Command{
  Use:   "parse_saml_idp_metadata",
  Short: "Parse SAML IdP XML",
  Long: `### Parse the given xml as a SAML IdP metadata document and return the result.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("parse_saml_idp_metadata called")
  },
}


var fetch_and_parse_saml_idp_metadataCmd = &cobra.Command{
  Use:   "fetch_and_parse_saml_idp_metadata",
  Short: "Parse SAML IdP Url",
  Long: `### Fetch the given url and parse it as a SAML IdP metadata document and return the result.
Note that this requires that the url be public or at least at a location where the Looker instance
can fetch it without requiring any special authentication.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetch_and_parse_saml_idp_metadata called")
  },
}


var session_configCmd = &cobra.Command{
  Use:   "session_config",
  Short: "Get Session Config",
  Long: `### Get session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("session_config called")
  },
}


var update_session_configCmd = &cobra.Command{
  Use:   "update_session_config",
  Short: "Update Session Config",
  Long: `### Update session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_session_config called")
  },
}


var all_user_login_lockoutsCmd = &cobra.Command{
  Use:   "all_user_login_lockouts",
  Short: "Get All User Login Lockouts",
  Long: `### Get currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_login_lockouts called")
  },
}


var search_user_login_lockoutsCmd = &cobra.Command{
  Use:   "search_user_login_lockouts",
  Short: "Search User Login Lockouts",
  Long: `### Search currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_user_login_lockouts called")
  },
}


var delete_user_login_lockoutCmd = &cobra.Command{
  Use:   "delete_user_login_lockout",
  Short: "Delete User Login Lockout",
  Long: `### Removes login lockout for the associated user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_login_lockout called")
  },
}




var colorCollectionCmd = &cobra.Command{
  Use:   "ColorCollection",
  Short: "Manage Color Collections",
  Long: "Manage Color Collections",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ColorCollection called")
  },
}


var all_color_collectionsCmd = &cobra.Command{
  Use:   "all_color_collections",
  Short: "Get all Color Collections",
  Long: `### Get an array of all existing Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_color_collections called")
  },
}


var create_color_collectionCmd = &cobra.Command{
  Use:   "create_color_collection",
  Short: "Create ColorCollection",
  Long: `### Create a custom color collection with the specified information

Creates a new custom color collection object, returning the details, including the created id.

**Update** an existing color collection with [Update Color Collection](#!/ColorCollection/update_color_collection)

**Permanently delete** an existing custom color collection with [Delete Color Collection](#!/ColorCollection/delete_color_collection)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_color_collection called")
  },
}


var color_collections_customCmd = &cobra.Command{
  Use:   "color_collections_custom",
  Short: "Get all Custom Color Collections",
  Long: `### Get an array of all existing **Custom** Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("color_collections_custom called")
  },
}


var color_collections_standardCmd = &cobra.Command{
  Use:   "color_collections_standard",
  Short: "Get all Standard Color Collections",
  Long: `### Get an array of all existing **Standard** Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("color_collections_standard called")
  },
}


var default_color_collectionCmd = &cobra.Command{
  Use:   "default_color_collection",
  Short: "Get Default Color Collection",
  Long: `### Get the default color collection

Use this to retrieve the default Color Collection.

Set the default color collection with [ColorCollection](#!/ColorCollection/set_default_color_collection)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("default_color_collection called")
  },
}


var set_default_color_collectionCmd = &cobra.Command{
  Use:   "set_default_color_collection",
  Short: "Set Default Color Collection",
  Long: `### Set the global default Color Collection by ID

Returns the new specified default Color Collection object.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_default_color_collection called")
  },
}


var color_collectionCmd = &cobra.Command{
  Use:   "color_collection",
  Short: "Get Color Collection by ID",
  Long: `### Get a Color Collection by ID

Use this to retrieve a specific Color Collection.
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("color_collection called")
  },
}


var update_color_collectionCmd = &cobra.Command{
  Use:   "update_color_collection",
  Short: "Update Custom Color collection",
  Long: `### Update a custom color collection by id.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_color_collection called")
  },
}


var delete_color_collectionCmd = &cobra.Command{
  Use:   "delete_color_collection",
  Short: "Delete ColorCollection",
  Long: `### Delete a custom color collection by id

This operation permanently deletes the identified **Custom** color collection.

**Standard** color collections cannot be deleted

Because multiple color collections can have the same label, they must be deleted by ID, not name.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return `Not Found` (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_color_collection called")
  },
}




var configCmd = &cobra.Command{
  Use:   "Config",
  Short: "Manage General Configuration",
  Long: "Manage General Configuration",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Config called")
  },
}


var backup_configurationCmd = &cobra.Command{
  Use:   "backup_configuration",
  Short: "Get Backup Configuration",
  Long: `### WARNING: The Looker internal database backup function has been deprecated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("backup_configuration called")
  },
}


var update_backup_configurationCmd = &cobra.Command{
  Use:   "update_backup_configuration",
  Short: "Update Backup Configuration",
  Long: `### WARNING: The Looker internal database backup function has been deprecated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_backup_configuration called")
  },
}


var cloud_storage_configurationCmd = &cobra.Command{
  Use:   "cloud_storage_configuration",
  Short: "Get Cloud Storage",
  Long: `Get the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("cloud_storage_configuration called")
  },
}


var update_cloud_storage_configurationCmd = &cobra.Command{
  Use:   "update_cloud_storage_configuration",
  Short: "Update Cloud Storage",
  Long: `Update the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_cloud_storage_configuration called")
  },
}


var custom_welcome_emailCmd = &cobra.Command{
  Use:   "custom_welcome_email",
  Short: "Get Custom Welcome Email",
  Long: `### Get the current status and content of custom welcome emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("custom_welcome_email called")
  },
}


var update_custom_welcome_emailCmd = &cobra.Command{
  Use:   "update_custom_welcome_email",
  Short: "Update Custom Welcome Email Content",
  Long: `Update custom welcome email setting and values. Optionally send a test email with the new content to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_custom_welcome_email called")
  },
}


var update_custom_welcome_email_testCmd = &cobra.Command{
  Use:   "update_custom_welcome_email_test",
  Short: "Send a test welcome email to the currently logged in user with the supplied content ",
  Long: `Requests to this endpoint will send a welcome email with the custom content provided in the body to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_custom_welcome_email_test called")
  },
}


var digest_emails_enabledCmd = &cobra.Command{
  Use:   "digest_emails_enabled",
  Short: "Get Digest_emails",
  Long: `### Retrieve the value for whether or not digest emails is enabled
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("digest_emails_enabled called")
  },
}


var update_digest_emails_enabledCmd = &cobra.Command{
  Use:   "update_digest_emails_enabled",
  Short: "Update Digest_emails",
  Long: `### Update the setting for enabling/disabling digest emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_digest_emails_enabled called")
  },
}


var create_digest_email_sendCmd = &cobra.Command{
  Use:   "create_digest_email_send",
  Short: "Deliver digest email contents",
  Long: `### Trigger the generation of digest email records and send them to Looker's internal system. This does not send
any actual emails, it generates records containing content which may be of interest for users who have become inactive.
Emails will be sent at a later time from Looker's internal system if the Digest Emails feature is enabled in settings.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_digest_email_send called")
  },
}


var internal_help_resources_contentCmd = &cobra.Command{
  Use:   "internal_help_resources_content",
  Short: "Get Internal Help Resources Content",
  Long: `### Set the menu item name and content for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internal_help_resources_content called")
  },
}


var update_internal_help_resources_contentCmd = &cobra.Command{
  Use:   "update_internal_help_resources_content",
  Short: "Update internal help resources content",
  Long: `Update internal help resources content
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_internal_help_resources_content called")
  },
}


var internal_help_resourcesCmd = &cobra.Command{
  Use:   "internal_help_resources",
  Short: "Get Internal Help Resources",
  Long: `### Get and set the options for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internal_help_resources called")
  },
}


var update_internal_help_resourcesCmd = &cobra.Command{
  Use:   "update_internal_help_resources",
  Short: "Update internal help resources configuration",
  Long: `Update internal help resources settings
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_internal_help_resources called")
  },
}


var all_legacy_featuresCmd = &cobra.Command{
  Use:   "all_legacy_features",
  Short: "Get All Legacy Features",
  Long: `### Get all legacy features.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_legacy_features called")
  },
}


var legacy_featureCmd = &cobra.Command{
  Use:   "legacy_feature",
  Short: "Get Legacy Feature",
  Long: `### Get information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("legacy_feature called")
  },
}


var update_legacy_featureCmd = &cobra.Command{
  Use:   "update_legacy_feature",
  Short: "Update Legacy Feature",
  Long: `### Update information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_legacy_feature called")
  },
}


var all_localesCmd = &cobra.Command{
  Use:   "all_locales",
  Short: "Get All Locales",
  Long: `### Get a list of locales that Looker supports.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_locales called")
  },
}


var all_timezonesCmd = &cobra.Command{
  Use:   "all_timezones",
  Short: "Get All Timezones",
  Long: `### Get a list of timezones that Looker supports (e.g. useful for scheduling tasks).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_timezones called")
  },
}


var versionsCmd = &cobra.Command{
  Use:   "versions",
  Short: "Get ApiVersion",
  Long: `### Get information about all API versions supported by this Looker instance.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("versions called")
  },
}


var whitelabel_configurationCmd = &cobra.Command{
  Use:   "whitelabel_configuration",
  Short: "Get Whitelabel configuration",
  Long: `### This feature is enabled only by special license.
### Gets the whitelabel configuration, which includes hiding documentation links, custom favicon uploading, etc.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("whitelabel_configuration called")
  },
}


var update_whitelabel_configurationCmd = &cobra.Command{
  Use:   "update_whitelabel_configuration",
  Short: "Update Whitelabel configuration",
  Long: `### Update the whitelabel configuration
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_whitelabel_configuration called")
  },
}




var connectionCmd = &cobra.Command{
  Use:   "Connection",
  Short: "Manage Database Connections",
  Long: "Manage Database Connections",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Connection called")
  },
}


var all_connectionsCmd = &cobra.Command{
  Use:   "all_connections",
  Short: "Get All Connections",
  Long: `### Get information about all connections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_connections called")
  },
}


var create_connectionCmd = &cobra.Command{
  Use:   "create_connection",
  Short: "Create Connection",
  Long: `### Create a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_connection called")
  },
}


var connectionCmd = &cobra.Command{
  Use:   "connection",
  Short: "Get Connection",
  Long: `### Get information about a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection called")
  },
}


var update_connectionCmd = &cobra.Command{
  Use:   "update_connection",
  Short: "Update Connection",
  Long: `### Update a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_connection called")
  },
}


var delete_connectionCmd = &cobra.Command{
  Use:   "delete_connection",
  Short: "Delete Connection",
  Long: `### Delete a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_connection called")
  },
}


var delete_connection_overrideCmd = &cobra.Command{
  Use:   "delete_connection_override",
  Short: "Delete Connection Override",
  Long: `### Delete a connection override.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_connection_override called")
  },
}


var test_connectionCmd = &cobra.Command{
  Use:   "test_connection",
  Short: "Test Connection",
  Long: `### Test an existing connection.

Note that a connection's 'dialect' property has a 'connection_tests' property that lists the
specific types of tests that the connection supports.

This API is rate limited.

Unsupported tests in the request will be ignored.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_connection called")
  },
}


var test_connection_configCmd = &cobra.Command{
  Use:   "test_connection_config",
  Short: "Test Connection Configuration",
  Long: `### Test a connection configuration.

Note that a connection's 'dialect' property has a 'connection_tests' property that lists the
specific types of tests that the connection supports.

This API is rate limited.

Unsupported tests in the request will be ignored.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_connection_config called")
  },
}


var all_dialect_infosCmd = &cobra.Command{
  Use:   "all_dialect_infos",
  Short: "Get All Dialect Infos",
  Long: `### Get information about all dialects.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_dialect_infos called")
  },
}




var contentCmd = &cobra.Command{
  Use:   "Content",
  Short: "Manage Content",
  Long: "Manage Content",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Content called")
  },
}


var search_content_favoritesCmd = &cobra.Command{
  Use:   "search_content_favorites",
  Short: "Search Favorite Contents",
  Long: `### Search Favorite Content

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_content_favorites called")
  },
}


var content_favoriteCmd = &cobra.Command{
  Use:   "content_favorite",
  Short: "Get Favorite Content",
  Long: `### Get favorite content by its id`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_favorite called")
  },
}


var delete_content_favoriteCmd = &cobra.Command{
  Use:   "delete_content_favorite",
  Short: "Delete Favorite Content",
  Long: `### Delete favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_content_favorite called")
  },
}


var create_content_favoriteCmd = &cobra.Command{
  Use:   "create_content_favorite",
  Short: "Create Favorite Content",
  Long: `### Create favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_content_favorite called")
  },
}


var all_content_metadatasCmd = &cobra.Command{
  Use:   "all_content_metadatas",
  Short: "Get All Content Metadatas",
  Long: `### Get information about all content metadata in a space.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_content_metadatas called")
  },
}


var content_metadataCmd = &cobra.Command{
  Use:   "content_metadata",
  Short: "Get Content Metadata",
  Long: `### Get information about an individual content metadata record.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_metadata called")
  },
}


var update_content_metadataCmd = &cobra.Command{
  Use:   "update_content_metadata",
  Short: "Update Content Metadata",
  Long: `### Move a piece of content.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_content_metadata called")
  },
}


var all_content_metadata_accessesCmd = &cobra.Command{
  Use:   "all_content_metadata_accesses",
  Short: "Get All Content Metadata Accesses",
  Long: `### All content metadata access records for a content metadata item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_content_metadata_accesses called")
  },
}


var create_content_metadata_accessCmd = &cobra.Command{
  Use:   "create_content_metadata_access",
  Short: "Create Content Metadata Access",
  Long: `### Create content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_content_metadata_access called")
  },
}


var update_content_metadata_accessCmd = &cobra.Command{
  Use:   "update_content_metadata_access",
  Short: "Update Content Metadata Access",
  Long: `### Update type of access for content metadata.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_content_metadata_access called")
  },
}


var delete_content_metadata_accessCmd = &cobra.Command{
  Use:   "delete_content_metadata_access",
  Short: "Delete Content Metadata Access",
  Long: `### Remove content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_content_metadata_access called")
  },
}


var content_thumbnailCmd = &cobra.Command{
  Use:   "content_thumbnail",
  Short: "Get Content Thumbnail",
  Long: `### Get an image representing the contents of a dashboard or look.

The returned thumbnail is an abstract representation of the contents of a dashbord or look and does not
reflect the actual data displayed in the respective visualizations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_thumbnail called")
  },
}


var content_validationCmd = &cobra.Command{
  Use:   "content_validation",
  Short: "Validate Content",
  Long: `### Validate All Content

Performs validation of all looks and dashboards
Returns a list of errors found as well as metadata about the content validation run.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_validation called")
  },
}


var search_content_viewsCmd = &cobra.Command{
  Use:   "search_content_views",
  Short: "Search Content Views",
  Long: `### Search Content Views

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_content_views called")
  },
}


var vector_thumbnailCmd = &cobra.Command{
  Use:   "vector_thumbnail",
  Short: "Get Vector Thumbnail",
  Long: `### Get a vector image representing the contents of a dashboard or look.

# DEPRECATED:  Use [content_thumbnail()](#!/Content/content_thumbnail)

The returned thumbnail is an abstract representation of the contents of a dashbord or look and does not
reflect the actual data displayed in the respective visualizations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("vector_thumbnail called")
  },
}




var dashboardCmd = &cobra.Command{
  Use:   "Dashboard",
  Short: "Manage Dashboards",
  Long: "Manage Dashboards",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Dashboard called")
  },
}


var all_dashboardsCmd = &cobra.Command{
  Use:   "all_dashboards",
  Short: "Get All Dashboards",
  Long: `### Get information about all active dashboards.

Returns an array of **abbreviated dashboard objects**. Dashboards marked as deleted are excluded from this list.

Get the **full details** of a specific dashboard by id with [dashboard()](#!/Dashboard/dashboard)

Find **deleted dashboards** with [search_dashboards()](#!/Dashboard/search_dashboards)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_dashboards called")
  },
}


var create_dashboardCmd = &cobra.Command{
  Use:   "create_dashboard",
  Short: "Create Dashboard",
  Long: `### Create a new dashboard

Creates a new dashboard object and returns the details of the newly created dashboard.

`Title`, `user_id`, and `space_id` are all required fields.
`Space_id` and `user_id` must contain the id of an existing space or user, respectively.
A dashboard's `title` must be unique within the space in which it resides.

If you receive a 422 error response when creating a dashboard, be sure to look at the
response body for information about exactly which fields are missing or contain invalid data.

You can **update** an existing dashboard with [update_dashboard()](#!/Dashboard/update_dashboard)

You can **permanently delete** an existing dashboard with [delete_dashboard()](#!/Dashboard/delete_dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard called")
  },
}


var search_dashboardsCmd = &cobra.Command{
  Use:   "search_dashboards",
  Short: "Search Dashboards",
  Long: `### Search Dashboards

Returns an **array of dashboard objects** that match the specified search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


The parameters `limit`, and `offset` are recommended for fetching results in page-size chunks.

Get a **single dashboard** by id with [dashboard()](#!/Dashboard/dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_dashboards called")
  },
}


var import_lookml_dashboardCmd = &cobra.Command{
  Use:   "import_lookml_dashboard",
  Short: "Import LookML Dashboard",
  Long: `### Import a LookML dashboard to a space as a UDD
Creates a UDD (a dashboard which exists in the Looker database rather than as a LookML file) from the LookML dashboard
and places it in the space specified. The created UDD will have a lookml_link_id which links to the original LookML dashboard.

To give the imported dashboard specify a (e.g. title: "my title") in the body of your request, otherwise the imported
dashboard will have the same title as the original LookML dashboard.

For this operation to succeed the user must have permission to see the LookML dashboard in question, and have permission to
create content in the space the dashboard is being imported to.

**Sync** a linked UDD with [sync_lookml_dashboard()](#!/Dashboard/sync_lookml_dashboard)
**Unlink** a linked UDD by setting lookml_link_id to null with [update_dashboard()](#!/Dashboard/update_dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("import_lookml_dashboard called")
  },
}


var sync_lookml_dashboardCmd = &cobra.Command{
  Use:   "sync_lookml_dashboard",
  Short: "Sync LookML Dashboard",
  Long: `### Update all linked dashboards to match the specified LookML dashboard.

Any UDD (a dashboard which exists in the Looker database rather than as a LookML file) which has a `lookml_link_id`
property value referring to a LookML dashboard's id (model::dashboardname) will be updated so that it matches the current state of the LookML dashboard.

For this operation to succeed the user must have permission to view the LookML dashboard, and only linked dashboards
that the user has permission to update will be synced.

To **link** or **unlink** a UDD set the `lookml_link_id` property with [update_dashboard()](#!/Dashboard/update_dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sync_lookml_dashboard called")
  },
}


var dashboardCmd = &cobra.Command{
  Use:   "dashboard",
  Short: "Get Dashboard",
  Long: `### Get information about a dashboard

Returns the full details of the identified dashboard object

Get a **summary list** of all active dashboards with [all_dashboards()](#!/Dashboard/all_dashboards)

You can **Search** for dashboards with [search_dashboards()](#!/Dashboard/search_dashboards)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard called")
  },
}


var update_dashboardCmd = &cobra.Command{
  Use:   "update_dashboard",
  Short: "Update Dashboard",
  Long: `### Update a dashboard

You can use this function to change the string and integer properties of
a dashboard. Nested objects such as filters, dashboard elements, or dashboard layout components
cannot be modified by this function - use the update functions for the respective
nested object types (like [update_dashboard_filter()](#!/3.1/Dashboard/update_dashboard_filter) to change a filter)
to modify nested objects referenced by a dashboard.

If you receive a 422 error response when updating a dashboard, be sure to look at the
response body for information about exactly which fields are missing or contain invalid data.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard called")
  },
}


var delete_dashboardCmd = &cobra.Command{
  Use:   "delete_dashboard",
  Short: "Delete Dashboard",
  Long: `### Delete the dashboard with the specified id

Permanently **deletes** a dashboard. (The dashboard cannot be recovered after this operation.)

"Soft" delete or hide a dashboard by setting its `deleted` status to `True` with [update_dashboard()](#!/Dashboard/update_dashboard).

Note: When a dashboard is deleted in the UI, it is soft deleted. Use this API call to permanently remove it, if desired.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard called")
  },
}


var dashboard_aggregate_table_lookmlCmd = &cobra.Command{
  Use:   "dashboard_aggregate_table_lookml",
  Short: "Get Aggregate Table LookML for a dashboard",
  Long: `### Get Aggregate Table LookML for Each Query on a Dahboard

Returns a JSON object that contains the dashboard id and Aggregate Table lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_aggregate_table_lookml called")
  },
}


var dashboard_lookmlCmd = &cobra.Command{
  Use:   "dashboard_lookml",
  Short: "Get lookml of a UDD",
  Long: `### Get lookml of a UDD

Returns a JSON object that contains the dashboard id and the full lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_lookml called")
  },
}


var search_dashboard_elementsCmd = &cobra.Command{
  Use:   "search_dashboard_elements",
  Short: "Search Dashboard Elements",
  Long: `### Search Dashboard Elements

Returns an **array of DashboardElement objects** that match the specified search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_dashboard_elements called")
  },
}


var dashboard_elementCmd = &cobra.Command{
  Use:   "dashboard_element",
  Short: "Get DashboardElement",
  Long: `### Get information about the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_element called")
  },
}


var update_dashboard_elementCmd = &cobra.Command{
  Use:   "update_dashboard_element",
  Short: "Update DashboardElement",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_element called")
  },
}


var delete_dashboard_elementCmd = &cobra.Command{
  Use:   "delete_dashboard_element",
  Short: "Delete DashboardElement",
  Long: `### Delete a dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_element called")
  },
}


var dashboard_dashboard_elementsCmd = &cobra.Command{
  Use:   "dashboard_dashboard_elements",
  Short: "Get All DashboardElements",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_elements called")
  },
}


var create_dashboard_elementCmd = &cobra.Command{
  Use:   "create_dashboard_element",
  Short: "Create DashboardElement",
  Long: `### Create a dashboard element on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_element called")
  },
}


var dashboard_filterCmd = &cobra.Command{
  Use:   "dashboard_filter",
  Short: "Get Dashboard Filter",
  Long: `### Get information about the dashboard filters with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_filter called")
  },
}


var update_dashboard_filterCmd = &cobra.Command{
  Use:   "update_dashboard_filter",
  Short: "Update Dashboard Filter",
  Long: `### Update the dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_filter called")
  },
}


var delete_dashboard_filterCmd = &cobra.Command{
  Use:   "delete_dashboard_filter",
  Short: "Delete Dashboard Filter",
  Long: `### Delete a dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_filter called")
  },
}


var dashboard_dashboard_filtersCmd = &cobra.Command{
  Use:   "dashboard_dashboard_filters",
  Short: "Get All Dashboard Filters",
  Long: `### Get information about all the dashboard filters on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_filters called")
  },
}


var create_dashboard_filterCmd = &cobra.Command{
  Use:   "create_dashboard_filter",
  Short: "Create Dashboard Filter",
  Long: `### Create a dashboard filter on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_filter called")
  },
}


var dashboard_layout_componentCmd = &cobra.Command{
  Use:   "dashboard_layout_component",
  Short: "Get DashboardLayoutComponent",
  Long: `### Get information about the dashboard elements with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout_component called")
  },
}


var update_dashboard_layout_componentCmd = &cobra.Command{
  Use:   "update_dashboard_layout_component",
  Short: "Update DashboardLayoutComponent",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_layout_component called")
  },
}


var dashboard_layout_dashboard_layout_componentsCmd = &cobra.Command{
  Use:   "dashboard_layout_dashboard_layout_components",
  Short: "Get All DashboardLayoutComponents",
  Long: `### Get information about all the dashboard layout components for a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout_dashboard_layout_components called")
  },
}


var dashboard_layoutCmd = &cobra.Command{
  Use:   "dashboard_layout",
  Short: "Get DashboardLayout",
  Long: `### Get information about the dashboard layouts with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout called")
  },
}


var update_dashboard_layoutCmd = &cobra.Command{
  Use:   "update_dashboard_layout",
  Short: "Update DashboardLayout",
  Long: `### Update the dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_layout called")
  },
}


var delete_dashboard_layoutCmd = &cobra.Command{
  Use:   "delete_dashboard_layout",
  Short: "Delete DashboardLayout",
  Long: `### Delete a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_layout called")
  },
}


var dashboard_dashboard_layoutsCmd = &cobra.Command{
  Use:   "dashboard_dashboard_layouts",
  Short: "Get All DashboardLayouts",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_layouts called")
  },
}


var create_dashboard_layoutCmd = &cobra.Command{
  Use:   "create_dashboard_layout",
  Short: "Create DashboardLayout",
  Long: `### Create a dashboard layout on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_layout called")
  },
}




var dataActionCmd = &cobra.Command{
  Use:   "DataAction",
  Short: "Run Data Actions",
  Long: "Run Data Actions",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("DataAction called")
  },
}


var perform_data_actionCmd = &cobra.Command{
  Use:   "perform_data_action",
  Short: "Send a Data Action",
  Long: `Perform a data action. The data action object can be obtained from query results, and used to perform an arbitrary action.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("perform_data_action called")
  },
}


var fetch_remote_data_action_formCmd = &cobra.Command{
  Use:   "fetch_remote_data_action_form",
  Short: "Fetch Remote Data Action Form",
  Long: `For some data actions, the remote server may supply a form requesting further user input. This endpoint takes a data action, asks the remote server to generate a form for it, and returns that form to you for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetch_remote_data_action_form called")
  },
}




var datagroupCmd = &cobra.Command{
  Use:   "Datagroup",
  Short: "Manage Datagroups",
  Long: "Manage Datagroups",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Datagroup called")
  },
}


var all_datagroupsCmd = &cobra.Command{
  Use:   "all_datagroups",
  Short: "Get All Datagroups",
  Long: `### Get information about all datagroups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_datagroups called")
  },
}


var datagroupCmd = &cobra.Command{
  Use:   "datagroup",
  Short: "Get Datagroup",
  Long: `### Get information about a datagroup.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("datagroup called")
  },
}


var update_datagroupCmd = &cobra.Command{
  Use:   "update_datagroup",
  Short: "Update Datagroup",
  Long: `### Update a datagroup using the specified params.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_datagroup called")
  },
}




var derivedTableCmd = &cobra.Command{
  Use:   "DerivedTable",
  Short: "View Derived Table graphs",
  Long: "View Derived Table graphs",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("DerivedTable called")
  },
}


var graph_derived_tables_for_modelCmd = &cobra.Command{
  Use:   "graph_derived_tables_for_model",
  Short: "Get Derived Table graph for model",
  Long: `### Discover information about derived tables
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graph_derived_tables_for_model called")
  },
}


var graph_derived_tables_for_viewCmd = &cobra.Command{
  Use:   "graph_derived_tables_for_view",
  Short: "Get subgraph of derived table and dependencies",
  Long: `### Get the subgraph representing this derived table and its dependencies.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graph_derived_tables_for_view called")
  },
}




var folderCmd = &cobra.Command{
  Use:   "Folder",
  Short: "Manage Folders",
  Long: "Manage Folders",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Folder called")
  },
}


var search_foldersCmd = &cobra.Command{
  Use:   "search_folders",
  Short: "Search Folders",
  Long: `Search for folders by creator id, parent id, name, etc`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_folders called")
  },
}


var folderCmd = &cobra.Command{
  Use:   "folder",
  Short: "Get Folder",
  Long: `### Get information about the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder called")
  },
}


var update_folderCmd = &cobra.Command{
  Use:   "update_folder",
  Short: "Update Folder",
  Long: `### Update the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_folder called")
  },
}


var delete_folderCmd = &cobra.Command{
  Use:   "delete_folder",
  Short: "Delete Folder",
  Long: `### Delete the folder with a specific id including any children folders.
**DANGER** this will delete all looks and dashboards in the folder.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_folder called")
  },
}


var all_foldersCmd = &cobra.Command{
  Use:   "all_folders",
  Short: "Get All Folders",
  Long: `### Get information about all folders.

In API 3.x, this will not return empty personal folders, unless they belong to the calling user.
In API 4.0+, all personal folders will be returned.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_folders called")
  },
}


var create_folderCmd = &cobra.Command{
  Use:   "create_folder",
  Short: "Create Folder",
  Long: `### Create a folder with specified information.

Caller must have permission to edit the parent folder and to create folders, otherwise the request
returns 404 Not Found.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_folder called")
  },
}


var folder_childrenCmd = &cobra.Command{
  Use:   "folder_children",
  Short: "Get Folder Children",
  Long: `### Get the children of a folder.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_children called")
  },
}


var folder_children_searchCmd = &cobra.Command{
  Use:   "folder_children_search",
  Short: "Search Folder Children",
  Long: `### Search the children of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_children_search called")
  },
}


var folder_parentCmd = &cobra.Command{
  Use:   "folder_parent",
  Short: "Get Folder Parent",
  Long: `### Get the parent of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_parent called")
  },
}


var folder_ancestorsCmd = &cobra.Command{
  Use:   "folder_ancestors",
  Short: "Get Folder Ancestors",
  Long: `### Get the ancestors of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_ancestors called")
  },
}


var folder_looksCmd = &cobra.Command{
  Use:   "folder_looks",
  Short: "Get Folder Looks",
  Long: `### Get all looks in a folder.
In API 3.x, this will return all looks in a folder, including looks in the trash.
In API 4.0+, all looks in a folder will be returned, excluding looks in the trash.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_looks called")
  },
}


var folder_dashboardsCmd = &cobra.Command{
  Use:   "folder_dashboards",
  Short: "Get Folder Dashboards",
  Long: `### Get the dashboards in a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_dashboards called")
  },
}




var groupCmd = &cobra.Command{
  Use:   "Group",
  Short: "Manage Groups",
  Long: "Manage Groups",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Group called")
  },
}


var all_groupsCmd = &cobra.Command{
  Use:   "all_groups",
  Short: "Get All Groups",
  Long: `### Get information about all groups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_groups called")
  },
}


var create_groupCmd = &cobra.Command{
  Use:   "create_group",
  Short: "Create Group",
  Long: `### Creates a new group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_group called")
  },
}


var search_groupsCmd = &cobra.Command{
  Use:   "search_groups",
  Short: "Search Groups",
  Long: `### Search groups

Returns all group records that match the given search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_groups called")
  },
}


var groupCmd = &cobra.Command{
  Use:   "group",
  Short: "Get Group",
  Long: `### Get information about a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("group called")
  },
}


var update_groupCmd = &cobra.Command{
  Use:   "update_group",
  Short: "Update Group",
  Long: `### Updates the a group (admin only).`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_group called")
  },
}


var delete_groupCmd = &cobra.Command{
  Use:   "delete_group",
  Short: "Delete Group",
  Long: `### Deletes a group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group called")
  },
}


var all_group_groupsCmd = &cobra.Command{
  Use:   "all_group_groups",
  Short: "Get All Groups in Group",
  Long: `### Get information about all the groups in a group
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_group_groups called")
  },
}


var add_group_groupCmd = &cobra.Command{
  Use:   "add_group_group",
  Short: "Add a Group to Group",
  Long: `### Adds a new group to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("add_group_group called")
  },
}


var all_group_usersCmd = &cobra.Command{
  Use:   "all_group_users",
  Short: "Get All Users in Group",
  Long: `### Get information about all the users directly included in a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_group_users called")
  },
}


var add_group_userCmd = &cobra.Command{
  Use:   "add_group_user",
  Short: "Add a User to Group",
  Long: `### Adds a new user to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("add_group_user called")
  },
}


var delete_group_userCmd = &cobra.Command{
  Use:   "delete_group_user",
  Short: "Remove a User from Group",
  Long: `### Removes a user from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group_user called")
  },
}


var delete_group_from_groupCmd = &cobra.Command{
  Use:   "delete_group_from_group",
  Short: "Deletes a Group from Group",
  Long: `### Removes a group from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group_from_group called")
  },
}


var update_user_attribute_group_valueCmd = &cobra.Command{
  Use:   "update_user_attribute_group_value",
  Short: "Set User Attribute Group Value",
  Long: `### Set the value of a user attribute for a group.

For information about how user attribute values are calculated, see [Set User Attribute Group Values](#!/UserAttribute/set_user_attribute_group_values).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_attribute_group_value called")
  },
}


var delete_user_attribute_group_valueCmd = &cobra.Command{
  Use:   "delete_user_attribute_group_value",
  Short: "Delete User Attribute Group Value",
  Long: `### Remove a user attribute value from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_attribute_group_value called")
  },
}




var homepageCmd = &cobra.Command{
  Use:   "Homepage",
  Short: "Manage Homepage",
  Long: "Manage Homepage",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Homepage called")
  },
}


var all_homepagesCmd = &cobra.Command{
  Use:   "all_homepages",
  Short: "Get All Homepages",
  Long: `### Get information about all homepages.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_homepages called")
  },
}


var create_homepageCmd = &cobra.Command{
  Use:   "create_homepage",
  Short: "Create Homepage",
  Long: `### Create a new homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_homepage called")
  },
}


var search_homepagesCmd = &cobra.Command{
  Use:   "search_homepages",
  Short: "Search Homepages",
  Long: `### Search Homepages

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_homepages called")
  },
}


var homepageCmd = &cobra.Command{
  Use:   "homepage",
  Short: "Get Homepage",
  Long: `### Get information about a homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepage called")
  },
}


var update_homepageCmd = &cobra.Command{
  Use:   "update_homepage",
  Short: "Update Homepage",
  Long: `### Update a homepage definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_homepage called")
  },
}


var delete_homepageCmd = &cobra.Command{
  Use:   "delete_homepage",
  Short: "Delete Homepage",
  Long: `### Delete a homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_homepage called")
  },
}


var all_homepage_itemsCmd = &cobra.Command{
  Use:   "all_homepage_items",
  Short: "Get All Homepage Items",
  Long: `### Get information about all homepage items.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_homepage_items called")
  },
}


var create_homepage_itemCmd = &cobra.Command{
  Use:   "create_homepage_item",
  Short: "Create Homepage Item",
  Long: `### Create a new homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_homepage_item called")
  },
}


var homepage_itemCmd = &cobra.Command{
  Use:   "homepage_item",
  Short: "Get Homepage Item",
  Long: `### Get information about a homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepage_item called")
  },
}


var update_homepage_itemCmd = &cobra.Command{
  Use:   "update_homepage_item",
  Short: "Update Homepage Item",
  Long: `### Update a homepage item definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_homepage_item called")
  },
}


var delete_homepage_itemCmd = &cobra.Command{
  Use:   "delete_homepage_item",
  Short: "Delete Homepage Item",
  Long: `### Delete a homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_homepage_item called")
  },
}


var all_homepage_sectionsCmd = &cobra.Command{
  Use:   "all_homepage_sections",
  Short: "Get All Homepage sections",
  Long: `### Get information about all homepage sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_homepage_sections called")
  },
}


var create_homepage_sectionCmd = &cobra.Command{
  Use:   "create_homepage_section",
  Short: "Create Homepage section",
  Long: `### Create a new homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_homepage_section called")
  },
}


var homepage_sectionCmd = &cobra.Command{
  Use:   "homepage_section",
  Short: "Get Homepage section",
  Long: `### Get information about a homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepage_section called")
  },
}


var update_homepage_sectionCmd = &cobra.Command{
  Use:   "update_homepage_section",
  Short: "Update Homepage section",
  Long: `### Update a homepage section definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_homepage_section called")
  },
}


var delete_homepage_sectionCmd = &cobra.Command{
  Use:   "delete_homepage_section",
  Short: "Delete Homepage section",
  Long: `### Delete a homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_homepage_section called")
  },
}


var all_primary_homepage_sectionsCmd = &cobra.Command{
  Use:   "all_primary_homepage_sections",
  Short: "Get All Primary homepage sections",
  Long: `### Get information about the primary homepage's sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_primary_homepage_sections called")
  },
}




var integrationCmd = &cobra.Command{
  Use:   "Integration",
  Short: "Manage Integrations",
  Long: "Manage Integrations",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Integration called")
  },
}


var all_integration_hubsCmd = &cobra.Command{
  Use:   "all_integration_hubs",
  Short: "Get All Integration Hubs",
  Long: `### Get information about all Integration Hubs.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_integration_hubs called")
  },
}


var create_integration_hubCmd = &cobra.Command{
  Use:   "create_integration_hub",
  Short: "Create Integration Hub",
  Long: `### Create a new Integration Hub.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_integration_hub called")
  },
}


var integration_hubCmd = &cobra.Command{
  Use:   "integration_hub",
  Short: "Get Integration Hub",
  Long: `### Get information about a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration_hub called")
  },
}


var update_integration_hubCmd = &cobra.Command{
  Use:   "update_integration_hub",
  Short: "Update Integration Hub",
  Long: `### Update a Integration Hub definition.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_integration_hub called")
  },
}


var delete_integration_hubCmd = &cobra.Command{
  Use:   "delete_integration_hub",
  Short: "Delete Integration Hub",
  Long: `### Delete a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_integration_hub called")
  },
}


var accept_integration_hub_legal_agreementCmd = &cobra.Command{
  Use:   "accept_integration_hub_legal_agreement",
  Short: "Accept Integration Hub Legal Agreement",
  Long: `Accepts the legal agreement for a given integration hub. This only works for integration hubs that have legal_agreement_required set to true and legal_agreement_signed set to false.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("accept_integration_hub_legal_agreement called")
  },
}


var all_integrationsCmd = &cobra.Command{
  Use:   "all_integrations",
  Short: "Get All Integrations",
  Long: `### Get information about all Integrations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_integrations called")
  },
}


var integrationCmd = &cobra.Command{
  Use:   "integration",
  Short: "Get Integration",
  Long: `### Get information about a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration called")
  },
}


var update_integrationCmd = &cobra.Command{
  Use:   "update_integration",
  Short: "Update Integration",
  Long: `### Update parameters on a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_integration called")
  },
}


var fetch_integration_formCmd = &cobra.Command{
  Use:   "fetch_integration_form",
  Short: "Fetch Remote Integration Form",
  Long: `Returns the Integration form for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetch_integration_form called")
  },
}


var test_integrationCmd = &cobra.Command{
  Use:   "test_integration",
  Short: "Test integration",
  Long: `Tests the integration to make sure all the settings are working.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_integration called")
  },
}




var lookCmd = &cobra.Command{
  Use:   "Look",
  Short: "Run and Manage Looks",
  Long: "Run and Manage Looks",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Look called")
  },
}


var all_looksCmd = &cobra.Command{
  Use:   "all_looks",
  Short: "Get All Looks",
  Long: `### Get information about all active Looks

Returns an array of **abbreviated Look objects** describing all the looks that the caller has access to. Soft-deleted Looks are **not** included.

Get the **full details** of a specific look by id with [look(id)](#!/Look/look)

Find **soft-deleted looks** with [search_looks()](#!/Look/search_looks)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_looks called")
  },
}


var create_lookCmd = &cobra.Command{
  Use:   "create_look",
  Short: "Create Look",
  Long: `### Create a Look

To create a look to display query data, first create the query with [create_query()](#!/Query/create_query)
then assign the query's id to the `query_id` property in the call to `create_look()`.

To place the look into a particular space, assign the space's id to the `space_id` property
in the call to `create_look()`.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_look called")
  },
}


var search_looksCmd = &cobra.Command{
  Use:   "search_looks",
  Short: "Search Looks",
  Long: `### Search Looks

Returns an **array of Look objects** that match the specified search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


Get a **single look** by id with [look(id)](#!/Look/look)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_looks called")
  },
}


var lookCmd = &cobra.Command{
  Use:   "look",
  Short: "Get Look",
  Long: `### Get a Look.

Returns detailed information about a Look and its associated Query.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("look called")
  },
}


var update_lookCmd = &cobra.Command{
  Use:   "update_look",
  Short: "Update Look",
  Long: `### Modify a Look

Use this function to modify parts of a look. Property values given in a call to `update_look` are
applied to the existing look, so there's no need to include properties whose values are not changing.
It's best to specify only the properties you want to change and leave everything else out
of your `update_look` call. **Look properties marked 'read-only' will be ignored.**

When a user deletes a look in the Looker UI, the look data remains in the database but is
marked with a deleted flag ("soft-deleted"). Soft-deleted looks can be undeleted (by an admin)
if the delete was in error.

To soft-delete a look via the API, use [update_look()](#!/Look/update_look) to change the look's `deleted` property to `true`.
You can undelete a look by calling `update_look` to change the look's `deleted` property to `false`.

Soft-deleted looks are excluded from the results of [all_looks()](#!/Look/all_looks) and [search_looks()](#!/Look/search_looks), so they
essentially disappear from view even though they still reside in the db.
In API 3.1 and later, you can pass `deleted: true` as a parameter to [search_looks()](#!/3.1/Look/search_looks) to list soft-deleted looks.

NOTE: [delete_look()](#!/Look/delete_look) performs a "hard delete" - the look data is removed from the Looker
database and destroyed. There is no "undo" for `delete_look()`.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_look called")
  },
}


var delete_lookCmd = &cobra.Command{
  Use:   "delete_look",
  Short: "Delete Look",
  Long: `### Permanently Delete a Look

This operation **permanently** removes a look from the Looker database.

NOTE: There is no "undo" for this kind of delete.

For information about soft-delete (which can be undone) see [update_look()](#!/Look/update_look).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_look called")
  },
}


var run_lookCmd = &cobra.Command{
  Use:   "run_look",
  Short: "Run Look",
  Long: `### Run a Look

Runs a given look's query and returns the results in the requested format.

Supported formats:

| result_format | Description
| :-----------: | :--- |
| json | Plain json
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| md | Simple markdown
| xlsx | MS Excel spreadsheet
| sql | Returns the generated SQL rather than running the query
| png | A PNG image of the visualization of the query
| jpg | A JPG image of the visualization of the query


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_look called")
  },
}




var lookmlModelCmd = &cobra.Command{
  Use:   "LookmlModel",
  Short: "Manage LookML Models",
  Long: "Manage LookML Models",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("LookmlModel called")
  },
}


var all_lookml_modelsCmd = &cobra.Command{
  Use:   "all_lookml_models",
  Short: "Get All LookML Models",
  Long: `### Get information about all lookml models.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_lookml_models called")
  },
}


var create_lookml_modelCmd = &cobra.Command{
  Use:   "create_lookml_model",
  Short: "Create LookML Model",
  Long: `### Create a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_lookml_model called")
  },
}


var lookml_modelCmd = &cobra.Command{
  Use:   "lookml_model",
  Short: "Get LookML Model",
  Long: `### Get information about a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookml_model called")
  },
}


var update_lookml_modelCmd = &cobra.Command{
  Use:   "update_lookml_model",
  Short: "Update LookML Model",
  Long: `### Update a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_lookml_model called")
  },
}


var delete_lookml_modelCmd = &cobra.Command{
  Use:   "delete_lookml_model",
  Short: "Delete LookML Model",
  Long: `### Delete a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_lookml_model called")
  },
}


var lookml_model_exploreCmd = &cobra.Command{
  Use:   "lookml_model_explore",
  Short: "Get LookML Model Explore",
  Long: `### Get information about a lookml model explore.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookml_model_explore called")
  },
}




var projectCmd = &cobra.Command{
  Use:   "Project",
  Short: "Manage Projects",
  Long: "Manage Projects",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Project called")
  },
}


var all_git_branchesCmd = &cobra.Command{
  Use:   "all_git_branches",
  Short: "Get All Git Branches",
  Long: `### Get All Git Branches

Returns a list of git branches in the project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_git_branches called")
  },
}


var git_branchCmd = &cobra.Command{
  Use:   "git_branch",
  Short: "Get Active Git Branch",
  Long: `### Get the Current Git Branch

Returns the git branch currently checked out in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("git_branch called")
  },
}


var update_git_branchCmd = &cobra.Command{
  Use:   "update_git_branch",
  Short: "Update Project Git Branch",
  Long: `### Checkout and/or reset --hard an existing Git Branch

Only allowed in development mode
  - Call `update_session` to select the 'dev' workspace.

Checkout an existing branch if name field is different from the name of the currently checked out branch.

Optionally specify a branch name, tag name or commit SHA to which the branch should be reset.
  **DANGER** hard reset will be force pushed to the remote. Unsaved changes and commits may be permanently lost.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_git_branch called")
  },
}


var create_git_branchCmd = &cobra.Command{
  Use:   "create_git_branch",
  Short: "Checkout New Git Branch",
  Long: `### Create and Checkout a Git Branch

Creates and checks out a new branch in the given project repository
Only allowed in development mode
  - Call `update_session` to select the 'dev' workspace.

Optionally specify a branch name, tag name or commit SHA as the start point in the ref field.
  If no ref is specified, HEAD of the current branch will be used as the start point for the new branch.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_git_branch called")
  },
}


var find_git_branchCmd = &cobra.Command{
  Use:   "find_git_branch",
  Short: "Find a Git Branch",
  Long: `### Get the specified Git Branch

Returns the git branch specified in branch_name path param if it exists in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("find_git_branch called")
  },
}


var delete_git_branchCmd = &cobra.Command{
  Use:   "delete_git_branch",
  Short: "Delete a Git Branch",
  Long: `### Delete the specified Git Branch

Delete git branch specified in branch_name path param from local and remote of specified project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_git_branch called")
  },
}


var deploy_ref_to_productionCmd = &cobra.Command{
  Use:   "deploy_ref_to_production",
  Short: "Deploy Remote Branch or Ref to Production",
  Long: `### Deploy a Remote Branch or Ref to Production

Git must have been configured and deploy permission required.

Deploy is a one/two step process
1. If this is the first deploy of this project, create the production project with git repository.
2. Pull the branch or ref into the production project.

Can only specify either a branch or a ref.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deploy_ref_to_production called")
  },
}


var deploy_to_productionCmd = &cobra.Command{
  Use:   "deploy_to_production",
  Short: "Deploy To Production",
  Long: `### Deploy LookML from this Development Mode Project to Production

Git must have been configured, must be in dev mode and deploy permission required

Deploy is a two / three step process:

1. Push commits in current branch of dev mode project to the production branch (origin/master).
   Note a. This step is skipped in read-only projects.
   Note b. If this step is unsuccessful for any reason (e.g. rejected non-fastforward because production branch has
             commits not in current branch), subsequent steps will be skipped.
2. If this is the first deploy of this project, create the production project with git repository.
3. Pull the production branch into the production project.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deploy_to_production called")
  },
}


var reset_project_to_productionCmd = &cobra.Command{
  Use:   "reset_project_to_production",
  Short: "Reset To Production",
  Long: `### Reset a project to the revision of the project that is in production.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("reset_project_to_production called")
  },
}


var reset_project_to_remoteCmd = &cobra.Command{
  Use:   "reset_project_to_remote",
  Short: "Reset To Remote",
  Long: `### Reset a project development branch to the revision of the project that is on the remote.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("reset_project_to_remote called")
  },
}


var all_projectsCmd = &cobra.Command{
  Use:   "all_projects",
  Short: "Get All Projects",
  Long: `### Get All Projects

Returns all projects visible to the current user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_projects called")
  },
}


var create_projectCmd = &cobra.Command{
  Use:   "create_project",
  Short: "Create Project",
  Long: `### Create A Project

dev mode required.
- Call `update_session` to select the 'dev' workspace.

`name` is required.
`git_remote_url` is not allowed. To configure Git for the newly created project, follow the instructions in `update_project`.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_project called")
  },
}


var projectCmd = &cobra.Command{
  Use:   "project",
  Short: "Get Project",
  Long: `### Get A Project

Returns the project with the given project id
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project called")
  },
}


var update_projectCmd = &cobra.Command{
  Use:   "update_project",
  Short: "Update Project",
  Long: `### Update Project Configuration

Apply changes to a project's configuration.


#### Configuring Git for a Project

To set up a Looker project with a remote git repository, follow these steps:

1. Call `update_session` to select the 'dev' workspace.
1. Call `create_git_deploy_key` to create a new deploy key for the project
1. Copy the deploy key text into the remote git repository's ssh key configuration
1. Call `update_project` to set project's `git_remote_url` ()and `git_service_name`, if necessary).

When you modify a project's `git_remote_url`, Looker connects to the remote repository to fetch
metadata. The remote git repository MUST be configured with the Looker-generated deploy
key for this project prior to setting the project's `git_remote_url`.

To set up a Looker project with a git repository residing on the Looker server (a 'bare' git repo):

1. Call `update_session` to select the 'dev' workspace.
1. Call `update_project` setting `git_remote_url` to null and `git_service_name` to "bare".

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_project called")
  },
}


var manifestCmd = &cobra.Command{
  Use:   "manifest",
  Short: "Get Manifest",
  Long: `### Get A Projects Manifest object

Returns the project with the given project id
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("manifest called")
  },
}


var git_deploy_keyCmd = &cobra.Command{
  Use:   "git_deploy_key",
  Short: "Git Deploy Key",
  Long: `### Git Deploy Key

Returns the ssh public key previously created for a project's git repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("git_deploy_key called")
  },
}


var create_git_deploy_keyCmd = &cobra.Command{
  Use:   "create_git_deploy_key",
  Short: "Create Deploy Key",
  Long: `### Create Git Deploy Key

Create a public/private key pair for authenticating ssh git requests from Looker to a remote git repository
for a particular Looker project.

Returns the public key of the generated ssh key pair.

Copy this public key to your remote git repository's ssh keys configuration so that the remote git service can
validate and accept git requests from the Looker server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_git_deploy_key called")
  },
}


var project_validation_resultsCmd = &cobra.Command{
  Use:   "project_validation_results",
  Short: "Cached Project Validation Results",
  Long: `### Get Cached Project Validation Results

Returns the cached results of a previous project validation calculation, if any.
Returns http status 204 No Content if no validation results exist.

Validating the content of all the files in a project can be computationally intensive
for large projects. Use this API to simply fetch the results of the most recent
project validation rather than revalidating the entire project from scratch.

A value of `"stale": true` in the response indicates that the project has changed since
the cached validation results were computed. The cached validation results may no longer
reflect the current state of the project.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project_validation_results called")
  },
}


var validate_projectCmd = &cobra.Command{
  Use:   "validate_project",
  Short: "Validate Project",
  Long: `### Validate Project

Performs lint validation of all lookml files in the project.
Returns a list of errors found, if any.

Validating the content of all the files in a project can be computationally intensive
for large projects. For best performance, call `validate_project(project_id)` only
when you really want to recompute project validation. To quickly display the results of
the most recent project validation (without recomputing), use `project_validation_results(project_id)`
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("validate_project called")
  },
}


var project_workspaceCmd = &cobra.Command{
  Use:   "project_workspace",
  Short: "Get Project Workspace",
  Long: `### Get Project Workspace

Returns information about the state of the project files in the currently selected workspace
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project_workspace called")
  },
}


var all_project_filesCmd = &cobra.Command{
  Use:   "all_project_files",
  Short: "Get All Project Files",
  Long: `### Get All Project Files

Returns a list of the files in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_project_files called")
  },
}


var project_fileCmd = &cobra.Command{
  Use:   "project_file",
  Short: "Get Project File",
  Long: `### Get Project File Info

Returns information about a file in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project_file called")
  },
}


var all_git_connection_testsCmd = &cobra.Command{
  Use:   "all_git_connection_tests",
  Short: "Get All Git Connection Tests",
  Long: `### Get All Git Connection Tests

dev mode required.
  - Call `update_session` to select the 'dev' workspace.

Returns a list of tests which can be run against a project's (or the dependency project for the provided remote_url) git connection. Call [Run Git Connection Test](#!/Project/run_git_connection_test) to execute each test in sequence.

Tests are ordered by increasing specificity. Tests should be run in the order returned because later tests require functionality tested by tests earlier in the test list.

For example, a late-stage test for write access is meaningless if connecting to the git server (an early test) is failing.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_git_connection_tests called")
  },
}


var run_git_connection_testCmd = &cobra.Command{
  Use:   "run_git_connection_test",
  Short: "Run Git Connection Test",
  Long: `### Run a git connection test

Run the named test on the git service used by this project (or the dependency project for the provided remote_url) and return the result. This
is intended to help debug git connections when things do not work properly, to give
more helpful information about why a git url is not working with Looker.

Tests should be run in the order they are returned by [Get All Git Connection Tests](#!/Project/all_git_connection_tests).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_git_connection_test called")
  },
}


var all_lookml_testsCmd = &cobra.Command{
  Use:   "all_lookml_tests",
  Short: "Get All LookML Tests",
  Long: `### Get All LookML Tests

Returns a list of tests which can be run to validate a project's LookML code and/or the underlying data,
optionally filtered by the file id.
Call [Run LookML Test](#!/Project/run_lookml_test) to execute tests.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_lookml_tests called")
  },
}


var run_lookml_testCmd = &cobra.Command{
  Use:   "run_lookml_test",
  Short: "Run LookML Test",
  Long: `### Run LookML Tests

Runs all tests in the project, optionally filtered by file, test, and/or model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_lookml_test called")
  },
}


var tag_refCmd = &cobra.Command{
  Use:   "tag_ref",
  Short: "Tag Ref",
  Long: `### Creates a tag for the most recent commit, or a specific ref is a SHA is provided

This is an internal-only, undocumented route.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("tag_ref called")
  },
}


var update_repository_credentialCmd = &cobra.Command{
  Use:   "update_repository_credential",
  Short: "Create Repository Credential",
  Long: `### Configure Repository Credential for a remote dependency

Admin required.

`root_project_id` is required.
`credential_id` is required.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_repository_credential called")
  },
}


var delete_repository_credentialCmd = &cobra.Command{
  Use:   "delete_repository_credential",
  Short: "Delete Repository Credential",
  Long: `### Repository Credential for a remote dependency

Admin required.

`root_project_id` is required.
`credential_id` is required.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_repository_credential called")
  },
}


var get_all_repository_credentialsCmd = &cobra.Command{
  Use:   "get_all_repository_credentials",
  Short: "Get All Repository Credentials",
  Long: `### Get all Repository Credentials for a project

`root_project_id` is required.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_all_repository_credentials called")
  },
}




var queryCmd = &cobra.Command{
  Use:   "Query",
  Short: "Run and Manage Queries",
  Long: "Run and Manage Queries",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Query called")
  },
}


var create_query_taskCmd = &cobra.Command{
  Use:   "create_query_task",
  Short: "Run Query Async",
  Long: `### Create an async query task

Creates a query task (job) to run a previously created query asynchronously. Returns a Query Task ID.

Use [query_task(query_task_id)](#!/Query/query_task) to check the execution status of the query task.
After the query task status reaches "Complete", use [query_task_results(query_task_id)](#!/Query/query_task_results) to fetch the results of the query.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_query_task called")
  },
}


var query_task_multi_resultsCmd = &cobra.Command{
  Use:   "query_task_multi_results",
  Short: "Get Multiple Async Query Results",
  Long: `### Fetch results of multiple async queries

Returns the results of multiple async queries in one request.

For Query Tasks that are not completed, the response will include the execution status of the Query Task but will not include query results.
Query Tasks whose results have expired will have a status of 'expired'.
If the user making the API request does not have sufficient privileges to view a Query Task result, the result will have a status of 'missing'
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("query_task_multi_results called")
  },
}


var query_taskCmd = &cobra.Command{
  Use:   "query_task",
  Short: "Get Async Query Info",
  Long: `### Get Query Task details

Use this function to check the status of an async query task. After the status
reaches "Complete", you can call [query_task_results(query_task_id)](#!/Query/query_task_results) to
retrieve the results of the query.

Use [create_query_task()](#!/Query/create_query_task) to create an async query task.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("query_task called")
  },
}


var query_task_resultsCmd = &cobra.Command{
  Use:   "query_task_results",
  Short: "Get Async Query Results",
  Long: `### Get Async Query Results

Returns the results of an async query task if the query has completed.

If the query task is still running or waiting to run, this function returns 204 No Content.

If the query task ID is invalid or the cached results of the query task have expired, this function returns 404 Not Found.

Use [query_task(query_task_id)](#!/Query/query_task) to check the execution status of the query task
Call query_task_results only after the query task status reaches "Complete".

You can also use [query_task_multi_results()](#!/Query/query_task_multi_results) retrieve the
results of multiple async query tasks at the same time.

#### SQL Error Handling:
If the query fails due to a SQL db error, how this is communicated depends on the result_format you requested in `create_query_task()`.

For `json_detail` result_format: `query_task_results()` will respond with HTTP status '200 OK' and db SQL error info
will be in the `errors` property of the response object. The 'data' property will be empty.

For all other result formats: `query_task_results()` will respond with HTTP status `400 Bad Request` and some db SQL error info
will be in the message of the 400 error response, but not as detailed as expressed in `json_detail.errors`.
These data formats can only carry row data, and error info is not row data.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("query_task_results called")
  },
}


var queryCmd = &cobra.Command{
  Use:   "query",
  Short: "Get Query",
  Long: `### Get a previously created query by id.

A Looker query object includes the various parameters that define a database query that has been run or
could be run in the future. These parameters include: model, view, fields, filters, pivots, etc.
Query *results* are not part of the query object.

Query objects are unique and immutable. Query objects are created automatically in Looker as users explore data.
Looker does not delete them; they become part of the query history. When asked to create a query for
any given set of parameters, Looker will first try to find an existing query object with matching
parameters and will only create a new object when an appropriate object can not be found.

This 'get' method is used to get the details about a query for a given id. See the other methods here
to 'create' and 'run' queries.

Note that some fields like 'filter_config' and 'vis_config' etc are specific to how the Looker UI
builds queries and visualizations and are not generally useful for API use. They are not required when
creating new queries and can usually just be ignored.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("query called")
  },
}


var query_for_slugCmd = &cobra.Command{
  Use:   "query_for_slug",
  Short: "Get Query for Slug",
  Long: `### Get the query for a given query slug.

This returns the query for the 'slug' in a query share URL.

The 'slug' is a randomly chosen short string that is used as an alternative to the query's id value
for use in URLs etc. This method exists as a convenience to help you use the API to 'find' queries that
have been created using the Looker UI.

You can use the Looker explore page to build a query and then choose the 'Share' option to
show the share url for the query. Share urls generally look something like 'https://looker.yourcompany/x/vwGSbfc'.
The trailing 'vwGSbfc' is the share slug. You can pass that string to this api method to get details about the query.
Those details include the 'id' that you can use to run the query. Or, you can copy the query body
(perhaps with your own modification) and use that as the basis to make/run new queries.

This will also work with slugs from Looker explore urls like
'https://looker.yourcompany/explore/ecommerce/orders?qid=aogBgL6o3cKK1jN3RoZl5s'. In this case
'aogBgL6o3cKK1jN3RoZl5s' is the slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("query_for_slug called")
  },
}


var create_queryCmd = &cobra.Command{
  Use:   "create_query",
  Short: "Create Query",
  Long: `### Create a query.

This allows you to create a new query that you can later run. Looker queries are immutable once created
and are not deleted. If you create a query that is exactly like an existing query then the existing query
will be returned and no new query will be created. Whether a new query is created or not, you can use
the 'id' in the returned query with the 'run' method.

The query parameters are passed as json in the body of the request.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_query called")
  },
}


var run_queryCmd = &cobra.Command{
  Use:   "run_query",
  Short: "Run Query",
  Long: `### Run a saved query.

This runs a previously saved query. You can use this on a query that was generated in the Looker UI
or one that you have explicitly created using the API. You can also use a query 'id' from a saved 'Look'.

The 'result_format' parameter specifies the desired structure and format of the response.

Supported formats:

| result_format | Description
| :-----------: | :--- |
| json | Plain json
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| md | Simple markdown
| xlsx | MS Excel spreadsheet
| sql | Returns the generated SQL rather than running the query
| png | A PNG image of the visualization of the query
| jpg | A JPG image of the visualization of the query


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_query called")
  },
}


var run_inline_queryCmd = &cobra.Command{
  Use:   "run_inline_query",
  Short: "Run Inline Query",
  Long: `### Run the query that is specified inline in the posted body.

This allows running a query as defined in json in the posted body. This combines
the two actions of posting & running a query into one step.

Here is an example body in json:
```
{
  "model":"thelook",
  "view":"inventory_items",
  "fields":["category.name","inventory_items.days_in_inventory_tier","products.count"],
  "filters":{"category.name":"socks"},
  "sorts":["products.count desc 0"],
  "limit":"500",
  "query_timezone":"America/Los_Angeles"
}
```

When using the Ruby SDK this would be passed as a Ruby hash like:
```
{
 :model=>"thelook",
 :view=>"inventory_items",
 :fields=>
  ["category.name",
   "inventory_items.days_in_inventory_tier",
   "products.count"],
 :filters=>{:"category.name"=>"socks"},
 :sorts=>["products.count desc 0"],
 :limit=>"500",
 :query_timezone=>"America/Los_Angeles",
}
```

This will return the result of running the query in the format specified by the 'result_format' parameter.

Supported formats:

| result_format | Description
| :-----------: | :--- |
| json | Plain json
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| md | Simple markdown
| xlsx | MS Excel spreadsheet
| sql | Returns the generated SQL rather than running the query
| png | A PNG image of the visualization of the query
| jpg | A JPG image of the visualization of the query


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_inline_query called")
  },
}


var run_url_encoded_queryCmd = &cobra.Command{
  Use:   "run_url_encoded_query",
  Short: "Run Url Encoded Query",
  Long: `### Run an URL encoded query.

This requires the caller to encode the specifiers for the query into the URL query part using
Looker-specific syntax as explained below.

Generally, you would want to use one of the methods that takes the parameters as json in the POST body
for creating and/or running queries. This method exists for cases where one really needs to encode the
parameters into the URL of a single 'GET' request. This matches the way that the Looker UI formats
'explore' URLs etc.

The parameters here are very similar to the json body formatting except that the filter syntax is
tricky. Unfortunately, this format makes this method not currently callable via the 'Try it out!' button
in this documentation page. But, this is callable when creating URLs manually or when using the Looker SDK.

Here is an example inline query URL:

```
https://looker.mycompany.com:19999/api/3.0/queries/models/thelook/views/inventory_items/run/json?fields=category.name,inventory_items.days_in_inventory_tier,products.count&f[category.name]=socks&sorts=products.count+desc+0&limit=500&query_timezone=America/Los_Angeles
```

When invoking this endpoint with the Ruby SDK, pass the query parameter parts as a hash. The hash to match the above would look like:

```ruby
query_params =
{
  :fields => "category.name,inventory_items.days_in_inventory_tier,products.count",
  :"f[category.name]" => "socks",
  :sorts => "products.count desc 0",
  :limit => "500",
  :query_timezone => "America/Los_Angeles"
}
response = ruby_sdk.run_url_encoded_query('thelook','inventory_items','json', query_params)

```

Again, it is generally easier to use the variant of this method that passes the full query in the POST body.
This method is available for cases where other alternatives won't fit the need.

Supported formats:

| result_format | Description
| :-----------: | :--- |
| json | Plain json
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| md | Simple markdown
| xlsx | MS Excel spreadsheet
| sql | Returns the generated SQL rather than running the query
| png | A PNG image of the visualization of the query
| jpg | A JPG image of the visualization of the query


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_url_encoded_query called")
  },
}


var merge_queryCmd = &cobra.Command{
  Use:   "merge_query",
  Short: "Get Merge Query",
  Long: `### Get Merge Query

Returns a merge query object given its id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("merge_query called")
  },
}


var create_merge_queryCmd = &cobra.Command{
  Use:   "create_merge_query",
  Short: "Create Merge Query",
  Long: `### Create Merge Query

Creates a new merge query object.

A merge query takes the results of one or more queries and combines (merges) the results
according to field mapping definitions. The result is similar to a SQL left outer join.

A merge query can merge results of queries from different SQL databases.

The order that queries are defined in the source_queries array property is significant. The
first query in the array defines the primary key into which the results of subsequent
queries will be merged.

Like model/view query objects, merge queries are immutable and have structural identity - if
you make a request to create a new merge query that is identical to an existing merge query,
the existing merge query will be returned instead of creating a duplicate. Conversely, any
change to the contents of a merge query will produce a new object with a new id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_merge_query called")
  },
}


var all_running_queriesCmd = &cobra.Command{
  Use:   "all_running_queries",
  Short: "Get All Running Queries",
  Long: `Get information about all running queries.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_running_queries called")
  },
}


var kill_queryCmd = &cobra.Command{
  Use:   "kill_query",
  Short: "Kill Running Query",
  Long: `Kill a query with a specific query_task_id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("kill_query called")
  },
}


var sql_queryCmd = &cobra.Command{
  Use:   "sql_query",
  Short: "Get SQL Runner Query",
  Long: `Get a SQL Runner query.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sql_query called")
  },
}


var create_sql_queryCmd = &cobra.Command{
  Use:   "create_sql_query",
  Short: "Create SQL Runner Query",
  Long: `### Create a SQL Runner Query

Either the `connection_name` or `model_name` parameter MUST be provided.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_sql_query called")
  },
}


var run_sql_queryCmd = &cobra.Command{
  Use:   "run_sql_query",
  Short: "Run SQL Runner Query",
  Long: `Execute a SQL Runner query in a given result_format.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_sql_query called")
  },
}




var renderTaskCmd = &cobra.Command{
  Use:   "RenderTask",
  Short: "Manage Render Tasks",
  Long: "Manage Render Tasks",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("RenderTask called")
  },
}


var create_lookml_dashboard_render_taskCmd = &cobra.Command{
  Use:   "create_lookml_dashboard_render_task",
  Short: "Create Lookml Dashboard Render Task",
  Long: `### Create a new task to render a lookml dashboard to a document or image.

# DEPRECATED:  Use [create_dashboard_render_task()](#!/RenderTask/create_dashboard_render_task) in API 4.0+

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_lookml_dashboard_render_task called")
  },
}


var create_look_render_taskCmd = &cobra.Command{
  Use:   "create_look_render_task",
  Short: "Create Look Render Task",
  Long: `### Create a new task to render a look to an image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_look_render_task called")
  },
}


var create_query_render_taskCmd = &cobra.Command{
  Use:   "create_query_render_task",
  Short: "Create Query Render Task",
  Long: `### Create a new task to render an existing query to an image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_query_render_task called")
  },
}


var create_dashboard_render_taskCmd = &cobra.Command{
  Use:   "create_dashboard_render_task",
  Short: "Create Dashboard Render Task",
  Long: `### Create a new task to render a dashboard to a document or image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_render_task called")
  },
}


var render_taskCmd = &cobra.Command{
  Use:   "render_task",
  Short: "Get Render Task",
  Long: `### Get information about a render task.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("render_task called")
  },
}


var render_task_resultsCmd = &cobra.Command{
  Use:   "render_task_results",
  Short: "Render Task Results",
  Long: `### Get the document or image produced by a completed render task.

Note that the PDF or image result will be a binary blob in the HTTP response, as indicated by the
Content-Type in the response headers. This may require specialized (or at least different) handling than text
responses such as JSON. You may need to tell your HTTP client that the response is binary so that it does not
attempt to parse the binary data as text.

If the render task exists but has not finished rendering the results, the response HTTP status will be
**202 Accepted**, the response body will be empty, and the response will have a Retry-After header indicating
that the caller should repeat the request at a later time.

Returns 404 if the render task cannot be found, if the cached result has expired, or if the caller
does not have permission to view the results.

For detailed information about the status of the render task, use [Render Task](#!/RenderTask/render_task).
Polling loops waiting for completion of a render task would be better served by polling **render_task(id)** until
the task status reaches completion (or error) instead of polling **render_task_results(id)** alone.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("render_task_results called")
  },
}




var roleCmd = &cobra.Command{
  Use:   "Role",
  Short: "Manage Roles",
  Long: "Manage Roles",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Role called")
  },
}


var search_model_setsCmd = &cobra.Command{
  Use:   "search_model_sets",
  Short: "Search Model Sets",
  Long: `### Search model sets
Returns all model set records that match the given search criteria.
If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_model_sets called")
  },
}


var model_setCmd = &cobra.Command{
  Use:   "model_set",
  Short: "Get Model Set",
  Long: `### Get information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("model_set called")
  },
}


var update_model_setCmd = &cobra.Command{
  Use:   "update_model_set",
  Short: "Update Model Set",
  Long: `### Update information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_model_set called")
  },
}


var delete_model_setCmd = &cobra.Command{
  Use:   "delete_model_set",
  Short: "Delete Model Set",
  Long: `### Delete the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_model_set called")
  },
}


var all_model_setsCmd = &cobra.Command{
  Use:   "all_model_sets",
  Short: "Get All Model Sets",
  Long: `### Get information about all model sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_model_sets called")
  },
}


var create_model_setCmd = &cobra.Command{
  Use:   "create_model_set",
  Short: "Create Model Set",
  Long: `### Create a model set with the specified information. Model sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_model_set called")
  },
}


var all_permissionsCmd = &cobra.Command{
  Use:   "all_permissions",
  Short: "Get All Permissions",
  Long: `### Get all supported permissions.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_permissions called")
  },
}


var search_permission_setsCmd = &cobra.Command{
  Use:   "search_permission_sets",
  Short: "Search Permission Sets",
  Long: `### Search permission sets
Returns all permission set records that match the given search criteria.
If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_permission_sets called")
  },
}


var permission_setCmd = &cobra.Command{
  Use:   "permission_set",
  Short: "Get Permission Set",
  Long: `### Get information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("permission_set called")
  },
}


var update_permission_setCmd = &cobra.Command{
  Use:   "update_permission_set",
  Short: "Update Permission Set",
  Long: `### Update information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_permission_set called")
  },
}


var delete_permission_setCmd = &cobra.Command{
  Use:   "delete_permission_set",
  Short: "Delete Permission Set",
  Long: `### Delete the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_permission_set called")
  },
}


var all_permission_setsCmd = &cobra.Command{
  Use:   "all_permission_sets",
  Short: "Get All Permission Sets",
  Long: `### Get information about all permission sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_permission_sets called")
  },
}


var create_permission_setCmd = &cobra.Command{
  Use:   "create_permission_set",
  Short: "Create Permission Set",
  Long: `### Create a permission set with the specified information. Permission sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_permission_set called")
  },
}


var all_rolesCmd = &cobra.Command{
  Use:   "all_roles",
  Short: "Get All Roles",
  Long: `### Get information about all roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_roles called")
  },
}


var create_roleCmd = &cobra.Command{
  Use:   "create_role",
  Short: "Create Role",
  Long: `### Create a role with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_role called")
  },
}


var search_rolesCmd = &cobra.Command{
  Use:   "search_roles",
  Short: "Search Roles",
  Long: `### Search roles

Returns all role records that match the given search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_roles called")
  },
}


var roleCmd = &cobra.Command{
  Use:   "role",
  Short: "Get Role",
  Long: `### Get information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role called")
  },
}


var update_roleCmd = &cobra.Command{
  Use:   "update_role",
  Short: "Update Role",
  Long: `### Update information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_role called")
  },
}


var delete_roleCmd = &cobra.Command{
  Use:   "delete_role",
  Short: "Delete Role",
  Long: `### Delete the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_role called")
  },
}


var role_groupsCmd = &cobra.Command{
  Use:   "role_groups",
  Short: "Get Role Groups",
  Long: `### Get information about all the groups with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role_groups called")
  },
}


var set_role_groupsCmd = &cobra.Command{
  Use:   "set_role_groups",
  Short: "Update Role Groups",
  Long: `### Set all groups for a role, removing all existing group associations from that role.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_role_groups called")
  },
}


var role_usersCmd = &cobra.Command{
  Use:   "role_users",
  Short: "Get Role Users",
  Long: `### Get information about all the users with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role_users called")
  },
}


var set_role_usersCmd = &cobra.Command{
  Use:   "set_role_users",
  Short: "Update Role Users",
  Long: `### Set all the users of the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_role_users called")
  },
}




var scheduledPlanCmd = &cobra.Command{
  Use:   "ScheduledPlan",
  Short: "Manage Scheduled Plans",
  Long: "Manage Scheduled Plans",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ScheduledPlan called")
  },
}


var scheduled_plans_for_spaceCmd = &cobra.Command{
  Use:   "scheduled_plans_for_space",
  Short: "Scheduled Plans for Space",
  Long: `### Get Scheduled Plans for a Space

Returns scheduled plans owned by the caller for a given space id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plans_for_space called")
  },
}


var scheduled_planCmd = &cobra.Command{
  Use:   "scheduled_plan",
  Short: "Get Scheduled Plan",
  Long: `### Get Information About a Scheduled Plan

Admins can fetch information about other users' Scheduled Plans.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plan called")
  },
}


var update_scheduled_planCmd = &cobra.Command{
  Use:   "update_scheduled_plan",
  Short: "Update Scheduled Plan",
  Long: `### Update a Scheduled Plan

Admins can update other users' Scheduled Plans.

Note: Any scheduled plan destinations specified in an update will **replace** all scheduled plan destinations
currently defined for the scheduled plan.

For Example: If a scheduled plan has destinations A, B, and C, and you call update on this scheduled plan
specifying only B in the destinations, then destinations A and C will be deleted by the update.

Updating a scheduled plan to assign null or an empty array to the scheduled_plan_destinations property is an error, as a scheduled plan must always have at least one destination.

If you omit the scheduled_plan_destinations property from the object passed to update, then the destinations
defined on the original scheduled plan will remain unchanged.

#### Email Permissions:

For details about permissions required to schedule delivery to email and the safeguards
Looker offers to protect against sending to unauthorized email destinations, see [Email Domain Whitelist for Scheduled Looks](https://docs.looker.com/r/api/embed-permissions).


#### Scheduled Plan Destination Formats

Scheduled plan destinations must specify the data format to produce and send to the destination.

Formats:

| format | Description
| :-----------: | :--- |
| json | A JSON object containing a `data` property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the `data` property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. `wysiwyg_pdf` is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_scheduled_plan called")
  },
}


var delete_scheduled_planCmd = &cobra.Command{
  Use:   "delete_scheduled_plan",
  Short: "Delete Scheduled Plan",
  Long: `### Delete a Scheduled Plan

Normal users can only delete their own scheduled plans.
Admins can delete other users' scheduled plans.
This delete cannot be undone.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_scheduled_plan called")
  },
}


var all_scheduled_plansCmd = &cobra.Command{
  Use:   "all_scheduled_plans",
  Short: "Get All Scheduled Plans",
  Long: `### List All Scheduled Plans

Returns all scheduled plans which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass `all_users=true`.


The caller must have `see_schedules` permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_scheduled_plans called")
  },
}


var create_scheduled_planCmd = &cobra.Command{
  Use:   "create_scheduled_plan",
  Short: "Create Scheduled Plan",
  Long: `### Create a Scheduled Plan

Create a scheduled plan to render a Look or Dashboard on a recurring schedule.

To create a scheduled plan, you MUST provide values for the following fields:
`name`
and
`look_id`, `dashboard_id`, `lookml_dashboard_id`, or `query_id`
and
`cron_tab` or `datagroup`
and
at least one scheduled_plan_destination

A scheduled plan MUST have at least one scheduled_plan_destination defined.

When `look_id` is set, `require_no_results`, `require_results`, and `require_change` are all required.

If `create_scheduled_plan` fails with a 422 error, be sure to look at the error messages in the response which will explain exactly what fields are missing or values that are incompatible.

The queries that provide the data for the look or dashboard are run in the context of user account that owns the scheduled plan.

When `run_as_recipient` is `false` or not specified, the queries that provide the data for the
look or dashboard are run in the context of user account that owns the scheduled plan.

When `run_as_recipient` is `true` and all the email recipients are Looker user accounts, the
queries are run in the context of each recipient, so different recipients may see different
data from the same scheduled render of a look or dashboard. For more details, see [Run As Recipient](https://looker.com/docs/r/admin/run-as-recipient).

Admins can create and modify scheduled plans on behalf of other users by specifying a user id.
Non-admin users may not create or modify scheduled plans by or for other users.

#### Email Permissions:

For details about permissions required to schedule delivery to email and the safeguards
Looker offers to protect against sending to unauthorized email destinations, see [Email Domain Whitelist for Scheduled Looks](https://docs.looker.com/r/api/embed-permissions).


#### Scheduled Plan Destination Formats

Scheduled plan destinations must specify the data format to produce and send to the destination.

Formats:

| format | Description
| :-----------: | :--- |
| json | A JSON object containing a `data` property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the `data` property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. `wysiwyg_pdf` is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_scheduled_plan called")
  },
}


var scheduled_plan_run_onceCmd = &cobra.Command{
  Use:   "scheduled_plan_run_once",
  Short: "Run Scheduled Plan Once",
  Long: `### Run a Scheduled Plan Immediately

Create a scheduled plan that runs only once, and immediately.

This can be useful for testing a Scheduled Plan before committing to a production schedule.

Admins can create scheduled plans on behalf of other users by specifying a user id.

This API is rate limited to prevent it from being used for relay spam or DoS attacks

#### Email Permissions:

For details about permissions required to schedule delivery to email and the safeguards
Looker offers to protect against sending to unauthorized email destinations, see [Email Domain Whitelist for Scheduled Looks](https://docs.looker.com/r/api/embed-permissions).


#### Scheduled Plan Destination Formats

Scheduled plan destinations must specify the data format to produce and send to the destination.

Formats:

| format | Description
| :-----------: | :--- |
| json | A JSON object containing a `data` property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the `data` property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. `wysiwyg_pdf` is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plan_run_once called")
  },
}


var scheduled_plans_for_lookCmd = &cobra.Command{
  Use:   "scheduled_plans_for_look",
  Short: "Scheduled Plans for Look",
  Long: `### Get Scheduled Plans for a Look

Returns all scheduled plans for a look which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass `all_users=true`.


The caller must have `see_schedules` permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plans_for_look called")
  },
}


var scheduled_plans_for_dashboardCmd = &cobra.Command{
  Use:   "scheduled_plans_for_dashboard",
  Short: "Scheduled Plans for Dashboard",
  Long: `### Get Scheduled Plans for a Dashboard

Returns all scheduled plans for a dashboard which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass `all_users=true`.


The caller must have `see_schedules` permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plans_for_dashboard called")
  },
}


var scheduled_plans_for_lookml_dashboardCmd = &cobra.Command{
  Use:   "scheduled_plans_for_lookml_dashboard",
  Short: "Scheduled Plans for LookML Dashboard",
  Long: `### Get Scheduled Plans for a LookML Dashboard

Returns all scheduled plans for a LookML Dashboard which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass `all_users=true`.


The caller must have `see_schedules` permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plans_for_lookml_dashboard called")
  },
}


var scheduled_plan_run_once_by_idCmd = &cobra.Command{
  Use:   "scheduled_plan_run_once_by_id",
  Short: "Run Scheduled Plan Once by Id",
  Long: `### Run a Scheduled Plan By Id Immediately
This function creates a run-once schedule plan based on an existing scheduled plan,
applies modifications (if any) to the new scheduled plan, and runs the new schedule plan immediately.
This can be useful for testing modifications to an existing scheduled plan before committing to a production schedule.

This function internally performs the following operations:

1. Copies the properties of the existing scheduled plan into a new scheduled plan
2. Copies any properties passed in the JSON body of this request into the new scheduled plan (replacing the original values)
3. Creates the new scheduled plan
4. Runs the new scheduled plan

The original scheduled plan is not modified by this operation.
Admins can create, modify, and run scheduled plans on behalf of other users by specifying a user id.
Non-admins can only create, modify, and run their own scheduled plans.

#### Email Permissions:

For details about permissions required to schedule delivery to email and the safeguards
Looker offers to protect against sending to unauthorized email destinations, see [Email Domain Whitelist for Scheduled Looks](https://docs.looker.com/r/api/embed-permissions).


#### Scheduled Plan Destination Formats

Scheduled plan destinations must specify the data format to produce and send to the destination.

Formats:

| format | Description
| :-----------: | :--- |
| json | A JSON object containing a `data` property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the `data` property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. `wysiwyg_pdf` is only valid for dashboards, for example.



This API is rate limited to prevent it from being used for relay spam or DoS attacks

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plan_run_once_by_id called")
  },
}




var sessionCmd = &cobra.Command{
  Use:   "Session",
  Short: "Session Information",
  Long: "Session Information",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Session called")
  },
}


var sessionCmd = &cobra.Command{
  Use:   "session",
  Short: "Get Session",
  Long: `### Get API Session

Returns information about the current API session, such as which workspace is selected for the session.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("session called")
  },
}


var update_sessionCmd = &cobra.Command{
  Use:   "update_session",
  Short: "Update Session",
  Long: `### Update API Session

#### API Session Workspace

You can use this endpoint to change the active workspace for the current API session.

Only one workspace can be active in a session. The active workspace can be changed
any number of times in a session.

The default workspace for API sessions is the "production" workspace.

All Looker APIs that use projects or lookml models (such as running queries) will
use the version of project and model files defined by this workspace for the lifetime of the
current API session or until the session workspace is changed again.

An API session has the same lifetime as the access_token used to authenticate API requests. Each successful
API login generates a new access_token and a new API session.

If your Looker API client application needs to work in a dev workspace across multiple
API sessions, be sure to select the dev workspace after each login.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_session called")
  },
}




var spaceCmd = &cobra.Command{
  Use:   "Space",
  Short: "Manage Spaces",
  Long: "Manage Spaces",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Space called")
  },
}


var search_spacesCmd = &cobra.Command{
  Use:   "search_spaces",
  Short: "Search Spaces",
  Long: `### Search Spaces

  Returns an **array of space objects** that match the given search criteria.

  If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


  The parameters `limit`, and `offset` are recommended for fetching results in page-size chunks.

  Get a **single space** by id with [Space](#!/Space/space)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_spaces called")
  },
}


var spaceCmd = &cobra.Command{
  Use:   "space",
  Short: "Get Space",
  Long: `### Get information about the space with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space called")
  },
}


var update_spaceCmd = &cobra.Command{
  Use:   "update_space",
  Short: "Update Space",
  Long: `### Update the space with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_space called")
  },
}


var delete_spaceCmd = &cobra.Command{
  Use:   "delete_space",
  Short: "Delete Space",
  Long: `### Delete the space with a specific id including any children spaces.
**DANGER** this will delete all looks and dashboards in the space.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_space called")
  },
}


var all_spacesCmd = &cobra.Command{
  Use:   "all_spaces",
  Short: "Get All Spaces",
  Long: `### Get information about all spaces.

In API 3.x, this will not return empty personal spaces, unless they belong to the calling user.
In API 4.0+, all personal spaces will be returned.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_spaces called")
  },
}


var create_spaceCmd = &cobra.Command{
  Use:   "create_space",
  Short: "Create Space",
  Long: `### Create a space with specified information.

Caller must have permission to edit the parent space and to create spaces, otherwise the request
returns 404 Not Found.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_space called")
  },
}


var space_childrenCmd = &cobra.Command{
  Use:   "space_children",
  Short: "Get Space Children",
  Long: `### Get the children of a space.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_children called")
  },
}


var space_children_searchCmd = &cobra.Command{
  Use:   "space_children_search",
  Short: "Search Space Children",
  Long: `### Search the children of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_children_search called")
  },
}


var space_parentCmd = &cobra.Command{
  Use:   "space_parent",
  Short: "Get Space Parent",
  Long: `### Get the parent of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_parent called")
  },
}


var space_ancestorsCmd = &cobra.Command{
  Use:   "space_ancestors",
  Short: "Get Space Ancestors",
  Long: `### Get the ancestors of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_ancestors called")
  },
}


var space_looksCmd = &cobra.Command{
  Use:   "space_looks",
  Short: "Get Space Looks",
  Long: `### Get all looks in a space.
In API 3.x, this will return all looks in a space, including looks in the trash.
In API 4.0+, all looks in a space will be returned, excluding looks in the trash.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_looks called")
  },
}


var space_dashboardsCmd = &cobra.Command{
  Use:   "space_dashboards",
  Short: "Get Space Dashboards",
  Long: `### Get the dashboards in a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space_dashboards called")
  },
}




var themeCmd = &cobra.Command{
  Use:   "Theme",
  Short: "Manage Themes",
  Long: "Manage Themes",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Theme called")
  },
}


var all_themesCmd = &cobra.Command{
  Use:   "all_themes",
  Short: "Get All Themes",
  Long: `### Get an array of all existing themes

Get a **single theme** by id with [Theme](#!/Theme/theme)

This method returns an array of all existing themes. The active time for the theme is not considered.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_themes called")
  },
}


var create_themeCmd = &cobra.Command{
  Use:   "create_theme",
  Short: "Create Theme",
  Long: `### Create a theme

Creates a new theme object, returning the theme details, including the created id.

If `settings` are not specified, the default theme settings will be copied into the new theme.

The theme `name` can only contain alphanumeric characters or underscores. Theme names should not contain any confidential information, such as customer names.

**Update** an existing theme with [Update Theme](#!/Theme/update_theme)

**Permanently delete** an existing theme with [Delete Theme](#!/Theme/delete_theme)

For more information, see [Creating and Applying Themes](https://looker.com/docs/r/admin/themes).

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_theme called")
  },
}


var search_themesCmd = &cobra.Command{
  Use:   "search_themes",
  Short: "Search Themes",
  Long: `### Search all themes for matching criteria.

Returns an **array of theme objects** that match the specified search criteria.

| Search Parameters | Description
| :-------------------: | :------ |
| `begin_at` only | Find themes active at or after `begin_at`
| `end_at` only | Find themes active at or before `end_at`
| both set | Find themes with an active inclusive period between `begin_at` and `end_at`

Note: Range matching requires boolean AND logic.
When using `begin_at` and `end_at` together, do not use `filter_or`=TRUE

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


Get a **single theme** by id with [Theme](#!/Theme/theme)

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_themes called")
  },
}


var default_themeCmd = &cobra.Command{
  Use:   "default_theme",
  Short: "Get Default Theme",
  Long: `### Get the default theme

Returns the active theme object set as the default.

The **default** theme name can be set in the UI on the Admin|Theme UI page

The optional `ts` parameter can specify a different timestamp than "now." If specified, it returns the default theme at the time indicated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("default_theme called")
  },
}


var set_default_themeCmd = &cobra.Command{
  Use:   "set_default_theme",
  Short: "Set Default Theme",
  Long: `### Set the global default theme by theme name

Only Admin users can call this function.

Only an active theme with no expiration (`end_at` not set) can be assigned as the default theme. As long as a theme has an active record with no expiration, it can be set as the default.

[Create Theme](#!/Theme/create) has detailed information on rules for default and active themes

Returns the new specified default theme object.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_default_theme called")
  },
}


var active_themesCmd = &cobra.Command{
  Use:   "active_themes",
  Short: "Get Active Themes",
  Long: `### Get active themes

Returns an array of active themes.

If the `name` parameter is specified, it will return an array with one theme if it's active and found.

The optional `ts` parameter can specify a different timestamp than "now."

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("active_themes called")
  },
}


var theme_or_defaultCmd = &cobra.Command{
  Use:   "theme_or_default",
  Short: "Get Theme or Default",
  Long: `### Get the named theme if it's active. Otherwise, return the default theme

The optional `ts` parameter can specify a different timestamp than "now."
Note: API users with `show` ability can call this function

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("theme_or_default called")
  },
}


var validate_themeCmd = &cobra.Command{
  Use:   "validate_theme",
  Short: "Validate Theme",
  Long: `### Validate a theme with the specified information

Validates all values set for the theme, returning any errors encountered, or 200 OK if valid

See [Create Theme](#!/Theme/create_theme) for constraints

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("validate_theme called")
  },
}


var themeCmd = &cobra.Command{
  Use:   "theme",
  Short: "Get Theme",
  Long: `### Get a theme by ID

Use this to retrieve a specific theme, whether or not it's currently active.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("theme called")
  },
}


var update_themeCmd = &cobra.Command{
  Use:   "update_theme",
  Short: "Update Theme",
  Long: `### Update the theme by id.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_theme called")
  },
}


var delete_themeCmd = &cobra.Command{
  Use:   "delete_theme",
  Short: "Delete Theme",
  Long: `### Delete a specific theme by id

This operation permanently deletes the identified theme from the database.

Because multiple themes can have the same name (with different activation time spans) themes can only be deleted by ID.

All IDs associated with a theme name can be retrieved by searching for the theme name with [Theme Search](#!/Theme/search).

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_theme called")
  },
}




var userCmd = &cobra.Command{
  Use:   "User",
  Short: "Manage Users",
  Long: "Manage Users",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("User called")
  },
}


var meCmd = &cobra.Command{
  Use:   "me",
  Short: "Get Current User",
  Long: `### Get information about the current user; i.e. the user account currently calling the API.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("me called")
  },
}


var all_usersCmd = &cobra.Command{
  Use:   "all_users",
  Short: "Get All Users",
  Long: `### Get information about all users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_users called")
  },
}


var create_userCmd = &cobra.Command{
  Use:   "create_user",
  Short: "Create User",
  Long: `### Create a user with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user called")
  },
}


var search_usersCmd = &cobra.Command{
  Use:   "search_users",
  Short: "Search Users",
  Long: `### Search users

Returns all<sup>*</sup> user records that match the given search criteria.

If multiple search params are given and `filter_or` is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If `filter_or` is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain `%` and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


(<sup>*</sup>) Results are always filtered to the level of information the caller is permitted to view.
Looker admins can see all user details; normal users in an open system can see
names of other users but no details; normal users in a closed system can only see
names of other users who are members of the same group as the user.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_users called")
  },
}


var search_users_namesCmd = &cobra.Command{
  Use:   "search_users_names",
  Short: "Search User Names",
  Long: `### Search for user accounts by name

Returns all user accounts where `first_name` OR `last_name` OR `email` field values match a pattern.
The pattern can contain `%` and `_` wildcards as in SQL LIKE expressions.

Any additional search params will be combined into a logical AND expression.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_users_names called")
  },
}


var userCmd = &cobra.Command{
  Use:   "user",
  Short: "Get User by Id",
  Long: `### Get information about the user with a specific id.

If the caller is an admin or the caller is the user being specified, then full user information will
be returned. Otherwise, a minimal 'public' variant of the user information will be returned. This contains
The user name and avatar url, but no sensitive information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user called")
  },
}


var update_userCmd = &cobra.Command{
  Use:   "update_user",
  Short: "Update User",
  Long: `### Update information about the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user called")
  },
}


var delete_userCmd = &cobra.Command{
  Use:   "delete_user",
  Short: "Delete User",
  Long: `### Delete the user with a specific id.

**DANGER** this will delete the user and all looks and other information owned by the user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user called")
  },
}


var user_for_credentialCmd = &cobra.Command{
  Use:   "user_for_credential",
  Short: "Get User by Credential Id",
  Long: `### Get information about the user with a credential of given type with specific id.

This is used to do things like find users by their embed external_user_id. Or, find the user with
a given api3 client_id, etc. The 'credential_type' matches the 'type' name of the various credential
types. It must be one of the values listed in the table below. The 'credential_id' is your unique Id
for the user and is specific to each type of credential.

An example using the Ruby sdk might look like:

`sdk.user_for_credential('embed', 'customer-4959425')`

This table shows the supported 'Credential Type' strings. The right column is for reference; it shows
which field in the given credential type is actually searched when finding a user with the supplied
'credential_id'.

| Credential Types | Id Field Matched |
| ---------------- | ---------------- |
| email            | email            |
| google           | google_user_id   |
| saml             | saml_user_id     |
| oidc             | oidc_user_id     |
| ldap             | ldap_id          |
| api              | token            |
| api3             | client_id        |
| embed            | external_user_id |
| looker_openid    | email            |

**NOTE**: The 'api' credential type was only used with the legacy Looker query API and is no longer supported. The credential type for API you are currently looking at is 'api3'.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_for_credential called")
  },
}


var user_credentials_emailCmd = &cobra.Command{
  Use:   "user_credentials_email",
  Short: "Get Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_email called")
  },
}


var create_user_credentials_emailCmd = &cobra.Command{
  Use:   "create_user_credentials_email",
  Short: "Create Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_email called")
  },
}


var update_user_credentials_emailCmd = &cobra.Command{
  Use:   "update_user_credentials_email",
  Short: "Update Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_credentials_email called")
  },
}


var delete_user_credentials_emailCmd = &cobra.Command{
  Use:   "delete_user_credentials_email",
  Short: "Delete Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_email called")
  },
}


var user_credentials_totpCmd = &cobra.Command{
  Use:   "user_credentials_totp",
  Short: "Get Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_totp called")
  },
}


var create_user_credentials_totpCmd = &cobra.Command{
  Use:   "create_user_credentials_totp",
  Short: "Create Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_totp called")
  },
}


var delete_user_credentials_totpCmd = &cobra.Command{
  Use:   "delete_user_credentials_totp",
  Short: "Delete Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_totp called")
  },
}


var user_credentials_ldapCmd = &cobra.Command{
  Use:   "user_credentials_ldap",
  Short: "Get LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_ldap called")
  },
}


var delete_user_credentials_ldapCmd = &cobra.Command{
  Use:   "delete_user_credentials_ldap",
  Short: "Delete LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_ldap called")
  },
}


var user_credentials_googleCmd = &cobra.Command{
  Use:   "user_credentials_google",
  Short: "Get Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_google called")
  },
}


var delete_user_credentials_googleCmd = &cobra.Command{
  Use:   "delete_user_credentials_google",
  Short: "Delete Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_google called")
  },
}


var user_credentials_samlCmd = &cobra.Command{
  Use:   "user_credentials_saml",
  Short: "Get Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_saml called")
  },
}


var delete_user_credentials_samlCmd = &cobra.Command{
  Use:   "delete_user_credentials_saml",
  Short: "Delete Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_saml called")
  },
}


var user_credentials_oidcCmd = &cobra.Command{
  Use:   "user_credentials_oidc",
  Short: "Get OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_oidc called")
  },
}


var delete_user_credentials_oidcCmd = &cobra.Command{
  Use:   "delete_user_credentials_oidc",
  Short: "Delete OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_oidc called")
  },
}


var user_credentials_api3Cmd = &cobra.Command{
  Use:   "user_credentials_api3",
  Short: "Get API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_api3 called")
  },
}


var delete_user_credentials_api3Cmd = &cobra.Command{
  Use:   "delete_user_credentials_api3",
  Short: "Delete API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_api3 called")
  },
}


var all_user_credentials_api3sCmd = &cobra.Command{
  Use:   "all_user_credentials_api3s",
  Short: "Get All API 3 Credentials",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_credentials_api3s called")
  },
}


var create_user_credentials_api3Cmd = &cobra.Command{
  Use:   "create_user_credentials_api3",
  Short: "Create API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_api3 called")
  },
}


var user_credentials_embedCmd = &cobra.Command{
  Use:   "user_credentials_embed",
  Short: "Get Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_embed called")
  },
}


var delete_user_credentials_embedCmd = &cobra.Command{
  Use:   "delete_user_credentials_embed",
  Short: "Delete Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_embed called")
  },
}


var all_user_credentials_embedsCmd = &cobra.Command{
  Use:   "all_user_credentials_embeds",
  Short: "Get All Embedding Credentials",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_credentials_embeds called")
  },
}


var user_credentials_looker_openidCmd = &cobra.Command{
  Use:   "user_credentials_looker_openid",
  Short: "Get Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_looker_openid called")
  },
}


var delete_user_credentials_looker_openidCmd = &cobra.Command{
  Use:   "delete_user_credentials_looker_openid",
  Short: "Delete Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_looker_openid called")
  },
}


var user_sessionCmd = &cobra.Command{
  Use:   "user_session",
  Short: "Get Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_session called")
  },
}


var delete_user_sessionCmd = &cobra.Command{
  Use:   "delete_user_session",
  Short: "Delete Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_session called")
  },
}


var all_user_sessionsCmd = &cobra.Command{
  Use:   "all_user_sessions",
  Short: "Get All Web Login Sessions",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_sessions called")
  },
}


var create_user_credentials_email_password_resetCmd = &cobra.Command{
  Use:   "create_user_credentials_email_password_reset",
  Short: "Create Password Reset Token",
  Long: `### Create a password reset token.
This will create a cryptographically secure random password reset token for the user.
If the user already has a password reset token then this invalidates the old token and creates a new one.
The token is expressed as the 'password_reset_url' of the user's email/password credential object.
This takes an optional 'expires' param to indicate if the new token should be an expiring token.
Tokens that expire are typically used for self-service password resets for existing users.
Invitation emails for new users typically are not set to expire.
The expire period is always 60 minutes when expires is enabled.
This method can be called with an empty body.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_email_password_reset called")
  },
}


var user_rolesCmd = &cobra.Command{
  Use:   "user_roles",
  Short: "Get User Roles",
  Long: `### Get information about roles of a given user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_roles called")
  },
}


var set_user_rolesCmd = &cobra.Command{
  Use:   "set_user_roles",
  Short: "Set User Roles",
  Long: `### Set roles of the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_user_roles called")
  },
}


var user_attribute_user_valuesCmd = &cobra.Command{
  Use:   "user_attribute_user_values",
  Short: "Get User Attribute Values",
  Long: `### Get user attribute values for a given user.

Returns the values of specified user attributes (or all user attributes) for a certain user.

A value for each user attribute is searched for in the following locations, in this order:

1. in the user's account information
1. in groups that the user is a member of
1. the default value of the user attribute

If more than one group has a value defined for a user attribute, the group with the lowest rank wins.

The response will only include user attributes for which values were found. Use `include_unset=true` to include
empty records for user attributes with no value.

The value of all hidden user attributes will be blank.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_attribute_user_values called")
  },
}


var set_user_attribute_user_valueCmd = &cobra.Command{
  Use:   "set_user_attribute_user_value",
  Short: "Set User Attribute User Value",
  Long: `### Store a custom value for a user attribute in a user's account settings.

Per-user user attribute values take precedence over group or default values.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_user_attribute_user_value called")
  },
}


var delete_user_attribute_user_valueCmd = &cobra.Command{
  Use:   "delete_user_attribute_user_value",
  Short: "Delete User Attribute User Value",
  Long: `### Delete a user attribute value from a user's account settings.

After the user attribute value is deleted from the user's account settings, subsequent requests
for the user attribute value for this user will draw from the user's groups or the default
value of the user attribute. See [Get User Attribute Values](#!/User/user_attribute_user_values) for more
information about how user attribute values are resolved.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_attribute_user_value called")
  },
}




var userAttributeCmd = &cobra.Command{
  Use:   "UserAttribute",
  Short: "Manage User Attributes",
  Long: "Manage User Attributes",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("UserAttribute called")
  },
}


var all_user_attributesCmd = &cobra.Command{
  Use:   "all_user_attributes",
  Short: "Get All User Attributes",
  Long: `### Get information about all user attributes.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_attributes called")
  },
}


var create_user_attributeCmd = &cobra.Command{
  Use:   "create_user_attribute",
  Short: "Create User Attribute",
  Long: `### Create a new user attribute

Permission information for a user attribute is conveyed through the `can` and `user_can_edit` fields.
The `user_can_edit` field indicates whether an attribute is user-editable _anywhere_ in the application.
The `can` field gives more granular access information, with the `set_value` child field indicating whether
an attribute's value can be set by [Setting the User Attribute User Value](#!/User/set_user_attribute_user_value).

Note: `name` and `label` fields must be unique across all user attributes in the Looker instance.
Attempting to create a new user attribute with a name or label that duplicates an existing
user attribute will fail with a 422 error.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_attribute called")
  },
}


var user_attributeCmd = &cobra.Command{
  Use:   "user_attribute",
  Short: "Get User Attribute",
  Long: `### Get information about a user attribute.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_attribute called")
  },
}


var update_user_attributeCmd = &cobra.Command{
  Use:   "update_user_attribute",
  Short: "Update User Attribute",
  Long: `### Update a user attribute definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_attribute called")
  },
}


var delete_user_attributeCmd = &cobra.Command{
  Use:   "delete_user_attribute",
  Short: "Delete User Attribute",
  Long: `### Delete a user attribute (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_attribute called")
  },
}


var all_user_attribute_group_valuesCmd = &cobra.Command{
  Use:   "all_user_attribute_group_values",
  Short: "Get User Attribute Group Values",
  Long: `### Returns all values of a user attribute defined by user groups, in precedence order.

A user may be a member of multiple groups which define different values for a given user attribute.
The order of group-values in the response determines precedence for selecting which group-value applies
to a given user.  For more information, see [Set User Attribute Group Values](#!/UserAttribute/set_user_attribute_group_values).

Results will only include groups that the caller's user account has permission to see.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_attribute_group_values called")
  },
}


var set_user_attribute_group_valuesCmd = &cobra.Command{
  Use:   "set_user_attribute_group_values",
  Short: "Set User Attribute Group Values",
  Long: `### Define values for a user attribute across a set of groups, in priority order.

This function defines all values for a user attribute defined by user groups. This is a global setting, potentially affecting
all users in the system. This function replaces any existing group value definitions for the indicated user attribute.

The value of a user attribute for a given user is determined by searching the following locations, in this order:

1. the user's account settings
2. the groups that the user is a member of
3. the default value of the user attribute, if any

The user may be a member of multiple groups which define different values for that user attribute. The order of items in the group_values parameter
determines which group takes priority for that user. Lowest array index wins.

An alternate method to indicate the selection precedence of group-values is to assign numbers to the 'rank' property of each
group-value object in the array. Lowest 'rank' value wins. If you use this technique, you must assign a
rank value to every group-value object in the array.

  To set a user attribute value for a single user, see [Set User Attribute User Value](#!/User/set_user_attribute_user_value).
To set a user attribute value for all members of a group, see [Set User Attribute Group Value](#!/Group/update_user_attribute_group_value).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_user_attribute_group_values called")
  },
}




var workspaceCmd = &cobra.Command{
  Use:   "Workspace",
  Short: "Manage Workspaces",
  Long: "Manage Workspaces",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Workspace called")
  },
}


var all_workspacesCmd = &cobra.Command{
  Use:   "all_workspaces",
  Short: "Get All Workspaces",
  Long: `### Get All Workspaces

Returns all workspaces available to the calling user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_workspaces called")
  },
}


var workspaceCmd = &cobra.Command{
  Use:   "workspace",
  Short: "Get Workspace",
  Long: `### Get A Workspace

Returns information about a workspace such as the git status and selected branches
of all projects available to the caller's user account.

A workspace defines which versions of project files will be used to evaluate expressions
and operations that use model definitions - operations such as running queries or rendering dashboards.
Each project has its own git repository, and each project in a workspace may be configured to reference
particular branch or revision within their respective repositories.

There are two predefined workspaces available: "production" and "dev".

The production workspace is shared across all Looker users. Models in the production workspace are read-only.
Changing files in production is accomplished by modifying files in a git branch and using Pull Requests
to merge the changes from the dev branch into the production branch, and then telling
Looker to sync with production.

The dev workspace is local to each Looker user. Changes made to project/model files in the dev workspace only affect
that user, and only when the dev workspace is selected as the active workspace for the API session.
(See set_session_workspace()).

The dev workspace is NOT unique to an API session. Two applications accessing the Looker API using
the same user account will see the same files in the dev workspace. To avoid collisions between
API clients it's best to have each client login with API3 credentials for a different user account.

Changes made to files in a dev workspace are persistent across API sessions. It's a good
idea to commit any changes you've made to the git repository, but not strictly required. Your modified files
reside in a special user-specific directory on the Looker server and will still be there when you login in again
later and use update_session(workspace_id: "dev") to select the dev workspace for the new API session.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("workspace called")
  },
}



func init() {

  apiAuthCmd.AddCommand(loginCmd)
  apiAuthCmd.AddCommand(login_userCmd)
  apiAuthCmd.AddCommand(logoutCmd)
  rootCmd.AddCommand(apiAuthCmd)
  authCmd.AddCommand(create_sso_embed_urlCmd)
  authCmd.AddCommand(ldap_configCmd)
  authCmd.AddCommand(update_ldap_configCmd)
  authCmd.AddCommand(test_ldap_config_connectionCmd)
  authCmd.AddCommand(test_ldap_config_authCmd)
  authCmd.AddCommand(test_ldap_config_user_infoCmd)
  authCmd.AddCommand(test_ldap_config_user_authCmd)
  authCmd.AddCommand(oidc_configCmd)
  authCmd.AddCommand(update_oidc_configCmd)
  authCmd.AddCommand(oidc_test_configCmd)
  authCmd.AddCommand(delete_oidc_test_configCmd)
  authCmd.AddCommand(create_oidc_test_configCmd)
  authCmd.AddCommand(password_configCmd)
  authCmd.AddCommand(update_password_configCmd)
  authCmd.AddCommand(force_password_reset_at_next_login_for_all_usersCmd)
  authCmd.AddCommand(saml_configCmd)
  authCmd.AddCommand(update_saml_configCmd)
  authCmd.AddCommand(saml_test_configCmd)
  authCmd.AddCommand(delete_saml_test_configCmd)
  authCmd.AddCommand(create_saml_test_configCmd)
  authCmd.AddCommand(parse_saml_idp_metadataCmd)
  authCmd.AddCommand(fetch_and_parse_saml_idp_metadataCmd)
  authCmd.AddCommand(session_configCmd)
  authCmd.AddCommand(update_session_configCmd)
  authCmd.AddCommand(all_user_login_lockoutsCmd)
  authCmd.AddCommand(search_user_login_lockoutsCmd)
  authCmd.AddCommand(delete_user_login_lockoutCmd)
  rootCmd.AddCommand(authCmd)
  colorCollectionCmd.AddCommand(all_color_collectionsCmd)
  colorCollectionCmd.AddCommand(create_color_collectionCmd)
  colorCollectionCmd.AddCommand(color_collections_customCmd)
  colorCollectionCmd.AddCommand(color_collections_standardCmd)
  colorCollectionCmd.AddCommand(default_color_collectionCmd)
  colorCollectionCmd.AddCommand(set_default_color_collectionCmd)
  colorCollectionCmd.AddCommand(color_collectionCmd)
  colorCollectionCmd.AddCommand(update_color_collectionCmd)
  colorCollectionCmd.AddCommand(delete_color_collectionCmd)
  rootCmd.AddCommand(colorCollectionCmd)
  configCmd.AddCommand(backup_configurationCmd)
  configCmd.AddCommand(update_backup_configurationCmd)
  configCmd.AddCommand(cloud_storage_configurationCmd)
  configCmd.AddCommand(update_cloud_storage_configurationCmd)
  configCmd.AddCommand(custom_welcome_emailCmd)
  configCmd.AddCommand(update_custom_welcome_emailCmd)
  configCmd.AddCommand(update_custom_welcome_email_testCmd)
  configCmd.AddCommand(digest_emails_enabledCmd)
  configCmd.AddCommand(update_digest_emails_enabledCmd)
  configCmd.AddCommand(create_digest_email_sendCmd)
  configCmd.AddCommand(internal_help_resources_contentCmd)
  configCmd.AddCommand(update_internal_help_resources_contentCmd)
  configCmd.AddCommand(internal_help_resourcesCmd)
  configCmd.AddCommand(update_internal_help_resourcesCmd)
  configCmd.AddCommand(all_legacy_featuresCmd)
  configCmd.AddCommand(legacy_featureCmd)
  configCmd.AddCommand(update_legacy_featureCmd)
  configCmd.AddCommand(all_localesCmd)
  configCmd.AddCommand(all_timezonesCmd)
  configCmd.AddCommand(versionsCmd)
  configCmd.AddCommand(whitelabel_configurationCmd)
  configCmd.AddCommand(update_whitelabel_configurationCmd)
  rootCmd.AddCommand(configCmd)
  connectionCmd.AddCommand(all_connectionsCmd)
  connectionCmd.AddCommand(create_connectionCmd)
  connectionCmd.AddCommand(connectionCmd)
  connectionCmd.AddCommand(update_connectionCmd)
  connectionCmd.AddCommand(delete_connectionCmd)
  connectionCmd.AddCommand(delete_connection_overrideCmd)
  connectionCmd.AddCommand(test_connectionCmd)
  connectionCmd.AddCommand(test_connection_configCmd)
  connectionCmd.AddCommand(all_dialect_infosCmd)
  rootCmd.AddCommand(connectionCmd)
  contentCmd.AddCommand(search_content_favoritesCmd)
  contentCmd.AddCommand(content_favoriteCmd)
  contentCmd.AddCommand(delete_content_favoriteCmd)
  contentCmd.AddCommand(create_content_favoriteCmd)
  contentCmd.AddCommand(all_content_metadatasCmd)
  contentCmd.AddCommand(content_metadataCmd)
  contentCmd.AddCommand(update_content_metadataCmd)
  contentCmd.AddCommand(all_content_metadata_accessesCmd)
  contentCmd.AddCommand(create_content_metadata_accessCmd)
  contentCmd.AddCommand(update_content_metadata_accessCmd)
  contentCmd.AddCommand(delete_content_metadata_accessCmd)
  contentCmd.AddCommand(content_thumbnailCmd)
  contentCmd.AddCommand(content_validationCmd)
  contentCmd.AddCommand(search_content_viewsCmd)
  contentCmd.AddCommand(vector_thumbnailCmd)
  rootCmd.AddCommand(contentCmd)
  dashboardCmd.AddCommand(all_dashboardsCmd)
  dashboardCmd.AddCommand(create_dashboardCmd)
  dashboardCmd.AddCommand(search_dashboardsCmd)
  dashboardCmd.AddCommand(import_lookml_dashboardCmd)
  dashboardCmd.AddCommand(sync_lookml_dashboardCmd)
  dashboardCmd.AddCommand(dashboardCmd)
  dashboardCmd.AddCommand(update_dashboardCmd)
  dashboardCmd.AddCommand(delete_dashboardCmd)
  dashboardCmd.AddCommand(dashboard_aggregate_table_lookmlCmd)
  dashboardCmd.AddCommand(dashboard_lookmlCmd)
  dashboardCmd.AddCommand(search_dashboard_elementsCmd)
  dashboardCmd.AddCommand(dashboard_elementCmd)
  dashboardCmd.AddCommand(update_dashboard_elementCmd)
  dashboardCmd.AddCommand(delete_dashboard_elementCmd)
  dashboardCmd.AddCommand(dashboard_dashboard_elementsCmd)
  dashboardCmd.AddCommand(create_dashboard_elementCmd)
  dashboardCmd.AddCommand(dashboard_filterCmd)
  dashboardCmd.AddCommand(update_dashboard_filterCmd)
  dashboardCmd.AddCommand(delete_dashboard_filterCmd)
  dashboardCmd.AddCommand(dashboard_dashboard_filtersCmd)
  dashboardCmd.AddCommand(create_dashboard_filterCmd)
  dashboardCmd.AddCommand(dashboard_layout_componentCmd)
  dashboardCmd.AddCommand(update_dashboard_layout_componentCmd)
  dashboardCmd.AddCommand(dashboard_layout_dashboard_layout_componentsCmd)
  dashboardCmd.AddCommand(dashboard_layoutCmd)
  dashboardCmd.AddCommand(update_dashboard_layoutCmd)
  dashboardCmd.AddCommand(delete_dashboard_layoutCmd)
  dashboardCmd.AddCommand(dashboard_dashboard_layoutsCmd)
  dashboardCmd.AddCommand(create_dashboard_layoutCmd)
  rootCmd.AddCommand(dashboardCmd)
  dataActionCmd.AddCommand(perform_data_actionCmd)
  dataActionCmd.AddCommand(fetch_remote_data_action_formCmd)
  rootCmd.AddCommand(dataActionCmd)
  datagroupCmd.AddCommand(all_datagroupsCmd)
  datagroupCmd.AddCommand(datagroupCmd)
  datagroupCmd.AddCommand(update_datagroupCmd)
  rootCmd.AddCommand(datagroupCmd)
  derivedTableCmd.AddCommand(graph_derived_tables_for_modelCmd)
  derivedTableCmd.AddCommand(graph_derived_tables_for_viewCmd)
  rootCmd.AddCommand(derivedTableCmd)
  folderCmd.AddCommand(search_foldersCmd)
  folderCmd.AddCommand(folderCmd)
  folderCmd.AddCommand(update_folderCmd)
  folderCmd.AddCommand(delete_folderCmd)
  folderCmd.AddCommand(all_foldersCmd)
  folderCmd.AddCommand(create_folderCmd)
  folderCmd.AddCommand(folder_childrenCmd)
  folderCmd.AddCommand(folder_children_searchCmd)
  folderCmd.AddCommand(folder_parentCmd)
  folderCmd.AddCommand(folder_ancestorsCmd)
  folderCmd.AddCommand(folder_looksCmd)
  folderCmd.AddCommand(folder_dashboardsCmd)
  rootCmd.AddCommand(folderCmd)
  groupCmd.AddCommand(all_groupsCmd)
  groupCmd.AddCommand(create_groupCmd)
  groupCmd.AddCommand(search_groupsCmd)
  groupCmd.AddCommand(groupCmd)
  groupCmd.AddCommand(update_groupCmd)
  groupCmd.AddCommand(delete_groupCmd)
  groupCmd.AddCommand(all_group_groupsCmd)
  groupCmd.AddCommand(add_group_groupCmd)
  groupCmd.AddCommand(all_group_usersCmd)
  groupCmd.AddCommand(add_group_userCmd)
  groupCmd.AddCommand(delete_group_userCmd)
  groupCmd.AddCommand(delete_group_from_groupCmd)
  groupCmd.AddCommand(update_user_attribute_group_valueCmd)
  groupCmd.AddCommand(delete_user_attribute_group_valueCmd)
  rootCmd.AddCommand(groupCmd)
  homepageCmd.AddCommand(all_homepagesCmd)
  homepageCmd.AddCommand(create_homepageCmd)
  homepageCmd.AddCommand(search_homepagesCmd)
  homepageCmd.AddCommand(homepageCmd)
  homepageCmd.AddCommand(update_homepageCmd)
  homepageCmd.AddCommand(delete_homepageCmd)
  homepageCmd.AddCommand(all_homepage_itemsCmd)
  homepageCmd.AddCommand(create_homepage_itemCmd)
  homepageCmd.AddCommand(homepage_itemCmd)
  homepageCmd.AddCommand(update_homepage_itemCmd)
  homepageCmd.AddCommand(delete_homepage_itemCmd)
  homepageCmd.AddCommand(all_homepage_sectionsCmd)
  homepageCmd.AddCommand(create_homepage_sectionCmd)
  homepageCmd.AddCommand(homepage_sectionCmd)
  homepageCmd.AddCommand(update_homepage_sectionCmd)
  homepageCmd.AddCommand(delete_homepage_sectionCmd)
  homepageCmd.AddCommand(all_primary_homepage_sectionsCmd)
  rootCmd.AddCommand(homepageCmd)
  integrationCmd.AddCommand(all_integration_hubsCmd)
  integrationCmd.AddCommand(create_integration_hubCmd)
  integrationCmd.AddCommand(integration_hubCmd)
  integrationCmd.AddCommand(update_integration_hubCmd)
  integrationCmd.AddCommand(delete_integration_hubCmd)
  integrationCmd.AddCommand(accept_integration_hub_legal_agreementCmd)
  integrationCmd.AddCommand(all_integrationsCmd)
  integrationCmd.AddCommand(integrationCmd)
  integrationCmd.AddCommand(update_integrationCmd)
  integrationCmd.AddCommand(fetch_integration_formCmd)
  integrationCmd.AddCommand(test_integrationCmd)
  rootCmd.AddCommand(integrationCmd)
  lookCmd.AddCommand(all_looksCmd)
  lookCmd.AddCommand(create_lookCmd)
  lookCmd.AddCommand(search_looksCmd)
  lookCmd.AddCommand(lookCmd)
  lookCmd.AddCommand(update_lookCmd)
  lookCmd.AddCommand(delete_lookCmd)
  lookCmd.AddCommand(run_lookCmd)
  rootCmd.AddCommand(lookCmd)
  lookmlModelCmd.AddCommand(all_lookml_modelsCmd)
  lookmlModelCmd.AddCommand(create_lookml_modelCmd)
  lookmlModelCmd.AddCommand(lookml_modelCmd)
  lookmlModelCmd.AddCommand(update_lookml_modelCmd)
  lookmlModelCmd.AddCommand(delete_lookml_modelCmd)
  lookmlModelCmd.AddCommand(lookml_model_exploreCmd)
  rootCmd.AddCommand(lookmlModelCmd)
  projectCmd.AddCommand(all_git_branchesCmd)
  projectCmd.AddCommand(git_branchCmd)
  projectCmd.AddCommand(update_git_branchCmd)
  projectCmd.AddCommand(create_git_branchCmd)
  projectCmd.AddCommand(find_git_branchCmd)
  projectCmd.AddCommand(delete_git_branchCmd)
  projectCmd.AddCommand(deploy_ref_to_productionCmd)
  projectCmd.AddCommand(deploy_to_productionCmd)
  projectCmd.AddCommand(reset_project_to_productionCmd)
  projectCmd.AddCommand(reset_project_to_remoteCmd)
  projectCmd.AddCommand(all_projectsCmd)
  projectCmd.AddCommand(create_projectCmd)
  projectCmd.AddCommand(projectCmd)
  projectCmd.AddCommand(update_projectCmd)
  projectCmd.AddCommand(manifestCmd)
  projectCmd.AddCommand(git_deploy_keyCmd)
  projectCmd.AddCommand(create_git_deploy_keyCmd)
  projectCmd.AddCommand(project_validation_resultsCmd)
  projectCmd.AddCommand(validate_projectCmd)
  projectCmd.AddCommand(project_workspaceCmd)
  projectCmd.AddCommand(all_project_filesCmd)
  projectCmd.AddCommand(project_fileCmd)
  projectCmd.AddCommand(all_git_connection_testsCmd)
  projectCmd.AddCommand(run_git_connection_testCmd)
  projectCmd.AddCommand(all_lookml_testsCmd)
  projectCmd.AddCommand(run_lookml_testCmd)
  projectCmd.AddCommand(tag_refCmd)
  projectCmd.AddCommand(update_repository_credentialCmd)
  projectCmd.AddCommand(delete_repository_credentialCmd)
  projectCmd.AddCommand(get_all_repository_credentialsCmd)
  rootCmd.AddCommand(projectCmd)
  queryCmd.AddCommand(create_query_taskCmd)
  queryCmd.AddCommand(query_task_multi_resultsCmd)
  queryCmd.AddCommand(query_taskCmd)
  queryCmd.AddCommand(query_task_resultsCmd)
  queryCmd.AddCommand(queryCmd)
  queryCmd.AddCommand(query_for_slugCmd)
  queryCmd.AddCommand(create_queryCmd)
  queryCmd.AddCommand(run_queryCmd)
  queryCmd.AddCommand(run_inline_queryCmd)
  queryCmd.AddCommand(run_url_encoded_queryCmd)
  queryCmd.AddCommand(merge_queryCmd)
  queryCmd.AddCommand(create_merge_queryCmd)
  queryCmd.AddCommand(all_running_queriesCmd)
  queryCmd.AddCommand(kill_queryCmd)
  queryCmd.AddCommand(sql_queryCmd)
  queryCmd.AddCommand(create_sql_queryCmd)
  queryCmd.AddCommand(run_sql_queryCmd)
  rootCmd.AddCommand(queryCmd)
  renderTaskCmd.AddCommand(create_lookml_dashboard_render_taskCmd)
  renderTaskCmd.AddCommand(create_look_render_taskCmd)
  renderTaskCmd.AddCommand(create_query_render_taskCmd)
  renderTaskCmd.AddCommand(create_dashboard_render_taskCmd)
  renderTaskCmd.AddCommand(render_taskCmd)
  renderTaskCmd.AddCommand(render_task_resultsCmd)
  rootCmd.AddCommand(renderTaskCmd)
  roleCmd.AddCommand(search_model_setsCmd)
  roleCmd.AddCommand(model_setCmd)
  roleCmd.AddCommand(update_model_setCmd)
  roleCmd.AddCommand(delete_model_setCmd)
  roleCmd.AddCommand(all_model_setsCmd)
  roleCmd.AddCommand(create_model_setCmd)
  roleCmd.AddCommand(all_permissionsCmd)
  roleCmd.AddCommand(search_permission_setsCmd)
  roleCmd.AddCommand(permission_setCmd)
  roleCmd.AddCommand(update_permission_setCmd)
  roleCmd.AddCommand(delete_permission_setCmd)
  roleCmd.AddCommand(all_permission_setsCmd)
  roleCmd.AddCommand(create_permission_setCmd)
  roleCmd.AddCommand(all_rolesCmd)
  roleCmd.AddCommand(create_roleCmd)
  roleCmd.AddCommand(search_rolesCmd)
  roleCmd.AddCommand(roleCmd)
  roleCmd.AddCommand(update_roleCmd)
  roleCmd.AddCommand(delete_roleCmd)
  roleCmd.AddCommand(role_groupsCmd)
  roleCmd.AddCommand(set_role_groupsCmd)
  roleCmd.AddCommand(role_usersCmd)
  roleCmd.AddCommand(set_role_usersCmd)
  rootCmd.AddCommand(roleCmd)
  scheduledPlanCmd.AddCommand(scheduled_plans_for_spaceCmd)
  scheduledPlanCmd.AddCommand(scheduled_planCmd)
  scheduledPlanCmd.AddCommand(update_scheduled_planCmd)
  scheduledPlanCmd.AddCommand(delete_scheduled_planCmd)
  scheduledPlanCmd.AddCommand(all_scheduled_plansCmd)
  scheduledPlanCmd.AddCommand(create_scheduled_planCmd)
  scheduledPlanCmd.AddCommand(scheduled_plan_run_onceCmd)
  scheduledPlanCmd.AddCommand(scheduled_plans_for_lookCmd)
  scheduledPlanCmd.AddCommand(scheduled_plans_for_dashboardCmd)
  scheduledPlanCmd.AddCommand(scheduled_plans_for_lookml_dashboardCmd)
  scheduledPlanCmd.AddCommand(scheduled_plan_run_once_by_idCmd)
  rootCmd.AddCommand(scheduledPlanCmd)
  sessionCmd.AddCommand(sessionCmd)
  sessionCmd.AddCommand(update_sessionCmd)
  rootCmd.AddCommand(sessionCmd)
  spaceCmd.AddCommand(search_spacesCmd)
  spaceCmd.AddCommand(spaceCmd)
  spaceCmd.AddCommand(update_spaceCmd)
  spaceCmd.AddCommand(delete_spaceCmd)
  spaceCmd.AddCommand(all_spacesCmd)
  spaceCmd.AddCommand(create_spaceCmd)
  spaceCmd.AddCommand(space_childrenCmd)
  spaceCmd.AddCommand(space_children_searchCmd)
  spaceCmd.AddCommand(space_parentCmd)
  spaceCmd.AddCommand(space_ancestorsCmd)
  spaceCmd.AddCommand(space_looksCmd)
  spaceCmd.AddCommand(space_dashboardsCmd)
  rootCmd.AddCommand(spaceCmd)
  themeCmd.AddCommand(all_themesCmd)
  themeCmd.AddCommand(create_themeCmd)
  themeCmd.AddCommand(search_themesCmd)
  themeCmd.AddCommand(default_themeCmd)
  themeCmd.AddCommand(set_default_themeCmd)
  themeCmd.AddCommand(active_themesCmd)
  themeCmd.AddCommand(theme_or_defaultCmd)
  themeCmd.AddCommand(validate_themeCmd)
  themeCmd.AddCommand(themeCmd)
  themeCmd.AddCommand(update_themeCmd)
  themeCmd.AddCommand(delete_themeCmd)
  rootCmd.AddCommand(themeCmd)
  userCmd.AddCommand(meCmd)
  userCmd.AddCommand(all_usersCmd)
  userCmd.AddCommand(create_userCmd)
  userCmd.AddCommand(search_usersCmd)
  userCmd.AddCommand(search_users_namesCmd)
  userCmd.AddCommand(userCmd)
  userCmd.AddCommand(update_userCmd)
  userCmd.AddCommand(delete_userCmd)
  userCmd.AddCommand(user_for_credentialCmd)
  userCmd.AddCommand(user_credentials_emailCmd)
  userCmd.AddCommand(create_user_credentials_emailCmd)
  userCmd.AddCommand(update_user_credentials_emailCmd)
  userCmd.AddCommand(delete_user_credentials_emailCmd)
  userCmd.AddCommand(user_credentials_totpCmd)
  userCmd.AddCommand(create_user_credentials_totpCmd)
  userCmd.AddCommand(delete_user_credentials_totpCmd)
  userCmd.AddCommand(user_credentials_ldapCmd)
  userCmd.AddCommand(delete_user_credentials_ldapCmd)
  userCmd.AddCommand(user_credentials_googleCmd)
  userCmd.AddCommand(delete_user_credentials_googleCmd)
  userCmd.AddCommand(user_credentials_samlCmd)
  userCmd.AddCommand(delete_user_credentials_samlCmd)
  userCmd.AddCommand(user_credentials_oidcCmd)
  userCmd.AddCommand(delete_user_credentials_oidcCmd)
  userCmd.AddCommand(user_credentials_api3Cmd)
  userCmd.AddCommand(delete_user_credentials_api3Cmd)
  userCmd.AddCommand(all_user_credentials_api3sCmd)
  userCmd.AddCommand(create_user_credentials_api3Cmd)
  userCmd.AddCommand(user_credentials_embedCmd)
  userCmd.AddCommand(delete_user_credentials_embedCmd)
  userCmd.AddCommand(all_user_credentials_embedsCmd)
  userCmd.AddCommand(user_credentials_looker_openidCmd)
  userCmd.AddCommand(delete_user_credentials_looker_openidCmd)
  userCmd.AddCommand(user_sessionCmd)
  userCmd.AddCommand(delete_user_sessionCmd)
  userCmd.AddCommand(all_user_sessionsCmd)
  userCmd.AddCommand(create_user_credentials_email_password_resetCmd)
  userCmd.AddCommand(user_rolesCmd)
  userCmd.AddCommand(set_user_rolesCmd)
  userCmd.AddCommand(user_attribute_user_valuesCmd)
  userCmd.AddCommand(set_user_attribute_user_valueCmd)
  userCmd.AddCommand(delete_user_attribute_user_valueCmd)
  rootCmd.AddCommand(userCmd)
  userAttributeCmd.AddCommand(all_user_attributesCmd)
  userAttributeCmd.AddCommand(create_user_attributeCmd)
  userAttributeCmd.AddCommand(user_attributeCmd)
  userAttributeCmd.AddCommand(update_user_attributeCmd)
  userAttributeCmd.AddCommand(delete_user_attributeCmd)
  userAttributeCmd.AddCommand(all_user_attribute_group_valuesCmd)
  userAttributeCmd.AddCommand(set_user_attribute_group_valuesCmd)
  rootCmd.AddCommand(userAttributeCmd)
  workspaceCmd.AddCommand(all_workspacesCmd)
  workspaceCmd.AddCommand(workspaceCmd)
  rootCmd.AddCommand(workspaceCmd)
}