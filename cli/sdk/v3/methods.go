
package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

var apiAuthCmd = &cobra.Command{
  Use:   "ApiAuth",
  Short: "API Authentication",
  Long: "API Authentication",
}


var loginCmd = &cobra.Command{
  Use:   "login",
  Short: "Login",
  Long: `### Present client credentials to obtain an authorization token

Looker API implements the OAuth2 [Resource Owner Password Credentials Grant](https://looker.com/docs/r/api/outh2_resource_owner_pc) pattern.
The client credentials required for this login must be obtained by creating an API3 key on a user account
in the Looker Admin console. The API3 key consists of a public 'client_id' and a private 'client_secret'.

The access token returned by 'login' must be used in the HTTP Authorization header of subsequent
API requests, like this:
'''
Authorization: token 4QDkCyCtZzYgj4C2p2cj3csJH7zqS5RzKs2kTnG4
'''
Replace "4QDkCy..." with the 'access_token' value returned by 'login'.
The word 'token' is a string literal and must be included exactly as shown.

This function can accept 'client_id' and 'client_secret' parameters as URL query params or as www-form-urlencoded params in the body of the HTTP request. Since there is a small risk that URL parameters may be visible to intermediate nodes on the network route (proxies, routers, etc), passing credentials in the body of the request is considered more secure than URL params.

Example of passing credentials in the HTTP request body:
''''
POST HTTP /login
Content-Type: application/x-www-form-urlencoded

client_id=CGc9B7v7J48dQSJvxxx&client_secret=nNVS9cSS3xNpSC9JdsBvvvvv
''''

### Best Practice:
Always pass credentials in body params. Pass credentials in URL query params **only** when you cannot pass body params due to application, tool, or other limitations.

For more information and detailed examples of Looker API authorization, see [How to Authenticate to Looker API3](https://github.com/looker/looker-sdk-ruby/blob/master/authentication.md).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("login called")
    
    client_id, _ := cmd.Flags().GetString("client_id")
    fmt.Println("client_id set to ", client_id)

    client_secret, _ := cmd.Flags().GetString("client_secret")
    fmt.Println("client_secret set to ", client_secret)
  },
}


var loginUserCmd = &cobra.Command{
  Use:   "loginUser",
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
    fmt.Println("loginUser called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    associative, _ := cmd.Flags().GetBool("associative")
    fmt.Println("associative set to ", associative)
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
}


var createSsoEmbedUrlCmd = &cobra.Command{
  Use:   "createSsoEmbedUrl",
  Short: "Create SSO Embed Url",
  Long: `### Create SSO Embed URL

Creates an SSO embed URL and cryptographically signs it with an embed secret.
This signed URL can then be used to instantiate a Looker embed session in a PBL web application.
Do not make any modifications to this URL - any change may invalidate the signature and
cause the URL to fail to load a Looker embed session.

A signed SSO embed URL can only be used once. After it has been used to request a page from the
Looker server, the URL is invalid. Future requests using the same URL will fail. This is to prevent
'replay attacks'.

The 'target_url' property must be a complete URL of a Looker UI page - scheme, hostname, path and query params.
To load a dashboard with id 56 and with a filter of 'Date=1 years', the looker URL would look like 'https:/myname.looker.com/dashboards/56?Date=1%20years'.
The best way to obtain this target_url is to navigate to the desired Looker page in your web browser,
copy the URL shown in the browser address bar and paste it into the 'target_url' property as a quoted string value in this API request.

Permissions for the embed user are defined by the groups in which the embed user is a member (group_ids property)
and the lists of models and permissions assigned to the embed user.
At a minimum, you must provide values for either the group_ids property, or both the models and permissions properties.
These properties are additive; an embed user can be a member of certain groups AND be granted access to models and permissions.

The embed user's access is the union of permissions granted by the group_ids, models, and permissions properties.

This function does not strictly require all group_ids, user attribute names, or model names to exist at the moment the
SSO embed url is created. Unknown group_id, user attribute names or model names will be passed through to the output URL.
To diagnose potential problems with an SSO embed URL, you can copy the signed URL into the Embed URI Validator text box in '<your looker instance>/admin/embed'.

The 'secret_id' parameter is optional. If specified, its value must be the id of an active secret defined in the Looker instance.
if not specified, the URL will be signed using the newest active secret defined in the Looker instance.

#### Security Note
Protect this signed URL as you would an access token or password credentials - do not write
it to disk, do not pass it to a third party, and only pass it through a secure HTTPS
encrypted transport.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSsoEmbedUrl called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var ldapConfigCmd = &cobra.Command{
  Use:   "ldapConfig",
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
    fmt.Println("ldapConfig called")
    
  },
}


var updateLdapConfigCmd = &cobra.Command{
  Use:   "updateLdapConfig",
  Short: "Update LDAP Configuration",
  Long: `### Update the LDAP configuration.

Configuring LDAP impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the LDAP configuration.

LDAP is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any LDAP setting changes be tested using the APIs below before being set globally.

See the [Looker LDAP docs](https://www.looker.com/docs/r/api/ldap_setup) for additional information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateLdapConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var testLdapConfigConnectionCmd = &cobra.Command{
  Use:   "testLdapConfigConnection",
  Short: "Test LDAP Connection",
  Long: `### Test the connection settings for an LDAP configuration.

This tests that the connection is possible given a connection_host and connection_port.

**connection_host** and **connection_port** are required. **connection_tls** is optional.

Example:
'''json
{
  "connection_host": "ldap.example.com",
  "connection_port": "636",
  "connection_tls": true
}
'''

No authentication to the LDAP server is attempted.

The active LDAP settings are not modified.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testLdapConfigConnection called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var testLdapConfigAuthCmd = &cobra.Command{
  Use:   "testLdapConfigAuth",
  Short: "Test LDAP Auth",
  Long: `### Test the connection authentication settings for an LDAP configuration.

This tests that the connection is possible and that a 'server' account to be used by Looker can       authenticate to the LDAP server given connection and authentication information.

**connection_host**, **connection_port**, and **auth_username**, are required.       **connection_tls** and **auth_password** are optional.

Example:
'''json
{
  "connection_host": "ldap.example.com",
  "connection_port": "636",
  "connection_tls": true,
  "auth_username": "cn=looker,dc=example,dc=com",
  "auth_password": "secret"
}
'''

Looker will never return an **auth_password**. If this request omits the **auth_password** field, then       the **auth_password** value from the active config (if present) will be used for the test.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testLdapConfigAuth called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var testLdapConfigUserInfoCmd = &cobra.Command{
  Use:   "testLdapConfigUserInfo",
  Short: "Test LDAP User Info",
  Long: `### Test the user authentication settings for an LDAP configuration without authenticating the user.

This test will let you easily test the mapping for user properties and roles for any user without      needing to authenticate as that user.

This test accepts a full LDAP configuration along with a username and attempts to find the full info      for the user from the LDAP server without actually authenticating the user. So, user password is not      required.The configuration is validated before attempting to contact the server.

**test_ldap_user** is required.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testLdapConfigUserInfo called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var testLdapConfigUserAuthCmd = &cobra.Command{
  Use:   "testLdapConfigUserAuth",
  Short: "Test LDAP User Auth",
  Long: `### Test the user authentication settings for an LDAP configuration.

This test accepts a full LDAP configuration along with a username/password pair and attempts to       authenticate the user with the LDAP server. The configuration is validated before attempting the       authentication.

Looker will never return an **auth_password**. If this request omits the **auth_password** field, then       the **auth_password** value from the active config (if present) will be used for the test.

**test_ldap_user** and **test_ldap_password** are required.

The active LDAP settings are not modified.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testLdapConfigUserAuth called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var oidcConfigCmd = &cobra.Command{
  Use:   "oidcConfig",
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
    fmt.Println("oidcConfig called")
    
  },
}


var updateOidcConfigCmd = &cobra.Command{
  Use:   "updateOidcConfig",
  Short: "Update OIDC Configuration",
  Long: `### Update the OIDC configuration.

Configuring OIDC impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the OIDC configuration.

OIDC is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any OIDC setting changes be tested using the APIs below before being set globally.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateOidcConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var oidcTestConfigCmd = &cobra.Command{
  Use:   "oidcTestConfig",
  Short: "Get OIDC Test Configuration",
  Long: `### Get a OIDC test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oidcTestConfig called")
    
    test_slug, _ := cmd.Flags().GetString("test_slug")
    fmt.Println("test_slug set to ", test_slug)
  },
}


var deleteOidcTestConfigCmd = &cobra.Command{
  Use:   "deleteOidcTestConfig",
  Short: "Delete OIDC Test Configuration",
  Long: `### Delete a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteOidcTestConfig called")
    
    test_slug, _ := cmd.Flags().GetString("test_slug")
    fmt.Println("test_slug set to ", test_slug)
  },
}


var createOidcTestConfigCmd = &cobra.Command{
  Use:   "createOidcTestConfig",
  Short: "Create OIDC Test Configuration",
  Long: `### Create a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createOidcTestConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var passwordConfigCmd = &cobra.Command{
  Use:   "passwordConfig",
  Short: "Get Password Config",
  Long: `### Get password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("passwordConfig called")
    
  },
}


var updatePasswordConfigCmd = &cobra.Command{
  Use:   "updatePasswordConfig",
  Short: "Update Password Config",
  Long: `### Update password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updatePasswordConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var forcePasswordResetAtNextLoginForAllUsersCmd = &cobra.Command{
  Use:   "forcePasswordResetAtNextLoginForAllUsers",
  Short: "Force password reset",
  Long: `### Force all credentials_email users to reset their login passwords upon their next login.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("forcePasswordResetAtNextLoginForAllUsers called")
    
  },
}


var samlConfigCmd = &cobra.Command{
  Use:   "samlConfig",
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
    fmt.Println("samlConfig called")
    
  },
}


var updateSamlConfigCmd = &cobra.Command{
  Use:   "updateSamlConfig",
  Short: "Update SAML Configuration",
  Long: `### Update the SAML configuration.

Configuring SAML impacts authentication for all users. This configuration should be done carefully.

Only Looker administrators can read and update the SAML configuration.

SAML is enabled or disabled for Looker using the **enabled** field.

It is **highly** recommended that any SAML setting changes be tested using the APIs below before being set globally.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateSamlConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var samlTestConfigCmd = &cobra.Command{
  Use:   "samlTestConfig",
  Short: "Get SAML Test Configuration",
  Long: `### Get a SAML test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("samlTestConfig called")
    
    test_slug, _ := cmd.Flags().GetString("test_slug")
    fmt.Println("test_slug set to ", test_slug)
  },
}


var deleteSamlTestConfigCmd = &cobra.Command{
  Use:   "deleteSamlTestConfig",
  Short: "Delete SAML Test Configuration",
  Long: `### Delete a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteSamlTestConfig called")
    
    test_slug, _ := cmd.Flags().GetString("test_slug")
    fmt.Println("test_slug set to ", test_slug)
  },
}


var createSamlTestConfigCmd = &cobra.Command{
  Use:   "createSamlTestConfig",
  Short: "Create SAML Test Configuration",
  Long: `### Create a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSamlTestConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var parseSamlIdpMetadataCmd = &cobra.Command{
  Use:   "parseSamlIdpMetadata",
  Short: "Parse SAML IdP XML",
  Long: `### Parse the given xml as a SAML IdP metadata document and return the result.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("parseSamlIdpMetadata called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var fetchAndParseSamlIdpMetadataCmd = &cobra.Command{
  Use:   "fetchAndParseSamlIdpMetadata",
  Short: "Parse SAML IdP Url",
  Long: `### Fetch the given url and parse it as a SAML IdP metadata document and return the result.
Note that this requires that the url be public or at least at a location where the Looker instance
can fetch it without requiring any special authentication.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetchAndParseSamlIdpMetadata called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var sessionConfigCmd = &cobra.Command{
  Use:   "sessionConfig",
  Short: "Get Session Config",
  Long: `### Get session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sessionConfig called")
    
  },
}


var updateSessionConfigCmd = &cobra.Command{
  Use:   "updateSessionConfig",
  Short: "Update Session Config",
  Long: `### Update session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateSessionConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allUserLoginLockoutsCmd = &cobra.Command{
  Use:   "allUserLoginLockouts",
  Short: "Get All User Login Lockouts",
  Long: `### Get currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserLoginLockouts called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchUserLoginLockoutsCmd = &cobra.Command{
  Use:   "searchUserLoginLockouts",
  Short: "Search User Login Lockouts",
  Long: `### Search currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchUserLoginLockouts called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    auth_type, _ := cmd.Flags().GetString("auth_type")
    fmt.Println("auth_type set to ", auth_type)

    full_name, _ := cmd.Flags().GetString("full_name")
    fmt.Println("full_name set to ", full_name)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to ", email)

    remote_id, _ := cmd.Flags().GetString("remote_id")
    fmt.Println("remote_id set to ", remote_id)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var deleteUserLoginLockoutCmd = &cobra.Command{
  Use:   "deleteUserLoginLockout",
  Short: "Delete User Login Lockout",
  Long: `### Removes login lockout for the associated user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserLoginLockout called")
    
    key, _ := cmd.Flags().GetString("key")
    fmt.Println("key set to ", key)
  },
}




var colorCollectionCmd = &cobra.Command{
  Use:   "ColorCollection",
  Short: "Manage Color Collections",
  Long: "Manage Color Collections",
}


var allColorCollectionsCmd = &cobra.Command{
  Use:   "allColorCollections",
  Short: "Get all Color Collections",
  Long: `### Get an array of all existing Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allColorCollections called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createColorCollectionCmd = &cobra.Command{
  Use:   "createColorCollection",
  Short: "Create ColorCollection",
  Long: `### Create a custom color collection with the specified information

Creates a new custom color collection object, returning the details, including the created id.

**Update** an existing color collection with [Update Color Collection](#!/ColorCollection/update_color_collection)

**Permanently delete** an existing custom color collection with [Delete Color Collection](#!/ColorCollection/delete_color_collection)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createColorCollection called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var colorCollectionsCustomCmd = &cobra.Command{
  Use:   "colorCollectionsCustom",
  Short: "Get all Custom Color Collections",
  Long: `### Get an array of all existing **Custom** Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("colorCollectionsCustom called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var colorCollectionsStandardCmd = &cobra.Command{
  Use:   "colorCollectionsStandard",
  Short: "Get all Standard Color Collections",
  Long: `### Get an array of all existing **Standard** Color Collections
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("colorCollectionsStandard called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var defaultColorCollectionCmd = &cobra.Command{
  Use:   "defaultColorCollection",
  Short: "Get Default Color Collection",
  Long: `### Get the default color collection

Use this to retrieve the default Color Collection.

Set the default color collection with [ColorCollection](#!/ColorCollection/set_default_color_collection)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("defaultColorCollection called")
    
  },
}


var setDefaultColorCollectionCmd = &cobra.Command{
  Use:   "setDefaultColorCollection",
  Short: "Set Default Color Collection",
  Long: `### Set the global default Color Collection by ID

Returns the new specified default Color Collection object.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setDefaultColorCollection called")
    
    collection_id, _ := cmd.Flags().GetString("collection_id")
    fmt.Println("collection_id set to ", collection_id)
  },
}


var colorCollectionCmd9328 = &cobra.Command{
  Use:   "colorCollection",
  Short: "Get Color Collection by ID",
  Long: `### Get a Color Collection by ID

Use this to retrieve a specific Color Collection.
Get a **single** color collection by id with [ColorCollection](#!/ColorCollection/color_collection)

Get all **standard** color collections with [ColorCollection](#!/ColorCollection/color_collections_standard)

Get all **custom** color collections with [ColorCollection](#!/ColorCollection/color_collections_custom)

**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("colorCollection called")
    
    collection_id, _ := cmd.Flags().GetString("collection_id")
    fmt.Println("collection_id set to ", collection_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateColorCollectionCmd = &cobra.Command{
  Use:   "updateColorCollection",
  Short: "Update Custom Color collection",
  Long: `### Update a custom color collection by id.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateColorCollection called")
    
    collection_id, _ := cmd.Flags().GetString("collection_id")
    fmt.Println("collection_id set to ", collection_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteColorCollectionCmd = &cobra.Command{
  Use:   "deleteColorCollection",
  Short: "Delete ColorCollection",
  Long: `### Delete a custom color collection by id

This operation permanently deletes the identified **Custom** color collection.

**Standard** color collections cannot be deleted

Because multiple color collections can have the same label, they must be deleted by ID, not name.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteColorCollection called")
    
    collection_id, _ := cmd.Flags().GetString("collection_id")
    fmt.Println("collection_id set to ", collection_id)
  },
}




var configCmd = &cobra.Command{
  Use:   "Config",
  Short: "Manage General Configuration",
  Long: "Manage General Configuration",
}


var backupConfigurationCmd = &cobra.Command{
  Use:   "backupConfiguration",
  Short: "Get Backup Configuration",
  Long: `### WARNING: The Looker internal database backup function has been deprecated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("backupConfiguration called")
    
  },
}


var updateBackupConfigurationCmd = &cobra.Command{
  Use:   "updateBackupConfiguration",
  Short: "Update Backup Configuration",
  Long: `### WARNING: The Looker internal database backup function has been deprecated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateBackupConfiguration called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var cloudStorageConfigurationCmd = &cobra.Command{
  Use:   "cloudStorageConfiguration",
  Short: "Get Cloud Storage",
  Long: `Get the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("cloudStorageConfiguration called")
    
  },
}


var updateCloudStorageConfigurationCmd = &cobra.Command{
  Use:   "updateCloudStorageConfiguration",
  Short: "Update Cloud Storage",
  Long: `Update the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateCloudStorageConfiguration called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var customWelcomeEmailCmd = &cobra.Command{
  Use:   "customWelcomeEmail",
  Short: "Get Custom Welcome Email",
  Long: `### Get the current status and content of custom welcome emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("customWelcomeEmail called")
    
  },
}


var updateCustomWelcomeEmailCmd = &cobra.Command{
  Use:   "updateCustomWelcomeEmail",
  Short: "Update Custom Welcome Email Content",
  Long: `Update custom welcome email setting and values. Optionally send a test email with the new content to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateCustomWelcomeEmail called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    send_test_welcome_email, _ := cmd.Flags().GetBool("send_test_welcome_email")
    fmt.Println("send_test_welcome_email set to ", send_test_welcome_email)
  },
}


var updateCustomWelcomeEmailTestCmd = &cobra.Command{
  Use:   "updateCustomWelcomeEmailTest",
  Short: "Send a test welcome email to the currently logged in user with the supplied content ",
  Long: `Requests to this endpoint will send a welcome email with the custom content provided in the body to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateCustomWelcomeEmailTest called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var digestEmailsEnabledCmd = &cobra.Command{
  Use:   "digestEmailsEnabled",
  Short: "Get Digest_emails",
  Long: `### Retrieve the value for whether or not digest emails is enabled
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("digestEmailsEnabled called")
    
  },
}


var updateDigestEmailsEnabledCmd = &cobra.Command{
  Use:   "updateDigestEmailsEnabled",
  Short: "Update Digest_emails",
  Long: `### Update the setting for enabling/disabling digest emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDigestEmailsEnabled called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var createDigestEmailSendCmd = &cobra.Command{
  Use:   "createDigestEmailSend",
  Short: "Deliver digest email contents",
  Long: `### Trigger the generation of digest email records and send them to Looker's internal system. This does not send
any actual emails, it generates records containing content which may be of interest for users who have become inactive.
Emails will be sent at a later time from Looker's internal system if the Digest Emails feature is enabled in settings.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDigestEmailSend called")
    
  },
}


var internalHelpResourcesContentCmd = &cobra.Command{
  Use:   "internalHelpResourcesContent",
  Short: "Get Internal Help Resources Content",
  Long: `### Set the menu item name and content for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internalHelpResourcesContent called")
    
  },
}


var updateInternalHelpResourcesContentCmd = &cobra.Command{
  Use:   "updateInternalHelpResourcesContent",
  Short: "Update internal help resources content",
  Long: `Update internal help resources content
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateInternalHelpResourcesContent called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var internalHelpResourcesCmd = &cobra.Command{
  Use:   "internalHelpResources",
  Short: "Get Internal Help Resources",
  Long: `### Get and set the options for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internalHelpResources called")
    
  },
}


var updateInternalHelpResourcesCmd = &cobra.Command{
  Use:   "updateInternalHelpResources",
  Short: "Update internal help resources configuration",
  Long: `Update internal help resources settings
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateInternalHelpResources called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allLegacyFeaturesCmd = &cobra.Command{
  Use:   "allLegacyFeatures",
  Short: "Get All Legacy Features",
  Long: `### Get all legacy features.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLegacyFeatures called")
    
  },
}


var legacyFeatureCmd = &cobra.Command{
  Use:   "legacyFeature",
  Short: "Get Legacy Feature",
  Long: `### Get information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("legacyFeature called")
    
    legacy_feature_id, _ := cmd.Flags().GetInt64("legacy_feature_id")
    fmt.Println("legacy_feature_id set to ", legacy_feature_id)
  },
}


var updateLegacyFeatureCmd = &cobra.Command{
  Use:   "updateLegacyFeature",
  Short: "Update Legacy Feature",
  Long: `### Update information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateLegacyFeature called")
    
    legacy_feature_id, _ := cmd.Flags().GetInt64("legacy_feature_id")
    fmt.Println("legacy_feature_id set to ", legacy_feature_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allLocalesCmd = &cobra.Command{
  Use:   "allLocales",
  Short: "Get All Locales",
  Long: `### Get a list of locales that Looker supports.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLocales called")
    
  },
}


var allTimezonesCmd = &cobra.Command{
  Use:   "allTimezones",
  Short: "Get All Timezones",
  Long: `### Get a list of timezones that Looker supports (e.g. useful for scheduling tasks).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allTimezones called")
    
  },
}


var versionsCmd = &cobra.Command{
  Use:   "versions",
  Short: "Get ApiVersion",
  Long: `### Get information about all API versions supported by this Looker instance.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("versions called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var whitelabelConfigurationCmd = &cobra.Command{
  Use:   "whitelabelConfiguration",
  Short: "Get Whitelabel configuration",
  Long: `### This feature is enabled only by special license.
### Gets the whitelabel configuration, which includes hiding documentation links, custom favicon uploading, etc.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("whitelabelConfiguration called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateWhitelabelConfigurationCmd = &cobra.Command{
  Use:   "updateWhitelabelConfiguration",
  Short: "Update Whitelabel configuration",
  Long: `### Update the whitelabel configuration
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateWhitelabelConfiguration called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var connectionCmd = &cobra.Command{
  Use:   "Connection",
  Short: "Manage Database Connections",
  Long: "Manage Database Connections",
}


var allConnectionsCmd = &cobra.Command{
  Use:   "allConnections",
  Short: "Get All Connections",
  Long: `### Get information about all connections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allConnections called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createConnectionCmd = &cobra.Command{
  Use:   "createConnection",
  Short: "Create Connection",
  Long: `### Create a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createConnection called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var connectionCmd8489 = &cobra.Command{
  Use:   "connection",
  Short: "Get Connection",
  Long: `### Get information about a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection called")
    
    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to ", connection_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateConnectionCmd = &cobra.Command{
  Use:   "updateConnection",
  Short: "Update Connection",
  Long: `### Update a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateConnection called")
    
    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to ", connection_name)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteConnectionCmd = &cobra.Command{
  Use:   "deleteConnection",
  Short: "Delete Connection",
  Long: `### Delete a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteConnection called")
    
    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to ", connection_name)
  },
}


var deleteConnectionOverrideCmd = &cobra.Command{
  Use:   "deleteConnectionOverride",
  Short: "Delete Connection Override",
  Long: `### Delete a connection override.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteConnectionOverride called")
    
    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to ", connection_name)

    override_context, _ := cmd.Flags().GetString("override_context")
    fmt.Println("override_context set to ", override_context)
  },
}


var testConnectionCmd = &cobra.Command{
  Use:   "testConnection",
  Short: "Test Connection",
  Long: `### Test an existing connection.

Note that a connection's 'dialect' property has a 'connection_tests' property that lists the
specific types of tests that the connection supports.

This API is rate limited.

Unsupported tests in the request will be ignored.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testConnection called")
    
    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to ", connection_name)

    tests, _ := cmd.Flags().GetString("tests")
    fmt.Println("tests set to ", tests)
  },
}


var testConnectionConfigCmd = &cobra.Command{
  Use:   "testConnectionConfig",
  Short: "Test Connection Configuration",
  Long: `### Test a connection configuration.

Note that a connection's 'dialect' property has a 'connection_tests' property that lists the
specific types of tests that the connection supports.

This API is rate limited.

Unsupported tests in the request will be ignored.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testConnectionConfig called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    tests, _ := cmd.Flags().GetString("tests")
    fmt.Println("tests set to ", tests)
  },
}


var allDialectInfosCmd = &cobra.Command{
  Use:   "allDialectInfos",
  Short: "Get All Dialect Infos",
  Long: `### Get information about all dialects.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allDialectInfos called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var contentCmd = &cobra.Command{
  Use:   "Content",
  Short: "Manage Content",
  Long: "Manage Content",
}


var searchContentFavoritesCmd = &cobra.Command{
  Use:   "searchContentFavorites",
  Short: "Search Favorite Contents",
  Long: `### Search Favorite Content

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchContentFavorites called")
    
    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    dashboard_id, _ := cmd.Flags().GetInt64("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var contentFavoriteCmd = &cobra.Command{
  Use:   "contentFavorite",
  Short: "Get Favorite Content",
  Long: `### Get favorite content by its id`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("contentFavorite called")
    
    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to ", content_favorite_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteContentFavoriteCmd = &cobra.Command{
  Use:   "deleteContentFavorite",
  Short: "Delete Favorite Content",
  Long: `### Delete favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteContentFavorite called")
    
    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to ", content_favorite_id)
  },
}


var createContentFavoriteCmd = &cobra.Command{
  Use:   "createContentFavorite",
  Short: "Create Favorite Content",
  Long: `### Create favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createContentFavorite called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allContentMetadatasCmd = &cobra.Command{
  Use:   "allContentMetadatas",
  Short: "Get All Content Metadatas",
  Long: `### Get information about all content metadata in a space.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allContentMetadatas called")
    
    parent_id, _ := cmd.Flags().GetInt64("parent_id")
    fmt.Println("parent_id set to ", parent_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var contentMetadataCmd = &cobra.Command{
  Use:   "contentMetadata",
  Short: "Get Content Metadata",
  Long: `### Get information about an individual content metadata record.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("contentMetadata called")
    
    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateContentMetadataCmd = &cobra.Command{
  Use:   "updateContentMetadata",
  Short: "Update Content Metadata",
  Long: `### Move a piece of content.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateContentMetadata called")
    
    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allContentMetadataAccessesCmd = &cobra.Command{
  Use:   "allContentMetadataAccesses",
  Short: "Get All Content Metadata Accesses",
  Long: `### All content metadata access records for a content metadata item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allContentMetadataAccesses called")
    
    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createContentMetadataAccessCmd = &cobra.Command{
  Use:   "createContentMetadataAccess",
  Short: "Create Content Metadata Access",
  Long: `### Create content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createContentMetadataAccess called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    send_boards_notification_email, _ := cmd.Flags().GetBool("send_boards_notification_email")
    fmt.Println("send_boards_notification_email set to ", send_boards_notification_email)
  },
}


var updateContentMetadataAccessCmd = &cobra.Command{
  Use:   "updateContentMetadataAccess",
  Short: "Update Content Metadata Access",
  Long: `### Update type of access for content metadata.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateContentMetadataAccess called")
    
    content_metadata_access_id, _ := cmd.Flags().GetInt64("content_metadata_access_id")
    fmt.Println("content_metadata_access_id set to ", content_metadata_access_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteContentMetadataAccessCmd = &cobra.Command{
  Use:   "deleteContentMetadataAccess",
  Short: "Delete Content Metadata Access",
  Long: `### Remove content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteContentMetadataAccess called")
    
    content_metadata_access_id, _ := cmd.Flags().GetInt64("content_metadata_access_id")
    fmt.Println("content_metadata_access_id set to ", content_metadata_access_id)
  },
}


var contentThumbnailCmd = &cobra.Command{
  Use:   "contentThumbnail",
  Short: "Get Content Thumbnail",
  Long: `### Get an image representing the contents of a dashboard or look.

The returned thumbnail is an abstract representation of the contents of a dashbord or look and does not
reflect the actual data displayed in the respective visualizations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("contentThumbnail called")
    
    type, _ := cmd.Flags().GetString("type")
    fmt.Println("type set to ", type)

    resource_id, _ := cmd.Flags().GetString("resource_id")
    fmt.Println("resource_id set to ", resource_id)

    reload, _ := cmd.Flags().GetString("reload")
    fmt.Println("reload set to ", reload)

    format, _ := cmd.Flags().GetString("format")
    fmt.Println("format set to ", format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to ", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to ", height)
  },
}


var contentValidationCmd = &cobra.Command{
  Use:   "contentValidation",
  Short: "Validate Content",
  Long: `### Validate All Content

Performs validation of all looks and dashboards
Returns a list of errors found as well as metadata about the content validation run.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("contentValidation called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchContentViewsCmd = &cobra.Command{
  Use:   "searchContentViews",
  Short: "Search Content Views",
  Long: `### Search Content Views

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchContentViews called")
    
    view_count, _ := cmd.Flags().GetInt64("view_count")
    fmt.Println("view_count set to ", view_count)

    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to ", look_id)

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    start_of_week_date, _ := cmd.Flags().GetString("start_of_week_date")
    fmt.Println("start_of_week_date set to ", start_of_week_date)

    all_time, _ := cmd.Flags().GetBool("all_time")
    fmt.Println("all_time set to ", all_time)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var vectorThumbnailCmd = &cobra.Command{
  Use:   "vectorThumbnail",
  Short: "Get Vector Thumbnail",
  Long: `### Get a vector image representing the contents of a dashboard or look.

# DEPRECATED:  Use [content_thumbnail()](#!/Content/content_thumbnail)

The returned thumbnail is an abstract representation of the contents of a dashbord or look and does not
reflect the actual data displayed in the respective visualizations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("vectorThumbnail called")
    
    type, _ := cmd.Flags().GetString("type")
    fmt.Println("type set to ", type)

    resource_id, _ := cmd.Flags().GetString("resource_id")
    fmt.Println("resource_id set to ", resource_id)

    reload, _ := cmd.Flags().GetString("reload")
    fmt.Println("reload set to ", reload)
  },
}




var dashboardCmd = &cobra.Command{
  Use:   "Dashboard",
  Short: "Manage Dashboards",
  Long: "Manage Dashboards",
}


var allDashboardsCmd = &cobra.Command{
  Use:   "allDashboards",
  Short: "Get All Dashboards",
  Long: `### Get information about all active dashboards.

Returns an array of **abbreviated dashboard objects**. Dashboards marked as deleted are excluded from this list.

Get the **full details** of a specific dashboard by id with [dashboard()](#!/Dashboard/dashboard)

Find **deleted dashboards** with [search_dashboards()](#!/Dashboard/search_dashboards)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allDashboards called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createDashboardCmd = &cobra.Command{
  Use:   "createDashboard",
  Short: "Create Dashboard",
  Long: `### Create a new dashboard

Creates a new dashboard object and returns the details of the newly created dashboard.

'Title', 'user_id', and 'space_id' are all required fields.
'Space_id' and 'user_id' must contain the id of an existing space or user, respectively.
A dashboard's 'title' must be unique within the space in which it resides.

If you receive a 422 error response when creating a dashboard, be sure to look at the
response body for information about exactly which fields are missing or contain invalid data.

You can **update** an existing dashboard with [update_dashboard()](#!/Dashboard/update_dashboard)

You can **permanently delete** an existing dashboard with [delete_dashboard()](#!/Dashboard/delete_dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboard called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var searchDashboardsCmd = &cobra.Command{
  Use:   "searchDashboards",
  Short: "Search Dashboards",
  Long: `### Search Dashboards

Returns an **array of dashboard objects** that match the specified search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


The parameters 'limit', and 'offset' are recommended for fetching results in page-size chunks.

Get a **single dashboard** by id with [dashboard()](#!/Dashboard/dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchDashboards called")
    
    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to ", slug)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to ", title)

    description, _ := cmd.Flags().GetString("description")
    fmt.Println("description set to ", description)

    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to ", content_favorite_id)

    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    deleted, _ := cmd.Flags().GetString("deleted")
    fmt.Println("deleted set to ", deleted)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to ", user_id)

    view_count, _ := cmd.Flags().GetString("view_count")
    fmt.Println("view_count set to ", view_count)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    curate, _ := cmd.Flags().GetBool("curate")
    fmt.Println("curate set to ", curate)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var importLookmlDashboardCmd = &cobra.Command{
  Use:   "importLookmlDashboard",
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
    fmt.Println("importLookmlDashboard called")
    
    lookml_dashboard_id, _ := cmd.Flags().GetString("lookml_dashboard_id")
    fmt.Println("lookml_dashboard_id set to ", lookml_dashboard_id)

    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    raw_locale, _ := cmd.Flags().GetBool("raw_locale")
    fmt.Println("raw_locale set to ", raw_locale)
  },
}


var syncLookmlDashboardCmd = &cobra.Command{
  Use:   "syncLookmlDashboard",
  Short: "Sync LookML Dashboard",
  Long: `### Update all linked dashboards to match the specified LookML dashboard.

Any UDD (a dashboard which exists in the Looker database rather than as a LookML file) which has a 'lookml_link_id'
property value referring to a LookML dashboard's id (model::dashboardname) will be updated so that it matches the current state of the LookML dashboard.

For this operation to succeed the user must have permission to view the LookML dashboard, and only linked dashboards
that the user has permission to update will be synced.

To **link** or **unlink** a UDD set the 'lookml_link_id' property with [update_dashboard()](#!/Dashboard/update_dashboard)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("syncLookmlDashboard called")
    
    lookml_dashboard_id, _ := cmd.Flags().GetString("lookml_dashboard_id")
    fmt.Println("lookml_dashboard_id set to ", lookml_dashboard_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    raw_locale, _ := cmd.Flags().GetBool("raw_locale")
    fmt.Println("raw_locale set to ", raw_locale)
  },
}


var dashboardCmd8169 = &cobra.Command{
  Use:   "dashboard",
  Short: "Get Dashboard",
  Long: `### Get information about a dashboard

Returns the full details of the identified dashboard object

Get a **summary list** of all active dashboards with [all_dashboards()](#!/Dashboard/all_dashboards)

You can **Search** for dashboards with [search_dashboards()](#!/Dashboard/search_dashboards)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateDashboardCmd = &cobra.Command{
  Use:   "updateDashboard",
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
    fmt.Println("updateDashboard called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteDashboardCmd = &cobra.Command{
  Use:   "deleteDashboard",
  Short: "Delete Dashboard",
  Long: `### Delete the dashboard with the specified id

Permanently **deletes** a dashboard. (The dashboard cannot be recovered after this operation.)

"Soft" delete or hide a dashboard by setting its 'deleted' status to 'True' with [update_dashboard()](#!/Dashboard/update_dashboard).

Note: When a dashboard is deleted in the UI, it is soft deleted. Use this API call to permanently remove it, if desired.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboard called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)
  },
}


var dashboardAggregateTableLookmlCmd = &cobra.Command{
  Use:   "dashboardAggregateTableLookml",
  Short: "Get Aggregate Table LookML for a dashboard",
  Long: `### Get Aggregate Table LookML for Each Query on a Dahboard

Returns a JSON object that contains the dashboard id and Aggregate Table lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardAggregateTableLookml called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)
  },
}


var dashboardLookmlCmd = &cobra.Command{
  Use:   "dashboardLookml",
  Short: "Get lookml of a UDD",
  Long: `### Get lookml of a UDD

Returns a JSON object that contains the dashboard id and the full lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLookml called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)
  },
}


var searchDashboardElementsCmd = &cobra.Command{
  Use:   "searchDashboardElements",
  Short: "Search Dashboard Elements",
  Long: `### Search Dashboard Elements

Returns an **array of DashboardElement objects** that match the specified search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchDashboardElements called")
    
    dashboard_id, _ := cmd.Flags().GetInt64("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to ", title)

    deleted, _ := cmd.Flags().GetBool("deleted")
    fmt.Println("deleted set to ", deleted)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var dashboardElementCmd = &cobra.Command{
  Use:   "dashboardElement",
  Short: "Get DashboardElement",
  Long: `### Get information about the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardElement called")
    
    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to ", dashboard_element_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateDashboardElementCmd = &cobra.Command{
  Use:   "updateDashboardElement",
  Short: "Update DashboardElement",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardElement called")
    
    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to ", dashboard_element_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteDashboardElementCmd = &cobra.Command{
  Use:   "deleteDashboardElement",
  Short: "Delete DashboardElement",
  Long: `### Delete a dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardElement called")
    
    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to ", dashboard_element_id)
  },
}


var dashboardDashboardElementsCmd = &cobra.Command{
  Use:   "dashboardDashboardElements",
  Short: "Get All DashboardElements",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardElements called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createDashboardElementCmd = &cobra.Command{
  Use:   "createDashboardElement",
  Short: "Create DashboardElement",
  Long: `### Create a dashboard element on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardElement called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var dashboardFilterCmd = &cobra.Command{
  Use:   "dashboardFilter",
  Short: "Get Dashboard Filter",
  Long: `### Get information about the dashboard filters with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardFilter called")
    
    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to ", dashboard_filter_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateDashboardFilterCmd = &cobra.Command{
  Use:   "updateDashboardFilter",
  Short: "Update Dashboard Filter",
  Long: `### Update the dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardFilter called")
    
    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to ", dashboard_filter_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteDashboardFilterCmd = &cobra.Command{
  Use:   "deleteDashboardFilter",
  Short: "Delete Dashboard Filter",
  Long: `### Delete a dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardFilter called")
    
    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to ", dashboard_filter_id)
  },
}


var dashboardDashboardFiltersCmd = &cobra.Command{
  Use:   "dashboardDashboardFilters",
  Short: "Get All Dashboard Filters",
  Long: `### Get information about all the dashboard filters on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardFilters called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createDashboardFilterCmd = &cobra.Command{
  Use:   "createDashboardFilter",
  Short: "Create Dashboard Filter",
  Long: `### Create a dashboard filter on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardFilter called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var dashboardLayoutComponentCmd = &cobra.Command{
  Use:   "dashboardLayoutComponent",
  Short: "Get DashboardLayoutComponent",
  Long: `### Get information about the dashboard elements with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayoutComponent called")
    
    dashboard_layout_component_id, _ := cmd.Flags().GetString("dashboard_layout_component_id")
    fmt.Println("dashboard_layout_component_id set to ", dashboard_layout_component_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateDashboardLayoutComponentCmd = &cobra.Command{
  Use:   "updateDashboardLayoutComponent",
  Short: "Update DashboardLayoutComponent",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardLayoutComponent called")
    
    dashboard_layout_component_id, _ := cmd.Flags().GetString("dashboard_layout_component_id")
    fmt.Println("dashboard_layout_component_id set to ", dashboard_layout_component_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var dashboardLayoutDashboardLayoutComponentsCmd = &cobra.Command{
  Use:   "dashboardLayoutDashboardLayoutComponents",
  Short: "Get All DashboardLayoutComponents",
  Long: `### Get information about all the dashboard layout components for a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayoutDashboardLayoutComponents called")
    
    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to ", dashboard_layout_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var dashboardLayoutCmd = &cobra.Command{
  Use:   "dashboardLayout",
  Short: "Get DashboardLayout",
  Long: `### Get information about the dashboard layouts with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayout called")
    
    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to ", dashboard_layout_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateDashboardLayoutCmd = &cobra.Command{
  Use:   "updateDashboardLayout",
  Short: "Update DashboardLayout",
  Long: `### Update the dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardLayout called")
    
    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to ", dashboard_layout_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteDashboardLayoutCmd = &cobra.Command{
  Use:   "deleteDashboardLayout",
  Short: "Delete DashboardLayout",
  Long: `### Delete a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardLayout called")
    
    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to ", dashboard_layout_id)
  },
}


var dashboardDashboardLayoutsCmd = &cobra.Command{
  Use:   "dashboardDashboardLayouts",
  Short: "Get All DashboardLayouts",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardLayouts called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createDashboardLayoutCmd = &cobra.Command{
  Use:   "createDashboardLayout",
  Short: "Create DashboardLayout",
  Long: `### Create a dashboard layout on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardLayout called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var dataActionCmd = &cobra.Command{
  Use:   "DataAction",
  Short: "Run Data Actions",
  Long: "Run Data Actions",
}


var performDataActionCmd = &cobra.Command{
  Use:   "performDataAction",
  Short: "Send a Data Action",
  Long: `Perform a data action. The data action object can be obtained from query results, and used to perform an arbitrary action.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("performDataAction called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var fetchRemoteDataActionFormCmd = &cobra.Command{
  Use:   "fetchRemoteDataActionForm",
  Short: "Fetch Remote Data Action Form",
  Long: `For some data actions, the remote server may supply a form requesting further user input. This endpoint takes a data action, asks the remote server to generate a form for it, and returns that form to you for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetchRemoteDataActionForm called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var datagroupCmd = &cobra.Command{
  Use:   "Datagroup",
  Short: "Manage Datagroups",
  Long: "Manage Datagroups",
}


var allDatagroupsCmd = &cobra.Command{
  Use:   "allDatagroups",
  Short: "Get All Datagroups",
  Long: `### Get information about all datagroups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allDatagroups called")
    
  },
}


var datagroupCmd9565 = &cobra.Command{
  Use:   "datagroup",
  Short: "Get Datagroup",
  Long: `### Get information about a datagroup.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("datagroup called")
    
    datagroup_id, _ := cmd.Flags().GetString("datagroup_id")
    fmt.Println("datagroup_id set to ", datagroup_id)
  },
}


var updateDatagroupCmd = &cobra.Command{
  Use:   "updateDatagroup",
  Short: "Update Datagroup",
  Long: `### Update a datagroup using the specified params.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDatagroup called")
    
    datagroup_id, _ := cmd.Flags().GetString("datagroup_id")
    fmt.Println("datagroup_id set to ", datagroup_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var derivedTableCmd = &cobra.Command{
  Use:   "DerivedTable",
  Short: "View Derived Table graphs",
  Long: "View Derived Table graphs",
}


var graphDerivedTablesForModelCmd = &cobra.Command{
  Use:   "graphDerivedTablesForModel",
  Short: "Get Derived Table graph for model",
  Long: `### Discover information about derived tables
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graphDerivedTablesForModel called")
    
    model, _ := cmd.Flags().GetString("model")
    fmt.Println("model set to ", model)

    format, _ := cmd.Flags().GetString("format")
    fmt.Println("format set to ", format)

    color, _ := cmd.Flags().GetString("color")
    fmt.Println("color set to ", color)
  },
}


var graphDerivedTablesForViewCmd = &cobra.Command{
  Use:   "graphDerivedTablesForView",
  Short: "Get subgraph of derived table and dependencies",
  Long: `### Get the subgraph representing this derived table and its dependencies.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graphDerivedTablesForView called")
    
    view, _ := cmd.Flags().GetString("view")
    fmt.Println("view set to ", view)

    models, _ := cmd.Flags().GetString("models")
    fmt.Println("models set to ", models)

    workspace, _ := cmd.Flags().GetString("workspace")
    fmt.Println("workspace set to ", workspace)
  },
}




var folderCmd = &cobra.Command{
  Use:   "Folder",
  Short: "Manage Folders",
  Long: "Manage Folders",
}


var searchFoldersCmd = &cobra.Command{
  Use:   "searchFolders",
  Short: "Search Folders",
  Long: `Search for folders by creator id, parent id, name, etc`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchFolders called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    parent_id, _ := cmd.Flags().GetString("parent_id")
    fmt.Println("parent_id set to ", parent_id)

    creator_id, _ := cmd.Flags().GetString("creator_id")
    fmt.Println("creator_id set to ", creator_id)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)

    is_shared_root, _ := cmd.Flags().GetBool("is_shared_root")
    fmt.Println("is_shared_root set to ", is_shared_root)
  },
}


var folderCmd4419 = &cobra.Command{
  Use:   "folder",
  Short: "Get Folder",
  Long: `### Get information about the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateFolderCmd = &cobra.Command{
  Use:   "updateFolder",
  Short: "Update Folder",
  Long: `### Update the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateFolder called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteFolderCmd = &cobra.Command{
  Use:   "deleteFolder",
  Short: "Delete Folder",
  Long: `### Delete the folder with a specific id including any children folders.
**DANGER** this will delete all looks and dashboards in the folder.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteFolder called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)
  },
}


var allFoldersCmd = &cobra.Command{
  Use:   "allFolders",
  Short: "Get All Folders",
  Long: `### Get information about all folders.

In API 3.x, this will not return empty personal folders, unless they belong to the calling user.
In API 4.0+, all personal folders will be returned.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allFolders called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createFolderCmd = &cobra.Command{
  Use:   "createFolder",
  Short: "Create Folder",
  Long: `### Create a folder with specified information.

Caller must have permission to edit the parent folder and to create folders, otherwise the request
returns 404 Not Found.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createFolder called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var folderChildrenCmd = &cobra.Command{
  Use:   "folderChildren",
  Short: "Get Folder Children",
  Long: `### Get the children of a folder.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderChildren called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var folderChildrenSearchCmd = &cobra.Command{
  Use:   "folderChildrenSearch",
  Short: "Search Folder Children",
  Long: `### Search the children of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderChildrenSearch called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)
  },
}


var folderParentCmd = &cobra.Command{
  Use:   "folderParent",
  Short: "Get Folder Parent",
  Long: `### Get the parent of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderParent called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var folderAncestorsCmd = &cobra.Command{
  Use:   "folderAncestors",
  Short: "Get Folder Ancestors",
  Long: `### Get the ancestors of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderAncestors called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var folderLooksCmd = &cobra.Command{
  Use:   "folderLooks",
  Short: "Get Folder Looks",
  Long: `### Get all looks in a folder.
In API 3.x, this will return all looks in a folder, including looks in the trash.
In API 4.0+, all looks in a folder will be returned, excluding looks in the trash.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderLooks called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var folderDashboardsCmd = &cobra.Command{
  Use:   "folderDashboards",
  Short: "Get Folder Dashboards",
  Long: `### Get the dashboards in a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderDashboards called")
    
    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to ", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var groupCmd = &cobra.Command{
  Use:   "Group",
  Short: "Manage Groups",
  Long: "Manage Groups",
}


var allGroupsCmd = &cobra.Command{
  Use:   "allGroups",
  Short: "Get All Groups",
  Long: `### Get information about all groups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGroups called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to ", ids)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    can_add_to_content_metadata, _ := cmd.Flags().GetBool("can_add_to_content_metadata")
    fmt.Println("can_add_to_content_metadata set to ", can_add_to_content_metadata)
  },
}


var createGroupCmd = &cobra.Command{
  Use:   "createGroup",
  Short: "Create Group",
  Long: `### Creates a new group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createGroup called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchGroupsCmd = &cobra.Command{
  Use:   "searchGroups",
  Short: "Search Groups",
  Long: `### Search groups

Returns all group records that match the given search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchGroups called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    external_group_id, _ := cmd.Flags().GetString("external_group_id")
    fmt.Println("external_group_id set to ", external_group_id)

    externally_managed, _ := cmd.Flags().GetBool("externally_managed")
    fmt.Println("externally_managed set to ", externally_managed)

    externally_orphaned, _ := cmd.Flags().GetBool("externally_orphaned")
    fmt.Println("externally_orphaned set to ", externally_orphaned)
  },
}


var groupCmd65 = &cobra.Command{
  Use:   "group",
  Short: "Get Group",
  Long: `### Get information about a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("group called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateGroupCmd = &cobra.Command{
  Use:   "updateGroup",
  Short: "Update Group",
  Long: `### Updates the a group (admin only).`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateGroup called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteGroupCmd = &cobra.Command{
  Use:   "deleteGroup",
  Short: "Delete Group",
  Long: `### Deletes a group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteGroup called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)
  },
}


var allGroupGroupsCmd = &cobra.Command{
  Use:   "allGroupGroups",
  Short: "Get All Groups in Group",
  Long: `### Get information about all the groups in a group
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGroupGroups called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var addGroupGroupCmd = &cobra.Command{
  Use:   "addGroupGroup",
  Short: "Add a Group to Group",
  Long: `### Adds a new group to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("addGroupGroup called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allGroupUsersCmd = &cobra.Command{
  Use:   "allGroupUsers",
  Short: "Get All Users in Group",
  Long: `### Get information about all the users directly included in a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGroupUsers called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var addGroupUserCmd = &cobra.Command{
  Use:   "addGroupUser",
  Short: "Add a User to Group",
  Long: `### Adds a new user to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("addGroupUser called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteGroupUserCmd = &cobra.Command{
  Use:   "deleteGroupUser",
  Short: "Remove a User from Group",
  Long: `### Removes a user from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteGroupUser called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var deleteGroupFromGroupCmd = &cobra.Command{
  Use:   "deleteGroupFromGroup",
  Short: "Deletes a Group from Group",
  Long: `### Removes a group from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteGroupFromGroup called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    deleting_group_id, _ := cmd.Flags().GetInt64("deleting_group_id")
    fmt.Println("deleting_group_id set to ", deleting_group_id)
  },
}


var updateUserAttributeGroupValueCmd = &cobra.Command{
  Use:   "updateUserAttributeGroupValue",
  Short: "Set User Attribute Group Value",
  Long: `### Set the value of a user attribute for a group.

For information about how user attribute values are calculated, see [Set User Attribute Group Values](#!/UserAttribute/set_user_attribute_group_values).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateUserAttributeGroupValue called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteUserAttributeGroupValueCmd = &cobra.Command{
  Use:   "deleteUserAttributeGroupValue",
  Short: "Delete User Attribute Group Value",
  Long: `### Remove a user attribute value from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserAttributeGroupValue called")
    
    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)
  },
}




var homepageCmd = &cobra.Command{
  Use:   "Homepage",
  Short: "Manage Homepage",
  Long: "Manage Homepage",
}


var allHomepagesCmd = &cobra.Command{
  Use:   "allHomepages",
  Short: "Get All Homepages",
  Long: `### Get information about all homepages.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allHomepages called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createHomepageCmd = &cobra.Command{
  Use:   "createHomepage",
  Short: "Create Homepage",
  Long: `### Create a new homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createHomepage called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchHomepagesCmd = &cobra.Command{
  Use:   "searchHomepages",
  Short: "Search Homepages",
  Long: `### Search Homepages

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchHomepages called")
    
    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to ", title)

    created_at, _ := cmd.Flags().GetString("created_at")
    fmt.Println("created_at set to ", created_at)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to ", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to ", last_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    favorited, _ := cmd.Flags().GetBool("favorited")
    fmt.Println("favorited set to ", favorited)

    creator_id, _ := cmd.Flags().GetString("creator_id")
    fmt.Println("creator_id set to ", creator_id)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var homepageCmd8294 = &cobra.Command{
  Use:   "homepage",
  Short: "Get Homepage",
  Long: `### Get information about a homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepage called")
    
    homepage_id, _ := cmd.Flags().GetInt64("homepage_id")
    fmt.Println("homepage_id set to ", homepage_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateHomepageCmd = &cobra.Command{
  Use:   "updateHomepage",
  Short: "Update Homepage",
  Long: `### Update a homepage definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateHomepage called")
    
    homepage_id, _ := cmd.Flags().GetInt64("homepage_id")
    fmt.Println("homepage_id set to ", homepage_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteHomepageCmd = &cobra.Command{
  Use:   "deleteHomepage",
  Short: "Delete Homepage",
  Long: `### Delete a homepage.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteHomepage called")
    
    homepage_id, _ := cmd.Flags().GetInt64("homepage_id")
    fmt.Println("homepage_id set to ", homepage_id)
  },
}


var allHomepageItemsCmd = &cobra.Command{
  Use:   "allHomepageItems",
  Short: "Get All Homepage Items",
  Long: `### Get information about all homepage items.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allHomepageItems called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    homepage_section_id, _ := cmd.Flags().GetString("homepage_section_id")
    fmt.Println("homepage_section_id set to ", homepage_section_id)
  },
}


var createHomepageItemCmd = &cobra.Command{
  Use:   "createHomepageItem",
  Short: "Create Homepage Item",
  Long: `### Create a new homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createHomepageItem called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var homepageItemCmd = &cobra.Command{
  Use:   "homepageItem",
  Short: "Get Homepage Item",
  Long: `### Get information about a homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepageItem called")
    
    homepage_item_id, _ := cmd.Flags().GetInt64("homepage_item_id")
    fmt.Println("homepage_item_id set to ", homepage_item_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateHomepageItemCmd = &cobra.Command{
  Use:   "updateHomepageItem",
  Short: "Update Homepage Item",
  Long: `### Update a homepage item definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateHomepageItem called")
    
    homepage_item_id, _ := cmd.Flags().GetInt64("homepage_item_id")
    fmt.Println("homepage_item_id set to ", homepage_item_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteHomepageItemCmd = &cobra.Command{
  Use:   "deleteHomepageItem",
  Short: "Delete Homepage Item",
  Long: `### Delete a homepage item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteHomepageItem called")
    
    homepage_item_id, _ := cmd.Flags().GetInt64("homepage_item_id")
    fmt.Println("homepage_item_id set to ", homepage_item_id)
  },
}


var allHomepageSectionsCmd = &cobra.Command{
  Use:   "allHomepageSections",
  Short: "Get All Homepage sections",
  Long: `### Get information about all homepage sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allHomepageSections called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var createHomepageSectionCmd = &cobra.Command{
  Use:   "createHomepageSection",
  Short: "Create Homepage section",
  Long: `### Create a new homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createHomepageSection called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var homepageSectionCmd = &cobra.Command{
  Use:   "homepageSection",
  Short: "Get Homepage section",
  Long: `### Get information about a homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("homepageSection called")
    
    homepage_section_id, _ := cmd.Flags().GetInt64("homepage_section_id")
    fmt.Println("homepage_section_id set to ", homepage_section_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateHomepageSectionCmd = &cobra.Command{
  Use:   "updateHomepageSection",
  Short: "Update Homepage section",
  Long: `### Update a homepage section definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateHomepageSection called")
    
    homepage_section_id, _ := cmd.Flags().GetInt64("homepage_section_id")
    fmt.Println("homepage_section_id set to ", homepage_section_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteHomepageSectionCmd = &cobra.Command{
  Use:   "deleteHomepageSection",
  Short: "Delete Homepage section",
  Long: `### Delete a homepage section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteHomepageSection called")
    
    homepage_section_id, _ := cmd.Flags().GetInt64("homepage_section_id")
    fmt.Println("homepage_section_id set to ", homepage_section_id)
  },
}


var allPrimaryHomepageSectionsCmd = &cobra.Command{
  Use:   "allPrimaryHomepageSections",
  Short: "Get All Primary homepage sections",
  Long: `### Get information about the primary homepage's sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allPrimaryHomepageSections called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var integrationCmd = &cobra.Command{
  Use:   "Integration",
  Short: "Manage Integrations",
  Long: "Manage Integrations",
}


var allIntegrationHubsCmd = &cobra.Command{
  Use:   "allIntegrationHubs",
  Short: "Get All Integration Hubs",
  Long: `### Get information about all Integration Hubs.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allIntegrationHubs called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createIntegrationHubCmd = &cobra.Command{
  Use:   "createIntegrationHub",
  Short: "Create Integration Hub",
  Long: `### Create a new Integration Hub.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createIntegrationHub called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var integrationHubCmd = &cobra.Command{
  Use:   "integrationHub",
  Short: "Get Integration Hub",
  Long: `### Get information about a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integrationHub called")
    
    integration_hub_id, _ := cmd.Flags().GetInt64("integration_hub_id")
    fmt.Println("integration_hub_id set to ", integration_hub_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateIntegrationHubCmd = &cobra.Command{
  Use:   "updateIntegrationHub",
  Short: "Update Integration Hub",
  Long: `### Update a Integration Hub definition.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateIntegrationHub called")
    
    integration_hub_id, _ := cmd.Flags().GetInt64("integration_hub_id")
    fmt.Println("integration_hub_id set to ", integration_hub_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteIntegrationHubCmd = &cobra.Command{
  Use:   "deleteIntegrationHub",
  Short: "Delete Integration Hub",
  Long: `### Delete a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteIntegrationHub called")
    
    integration_hub_id, _ := cmd.Flags().GetInt64("integration_hub_id")
    fmt.Println("integration_hub_id set to ", integration_hub_id)
  },
}


var acceptIntegrationHubLegalAgreementCmd = &cobra.Command{
  Use:   "acceptIntegrationHubLegalAgreement",
  Short: "Accept Integration Hub Legal Agreement",
  Long: `Accepts the legal agreement for a given integration hub. This only works for integration hubs that have legal_agreement_required set to true and legal_agreement_signed set to false.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("acceptIntegrationHubLegalAgreement called")
    
    integration_hub_id, _ := cmd.Flags().GetInt64("integration_hub_id")
    fmt.Println("integration_hub_id set to ", integration_hub_id)
  },
}


var allIntegrationsCmd = &cobra.Command{
  Use:   "allIntegrations",
  Short: "Get All Integrations",
  Long: `### Get information about all Integrations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allIntegrations called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    integration_hub_id, _ := cmd.Flags().GetString("integration_hub_id")
    fmt.Println("integration_hub_id set to ", integration_hub_id)
  },
}


var integrationCmd822 = &cobra.Command{
  Use:   "integration",
  Short: "Get Integration",
  Long: `### Get information about a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration called")
    
    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to ", integration_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateIntegrationCmd = &cobra.Command{
  Use:   "updateIntegration",
  Short: "Update Integration",
  Long: `### Update parameters on a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateIntegration called")
    
    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to ", integration_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var fetchIntegrationFormCmd = &cobra.Command{
  Use:   "fetchIntegrationForm",
  Short: "Fetch Remote Integration Form",
  Long: `Returns the Integration form for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetchIntegrationForm called")
    
    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to ", integration_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var testIntegrationCmd = &cobra.Command{
  Use:   "testIntegration",
  Short: "Test integration",
  Long: `Tests the integration to make sure all the settings are working.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testIntegration called")
    
    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to ", integration_id)
  },
}




var lookCmd = &cobra.Command{
  Use:   "Look",
  Short: "Run and Manage Looks",
  Long: "Run and Manage Looks",
}


var allLooksCmd = &cobra.Command{
  Use:   "allLooks",
  Short: "Get All Looks",
  Long: `### Get information about all active Looks

Returns an array of **abbreviated Look objects** describing all the looks that the caller has access to. Soft-deleted Looks are **not** included.

Get the **full details** of a specific look by id with [look(id)](#!/Look/look)

Find **soft-deleted looks** with [search_looks()](#!/Look/search_looks)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLooks called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createLookCmd = &cobra.Command{
  Use:   "createLook",
  Short: "Create Look",
  Long: `### Create a Look

To create a look to display query data, first create the query with [create_query()](#!/Query/create_query)
then assign the query's id to the 'query_id' property in the call to 'create_look()'.

To place the look into a particular space, assign the space's id to the 'space_id' property
in the call to 'create_look()'.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createLook called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchLooksCmd = &cobra.Command{
  Use:   "searchLooks",
  Short: "Search Looks",
  Long: `### Search Looks

Returns an **array of Look objects** that match the specified search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchLooks called")
    
    id, _ := cmd.Flags().GetString("id")
    fmt.Println("id set to ", id)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to ", title)

    description, _ := cmd.Flags().GetString("description")
    fmt.Println("description set to ", description)

    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to ", content_favorite_id)

    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to ", user_id)

    view_count, _ := cmd.Flags().GetString("view_count")
    fmt.Println("view_count set to ", view_count)

    deleted, _ := cmd.Flags().GetBool("deleted")
    fmt.Println("deleted set to ", deleted)

    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to ", query_id)

    curate, _ := cmd.Flags().GetBool("curate")
    fmt.Println("curate set to ", curate)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var lookCmd652 = &cobra.Command{
  Use:   "look",
  Short: "Get Look",
  Long: `### Get a Look.

Returns detailed information about a Look and its associated Query.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("look called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateLookCmd = &cobra.Command{
  Use:   "updateLook",
  Short: "Update Look",
  Long: `### Modify a Look

Use this function to modify parts of a look. Property values given in a call to 'update_look' are
applied to the existing look, so there's no need to include properties whose values are not changing.
It's best to specify only the properties you want to change and leave everything else out
of your 'update_look' call. **Look properties marked 'read-only' will be ignored.**

When a user deletes a look in the Looker UI, the look data remains in the database but is
marked with a deleted flag ("soft-deleted"). Soft-deleted looks can be undeleted (by an admin)
if the delete was in error.

To soft-delete a look via the API, use [update_look()](#!/Look/update_look) to change the look's 'deleted' property to 'true'.
You can undelete a look by calling 'update_look' to change the look's 'deleted' property to 'false'.

Soft-deleted looks are excluded from the results of [all_looks()](#!/Look/all_looks) and [search_looks()](#!/Look/search_looks), so they
essentially disappear from view even though they still reside in the db.
In API 3.1 and later, you can pass 'deleted: true' as a parameter to [search_looks()](#!/3.1/Look/search_looks) to list soft-deleted looks.

NOTE: [delete_look()](#!/Look/delete_look) performs a "hard delete" - the look data is removed from the Looker
database and destroyed. There is no "undo" for 'delete_look()'.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateLook called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteLookCmd = &cobra.Command{
  Use:   "deleteLook",
  Short: "Delete Look",
  Long: `### Permanently Delete a Look

This operation **permanently** removes a look from the Looker database.

NOTE: There is no "undo" for this kind of delete.

For information about soft-delete (which can be undone) see [update_look()](#!/Look/update_look).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteLook called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)
  },
}


var runLookCmd = &cobra.Command{
  Use:   "runLook",
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
    fmt.Println("runLook called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to ", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to ", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to ", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to ", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to ", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to ", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to ", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to ", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to ", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to ", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to ", server_table_calcs)
  },
}




var lookmlModelCmd = &cobra.Command{
  Use:   "LookmlModel",
  Short: "Manage LookML Models",
  Long: "Manage LookML Models",
}


var allLookmlModelsCmd = &cobra.Command{
  Use:   "allLookmlModels",
  Short: "Get All LookML Models",
  Long: `### Get information about all lookml models.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLookmlModels called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createLookmlModelCmd = &cobra.Command{
  Use:   "createLookmlModel",
  Short: "Create LookML Model",
  Long: `### Create a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createLookmlModel called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var lookmlModelCmd6917 = &cobra.Command{
  Use:   "lookmlModel",
  Short: "Get LookML Model",
  Long: `### Get information about a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookmlModel called")
    
    lookml_model_name, _ := cmd.Flags().GetString("lookml_model_name")
    fmt.Println("lookml_model_name set to ", lookml_model_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateLookmlModelCmd = &cobra.Command{
  Use:   "updateLookmlModel",
  Short: "Update LookML Model",
  Long: `### Update a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateLookmlModel called")
    
    lookml_model_name, _ := cmd.Flags().GetString("lookml_model_name")
    fmt.Println("lookml_model_name set to ", lookml_model_name)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteLookmlModelCmd = &cobra.Command{
  Use:   "deleteLookmlModel",
  Short: "Delete LookML Model",
  Long: `### Delete a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteLookmlModel called")
    
    lookml_model_name, _ := cmd.Flags().GetString("lookml_model_name")
    fmt.Println("lookml_model_name set to ", lookml_model_name)
  },
}


var lookmlModelExploreCmd = &cobra.Command{
  Use:   "lookmlModelExplore",
  Short: "Get LookML Model Explore",
  Long: `### Get information about a lookml model explore.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookmlModelExplore called")
    
    lookml_model_name, _ := cmd.Flags().GetString("lookml_model_name")
    fmt.Println("lookml_model_name set to ", lookml_model_name)

    explore_name, _ := cmd.Flags().GetString("explore_name")
    fmt.Println("explore_name set to ", explore_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var projectCmd = &cobra.Command{
  Use:   "Project",
  Short: "Manage Projects",
  Long: "Manage Projects",
}


var allGitBranchesCmd = &cobra.Command{
  Use:   "allGitBranches",
  Short: "Get All Git Branches",
  Long: `### Get All Git Branches

Returns a list of git branches in the project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGitBranches called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var gitBranchCmd = &cobra.Command{
  Use:   "gitBranch",
  Short: "Get Active Git Branch",
  Long: `### Get the Current Git Branch

Returns the git branch currently checked out in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("gitBranch called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var updateGitBranchCmd = &cobra.Command{
  Use:   "updateGitBranch",
  Short: "Update Project Git Branch",
  Long: `### Checkout and/or reset --hard an existing Git Branch

Only allowed in development mode
  - Call 'update_session' to select the 'dev' workspace.

Checkout an existing branch if name field is different from the name of the currently checked out branch.

Optionally specify a branch name, tag name or commit SHA to which the branch should be reset.
  **DANGER** hard reset will be force pushed to the remote. Unsaved changes and commits may be permanently lost.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateGitBranch called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var createGitBranchCmd = &cobra.Command{
  Use:   "createGitBranch",
  Short: "Checkout New Git Branch",
  Long: `### Create and Checkout a Git Branch

Creates and checks out a new branch in the given project repository
Only allowed in development mode
  - Call 'update_session' to select the 'dev' workspace.

Optionally specify a branch name, tag name or commit SHA as the start point in the ref field.
  If no ref is specified, HEAD of the current branch will be used as the start point for the new branch.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createGitBranch called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var findGitBranchCmd = &cobra.Command{
  Use:   "findGitBranch",
  Short: "Find a Git Branch",
  Long: `### Get the specified Git Branch

Returns the git branch specified in branch_name path param if it exists in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("findGitBranch called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    branch_name, _ := cmd.Flags().GetString("branch_name")
    fmt.Println("branch_name set to ", branch_name)
  },
}


var deleteGitBranchCmd = &cobra.Command{
  Use:   "deleteGitBranch",
  Short: "Delete a Git Branch",
  Long: `### Delete the specified Git Branch

Delete git branch specified in branch_name path param from local and remote of specified project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteGitBranch called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    branch_name, _ := cmd.Flags().GetString("branch_name")
    fmt.Println("branch_name set to ", branch_name)
  },
}


var deployRefToProductionCmd = &cobra.Command{
  Use:   "deployRefToProduction",
  Short: "Deploy Remote Branch or Ref to Production",
  Long: `### Deploy a Remote Branch or Ref to Production

Git must have been configured and deploy permission required.

Deploy is a one/two step process
1. If this is the first deploy of this project, create the production project with git repository.
2. Pull the branch or ref into the production project.

Can only specify either a branch or a ref.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deployRefToProduction called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    branch, _ := cmd.Flags().GetString("branch")
    fmt.Println("branch set to ", branch)

    ref, _ := cmd.Flags().GetString("ref")
    fmt.Println("ref set to ", ref)
  },
}


var deployToProductionCmd = &cobra.Command{
  Use:   "deployToProduction",
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
    fmt.Println("deployToProduction called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var resetProjectToProductionCmd = &cobra.Command{
  Use:   "resetProjectToProduction",
  Short: "Reset To Production",
  Long: `### Reset a project to the revision of the project that is in production.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("resetProjectToProduction called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var resetProjectToRemoteCmd = &cobra.Command{
  Use:   "resetProjectToRemote",
  Short: "Reset To Remote",
  Long: `### Reset a project development branch to the revision of the project that is on the remote.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("resetProjectToRemote called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var allProjectsCmd = &cobra.Command{
  Use:   "allProjects",
  Short: "Get All Projects",
  Long: `### Get All Projects

Returns all projects visible to the current user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allProjects called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createProjectCmd = &cobra.Command{
  Use:   "createProject",
  Short: "Create Project",
  Long: `### Create A Project

dev mode required.
- Call 'update_session' to select the 'dev' workspace.

'name' is required.
'git_remote_url' is not allowed. To configure Git for the newly created project, follow the instructions in 'update_project'.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createProject called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var projectCmd8042 = &cobra.Command{
  Use:   "project",
  Short: "Get Project",
  Long: `### Get A Project

Returns the project with the given project id
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateProjectCmd = &cobra.Command{
  Use:   "updateProject",
  Short: "Update Project",
  Long: `### Update Project Configuration

Apply changes to a project's configuration.


#### Configuring Git for a Project

To set up a Looker project with a remote git repository, follow these steps:

1. Call 'update_session' to select the 'dev' workspace.
1. Call 'create_git_deploy_key' to create a new deploy key for the project
1. Copy the deploy key text into the remote git repository's ssh key configuration
1. Call 'update_project' to set project's 'git_remote_url' ()and 'git_service_name', if necessary).

When you modify a project's 'git_remote_url', Looker connects to the remote repository to fetch
metadata. The remote git repository MUST be configured with the Looker-generated deploy
key for this project prior to setting the project's 'git_remote_url'.

To set up a Looker project with a git repository residing on the Looker server (a 'bare' git repo):

1. Call 'update_session' to select the 'dev' workspace.
1. Call 'update_project' setting 'git_remote_url' to null and 'git_service_name' to "bare".

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateProject called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
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
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var gitDeployKeyCmd = &cobra.Command{
  Use:   "gitDeployKey",
  Short: "Git Deploy Key",
  Long: `### Git Deploy Key

Returns the ssh public key previously created for a project's git repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("gitDeployKey called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var createGitDeployKeyCmd = &cobra.Command{
  Use:   "createGitDeployKey",
  Short: "Create Deploy Key",
  Long: `### Create Git Deploy Key

Create a public/private key pair for authenticating ssh git requests from Looker to a remote git repository
for a particular Looker project.

Returns the public key of the generated ssh key pair.

Copy this public key to your remote git repository's ssh keys configuration so that the remote git service can
validate and accept git requests from the Looker server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createGitDeployKey called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)
  },
}


var projectValidationResultsCmd = &cobra.Command{
  Use:   "projectValidationResults",
  Short: "Cached Project Validation Results",
  Long: `### Get Cached Project Validation Results

Returns the cached results of a previous project validation calculation, if any.
Returns http status 204 No Content if no validation results exist.

Validating the content of all the files in a project can be computationally intensive
for large projects. Use this API to simply fetch the results of the most recent
project validation rather than revalidating the entire project from scratch.

A value of '"stale": true' in the response indicates that the project has changed since
the cached validation results were computed. The cached validation results may no longer
reflect the current state of the project.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("projectValidationResults called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var validateProjectCmd = &cobra.Command{
  Use:   "validateProject",
  Short: "Validate Project",
  Long: `### Validate Project

Performs lint validation of all lookml files in the project.
Returns a list of errors found, if any.

Validating the content of all the files in a project can be computationally intensive
for large projects. For best performance, call 'validate_project(project_id)' only
when you really want to recompute project validation. To quickly display the results of
the most recent project validation (without recomputing), use 'project_validation_results(project_id)'
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("validateProject called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var projectWorkspaceCmd = &cobra.Command{
  Use:   "projectWorkspace",
  Short: "Get Project Workspace",
  Long: `### Get Project Workspace

Returns information about the state of the project files in the currently selected workspace
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("projectWorkspace called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var allProjectFilesCmd = &cobra.Command{
  Use:   "allProjectFiles",
  Short: "Get All Project Files",
  Long: `### Get All Project Files

Returns a list of the files in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allProjectFiles called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var projectFileCmd = &cobra.Command{
  Use:   "projectFile",
  Short: "Get Project File",
  Long: `### Get Project File Info

Returns information about a file in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("projectFile called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to ", file_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var allGitConnectionTestsCmd = &cobra.Command{
  Use:   "allGitConnectionTests",
  Short: "Get All Git Connection Tests",
  Long: `### Get All Git Connection Tests

dev mode required.
  - Call 'update_session' to select the 'dev' workspace.

Returns a list of tests which can be run against a project's (or the dependency project for the provided remote_url) git connection. Call [Run Git Connection Test](#!/Project/run_git_connection_test) to execute each test in sequence.

Tests are ordered by increasing specificity. Tests should be run in the order returned because later tests require functionality tested by tests earlier in the test list.

For example, a late-stage test for write access is meaningless if connecting to the git server (an early test) is failing.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGitConnectionTests called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    remote_url, _ := cmd.Flags().GetString("remote_url")
    fmt.Println("remote_url set to ", remote_url)
  },
}


var runGitConnectionTestCmd = &cobra.Command{
  Use:   "runGitConnectionTest",
  Short: "Run Git Connection Test",
  Long: `### Run a git connection test

Run the named test on the git service used by this project (or the dependency project for the provided remote_url) and return the result. This
is intended to help debug git connections when things do not work properly, to give
more helpful information about why a git url is not working with Looker.

Tests should be run in the order they are returned by [Get All Git Connection Tests](#!/Project/all_git_connection_tests).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("runGitConnectionTest called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    test_id, _ := cmd.Flags().GetString("test_id")
    fmt.Println("test_id set to ", test_id)

    remote_url, _ := cmd.Flags().GetString("remote_url")
    fmt.Println("remote_url set to ", remote_url)

    use_production, _ := cmd.Flags().GetString("use_production")
    fmt.Println("use_production set to ", use_production)
  },
}


var allLookmlTestsCmd = &cobra.Command{
  Use:   "allLookmlTests",
  Short: "Get All LookML Tests",
  Long: `### Get All LookML Tests

Returns a list of tests which can be run to validate a project's LookML code and/or the underlying data,
optionally filtered by the file id.
Call [Run LookML Test](#!/Project/run_lookml_test) to execute tests.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLookmlTests called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to ", file_id)
  },
}


var runLookmlTestCmd = &cobra.Command{
  Use:   "runLookmlTest",
  Short: "Run LookML Test",
  Long: `### Run LookML Tests

Runs all tests in the project, optionally filtered by file, test, and/or model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("runLookmlTest called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to ", file_id)

    test, _ := cmd.Flags().GetString("test")
    fmt.Println("test set to ", test)

    model, _ := cmd.Flags().GetString("model")
    fmt.Println("model set to ", model)
  },
}


var tagRefCmd = &cobra.Command{
  Use:   "tagRef",
  Short: "Tag Ref",
  Long: `### Creates a tag for the most recent commit, or a specific ref is a SHA is provided

This is an internal-only, undocumented route.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("tagRef called")
    
    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to ", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    commit_sha, _ := cmd.Flags().GetString("commit_sha")
    fmt.Println("commit_sha set to ", commit_sha)

    tag_name, _ := cmd.Flags().GetString("tag_name")
    fmt.Println("tag_name set to ", tag_name)

    tag_message, _ := cmd.Flags().GetString("tag_message")
    fmt.Println("tag_message set to ", tag_message)
  },
}


var updateRepositoryCredentialCmd = &cobra.Command{
  Use:   "updateRepositoryCredential",
  Short: "Create Repository Credential",
  Long: `### Configure Repository Credential for a remote dependency

Admin required.

'root_project_id' is required.
'credential_id' is required.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateRepositoryCredential called")
    
    root_project_id, _ := cmd.Flags().GetString("root_project_id")
    fmt.Println("root_project_id set to ", root_project_id)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to ", credential_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteRepositoryCredentialCmd = &cobra.Command{
  Use:   "deleteRepositoryCredential",
  Short: "Delete Repository Credential",
  Long: `### Repository Credential for a remote dependency

Admin required.

'root_project_id' is required.
'credential_id' is required.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteRepositoryCredential called")
    
    root_project_id, _ := cmd.Flags().GetString("root_project_id")
    fmt.Println("root_project_id set to ", root_project_id)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to ", credential_id)
  },
}


var getAllRepositoryCredentialsCmd = &cobra.Command{
  Use:   "getAllRepositoryCredentials",
  Short: "Get All Repository Credentials",
  Long: `### Get all Repository Credentials for a project

'root_project_id' is required.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("getAllRepositoryCredentials called")
    
    root_project_id, _ := cmd.Flags().GetString("root_project_id")
    fmt.Println("root_project_id set to ", root_project_id)
  },
}




var queryCmd = &cobra.Command{
  Use:   "Query",
  Short: "Run and Manage Queries",
  Long: "Run and Manage Queries",
}


var createQueryTaskCmd = &cobra.Command{
  Use:   "createQueryTask",
  Short: "Run Query Async",
  Long: `### Create an async query task

Creates a query task (job) to run a previously created query asynchronously. Returns a Query Task ID.

Use [query_task(query_task_id)](#!/Query/query_task) to check the execution status of the query task.
After the query task status reaches "Complete", use [query_task_results(query_task_id)](#!/Query/query_task_results) to fetch the results of the query.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createQueryTask called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to ", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to ", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to ", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to ", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to ", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to ", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to ", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to ", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to ", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to ", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to ", server_table_calcs)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var queryTaskMultiResultsCmd = &cobra.Command{
  Use:   "queryTaskMultiResults",
  Short: "Get Multiple Async Query Results",
  Long: `### Fetch results of multiple async queries

Returns the results of multiple async queries in one request.

For Query Tasks that are not completed, the response will include the execution status of the Query Task but will not include query results.
Query Tasks whose results have expired will have a status of 'expired'.
If the user making the API request does not have sufficient privileges to view a Query Task result, the result will have a status of 'missing'
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("queryTaskMultiResults called")
    
    query_task_ids, _ := cmd.Flags().GetString("query_task_ids")
    fmt.Println("query_task_ids set to ", query_task_ids)
  },
}


var queryTaskCmd = &cobra.Command{
  Use:   "queryTask",
  Short: "Get Async Query Info",
  Long: `### Get Query Task details

Use this function to check the status of an async query task. After the status
reaches "Complete", you can call [query_task_results(query_task_id)](#!/Query/query_task_results) to
retrieve the results of the query.

Use [create_query_task()](#!/Query/create_query_task) to create an async query task.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("queryTask called")
    
    query_task_id, _ := cmd.Flags().GetString("query_task_id")
    fmt.Println("query_task_id set to ", query_task_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var queryTaskResultsCmd = &cobra.Command{
  Use:   "queryTaskResults",
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
If the query fails due to a SQL db error, how this is communicated depends on the result_format you requested in 'create_query_task()'.

For 'json_detail' result_format: 'query_task_results()' will respond with HTTP status '200 OK' and db SQL error info
will be in the 'errors' property of the response object. The 'data' property will be empty.

For all other result formats: 'query_task_results()' will respond with HTTP status '400 Bad Request' and some db SQL error info
will be in the message of the 400 error response, but not as detailed as expressed in 'json_detail.errors'.
These data formats can only carry row data, and error info is not row data.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("queryTaskResults called")
    
    query_task_id, _ := cmd.Flags().GetString("query_task_id")
    fmt.Println("query_task_id set to ", query_task_id)
  },
}


var queryCmd3749 = &cobra.Command{
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
    
    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to ", query_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var queryForSlugCmd = &cobra.Command{
  Use:   "queryForSlug",
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
    fmt.Println("queryForSlug called")
    
    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to ", slug)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createQueryCmd = &cobra.Command{
  Use:   "createQuery",
  Short: "Create Query",
  Long: `### Create a query.

This allows you to create a new query that you can later run. Looker queries are immutable once created
and are not deleted. If you create a query that is exactly like an existing query then the existing query
will be returned and no new query will be created. Whether a new query is created or not, you can use
the 'id' in the returned query with the 'run' method.

The query parameters are passed as json in the body of the request.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createQuery called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var runQueryCmd = &cobra.Command{
  Use:   "runQuery",
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
    fmt.Println("runQuery called")
    
    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to ", query_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to ", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to ", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to ", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to ", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to ", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to ", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to ", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to ", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to ", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to ", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to ", server_table_calcs)
  },
}


var runInlineQueryCmd = &cobra.Command{
  Use:   "runInlineQuery",
  Short: "Run Inline Query",
  Long: `### Run the query that is specified inline in the posted body.

This allows running a query as defined in json in the posted body. This combines
the two actions of posting & running a query into one step.

Here is an example body in json:
'''
{
  "model":"thelook",
  "view":"inventory_items",
  "fields":["category.name","inventory_items.days_in_inventory_tier","products.count"],
  "filters":{"category.name":"socks"},
  "sorts":["products.count desc 0"],
  "limit":"500",
  "query_timezone":"America/Los_Angeles"
}
'''

When using the Ruby SDK this would be passed as a Ruby hash like:
'''
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
'''

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
    fmt.Println("runInlineQuery called")
    
    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to ", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to ", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to ", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to ", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to ", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to ", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to ", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to ", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to ", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to ", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to ", server_table_calcs)
  },
}


var runUrlEncodedQueryCmd = &cobra.Command{
  Use:   "runUrlEncodedQuery",
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

'''
https://looker.mycompany.com:19999/api/3.0/queries/models/thelook/views/inventory_items/run/json?fields=category.name,inventory_items.days_in_inventory_tier,products.count&f[category.name]=socks&sorts=products.count+desc+0&limit=500&query_timezone=America/Los_Angeles
'''

When invoking this endpoint with the Ruby SDK, pass the query parameter parts as a hash. The hash to match the above would look like:

'''ruby
query_params =
{
  :fields => "category.name,inventory_items.days_in_inventory_tier,products.count",
  :"f[category.name]" => "socks",
  :sorts => "products.count desc 0",
  :limit => "500",
  :query_timezone => "America/Los_Angeles"
}
response = ruby_sdk.run_url_encoded_query('thelook','inventory_items','json', query_params)

'''

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
    fmt.Println("runUrlEncodedQuery called")
    
    model_name, _ := cmd.Flags().GetString("model_name")
    fmt.Println("model_name set to ", model_name)

    view_name, _ := cmd.Flags().GetString("view_name")
    fmt.Println("view_name set to ", view_name)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)
  },
}


var mergeQueryCmd = &cobra.Command{
  Use:   "mergeQuery",
  Short: "Get Merge Query",
  Long: `### Get Merge Query

Returns a merge query object given its id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("mergeQuery called")
    
    merge_query_id, _ := cmd.Flags().GetString("merge_query_id")
    fmt.Println("merge_query_id set to ", merge_query_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createMergeQueryCmd = &cobra.Command{
  Use:   "createMergeQuery",
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
    fmt.Println("createMergeQuery called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var allRunningQueriesCmd = &cobra.Command{
  Use:   "allRunningQueries",
  Short: "Get All Running Queries",
  Long: `Get information about all running queries.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allRunningQueries called")
    
  },
}


var killQueryCmd = &cobra.Command{
  Use:   "killQuery",
  Short: "Kill Running Query",
  Long: `Kill a query with a specific query_task_id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("killQuery called")
    
    query_task_id, _ := cmd.Flags().GetString("query_task_id")
    fmt.Println("query_task_id set to ", query_task_id)
  },
}


var sqlQueryCmd = &cobra.Command{
  Use:   "sqlQuery",
  Short: "Get SQL Runner Query",
  Long: `Get a SQL Runner query.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sqlQuery called")
    
    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to ", slug)
  },
}


var createSqlQueryCmd = &cobra.Command{
  Use:   "createSqlQuery",
  Short: "Create SQL Runner Query",
  Long: `### Create a SQL Runner Query

Either the 'connection_name' or 'model_name' parameter MUST be provided.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSqlQuery called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var runSqlQueryCmd = &cobra.Command{
  Use:   "runSqlQuery",
  Short: "Run SQL Runner Query",
  Long: `Execute a SQL Runner query in a given result_format.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("runSqlQuery called")
    
    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to ", slug)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    download, _ := cmd.Flags().GetString("download")
    fmt.Println("download set to ", download)
  },
}




var renderTaskCmd = &cobra.Command{
  Use:   "RenderTask",
  Short: "Manage Render Tasks",
  Long: "Manage Render Tasks",
}


var createLookmlDashboardRenderTaskCmd = &cobra.Command{
  Use:   "createLookmlDashboardRenderTask",
  Short: "Create Lookml Dashboard Render Task",
  Long: `### Create a new task to render a lookml dashboard to a document or image.

# DEPRECATED:  Use [create_dashboard_render_task()](#!/RenderTask/create_dashboard_render_task) in API 4.0+

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createLookmlDashboardRenderTask called")
    
    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to ", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to ", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    pdf_paper_size, _ := cmd.Flags().GetString("pdf_paper_size")
    fmt.Println("pdf_paper_size set to ", pdf_paper_size)

    pdf_landscape, _ := cmd.Flags().GetBool("pdf_landscape")
    fmt.Println("pdf_landscape set to ", pdf_landscape)
  },
}


var createLookRenderTaskCmd = &cobra.Command{
  Use:   "createLookRenderTask",
  Short: "Create Look Render Task",
  Long: `### Create a new task to render a look to an image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createLookRenderTask called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to ", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to ", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createQueryRenderTaskCmd = &cobra.Command{
  Use:   "createQueryRenderTask",
  Short: "Create Query Render Task",
  Long: `### Create a new task to render an existing query to an image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createQueryRenderTask called")
    
    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to ", query_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to ", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to ", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createDashboardRenderTaskCmd = &cobra.Command{
  Use:   "createDashboardRenderTask",
  Short: "Create Dashboard Render Task",
  Long: `### Create a new task to render a dashboard to a document or image.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardRenderTask called")
    
    dashboard_id, _ := cmd.Flags().GetInt64("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to ", result_format)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to ", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to ", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    pdf_paper_size, _ := cmd.Flags().GetString("pdf_paper_size")
    fmt.Println("pdf_paper_size set to ", pdf_paper_size)

    pdf_landscape, _ := cmd.Flags().GetBool("pdf_landscape")
    fmt.Println("pdf_landscape set to ", pdf_landscape)
  },
}


var renderTaskCmd4463 = &cobra.Command{
  Use:   "renderTask",
  Short: "Get Render Task",
  Long: `### Get information about a render task.

Returns a render task object.
To check the status of a render task, pass the render_task.id to [Get Render Task](#!/RenderTask/get_render_task).
Once the render task is complete, you can download the resulting document or image using [Get Render Task Results](#!/RenderTask/get_render_task_results).

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("renderTask called")
    
    render_task_id, _ := cmd.Flags().GetString("render_task_id")
    fmt.Println("render_task_id set to ", render_task_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var renderTaskResultsCmd = &cobra.Command{
  Use:   "renderTaskResults",
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
    fmt.Println("renderTaskResults called")
    
    render_task_id, _ := cmd.Flags().GetString("render_task_id")
    fmt.Println("render_task_id set to ", render_task_id)
  },
}




var roleCmd = &cobra.Command{
  Use:   "Role",
  Short: "Manage Roles",
  Long: "Manage Roles",
}


var searchModelSetsCmd = &cobra.Command{
  Use:   "searchModelSets",
  Short: "Search Model Sets",
  Long: `### Search model sets
Returns all model set records that match the given search criteria.
If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchModelSets called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    all_access, _ := cmd.Flags().GetBool("all_access")
    fmt.Println("all_access set to ", all_access)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to ", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var modelSetCmd = &cobra.Command{
  Use:   "modelSet",
  Short: "Get Model Set",
  Long: `### Get information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("modelSet called")
    
    model_set_id, _ := cmd.Flags().GetInt64("model_set_id")
    fmt.Println("model_set_id set to ", model_set_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateModelSetCmd = &cobra.Command{
  Use:   "updateModelSet",
  Short: "Update Model Set",
  Long: `### Update information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateModelSet called")
    
    model_set_id, _ := cmd.Flags().GetInt64("model_set_id")
    fmt.Println("model_set_id set to ", model_set_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteModelSetCmd = &cobra.Command{
  Use:   "deleteModelSet",
  Short: "Delete Model Set",
  Long: `### Delete the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteModelSet called")
    
    model_set_id, _ := cmd.Flags().GetInt64("model_set_id")
    fmt.Println("model_set_id set to ", model_set_id)
  },
}


var allModelSetsCmd = &cobra.Command{
  Use:   "allModelSets",
  Short: "Get All Model Sets",
  Long: `### Get information about all model sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allModelSets called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createModelSetCmd = &cobra.Command{
  Use:   "createModelSet",
  Short: "Create Model Set",
  Long: `### Create a model set with the specified information. Model sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createModelSet called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allPermissionsCmd = &cobra.Command{
  Use:   "allPermissions",
  Short: "Get All Permissions",
  Long: `### Get all supported permissions.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allPermissions called")
    
  },
}


var searchPermissionSetsCmd = &cobra.Command{
  Use:   "searchPermissionSets",
  Short: "Search Permission Sets",
  Long: `### Search permission sets
Returns all permission set records that match the given search criteria.
If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchPermissionSets called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    all_access, _ := cmd.Flags().GetBool("all_access")
    fmt.Println("all_access set to ", all_access)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to ", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var permissionSetCmd = &cobra.Command{
  Use:   "permissionSet",
  Short: "Get Permission Set",
  Long: `### Get information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("permissionSet called")
    
    permission_set_id, _ := cmd.Flags().GetInt64("permission_set_id")
    fmt.Println("permission_set_id set to ", permission_set_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updatePermissionSetCmd = &cobra.Command{
  Use:   "updatePermissionSet",
  Short: "Update Permission Set",
  Long: `### Update information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updatePermissionSet called")
    
    permission_set_id, _ := cmd.Flags().GetInt64("permission_set_id")
    fmt.Println("permission_set_id set to ", permission_set_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deletePermissionSetCmd = &cobra.Command{
  Use:   "deletePermissionSet",
  Short: "Delete Permission Set",
  Long: `### Delete the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deletePermissionSet called")
    
    permission_set_id, _ := cmd.Flags().GetInt64("permission_set_id")
    fmt.Println("permission_set_id set to ", permission_set_id)
  },
}


var allPermissionSetsCmd = &cobra.Command{
  Use:   "allPermissionSets",
  Short: "Get All Permission Sets",
  Long: `### Get information about all permission sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allPermissionSets called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createPermissionSetCmd = &cobra.Command{
  Use:   "createPermissionSet",
  Short: "Create Permission Set",
  Long: `### Create a permission set with the specified information. Permission sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createPermissionSet called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var allRolesCmd = &cobra.Command{
  Use:   "allRoles",
  Short: "Get All Roles",
  Long: `### Get information about all roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allRoles called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to ", ids)
  },
}


var createRoleCmd = &cobra.Command{
  Use:   "createRole",
  Short: "Create Role",
  Long: `### Create a role with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createRole called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var searchRolesCmd = &cobra.Command{
  Use:   "searchRoles",
  Short: "Search Roles",
  Long: `### Search roles

Returns all role records that match the given search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchRoles called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to ", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var roleCmd4795 = &cobra.Command{
  Use:   "role",
  Short: "Get Role",
  Long: `### Get information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)
  },
}


var updateRoleCmd = &cobra.Command{
  Use:   "updateRole",
  Short: "Update Role",
  Long: `### Update information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateRole called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteRoleCmd = &cobra.Command{
  Use:   "deleteRole",
  Short: "Delete Role",
  Long: `### Delete the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteRole called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)
  },
}


var roleGroupsCmd = &cobra.Command{
  Use:   "roleGroups",
  Short: "Get Role Groups",
  Long: `### Get information about all the groups with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("roleGroups called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var setRoleGroupsCmd = &cobra.Command{
  Use:   "setRoleGroups",
  Short: "Update Role Groups",
  Long: `### Set all groups for a role, removing all existing group associations from that role.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setRoleGroups called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var roleUsersCmd = &cobra.Command{
  Use:   "roleUsers",
  Short: "Get Role Users",
  Long: `### Get information about all the users with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("roleUsers called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    direct_association_only, _ := cmd.Flags().GetBool("direct_association_only")
    fmt.Println("direct_association_only set to ", direct_association_only)
  },
}


var setRoleUsersCmd = &cobra.Command{
  Use:   "setRoleUsers",
  Short: "Update Role Users",
  Long: `### Set all the users of the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setRoleUsers called")
    
    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to ", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var scheduledPlanCmd = &cobra.Command{
  Use:   "ScheduledPlan",
  Short: "Manage Scheduled Plans",
  Long: "Manage Scheduled Plans",
}


var scheduledPlansForSpaceCmd = &cobra.Command{
  Use:   "scheduledPlansForSpace",
  Short: "Scheduled Plans for Space",
  Long: `### Get Scheduled Plans for a Space

Returns scheduled plans owned by the caller for a given space id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlansForSpace called")
    
    space_id, _ := cmd.Flags().GetInt64("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var scheduledPlanCmd6475 = &cobra.Command{
  Use:   "scheduledPlan",
  Short: "Get Scheduled Plan",
  Long: `### Get Information About a Scheduled Plan

Admins can fetch information about other users' Scheduled Plans.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlan called")
    
    scheduled_plan_id, _ := cmd.Flags().GetInt64("scheduled_plan_id")
    fmt.Println("scheduled_plan_id set to ", scheduled_plan_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateScheduledPlanCmd = &cobra.Command{
  Use:   "updateScheduledPlan",
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
| json | A JSON object containing a 'data' property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the 'data' property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. 'wysiwyg_pdf' is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateScheduledPlan called")
    
    scheduled_plan_id, _ := cmd.Flags().GetInt64("scheduled_plan_id")
    fmt.Println("scheduled_plan_id set to ", scheduled_plan_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteScheduledPlanCmd = &cobra.Command{
  Use:   "deleteScheduledPlan",
  Short: "Delete Scheduled Plan",
  Long: `### Delete a Scheduled Plan

Normal users can only delete their own scheduled plans.
Admins can delete other users' scheduled plans.
This delete cannot be undone.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteScheduledPlan called")
    
    scheduled_plan_id, _ := cmd.Flags().GetInt64("scheduled_plan_id")
    fmt.Println("scheduled_plan_id set to ", scheduled_plan_id)
  },
}


var allScheduledPlansCmd = &cobra.Command{
  Use:   "allScheduledPlans",
  Short: "Get All Scheduled Plans",
  Long: `### List All Scheduled Plans

Returns all scheduled plans which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass 'all_users=true'.


The caller must have 'see_schedules' permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allScheduledPlans called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to ", all_users)
  },
}


var createScheduledPlanCmd = &cobra.Command{
  Use:   "createScheduledPlan",
  Short: "Create Scheduled Plan",
  Long: `### Create a Scheduled Plan

Create a scheduled plan to render a Look or Dashboard on a recurring schedule.

To create a scheduled plan, you MUST provide values for the following fields:
'name'
and
'look_id', 'dashboard_id', 'lookml_dashboard_id', or 'query_id'
and
'cron_tab' or 'datagroup'
and
at least one scheduled_plan_destination

A scheduled plan MUST have at least one scheduled_plan_destination defined.

When 'look_id' is set, 'require_no_results', 'require_results', and 'require_change' are all required.

If 'create_scheduled_plan' fails with a 422 error, be sure to look at the error messages in the response which will explain exactly what fields are missing or values that are incompatible.

The queries that provide the data for the look or dashboard are run in the context of user account that owns the scheduled plan.

When 'run_as_recipient' is 'false' or not specified, the queries that provide the data for the
look or dashboard are run in the context of user account that owns the scheduled plan.

When 'run_as_recipient' is 'true' and all the email recipients are Looker user accounts, the
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
| json | A JSON object containing a 'data' property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the 'data' property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. 'wysiwyg_pdf' is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createScheduledPlan called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var scheduledPlanRunOnceCmd = &cobra.Command{
  Use:   "scheduledPlanRunOnce",
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
| json | A JSON object containing a 'data' property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the 'data' property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. 'wysiwyg_pdf' is only valid for dashboards, for example.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlanRunOnce called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var scheduledPlansForLookCmd = &cobra.Command{
  Use:   "scheduledPlansForLook",
  Short: "Scheduled Plans for Look",
  Long: `### Get Scheduled Plans for a Look

Returns all scheduled plans for a look which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass 'all_users=true'.


The caller must have 'see_schedules' permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlansForLook called")
    
    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to ", look_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to ", all_users)
  },
}


var scheduledPlansForDashboardCmd = &cobra.Command{
  Use:   "scheduledPlansForDashboard",
  Short: "Scheduled Plans for Dashboard",
  Long: `### Get Scheduled Plans for a Dashboard

Returns all scheduled plans for a dashboard which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass 'all_users=true'.


The caller must have 'see_schedules' permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlansForDashboard called")
    
    dashboard_id, _ := cmd.Flags().GetInt64("dashboard_id")
    fmt.Println("dashboard_id set to ", dashboard_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to ", all_users)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var scheduledPlansForLookmlDashboardCmd = &cobra.Command{
  Use:   "scheduledPlansForLookmlDashboard",
  Short: "Scheduled Plans for LookML Dashboard",
  Long: `### Get Scheduled Plans for a LookML Dashboard

Returns all scheduled plans for a LookML Dashboard which belong to the caller or given user.

If no user_id is provided, this function returns the scheduled plans owned by the caller.


To list all schedules for all users, pass 'all_users=true'.


The caller must have 'see_schedules' permission to see other users' scheduled plans.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlansForLookmlDashboard called")
    
    lookml_dashboard_id, _ := cmd.Flags().GetString("lookml_dashboard_id")
    fmt.Println("lookml_dashboard_id set to ", lookml_dashboard_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to ", all_users)
  },
}


var scheduledPlanRunOnceByIdCmd = &cobra.Command{
  Use:   "scheduledPlanRunOnceById",
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
| json | A JSON object containing a 'data' property which contains an array of JSON objects, one per row. No metadata.
| json_detail | Row data plus metadata describing the fields, pivots, table calcs, and other aspects of the query
| inline_json | Same as the JSON format, except that the 'data' property is a string containing JSON-escaped row data. Additional properties describe the data operation. This format is primarily used to send data to web hooks so that the web hook doesn't have to re-encode the JSON row data in order to pass it on to its ultimate destination.
| csv | Comma separated values with a header
| txt | Tab separated values with a header
| html | Simple html
| xlsx | MS Excel spreadsheet
| wysiwyg_pdf | Dashboard rendered in a tiled layout to produce a PDF document
| assembled_pdf | Dashboard rendered in a single column layout to produce a PDF document
| wysiwyg_png | Dashboard rendered in a tiled layout to produce a PNG image
||

Valid formats vary by destination type and source object. 'wysiwyg_pdf' is only valid for dashboards, for example.



This API is rate limited to prevent it from being used for relay spam or DoS attacks

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlanRunOnceById called")
    
    scheduled_plan_id, _ := cmd.Flags().GetInt64("scheduled_plan_id")
    fmt.Println("scheduled_plan_id set to ", scheduled_plan_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var sessionCmd = &cobra.Command{
  Use:   "Session",
  Short: "Session Information",
  Long: "Session Information",
}


var sessionCmd9658 = &cobra.Command{
  Use:   "session",
  Short: "Get Session",
  Long: `### Get API Session

Returns information about the current API session, such as which workspace is selected for the session.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("session called")
    
  },
}


var updateSessionCmd = &cobra.Command{
  Use:   "updateSession",
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
    fmt.Println("updateSession called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var spaceCmd = &cobra.Command{
  Use:   "Space",
  Short: "Manage Spaces",
  Long: "Manage Spaces",
}


var searchSpacesCmd = &cobra.Command{
  Use:   "searchSpaces",
  Short: "Search Spaces",
  Long: `### Search Spaces

  Returns an **array of space objects** that match the given search criteria.

  If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
example="dan%" will match "danger" and "Danzig" but not "David"
example="D_m%" will match "Damage" and "dump"

Integer search params can accept a single value or a comma separated list of values. The multiple
values will be combined under a logical OR operation - results will match at least one of
the given values.

Most search params can accept "IS NULL" and "NOT NULL" as special expressions to match
or exclude (respectively) rows where the column is null.

Boolean search params accept only "true" and "false" as values.


  The parameters 'limit', and 'offset' are recommended for fetching results in page-size chunks.

  Get a **single space** by id with [Space](#!/Space/space)
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchSpaces called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    parent_id, _ := cmd.Flags().GetString("parent_id")
    fmt.Println("parent_id set to ", parent_id)

    creator_id, _ := cmd.Flags().GetString("creator_id")
    fmt.Println("creator_id set to ", creator_id)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)

    is_shared_root, _ := cmd.Flags().GetBool("is_shared_root")
    fmt.Println("is_shared_root set to ", is_shared_root)
  },
}


var spaceCmd7986 = &cobra.Command{
  Use:   "space",
  Short: "Get Space",
  Long: `### Get information about the space with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("space called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateSpaceCmd = &cobra.Command{
  Use:   "updateSpace",
  Short: "Update Space",
  Long: `### Update the space with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateSpace called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteSpaceCmd = &cobra.Command{
  Use:   "deleteSpace",
  Short: "Delete Space",
  Long: `### Delete the space with a specific id including any children spaces.
**DANGER** this will delete all looks and dashboards in the space.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteSpace called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)
  },
}


var allSpacesCmd = &cobra.Command{
  Use:   "allSpaces",
  Short: "Get All Spaces",
  Long: `### Get information about all spaces.

In API 3.x, this will not return empty personal spaces, unless they belong to the calling user.
In API 4.0+, all personal spaces will be returned.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allSpaces called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createSpaceCmd = &cobra.Command{
  Use:   "createSpace",
  Short: "Create Space",
  Long: `### Create a space with specified information.

Caller must have permission to edit the parent space and to create spaces, otherwise the request
returns 404 Not Found.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSpace called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var spaceChildrenCmd = &cobra.Command{
  Use:   "spaceChildren",
  Short: "Get Space Children",
  Long: `### Get the children of a space.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceChildren called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var spaceChildrenSearchCmd = &cobra.Command{
  Use:   "spaceChildrenSearch",
  Short: "Search Space Children",
  Long: `### Search the children of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceChildrenSearch called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)
  },
}


var spaceParentCmd = &cobra.Command{
  Use:   "spaceParent",
  Short: "Get Space Parent",
  Long: `### Get the parent of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceParent called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var spaceAncestorsCmd = &cobra.Command{
  Use:   "spaceAncestors",
  Short: "Get Space Ancestors",
  Long: `### Get the ancestors of a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceAncestors called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var spaceLooksCmd = &cobra.Command{
  Use:   "spaceLooks",
  Short: "Get Space Looks",
  Long: `### Get all looks in a space.
In API 3.x, this will return all looks in a space, including looks in the trash.
In API 4.0+, all looks in a space will be returned, excluding looks in the trash.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceLooks called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var spaceDashboardsCmd = &cobra.Command{
  Use:   "spaceDashboards",
  Short: "Get Space Dashboards",
  Long: `### Get the dashboards in a space`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("spaceDashboards called")
    
    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to ", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}




var themeCmd = &cobra.Command{
  Use:   "Theme",
  Short: "Manage Themes",
  Long: "Manage Themes",
}


var allThemesCmd = &cobra.Command{
  Use:   "allThemes",
  Short: "Get All Themes",
  Long: `### Get an array of all existing themes

Get a **single theme** by id with [Theme](#!/Theme/theme)

This method returns an array of all existing themes. The active time for the theme is not considered.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allThemes called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createThemeCmd = &cobra.Command{
  Use:   "createTheme",
  Short: "Create Theme",
  Long: `### Create a theme

Creates a new theme object, returning the theme details, including the created id.

If 'settings' are not specified, the default theme settings will be copied into the new theme.

The theme 'name' can only contain alphanumeric characters or underscores. Theme names should not contain any confidential information, such as customer names.

**Update** an existing theme with [Update Theme](#!/Theme/update_theme)

**Permanently delete** an existing theme with [Delete Theme](#!/Theme/delete_theme)

For more information, see [Creating and Applying Themes](https://looker.com/docs/r/admin/themes).

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createTheme called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var searchThemesCmd = &cobra.Command{
  Use:   "searchThemes",
  Short: "Search Themes",
  Long: `### Search all themes for matching criteria.

Returns an **array of theme objects** that match the specified search criteria.

| Search Parameters | Description
| :-------------------: | :------ |
| 'begin_at' only | Find themes active at or after 'begin_at'
| 'end_at' only | Find themes active at or before 'end_at'
| both set | Find themes with an active inclusive period between 'begin_at' and 'end_at'

Note: Range matching requires boolean AND logic.
When using 'begin_at' and 'end_at' together, do not use 'filter_or'=TRUE

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchThemes called")
    
    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    begin_at, _ := cmd.Flags().GetString("begin_at")
    fmt.Println("begin_at set to ", begin_at)

    end_at, _ := cmd.Flags().GetString("end_at")
    fmt.Println("end_at set to ", end_at)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to ", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to ", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)
  },
}


var defaultThemeCmd = &cobra.Command{
  Use:   "defaultTheme",
  Short: "Get Default Theme",
  Long: `### Get the default theme

Returns the active theme object set as the default.

The **default** theme name can be set in the UI on the Admin|Theme UI page

The optional 'ts' parameter can specify a different timestamp than "now." If specified, it returns the default theme at the time indicated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("defaultTheme called")
    
    ts, _ := cmd.Flags().GetString("ts")
    fmt.Println("ts set to ", ts)
  },
}


var setDefaultThemeCmd = &cobra.Command{
  Use:   "setDefaultTheme",
  Short: "Set Default Theme",
  Long: `### Set the global default theme by theme name

Only Admin users can call this function.

Only an active theme with no expiration ('end_at' not set) can be assigned as the default theme. As long as a theme has an active record with no expiration, it can be set as the default.

[Create Theme](#!/Theme/create) has detailed information on rules for default and active themes

Returns the new specified default theme object.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setDefaultTheme called")
    
    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)
  },
}


var activeThemesCmd = &cobra.Command{
  Use:   "activeThemes",
  Short: "Get Active Themes",
  Long: `### Get active themes

Returns an array of active themes.

If the 'name' parameter is specified, it will return an array with one theme if it's active and found.

The optional 'ts' parameter can specify a different timestamp than "now."

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.


`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("activeThemes called")
    
    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    ts, _ := cmd.Flags().GetString("ts")
    fmt.Println("ts set to ", ts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var themeOrDefaultCmd = &cobra.Command{
  Use:   "themeOrDefault",
  Short: "Get Theme or Default",
  Long: `### Get the named theme if it's active. Otherwise, return the default theme

The optional 'ts' parameter can specify a different timestamp than "now."
Note: API users with 'show' ability can call this function

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("themeOrDefault called")
    
    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to ", name)

    ts, _ := cmd.Flags().GetString("ts")
    fmt.Println("ts set to ", ts)
  },
}


var validateThemeCmd = &cobra.Command{
  Use:   "validateTheme",
  Short: "Validate Theme",
  Long: `### Validate a theme with the specified information

Validates all values set for the theme, returning any errors encountered, or 200 OK if valid

See [Create Theme](#!/Theme/create_theme) for constraints

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("validateTheme called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var themeCmd5617 = &cobra.Command{
  Use:   "theme",
  Short: "Get Theme",
  Long: `### Get a theme by ID

Use this to retrieve a specific theme, whether or not it's currently active.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("theme called")
    
    theme_id, _ := cmd.Flags().GetString("theme_id")
    fmt.Println("theme_id set to ", theme_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateThemeCmd = &cobra.Command{
  Use:   "updateTheme",
  Short: "Update Theme",
  Long: `### Update the theme by id.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateTheme called")
    
    theme_id, _ := cmd.Flags().GetString("theme_id")
    fmt.Println("theme_id set to ", theme_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteThemeCmd = &cobra.Command{
  Use:   "deleteTheme",
  Short: "Delete Theme",
  Long: `### Delete a specific theme by id

This operation permanently deletes the identified theme from the database.

Because multiple themes can have the same name (with different activation time spans) themes can only be deleted by ID.

All IDs associated with a theme name can be retrieved by searching for the theme name with [Theme Search](#!/Theme/search).

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteTheme called")
    
    theme_id, _ := cmd.Flags().GetString("theme_id")
    fmt.Println("theme_id set to ", theme_id)
  },
}




var userCmd = &cobra.Command{
  Use:   "User",
  Short: "Manage Users",
  Long: "Manage Users",
}


var meCmd = &cobra.Command{
  Use:   "me",
  Short: "Get Current User",
  Long: `### Get information about the current user; i.e. the user account currently calling the API.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("me called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var allUsersCmd = &cobra.Command{
  Use:   "allUsers",
  Short: "Get All Users",
  Long: `### Get information about all users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUsers called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to ", ids)
  },
}


var createUserCmd = &cobra.Command{
  Use:   "createUser",
  Short: "Create User",
  Long: `### Create a user with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUser called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var searchUsersCmd = &cobra.Command{
  Use:   "searchUsers",
  Short: "Search Users",
  Long: `### Search users

Returns all<sup>*</sup> user records that match the given search criteria.

If multiple search params are given and 'filter_or' is FALSE or not specified,
search params are combined in a logical AND operation.
Only rows that match *all* search param criteria will be returned.

If 'filter_or' is TRUE, multiple search params are combined in a logical OR operation.
Results will include rows that match **any** of the search criteria.

String search params use case-insensitive matching.
String search params can contain '%' and '_' as SQL LIKE pattern match wildcard expressions.
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
    fmt.Println("searchUsers called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to ", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to ", last_name)

    verified_looker_employee, _ := cmd.Flags().GetBool("verified_looker_employee")
    fmt.Println("verified_looker_employee set to ", verified_looker_employee)

    embed_user, _ := cmd.Flags().GetBool("embed_user")
    fmt.Println("embed_user set to ", embed_user)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to ", email)

    is_disabled, _ := cmd.Flags().GetBool("is_disabled")
    fmt.Println("is_disabled set to ", is_disabled)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to ", filter_or)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to ", content_metadata_id)

    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to ", group_id)
  },
}


var searchUsersNamesCmd = &cobra.Command{
  Use:   "searchUsersNames",
  Short: "Search User Names",
  Long: `### Search for user accounts by name

Returns all user accounts where 'first_name' OR 'last_name' OR 'email' field values match a pattern.
The pattern can contain '%' and '_' wildcards as in SQL LIKE expressions.

Any additional search params will be combined into a logical AND expression.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchUsersNames called")
    
    pattern, _ := cmd.Flags().GetString("pattern")
    fmt.Println("pattern set to ", pattern)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to ", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to ", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to ", id)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to ", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to ", last_name)

    verified_looker_employee, _ := cmd.Flags().GetBool("verified_looker_employee")
    fmt.Println("verified_looker_employee set to ", verified_looker_employee)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to ", email)

    is_disabled, _ := cmd.Flags().GetBool("is_disabled")
    fmt.Println("is_disabled set to ", is_disabled)
  },
}


var userCmd4130 = &cobra.Command{
  Use:   "user",
  Short: "Get User by Id",
  Long: `### Get information about the user with a specific id.

If the caller is an admin or the caller is the user being specified, then full user information will
be returned. Otherwise, a minimal 'public' variant of the user information will be returned. This contains
The user name and avatar url, but no sensitive information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateUserCmd = &cobra.Command{
  Use:   "updateUser",
  Short: "Update User",
  Long: `### Update information about the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateUser called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCmd = &cobra.Command{
  Use:   "deleteUser",
  Short: "Delete User",
  Long: `### Delete the user with a specific id.

**DANGER** this will delete the user and all looks and other information owned by the user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUser called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userForCredentialCmd = &cobra.Command{
  Use:   "userForCredential",
  Short: "Get User by Credential Id",
  Long: `### Get information about the user with a credential of given type with specific id.

This is used to do things like find users by their embed external_user_id. Or, find the user with
a given api3 client_id, etc. The 'credential_type' matches the 'type' name of the various credential
types. It must be one of the values listed in the table below. The 'credential_id' is your unique Id
for the user and is specific to each type of credential.

An example using the Ruby sdk might look like:

'sdk.user_for_credential('embed', 'customer-4959425')'

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
    fmt.Println("userForCredential called")
    
    credential_type, _ := cmd.Flags().GetString("credential_type")
    fmt.Println("credential_type set to ", credential_type)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to ", credential_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userCredentialsEmailCmd = &cobra.Command{
  Use:   "userCredentialsEmail",
  Short: "Get Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsEmail called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createUserCredentialsEmailCmd = &cobra.Command{
  Use:   "createUserCredentialsEmail",
  Short: "Create Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsEmail called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateUserCredentialsEmailCmd = &cobra.Command{
  Use:   "updateUserCredentialsEmail",
  Short: "Update Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateUserCredentialsEmail called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsEmailCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmail",
  Short: "Delete Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsEmail called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsTotpCmd = &cobra.Command{
  Use:   "userCredentialsTotp",
  Short: "Get Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsTotp called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createUserCredentialsTotpCmd = &cobra.Command{
  Use:   "createUserCredentialsTotp",
  Short: "Create Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsTotp called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsTotpCmd = &cobra.Command{
  Use:   "deleteUserCredentialsTotp",
  Short: "Delete Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsTotp called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsLdapCmd = &cobra.Command{
  Use:   "userCredentialsLdap",
  Short: "Get LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsLdap called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsLdapCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLdap",
  Short: "Delete LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsLdap called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsGoogleCmd = &cobra.Command{
  Use:   "userCredentialsGoogle",
  Short: "Get Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsGoogle called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsGoogleCmd = &cobra.Command{
  Use:   "deleteUserCredentialsGoogle",
  Short: "Delete Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsGoogle called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsSamlCmd = &cobra.Command{
  Use:   "userCredentialsSaml",
  Short: "Get Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsSaml called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsSamlCmd = &cobra.Command{
  Use:   "deleteUserCredentialsSaml",
  Short: "Delete Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsSaml called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsOidcCmd = &cobra.Command{
  Use:   "userCredentialsOidc",
  Short: "Get OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsOidc called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsOidcCmd = &cobra.Command{
  Use:   "deleteUserCredentialsOidc",
  Short: "Delete OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsOidc called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userCredentialsApi3Cmd = &cobra.Command{
  Use:   "userCredentialsApi3",
  Short: "Get API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsApi3 called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    credentials_api3_id, _ := cmd.Flags().GetInt64("credentials_api3_id")
    fmt.Println("credentials_api3_id set to ", credentials_api3_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "deleteUserCredentialsApi3",
  Short: "Delete API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsApi3 called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    credentials_api3_id, _ := cmd.Flags().GetInt64("credentials_api3_id")
    fmt.Println("credentials_api3_id set to ", credentials_api3_id)
  },
}


var allUserCredentialsApi3sCmd = &cobra.Command{
  Use:   "allUserCredentialsApi3s",
  Short: "Get All API 3 Credentials",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserCredentialsApi3s called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "createUserCredentialsApi3",
  Short: "Create API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsApi3 called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userCredentialsEmbedCmd = &cobra.Command{
  Use:   "userCredentialsEmbed",
  Short: "Get Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsEmbed called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    credentials_embed_id, _ := cmd.Flags().GetInt64("credentials_embed_id")
    fmt.Println("credentials_embed_id set to ", credentials_embed_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsEmbedCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmbed",
  Short: "Delete Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsEmbed called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    credentials_embed_id, _ := cmd.Flags().GetInt64("credentials_embed_id")
    fmt.Println("credentials_embed_id set to ", credentials_embed_id)
  },
}


var allUserCredentialsEmbedsCmd = &cobra.Command{
  Use:   "allUserCredentialsEmbeds",
  Short: "Get All Embedding Credentials",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserCredentialsEmbeds called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "userCredentialsLookerOpenid",
  Short: "Get Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsLookerOpenid called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLookerOpenid",
  Short: "Delete Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsLookerOpenid called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)
  },
}


var userSessionCmd = &cobra.Command{
  Use:   "userSession",
  Short: "Get Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userSession called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    session_id, _ := cmd.Flags().GetInt64("session_id")
    fmt.Println("session_id set to ", session_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserSessionCmd = &cobra.Command{
  Use:   "deleteUserSession",
  Short: "Delete Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserSession called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    session_id, _ := cmd.Flags().GetInt64("session_id")
    fmt.Println("session_id set to ", session_id)
  },
}


var allUserSessionsCmd = &cobra.Command{
  Use:   "allUserSessions",
  Short: "Get All Web Login Sessions",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserSessions called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var createUserCredentialsEmailPasswordResetCmd = &cobra.Command{
  Use:   "createUserCredentialsEmailPasswordReset",
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
    fmt.Println("createUserCredentialsEmailPasswordReset called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    expires, _ := cmd.Flags().GetBool("expires")
    fmt.Println("expires set to ", expires)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userRolesCmd = &cobra.Command{
  Use:   "userRoles",
  Short: "Get User Roles",
  Long: `### Get information about roles of a given user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userRoles called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    direct_association_only, _ := cmd.Flags().GetBool("direct_association_only")
    fmt.Println("direct_association_only set to ", direct_association_only)
  },
}


var setUserRolesCmd = &cobra.Command{
  Use:   "setUserRoles",
  Short: "Set User Roles",
  Long: `### Set roles of the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setUserRoles called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userAttributeUserValuesCmd = &cobra.Command{
  Use:   "userAttributeUserValues",
  Short: "Get User Attribute Values",
  Long: `### Get user attribute values for a given user.

Returns the values of specified user attributes (or all user attributes) for a certain user.

A value for each user attribute is searched for in the following locations, in this order:

1. in the user's account information
1. in groups that the user is a member of
1. the default value of the user attribute

If more than one group has a value defined for a user attribute, the group with the lowest rank wins.

The response will only include user attributes for which values were found. Use 'include_unset=true' to include
empty records for user attributes with no value.

The value of all hidden user attributes will be blank.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userAttributeUserValues called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    user_attribute_ids, _ := cmd.Flags().GetString("user_attribute_ids")
    fmt.Println("user_attribute_ids set to ", user_attribute_ids)

    all_values, _ := cmd.Flags().GetBool("all_values")
    fmt.Println("all_values set to ", all_values)

    include_unset, _ := cmd.Flags().GetBool("include_unset")
    fmt.Println("include_unset set to ", include_unset)
  },
}


var setUserAttributeUserValueCmd = &cobra.Command{
  Use:   "setUserAttributeUserValue",
  Short: "Set User Attribute User Value",
  Long: `### Store a custom value for a user attribute in a user's account settings.

Per-user user attribute values take precedence over group or default values.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("setUserAttributeUserValue called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}


var deleteUserAttributeUserValueCmd = &cobra.Command{
  Use:   "deleteUserAttributeUserValue",
  Short: "Delete User Attribute User Value",
  Long: `### Delete a user attribute value from a user's account settings.

After the user attribute value is deleted from the user's account settings, subsequent requests
for the user attribute value for this user will draw from the user's groups or the default
value of the user attribute. See [Get User Attribute Values](#!/User/user_attribute_user_values) for more
information about how user attribute values are resolved.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserAttributeUserValue called")
    
    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to ", user_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)
  },
}




var userAttributeCmd = &cobra.Command{
  Use:   "UserAttribute",
  Short: "Manage User Attributes",
  Long: "Manage User Attributes",
}


var allUserAttributesCmd = &cobra.Command{
  Use:   "allUserAttributes",
  Short: "Get All User Attributes",
  Long: `### Get information about all user attributes.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserAttributes called")
    
    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to ", sorts)
  },
}


var createUserAttributeCmd = &cobra.Command{
  Use:   "createUserAttribute",
  Short: "Create User Attribute",
  Long: `### Create a new user attribute

Permission information for a user attribute is conveyed through the 'can' and 'user_can_edit' fields.
The 'user_can_edit' field indicates whether an attribute is user-editable _anywhere_ in the application.
The 'can' field gives more granular access information, with the 'set_value' child field indicating whether
an attribute's value can be set by [Setting the User Attribute User Value](#!/User/set_user_attribute_user_value).

Note: 'name' and 'label' fields must be unique across all user attributes in the Looker instance.
Attempting to create a new user attribute with a name or label that duplicates an existing
user attribute will fail with a 422 error.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserAttribute called")
    
    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var userAttributeCmd6881 = &cobra.Command{
  Use:   "userAttribute",
  Short: "Get User Attribute",
  Long: `### Get information about a user attribute.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userAttribute called")
    
    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var updateUserAttributeCmd = &cobra.Command{
  Use:   "updateUserAttribute",
  Short: "Update User Attribute",
  Long: `### Update a user attribute definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateUserAttribute called")
    
    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var deleteUserAttributeCmd = &cobra.Command{
  Use:   "deleteUserAttribute",
  Short: "Delete User Attribute",
  Long: `### Delete a user attribute (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserAttribute called")
    
    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)
  },
}


var allUserAttributeGroupValuesCmd = &cobra.Command{
  Use:   "allUserAttributeGroupValues",
  Short: "Get User Attribute Group Values",
  Long: `### Returns all values of a user attribute defined by user groups, in precedence order.

A user may be a member of multiple groups which define different values for a given user attribute.
The order of group-values in the response determines precedence for selecting which group-value applies
to a given user.  For more information, see [Set User Attribute Group Values](#!/UserAttribute/set_user_attribute_group_values).

Results will only include groups that the caller's user account has permission to see.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserAttributeGroupValues called")
    
    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to ", fields)
  },
}


var setUserAttributeGroupValuesCmd = &cobra.Command{
  Use:   "setUserAttributeGroupValues",
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
    fmt.Println("setUserAttributeGroupValues called")
    
    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to ", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to ", body)
  },
}




var workspaceCmd = &cobra.Command{
  Use:   "Workspace",
  Short: "Manage Workspaces",
  Long: "Manage Workspaces",
}


var allWorkspacesCmd = &cobra.Command{
  Use:   "allWorkspaces",
  Short: "Get All Workspaces",
  Long: `### Get All Workspaces

Returns all workspaces available to the calling user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allWorkspaces called")
    
  },
}


var workspaceCmd1119 = &cobra.Command{
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
    
    workspace_id, _ := cmd.Flags().GetString("workspace_id")
    fmt.Println("workspace_id set to ", workspace_id)
  },
}



func init() {


              apiAuthCmd.AddCommand(loginCmd)
            
              loginCmd.Flags().String("client_id", "ci", "", "client_id part of API3 Key.")
              
              

              loginCmd.Flags().String("client_secret", "cs", "", "client_secret part of API3 Key.")
              
              
            

              apiAuthCmd.AddCommand(loginUserCmd)
            
              loginUserCmd.Flags().Int64("user_id", "ui", 0, "Id of user.")
              cobra.MarkFlagRequired(loginUserCmd.Flags(), "user_id")
              

              loginUserCmd.Flags().BoolP("associative", "a", false, "When true (default), API calls using the returned access_token are attributed to the admin user who created the access_token. When false, API activity is attributed to the user the access_token runs as. False requires a looker license.")
              
              
            

              apiAuthCmd.AddCommand(logoutCmd)
            
            
  rootCmd.AddCommand(apiAuthCmd)

              authCmd.AddCommand(createSsoEmbedUrlCmd)
            
              createSsoEmbedUrlCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createSsoEmbedUrlCmd.Flags(), "body")
              
            

              authCmd.AddCommand(ldapConfigCmd)
            
            

              authCmd.AddCommand(updateLdapConfigCmd)
            
              updateLdapConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateLdapConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(testLdapConfigConnectionCmd)
            
              testLdapConfigConnectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(testLdapConfigConnectionCmd.Flags(), "body")
              
            

              authCmd.AddCommand(testLdapConfigAuthCmd)
            
              testLdapConfigAuthCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(testLdapConfigAuthCmd.Flags(), "body")
              
            

              authCmd.AddCommand(testLdapConfigUserInfoCmd)
            
              testLdapConfigUserInfoCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(testLdapConfigUserInfoCmd.Flags(), "body")
              
            

              authCmd.AddCommand(testLdapConfigUserAuthCmd)
            
              testLdapConfigUserAuthCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(testLdapConfigUserAuthCmd.Flags(), "body")
              
            

              authCmd.AddCommand(oidcConfigCmd)
            
            

              authCmd.AddCommand(updateOidcConfigCmd)
            
              updateOidcConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateOidcConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(oidcTestConfigCmd)
            
              oidcTestConfigCmd.Flags().String("test_slug", "ts", "", "Slug of test config")
              cobra.MarkFlagRequired(oidcTestConfigCmd.Flags(), "test_slug")
              
            

              authCmd.AddCommand(deleteOidcTestConfigCmd)
            
              deleteOidcTestConfigCmd.Flags().String("test_slug", "ts", "", "Slug of test config")
              cobra.MarkFlagRequired(deleteOidcTestConfigCmd.Flags(), "test_slug")
              
            

              authCmd.AddCommand(createOidcTestConfigCmd)
            
              createOidcTestConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createOidcTestConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(passwordConfigCmd)
            
            

              authCmd.AddCommand(updatePasswordConfigCmd)
            
              updatePasswordConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updatePasswordConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(forcePasswordResetAtNextLoginForAllUsersCmd)
            
            

              authCmd.AddCommand(samlConfigCmd)
            
            

              authCmd.AddCommand(updateSamlConfigCmd)
            
              updateSamlConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateSamlConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(samlTestConfigCmd)
            
              samlTestConfigCmd.Flags().String("test_slug", "ts", "", "Slug of test config")
              cobra.MarkFlagRequired(samlTestConfigCmd.Flags(), "test_slug")
              
            

              authCmd.AddCommand(deleteSamlTestConfigCmd)
            
              deleteSamlTestConfigCmd.Flags().String("test_slug", "ts", "", "Slug of test config")
              cobra.MarkFlagRequired(deleteSamlTestConfigCmd.Flags(), "test_slug")
              
            

              authCmd.AddCommand(createSamlTestConfigCmd)
            
              createSamlTestConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createSamlTestConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(parseSamlIdpMetadataCmd)
            
              parseSamlIdpMetadataCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(parseSamlIdpMetadataCmd.Flags(), "body")
              
            

              authCmd.AddCommand(fetchAndParseSamlIdpMetadataCmd)
            
              fetchAndParseSamlIdpMetadataCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(fetchAndParseSamlIdpMetadataCmd.Flags(), "body")
              
            

              authCmd.AddCommand(sessionConfigCmd)
            
            

              authCmd.AddCommand(updateSessionConfigCmd)
            
              updateSessionConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateSessionConfigCmd.Flags(), "body")
              
            

              authCmd.AddCommand(allUserLoginLockoutsCmd)
            
              allUserLoginLockoutsCmd.Flags().String("fields", "f", "", "Include only these fields in the response")
              
              
            

              authCmd.AddCommand(searchUserLoginLockoutsCmd)
            
              searchUserLoginLockoutsCmd.Flags().String("fields", "f", "", "Include only these fields in the response")
              
              

              searchUserLoginLockoutsCmd.Flags().Int64("page", "p", 0, "Return only page N of paginated results")
              
              

              searchUserLoginLockoutsCmd.Flags().Int64("per_page", "pp", 0, "Return N rows of data per page")
              
              

              searchUserLoginLockoutsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchUserLoginLockoutsCmd.Flags().String("auth_type", "at", "", "Auth type user is locked out for (email, ldap, totp, api)")
              
              

              searchUserLoginLockoutsCmd.Flags().String("full_name", "fn", "", "Match name")
              
              

              searchUserLoginLockoutsCmd.Flags().String("email", "e", "", "Match email")
              
              

              searchUserLoginLockoutsCmd.Flags().String("remote_id", "ri", "", "Match remote LDAP ID")
              
              

              searchUserLoginLockoutsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              authCmd.AddCommand(deleteUserLoginLockoutCmd)
            
              deleteUserLoginLockoutCmd.Flags().String("key", "k", "", "The key associated with the locked user")
              cobra.MarkFlagRequired(deleteUserLoginLockoutCmd.Flags(), "key")
              
            
  rootCmd.AddCommand(authCmd)

              colorCollectionCmd.AddCommand(allColorCollectionsCmd)
            
              allColorCollectionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              colorCollectionCmd.AddCommand(createColorCollectionCmd)
            
              createColorCollectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createColorCollectionCmd.Flags(), "body")
              
            

              colorCollectionCmd.AddCommand(colorCollectionsCustomCmd)
            
              colorCollectionsCustomCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              colorCollectionCmd.AddCommand(colorCollectionsStandardCmd)
            
              colorCollectionsStandardCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              colorCollectionCmd.AddCommand(defaultColorCollectionCmd)
            
            

              colorCollectionCmd.AddCommand(setDefaultColorCollectionCmd)
            
              setDefaultColorCollectionCmd.Flags().String("collection_id", "ci", "", "ID of color collection to set as default")
              cobra.MarkFlagRequired(setDefaultColorCollectionCmd.Flags(), "collection_id")
              
            

              colorCollectionCmd.AddCommand(colorCollectionCmd9328)
            
              colorCollectionCmd9328.Flags().String("collection_id", "ci", "", "Id of Color Collection")
              cobra.MarkFlagRequired(colorCollectionCmd9328.Flags(), "collection_id")
              

              colorCollectionCmd9328.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              colorCollectionCmd.AddCommand(updateColorCollectionCmd)
            
              updateColorCollectionCmd.Flags().String("collection_id", "ci", "", "Id of Custom Color Collection")
              cobra.MarkFlagRequired(updateColorCollectionCmd.Flags(), "collection_id")
              

              updateColorCollectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateColorCollectionCmd.Flags(), "body")
              
            

              colorCollectionCmd.AddCommand(deleteColorCollectionCmd)
            
              deleteColorCollectionCmd.Flags().String("collection_id", "ci", "", "Id of Color Collection")
              cobra.MarkFlagRequired(deleteColorCollectionCmd.Flags(), "collection_id")
              
            
  rootCmd.AddCommand(colorCollectionCmd)

              configCmd.AddCommand(backupConfigurationCmd)
            
            

              configCmd.AddCommand(updateBackupConfigurationCmd)
            
              updateBackupConfigurationCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateBackupConfigurationCmd.Flags(), "body")
              
            

              configCmd.AddCommand(cloudStorageConfigurationCmd)
            
            

              configCmd.AddCommand(updateCloudStorageConfigurationCmd)
            
              updateCloudStorageConfigurationCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateCloudStorageConfigurationCmd.Flags(), "body")
              
            

              configCmd.AddCommand(customWelcomeEmailCmd)
            
            

              configCmd.AddCommand(updateCustomWelcomeEmailCmd)
            
              updateCustomWelcomeEmailCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateCustomWelcomeEmailCmd.Flags(), "body")
              

              updateCustomWelcomeEmailCmd.Flags().BoolP("send_test_welcome_email", "stwe", false, "If true a test email with the content from the request will be sent to the current user after saving")
              
              
            

              configCmd.AddCommand(updateCustomWelcomeEmailTestCmd)
            
              updateCustomWelcomeEmailTestCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateCustomWelcomeEmailTestCmd.Flags(), "body")
              
            

              configCmd.AddCommand(digestEmailsEnabledCmd)
            
            

              configCmd.AddCommand(updateDigestEmailsEnabledCmd)
            
              updateDigestEmailsEnabledCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDigestEmailsEnabledCmd.Flags(), "body")
              
            

              configCmd.AddCommand(createDigestEmailSendCmd)
            
            

              configCmd.AddCommand(internalHelpResourcesContentCmd)
            
            

              configCmd.AddCommand(updateInternalHelpResourcesContentCmd)
            
              updateInternalHelpResourcesContentCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateInternalHelpResourcesContentCmd.Flags(), "body")
              
            

              configCmd.AddCommand(internalHelpResourcesCmd)
            
            

              configCmd.AddCommand(updateInternalHelpResourcesCmd)
            
              updateInternalHelpResourcesCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateInternalHelpResourcesCmd.Flags(), "body")
              
            

              configCmd.AddCommand(allLegacyFeaturesCmd)
            
            

              configCmd.AddCommand(legacyFeatureCmd)
            
              legacyFeatureCmd.Flags().Int64("legacy_feature_id", "lfi", 0, "id of legacy feature")
              cobra.MarkFlagRequired(legacyFeatureCmd.Flags(), "legacy_feature_id")
              
            

              configCmd.AddCommand(updateLegacyFeatureCmd)
            
              updateLegacyFeatureCmd.Flags().Int64("legacy_feature_id", "lfi", 0, "id of legacy feature")
              cobra.MarkFlagRequired(updateLegacyFeatureCmd.Flags(), "legacy_feature_id")
              

              updateLegacyFeatureCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateLegacyFeatureCmd.Flags(), "body")
              
            

              configCmd.AddCommand(allLocalesCmd)
            
            

              configCmd.AddCommand(allTimezonesCmd)
            
            

              configCmd.AddCommand(versionsCmd)
            
              versionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              configCmd.AddCommand(whitelabelConfigurationCmd)
            
              whitelabelConfigurationCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              configCmd.AddCommand(updateWhitelabelConfigurationCmd)
            
              updateWhitelabelConfigurationCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateWhitelabelConfigurationCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(configCmd)

              connectionCmd.AddCommand(allConnectionsCmd)
            
              allConnectionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              connectionCmd.AddCommand(createConnectionCmd)
            
              createConnectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createConnectionCmd.Flags(), "body")
              
            

              connectionCmd.AddCommand(connectionCmd8489)
            
              connectionCmd8489.Flags().String("connection_name", "cn", "", "Name of connection")
              cobra.MarkFlagRequired(connectionCmd8489.Flags(), "connection_name")
              

              connectionCmd8489.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              connectionCmd.AddCommand(updateConnectionCmd)
            
              updateConnectionCmd.Flags().String("connection_name", "cn", "", "Name of connection")
              cobra.MarkFlagRequired(updateConnectionCmd.Flags(), "connection_name")
              

              updateConnectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateConnectionCmd.Flags(), "body")
              
            

              connectionCmd.AddCommand(deleteConnectionCmd)
            
              deleteConnectionCmd.Flags().String("connection_name", "cn", "", "Name of connection")
              cobra.MarkFlagRequired(deleteConnectionCmd.Flags(), "connection_name")
              
            

              connectionCmd.AddCommand(deleteConnectionOverrideCmd)
            
              deleteConnectionOverrideCmd.Flags().String("connection_name", "cn", "", "Name of connection")
              cobra.MarkFlagRequired(deleteConnectionOverrideCmd.Flags(), "connection_name")
              

              deleteConnectionOverrideCmd.Flags().String("override_context", "oc", "", "Context of connection override")
              cobra.MarkFlagRequired(deleteConnectionOverrideCmd.Flags(), "override_context")
              
            

              connectionCmd.AddCommand(testConnectionCmd)
            
              testConnectionCmd.Flags().String("connection_name", "cn", "", "Name of connection")
              cobra.MarkFlagRequired(testConnectionCmd.Flags(), "connection_name")
              

              testConnectionCmd.Flags().String("tests", "t", "", "Array of names of tests to run")
              
              
            

              connectionCmd.AddCommand(testConnectionConfigCmd)
            
              testConnectionConfigCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(testConnectionConfigCmd.Flags(), "body")
              

              testConnectionConfigCmd.Flags().String("tests", "t", "", "Array of names of tests to run")
              
              
            

              connectionCmd.AddCommand(allDialectInfosCmd)
            
              allDialectInfosCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(connectionCmd)

              contentCmd.AddCommand(searchContentFavoritesCmd)
            
              searchContentFavoritesCmd.Flags().Int64("id", "i", 0, "Match content favorite id(s)")
              
              

              searchContentFavoritesCmd.Flags().Int64("user_id", "ui", 0, "Match user id(s)")
              
              

              searchContentFavoritesCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Match content metadata id(s)")
              
              

              searchContentFavoritesCmd.Flags().Int64("dashboard_id", "di", 0, "Match dashboard id(s)")
              
              

              searchContentFavoritesCmd.Flags().Int64("look_id", "li", 0, "Match look id(s)")
              
              

              searchContentFavoritesCmd.Flags().Int64("limit", "l", 0, "Number of results to return. (used with offset)")
              
              

              searchContentFavoritesCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any. (used with limit)")
              
              

              searchContentFavoritesCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchContentFavoritesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchContentFavoritesCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              contentCmd.AddCommand(contentFavoriteCmd)
            
              contentFavoriteCmd.Flags().Int64("content_favorite_id", "cfi", 0, "Id of favorite content")
              cobra.MarkFlagRequired(contentFavoriteCmd.Flags(), "content_favorite_id")
              

              contentFavoriteCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              contentCmd.AddCommand(deleteContentFavoriteCmd)
            
              deleteContentFavoriteCmd.Flags().Int64("content_favorite_id", "cfi", 0, "Id of favorite content")
              cobra.MarkFlagRequired(deleteContentFavoriteCmd.Flags(), "content_favorite_id")
              
            

              contentCmd.AddCommand(createContentFavoriteCmd)
            
              createContentFavoriteCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createContentFavoriteCmd.Flags(), "body")
              
            

              contentCmd.AddCommand(allContentMetadatasCmd)
            
              allContentMetadatasCmd.Flags().Int64("parent_id", "pi", 0, "Parent space of content.")
              cobra.MarkFlagRequired(allContentMetadatasCmd.Flags(), "parent_id")
              

              allContentMetadatasCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              contentCmd.AddCommand(contentMetadataCmd)
            
              contentMetadataCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Id of content metadata")
              cobra.MarkFlagRequired(contentMetadataCmd.Flags(), "content_metadata_id")
              

              contentMetadataCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              contentCmd.AddCommand(updateContentMetadataCmd)
            
              updateContentMetadataCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Id of content metadata")
              cobra.MarkFlagRequired(updateContentMetadataCmd.Flags(), "content_metadata_id")
              

              updateContentMetadataCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateContentMetadataCmd.Flags(), "body")
              
            

              contentCmd.AddCommand(allContentMetadataAccessesCmd)
            
              allContentMetadataAccessesCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Id of content metadata")
              cobra.MarkFlagRequired(allContentMetadataAccessesCmd.Flags(), "content_metadata_id")
              

              allContentMetadataAccessesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              contentCmd.AddCommand(createContentMetadataAccessCmd)
            
              createContentMetadataAccessCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createContentMetadataAccessCmd.Flags(), "body")
              

              createContentMetadataAccessCmd.Flags().BoolP("send_boards_notification_email", "sbne", false, "Optionally sends notification email when granting access to a board.")
              
              
            

              contentCmd.AddCommand(updateContentMetadataAccessCmd)
            
              updateContentMetadataAccessCmd.Flags().Int64("content_metadata_access_id", "cmai", 0, "Id of content metadata access")
              cobra.MarkFlagRequired(updateContentMetadataAccessCmd.Flags(), "content_metadata_access_id")
              

              updateContentMetadataAccessCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateContentMetadataAccessCmd.Flags(), "body")
              
            

              contentCmd.AddCommand(deleteContentMetadataAccessCmd)
            
              deleteContentMetadataAccessCmd.Flags().Int64("content_metadata_access_id", "cmai", 0, "Id of content metadata access")
              cobra.MarkFlagRequired(deleteContentMetadataAccessCmd.Flags(), "content_metadata_access_id")
              
            

              contentCmd.AddCommand(contentThumbnailCmd)
            
              contentThumbnailCmd.Flags().String("type", "t", "", "Either dashboard or look")
              cobra.MarkFlagRequired(contentThumbnailCmd.Flags(), "type")
              

              contentThumbnailCmd.Flags().String("resource_id", "ri", "", "ID of the dashboard or look to render")
              cobra.MarkFlagRequired(contentThumbnailCmd.Flags(), "resource_id")
              

              contentThumbnailCmd.Flags().String("reload", "r", "", "Whether or not to refresh the rendered image with the latest content")
              
              

              contentThumbnailCmd.Flags().String("format", "f", "", "A value of png produces a thumbnail in PNG format instead of SVG (default)")
              
              

              contentThumbnailCmd.Flags().Int64("width", "w", 0, "The width of the image if format is supplied")
              
              

              contentThumbnailCmd.Flags().Int64("height", "h", 0, "The height of the image if format is supplied")
              
              
            

              contentCmd.AddCommand(contentValidationCmd)
            
              contentValidationCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              contentCmd.AddCommand(searchContentViewsCmd)
            
              searchContentViewsCmd.Flags().Int64("view_count", "vc", 0, "Match view count")
              
              

              searchContentViewsCmd.Flags().Int64("group_id", "gi", 0, "Match Group Id")
              
              

              searchContentViewsCmd.Flags().String("look_id", "li", "", "Match look_id")
              
              

              searchContentViewsCmd.Flags().String("dashboard_id", "di", "", "Match dashboard_id")
              
              

              searchContentViewsCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Match content metadata id")
              
              

              searchContentViewsCmd.Flags().String("start_of_week_date", "sowd", "", "Match start of week date (format is "YYYY-MM-DD")")
              
              

              searchContentViewsCmd.Flags().BoolP("all_time", "at", false, "True if only all time view records should be returned")
              
              

              searchContentViewsCmd.Flags().Int64("user_id", "ui", 0, "Match user id")
              
              

              searchContentViewsCmd.Flags().String("fields", "f", "", "Requested fields")
              
              

              searchContentViewsCmd.Flags().Int64("limit", "l", 0, "Number of results to return. Use with `offset` to manage pagination of results")
              
              

              searchContentViewsCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning data")
              
              

              searchContentViewsCmd.Flags().String("sorts", "s", "", "Fields to sort by")
              
              

              searchContentViewsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              contentCmd.AddCommand(vectorThumbnailCmd)
            
              vectorThumbnailCmd.Flags().String("type", "t", "", "Either dashboard or look")
              cobra.MarkFlagRequired(vectorThumbnailCmd.Flags(), "type")
              

              vectorThumbnailCmd.Flags().String("resource_id", "ri", "", "ID of the dashboard or look to render")
              cobra.MarkFlagRequired(vectorThumbnailCmd.Flags(), "resource_id")
              

              vectorThumbnailCmd.Flags().String("reload", "r", "", "Whether or not to refresh the rendered image with the latest content")
              
              
            
  rootCmd.AddCommand(contentCmd)

              dashboardCmd.AddCommand(allDashboardsCmd)
            
              allDashboardsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(createDashboardCmd)
            
              createDashboardCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createDashboardCmd.Flags(), "body")
              
            

              dashboardCmd.AddCommand(searchDashboardsCmd)
            
              searchDashboardsCmd.Flags().Int64("id", "i", 0, "Match dashboard id.")
              
              

              searchDashboardsCmd.Flags().String("slug", "s", "", "Match dashboard slug.")
              
              

              searchDashboardsCmd.Flags().String("title", "t", "", "Match Dashboard title.")
              
              

              searchDashboardsCmd.Flags().String("description", "d", "", "Match Dashboard description.")
              
              

              searchDashboardsCmd.Flags().Int64("content_favorite_id", "cfi", 0, "Filter on a content favorite id.")
              
              

              searchDashboardsCmd.Flags().String("space_id", "si", "", "Filter on a particular space.")
              
              

              searchDashboardsCmd.Flags().String("folder_id", "fi", "", "Filter on a particular space.")
              
              

              searchDashboardsCmd.Flags().String("deleted", "d", "", "Filter on dashboards deleted status.")
              
              

              searchDashboardsCmd.Flags().String("user_id", "ui", "", "Filter on dashboards created by a particular user.")
              
              

              searchDashboardsCmd.Flags().String("view_count", "vc", "", "Filter on a particular value of view_count")
              
              

              searchDashboardsCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Filter on a content favorite id.")
              
              

              searchDashboardsCmd.Flags().BoolP("curate", "c", false, "Exclude items that exist only in personal spaces other than the users")
              
              

              searchDashboardsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchDashboardsCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              searchDashboardsCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              searchDashboardsCmd.Flags().Int64("limit", "l", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
              
              

              searchDashboardsCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
              
              

              searchDashboardsCmd.Flags().String("sorts", "s", "", "One or more fields to sort by. Sortable fields: [:title, :user_id, :id, :created_at, :space_id, :folder_id, :description, :view_count, :favorite_count, :slug, :content_favorite_id, :content_metadata_id, :deleted, :deleted_at, :last_viewed_at, :last_accessed_at]")
              
              

              searchDashboardsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              dashboardCmd.AddCommand(importLookmlDashboardCmd)
            
              importLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "ldi", "", "Id of LookML dashboard")
              cobra.MarkFlagRequired(importLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
              

              importLookmlDashboardCmd.Flags().String("space_id", "si", "", "Id of space to import the dashboard to")
              cobra.MarkFlagRequired(importLookmlDashboardCmd.Flags(), "space_id")
              

              importLookmlDashboardCmd.Flags().String("body", "b", "", "")
              
              

              importLookmlDashboardCmd.Flags().BoolP("raw_locale", "rl", false, "If true, and this dashboard is localized, export it with the raw keys, not localized.")
              
              
            

              dashboardCmd.AddCommand(syncLookmlDashboardCmd)
            
              syncLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "ldi", "", "Id of LookML dashboard, in the form 'model::dashboardname'")
              cobra.MarkFlagRequired(syncLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
              

              syncLookmlDashboardCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(syncLookmlDashboardCmd.Flags(), "body")
              

              syncLookmlDashboardCmd.Flags().BoolP("raw_locale", "rl", false, "If true, and this dashboard is localized, export it with the raw keys, not localized.")
              
              
            

              dashboardCmd.AddCommand(dashboardCmd8169)
            
              dashboardCmd8169.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardCmd8169.Flags(), "dashboard_id")
              

              dashboardCmd8169.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(updateDashboardCmd)
            
              updateDashboardCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(updateDashboardCmd.Flags(), "dashboard_id")
              

              updateDashboardCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDashboardCmd.Flags(), "body")
              
            

              dashboardCmd.AddCommand(deleteDashboardCmd)
            
              deleteDashboardCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(deleteDashboardCmd.Flags(), "dashboard_id")
              
            

              dashboardCmd.AddCommand(dashboardAggregateTableLookmlCmd)
            
              dashboardAggregateTableLookmlCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardAggregateTableLookmlCmd.Flags(), "dashboard_id")
              
            

              dashboardCmd.AddCommand(dashboardLookmlCmd)
            
              dashboardLookmlCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardLookmlCmd.Flags(), "dashboard_id")
              
            

              dashboardCmd.AddCommand(searchDashboardElementsCmd)
            
              searchDashboardElementsCmd.Flags().Int64("dashboard_id", "di", 0, "Select elements that refer to a given dashboard id")
              
              

              searchDashboardElementsCmd.Flags().Int64("look_id", "li", 0, "Select elements that refer to a given look id")
              
              

              searchDashboardElementsCmd.Flags().String("title", "t", "", "Match the title of element")
              
              

              searchDashboardElementsCmd.Flags().BoolP("deleted", "d", false, "Select soft-deleted dashboard elements")
              
              

              searchDashboardElementsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchDashboardElementsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              

              searchDashboardElementsCmd.Flags().String("sorts", "s", "", "Fields to sort by. Sortable fields: [:look_id, :dashboard_id, :deleted, :title]")
              
              
            

              dashboardCmd.AddCommand(dashboardElementCmd)
            
              dashboardElementCmd.Flags().String("dashboard_element_id", "dei", "", "Id of dashboard element")
              cobra.MarkFlagRequired(dashboardElementCmd.Flags(), "dashboard_element_id")
              

              dashboardElementCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(updateDashboardElementCmd)
            
              updateDashboardElementCmd.Flags().String("dashboard_element_id", "dei", "", "Id of dashboard element")
              cobra.MarkFlagRequired(updateDashboardElementCmd.Flags(), "dashboard_element_id")
              

              updateDashboardElementCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDashboardElementCmd.Flags(), "body")
              

              updateDashboardElementCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(deleteDashboardElementCmd)
            
              deleteDashboardElementCmd.Flags().String("dashboard_element_id", "dei", "", "Id of dashboard element")
              cobra.MarkFlagRequired(deleteDashboardElementCmd.Flags(), "dashboard_element_id")
              
            

              dashboardCmd.AddCommand(dashboardDashboardElementsCmd)
            
              dashboardDashboardElementsCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardDashboardElementsCmd.Flags(), "dashboard_id")
              

              dashboardDashboardElementsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(createDashboardElementCmd)
            
              createDashboardElementCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createDashboardElementCmd.Flags(), "body")
              

              createDashboardElementCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(dashboardFilterCmd)
            
              dashboardFilterCmd.Flags().String("dashboard_filter_id", "dfi", "", "Id of dashboard filters")
              cobra.MarkFlagRequired(dashboardFilterCmd.Flags(), "dashboard_filter_id")
              

              dashboardFilterCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(updateDashboardFilterCmd)
            
              updateDashboardFilterCmd.Flags().String("dashboard_filter_id", "dfi", "", "Id of dashboard filter")
              cobra.MarkFlagRequired(updateDashboardFilterCmd.Flags(), "dashboard_filter_id")
              

              updateDashboardFilterCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDashboardFilterCmd.Flags(), "body")
              

              updateDashboardFilterCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(deleteDashboardFilterCmd)
            
              deleteDashboardFilterCmd.Flags().String("dashboard_filter_id", "dfi", "", "Id of dashboard filter")
              cobra.MarkFlagRequired(deleteDashboardFilterCmd.Flags(), "dashboard_filter_id")
              
            

              dashboardCmd.AddCommand(dashboardDashboardFiltersCmd)
            
              dashboardDashboardFiltersCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardDashboardFiltersCmd.Flags(), "dashboard_id")
              

              dashboardDashboardFiltersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(createDashboardFilterCmd)
            
              createDashboardFilterCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createDashboardFilterCmd.Flags(), "body")
              

              createDashboardFilterCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              dashboardCmd.AddCommand(dashboardLayoutComponentCmd)
            
              dashboardLayoutComponentCmd.Flags().String("dashboard_layout_component_id", "dlci", "", "Id of dashboard layout component")
              cobra.MarkFlagRequired(dashboardLayoutComponentCmd.Flags(), "dashboard_layout_component_id")
              

              dashboardLayoutComponentCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(updateDashboardLayoutComponentCmd)
            
              updateDashboardLayoutComponentCmd.Flags().String("dashboard_layout_component_id", "dlci", "", "Id of dashboard layout component")
              cobra.MarkFlagRequired(updateDashboardLayoutComponentCmd.Flags(), "dashboard_layout_component_id")
              

              updateDashboardLayoutComponentCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDashboardLayoutComponentCmd.Flags(), "body")
              

              updateDashboardLayoutComponentCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(dashboardLayoutDashboardLayoutComponentsCmd)
            
              dashboardLayoutDashboardLayoutComponentsCmd.Flags().String("dashboard_layout_id", "dli", "", "Id of dashboard layout component")
              cobra.MarkFlagRequired(dashboardLayoutDashboardLayoutComponentsCmd.Flags(), "dashboard_layout_id")
              

              dashboardLayoutDashboardLayoutComponentsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(dashboardLayoutCmd)
            
              dashboardLayoutCmd.Flags().String("dashboard_layout_id", "dli", "", "Id of dashboard layouts")
              cobra.MarkFlagRequired(dashboardLayoutCmd.Flags(), "dashboard_layout_id")
              

              dashboardLayoutCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(updateDashboardLayoutCmd)
            
              updateDashboardLayoutCmd.Flags().String("dashboard_layout_id", "dli", "", "Id of dashboard layout")
              cobra.MarkFlagRequired(updateDashboardLayoutCmd.Flags(), "dashboard_layout_id")
              

              updateDashboardLayoutCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDashboardLayoutCmd.Flags(), "body")
              

              updateDashboardLayoutCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(deleteDashboardLayoutCmd)
            
              deleteDashboardLayoutCmd.Flags().String("dashboard_layout_id", "dli", "", "Id of dashboard layout")
              cobra.MarkFlagRequired(deleteDashboardLayoutCmd.Flags(), "dashboard_layout_id")
              
            

              dashboardCmd.AddCommand(dashboardDashboardLayoutsCmd)
            
              dashboardDashboardLayoutsCmd.Flags().String("dashboard_id", "di", "", "Id of dashboard")
              cobra.MarkFlagRequired(dashboardDashboardLayoutsCmd.Flags(), "dashboard_id")
              

              dashboardDashboardLayoutsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              dashboardCmd.AddCommand(createDashboardLayoutCmd)
            
              createDashboardLayoutCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createDashboardLayoutCmd.Flags(), "body")
              

              createDashboardLayoutCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(dashboardCmd)

              dataActionCmd.AddCommand(performDataActionCmd)
            
              performDataActionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(performDataActionCmd.Flags(), "body")
              
            

              dataActionCmd.AddCommand(fetchRemoteDataActionFormCmd)
            
              fetchRemoteDataActionFormCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(fetchRemoteDataActionFormCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(dataActionCmd)

              datagroupCmd.AddCommand(allDatagroupsCmd)
            
            

              datagroupCmd.AddCommand(datagroupCmd9565)
            
              datagroupCmd9565.Flags().String("datagroup_id", "di", "", "ID of datagroup.")
              cobra.MarkFlagRequired(datagroupCmd9565.Flags(), "datagroup_id")
              
            

              datagroupCmd.AddCommand(updateDatagroupCmd)
            
              updateDatagroupCmd.Flags().String("datagroup_id", "di", "", "ID of datagroup.")
              cobra.MarkFlagRequired(updateDatagroupCmd.Flags(), "datagroup_id")
              

              updateDatagroupCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateDatagroupCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(datagroupCmd)

              derivedTableCmd.AddCommand(graphDerivedTablesForModelCmd)
            
              graphDerivedTablesForModelCmd.Flags().String("model", "m", "", "The name of the Lookml model.")
              cobra.MarkFlagRequired(graphDerivedTablesForModelCmd.Flags(), "model")
              

              graphDerivedTablesForModelCmd.Flags().String("format", "f", "", "The format of the graph. Valid values are [dot]. Default is `dot`")
              
              

              graphDerivedTablesForModelCmd.Flags().String("color", "c", "", "Color denoting the build status of the graph. Grey = not built, green = built, yellow = building, red = error.")
              
              
            

              derivedTableCmd.AddCommand(graphDerivedTablesForViewCmd)
            
              graphDerivedTablesForViewCmd.Flags().String("view", "v", "", "The derived table's view name.")
              cobra.MarkFlagRequired(graphDerivedTablesForViewCmd.Flags(), "view")
              

              graphDerivedTablesForViewCmd.Flags().String("models", "m", "", "The models where this derived table is defined.")
              
              

              graphDerivedTablesForViewCmd.Flags().String("workspace", "w", "", "The model directory to look in, either `dev` or `production`.")
              
              
            
  rootCmd.AddCommand(derivedTableCmd)

              folderCmd.AddCommand(searchFoldersCmd)
            
              searchFoldersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchFoldersCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              searchFoldersCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              searchFoldersCmd.Flags().Int64("limit", "l", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
              
              

              searchFoldersCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
              
              

              searchFoldersCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchFoldersCmd.Flags().String("name", "n", "", "Match Space title.")
              
              

              searchFoldersCmd.Flags().Int64("id", "i", 0, "Match Space id")
              
              

              searchFoldersCmd.Flags().String("parent_id", "pi", "", "Filter on a children of a particular folder.")
              
              

              searchFoldersCmd.Flags().String("creator_id", "ci", "", "Filter on folder created by a particular user.")
              
              

              searchFoldersCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              

              searchFoldersCmd.Flags().BoolP("is_shared_root", "isr", false, "Match is shared root")
              
              
            

              folderCmd.AddCommand(folderCmd4419)
            
              folderCmd4419.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderCmd4419.Flags(), "folder_id")
              

              folderCmd4419.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              folderCmd.AddCommand(updateFolderCmd)
            
              updateFolderCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(updateFolderCmd.Flags(), "folder_id")
              

              updateFolderCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateFolderCmd.Flags(), "body")
              
            

              folderCmd.AddCommand(deleteFolderCmd)
            
              deleteFolderCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(deleteFolderCmd.Flags(), "folder_id")
              
            

              folderCmd.AddCommand(allFoldersCmd)
            
              allFoldersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              folderCmd.AddCommand(createFolderCmd)
            
              createFolderCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createFolderCmd.Flags(), "body")
              
            

              folderCmd.AddCommand(folderChildrenCmd)
            
              folderChildrenCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderChildrenCmd.Flags(), "folder_id")
              

              folderChildrenCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              folderChildrenCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              folderChildrenCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              folderChildrenCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              
            

              folderCmd.AddCommand(folderChildrenSearchCmd)
            
              folderChildrenSearchCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderChildrenSearchCmd.Flags(), "folder_id")
              

              folderChildrenSearchCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              folderChildrenSearchCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              folderChildrenSearchCmd.Flags().String("name", "n", "", "Match folder name.")
              
              
            

              folderCmd.AddCommand(folderParentCmd)
            
              folderParentCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderParentCmd.Flags(), "folder_id")
              

              folderParentCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              folderCmd.AddCommand(folderAncestorsCmd)
            
              folderAncestorsCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderAncestorsCmd.Flags(), "folder_id")
              

              folderAncestorsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              folderCmd.AddCommand(folderLooksCmd)
            
              folderLooksCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderLooksCmd.Flags(), "folder_id")
              

              folderLooksCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              folderCmd.AddCommand(folderDashboardsCmd)
            
              folderDashboardsCmd.Flags().String("folder_id", "fi", "", "Id of folder")
              cobra.MarkFlagRequired(folderDashboardsCmd.Flags(), "folder_id")
              

              folderDashboardsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(folderCmd)

              groupCmd.AddCommand(allGroupsCmd)
            
              allGroupsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allGroupsCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              allGroupsCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              allGroupsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              allGroupsCmd.Flags().String("ids", "i", "", "Optional of ids to get specific groups.")
              
              

              allGroupsCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Id of content metadata to which groups must have access.")
              
              

              allGroupsCmd.Flags().BoolP("can_add_to_content_metadata", "catcm", false, "Select only groups that either can/cannot be given access to content.")
              
              
            

              groupCmd.AddCommand(createGroupCmd)
            
              createGroupCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createGroupCmd.Flags(), "body")
              

              createGroupCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              groupCmd.AddCommand(searchGroupsCmd)
            
              searchGroupsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchGroupsCmd.Flags().Int64("limit", "l", 0, "Number of results to return (used with `offset`).")
              
              

              searchGroupsCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any (used with `limit`).")
              
              

              searchGroupsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchGroupsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              

              searchGroupsCmd.Flags().Int64("id", "i", 0, "Match group id.")
              
              

              searchGroupsCmd.Flags().String("name", "n", "", "Match group name.")
              
              

              searchGroupsCmd.Flags().String("external_group_id", "egi", "", "Match group external_group_id.")
              
              

              searchGroupsCmd.Flags().BoolP("externally_managed", "em", false, "Match group externally_managed.")
              
              

              searchGroupsCmd.Flags().BoolP("externally_orphaned", "eo", false, "Match group externally_orphaned.")
              
              
            

              groupCmd.AddCommand(groupCmd65)
            
              groupCmd65.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(groupCmd65.Flags(), "group_id")
              

              groupCmd65.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              groupCmd.AddCommand(updateGroupCmd)
            
              updateGroupCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(updateGroupCmd.Flags(), "group_id")
              

              updateGroupCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateGroupCmd.Flags(), "body")
              

              updateGroupCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              groupCmd.AddCommand(deleteGroupCmd)
            
              deleteGroupCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(deleteGroupCmd.Flags(), "group_id")
              
            

              groupCmd.AddCommand(allGroupGroupsCmd)
            
              allGroupGroupsCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(allGroupGroupsCmd.Flags(), "group_id")
              

              allGroupGroupsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              groupCmd.AddCommand(addGroupGroupCmd)
            
              addGroupGroupCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(addGroupGroupCmd.Flags(), "group_id")
              

              addGroupGroupCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(addGroupGroupCmd.Flags(), "body")
              
            

              groupCmd.AddCommand(allGroupUsersCmd)
            
              allGroupUsersCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(allGroupUsersCmd.Flags(), "group_id")
              

              allGroupUsersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allGroupUsersCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              allGroupUsersCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              allGroupUsersCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              
            

              groupCmd.AddCommand(addGroupUserCmd)
            
              addGroupUserCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(addGroupUserCmd.Flags(), "group_id")
              

              addGroupUserCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(addGroupUserCmd.Flags(), "body")
              
            

              groupCmd.AddCommand(deleteGroupUserCmd)
            
              deleteGroupUserCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(deleteGroupUserCmd.Flags(), "group_id")
              

              deleteGroupUserCmd.Flags().Int64("user_id", "ui", 0, "Id of user to remove from group")
              cobra.MarkFlagRequired(deleteGroupUserCmd.Flags(), "user_id")
              
            

              groupCmd.AddCommand(deleteGroupFromGroupCmd)
            
              deleteGroupFromGroupCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(deleteGroupFromGroupCmd.Flags(), "group_id")
              

              deleteGroupFromGroupCmd.Flags().Int64("deleting_group_id", "dgi", 0, "Id of group to delete")
              cobra.MarkFlagRequired(deleteGroupFromGroupCmd.Flags(), "deleting_group_id")
              
            

              groupCmd.AddCommand(updateUserAttributeGroupValueCmd)
            
              updateUserAttributeGroupValueCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "group_id")
              

              updateUserAttributeGroupValueCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "user_attribute_id")
              

              updateUserAttributeGroupValueCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "body")
              
            

              groupCmd.AddCommand(deleteUserAttributeGroupValueCmd)
            
              deleteUserAttributeGroupValueCmd.Flags().Int64("group_id", "gi", 0, "Id of group")
              cobra.MarkFlagRequired(deleteUserAttributeGroupValueCmd.Flags(), "group_id")
              

              deleteUserAttributeGroupValueCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(deleteUserAttributeGroupValueCmd.Flags(), "user_attribute_id")
              
            
  rootCmd.AddCommand(groupCmd)

              homepageCmd.AddCommand(allHomepagesCmd)
            
              allHomepagesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(createHomepageCmd)
            
              createHomepageCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createHomepageCmd.Flags(), "body")
              

              createHomepageCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(searchHomepagesCmd)
            
              searchHomepagesCmd.Flags().String("title", "t", "", "Matches homepage title.")
              
              

              searchHomepagesCmd.Flags().String("created_at", "ca", "", "Matches the timestamp for when the homepage was created.")
              
              

              searchHomepagesCmd.Flags().String("first_name", "fn", "", "The first name of the user who created this homepage.")
              
              

              searchHomepagesCmd.Flags().String("last_name", "ln", "", "The last name of the user who created this homepage.")
              
              

              searchHomepagesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchHomepagesCmd.Flags().BoolP("favorited", "f", false, "Return favorited homepages when true.")
              
              

              searchHomepagesCmd.Flags().String("creator_id", "ci", "", "Filter on homepages created by a particular user.")
              
              

              searchHomepagesCmd.Flags().Int64("page", "p", 0, "The page to return.")
              
              

              searchHomepagesCmd.Flags().Int64("per_page", "pp", 0, "The number of items in the returned page.")
              
              

              searchHomepagesCmd.Flags().Int64("offset", "o", 0, "The number of items to skip before returning any. (used with limit and takes priority over page and per_page)")
              
              

              searchHomepagesCmd.Flags().Int64("limit", "l", 0, "The maximum number of items to return. (used with offset and takes priority over page and per_page)")
              
              

              searchHomepagesCmd.Flags().String("sorts", "s", "", "The fields to sort the results by.")
              
              

              searchHomepagesCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              homepageCmd.AddCommand(homepageCmd8294)
            
              homepageCmd8294.Flags().Int64("homepage_id", "hi", 0, "Id of homepage")
              cobra.MarkFlagRequired(homepageCmd8294.Flags(), "homepage_id")
              

              homepageCmd8294.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(updateHomepageCmd)
            
              updateHomepageCmd.Flags().Int64("homepage_id", "hi", 0, "Id of homepage")
              cobra.MarkFlagRequired(updateHomepageCmd.Flags(), "homepage_id")
              

              updateHomepageCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateHomepageCmd.Flags(), "body")
              

              updateHomepageCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(deleteHomepageCmd)
            
              deleteHomepageCmd.Flags().Int64("homepage_id", "hi", 0, "Id of homepage")
              cobra.MarkFlagRequired(deleteHomepageCmd.Flags(), "homepage_id")
              
            

              homepageCmd.AddCommand(allHomepageItemsCmd)
            
              allHomepageItemsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allHomepageItemsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              allHomepageItemsCmd.Flags().String("homepage_section_id", "hsi", "", "Filter to a specific homepage section")
              
              
            

              homepageCmd.AddCommand(createHomepageItemCmd)
            
              createHomepageItemCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createHomepageItemCmd.Flags(), "body")
              

              createHomepageItemCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(homepageItemCmd)
            
              homepageItemCmd.Flags().Int64("homepage_item_id", "hii", 0, "Id of homepage item")
              cobra.MarkFlagRequired(homepageItemCmd.Flags(), "homepage_item_id")
              

              homepageItemCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(updateHomepageItemCmd)
            
              updateHomepageItemCmd.Flags().Int64("homepage_item_id", "hii", 0, "Id of homepage item")
              cobra.MarkFlagRequired(updateHomepageItemCmd.Flags(), "homepage_item_id")
              

              updateHomepageItemCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateHomepageItemCmd.Flags(), "body")
              

              updateHomepageItemCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(deleteHomepageItemCmd)
            
              deleteHomepageItemCmd.Flags().Int64("homepage_item_id", "hii", 0, "Id of homepage_item")
              cobra.MarkFlagRequired(deleteHomepageItemCmd.Flags(), "homepage_item_id")
              
            

              homepageCmd.AddCommand(allHomepageSectionsCmd)
            
              allHomepageSectionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allHomepageSectionsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              
            

              homepageCmd.AddCommand(createHomepageSectionCmd)
            
              createHomepageSectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createHomepageSectionCmd.Flags(), "body")
              

              createHomepageSectionCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(homepageSectionCmd)
            
              homepageSectionCmd.Flags().Int64("homepage_section_id", "hsi", 0, "Id of homepage section")
              cobra.MarkFlagRequired(homepageSectionCmd.Flags(), "homepage_section_id")
              

              homepageSectionCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(updateHomepageSectionCmd)
            
              updateHomepageSectionCmd.Flags().Int64("homepage_section_id", "hsi", 0, "Id of homepage section")
              cobra.MarkFlagRequired(updateHomepageSectionCmd.Flags(), "homepage_section_id")
              

              updateHomepageSectionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateHomepageSectionCmd.Flags(), "body")
              

              updateHomepageSectionCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              homepageCmd.AddCommand(deleteHomepageSectionCmd)
            
              deleteHomepageSectionCmd.Flags().Int64("homepage_section_id", "hsi", 0, "Id of homepage_section")
              cobra.MarkFlagRequired(deleteHomepageSectionCmd.Flags(), "homepage_section_id")
              
            

              homepageCmd.AddCommand(allPrimaryHomepageSectionsCmd)
            
              allPrimaryHomepageSectionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(homepageCmd)

              integrationCmd.AddCommand(allIntegrationHubsCmd)
            
              allIntegrationHubsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(createIntegrationHubCmd)
            
              createIntegrationHubCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createIntegrationHubCmd.Flags(), "body")
              

              createIntegrationHubCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(integrationHubCmd)
            
              integrationHubCmd.Flags().Int64("integration_hub_id", "ihi", 0, "Id of Integration Hub")
              cobra.MarkFlagRequired(integrationHubCmd.Flags(), "integration_hub_id")
              

              integrationHubCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(updateIntegrationHubCmd)
            
              updateIntegrationHubCmd.Flags().Int64("integration_hub_id", "ihi", 0, "Id of Integration Hub")
              cobra.MarkFlagRequired(updateIntegrationHubCmd.Flags(), "integration_hub_id")
              

              updateIntegrationHubCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateIntegrationHubCmd.Flags(), "body")
              

              updateIntegrationHubCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(deleteIntegrationHubCmd)
            
              deleteIntegrationHubCmd.Flags().Int64("integration_hub_id", "ihi", 0, "Id of integration_hub")
              cobra.MarkFlagRequired(deleteIntegrationHubCmd.Flags(), "integration_hub_id")
              
            

              integrationCmd.AddCommand(acceptIntegrationHubLegalAgreementCmd)
            
              acceptIntegrationHubLegalAgreementCmd.Flags().Int64("integration_hub_id", "ihi", 0, "Id of integration_hub")
              cobra.MarkFlagRequired(acceptIntegrationHubLegalAgreementCmd.Flags(), "integration_hub_id")
              
            

              integrationCmd.AddCommand(allIntegrationsCmd)
            
              allIntegrationsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allIntegrationsCmd.Flags().String("integration_hub_id", "ihi", "", "Filter to a specific provider")
              
              
            

              integrationCmd.AddCommand(integrationCmd822)
            
              integrationCmd822.Flags().String("integration_id", "ii", "", "Id of integration")
              cobra.MarkFlagRequired(integrationCmd822.Flags(), "integration_id")
              

              integrationCmd822.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(updateIntegrationCmd)
            
              updateIntegrationCmd.Flags().String("integration_id", "ii", "", "Id of integration")
              cobra.MarkFlagRequired(updateIntegrationCmd.Flags(), "integration_id")
              

              updateIntegrationCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateIntegrationCmd.Flags(), "body")
              

              updateIntegrationCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              integrationCmd.AddCommand(fetchIntegrationFormCmd)
            
              fetchIntegrationFormCmd.Flags().String("integration_id", "ii", "", "Id of integration")
              cobra.MarkFlagRequired(fetchIntegrationFormCmd.Flags(), "integration_id")
              

              fetchIntegrationFormCmd.Flags().String("body", "b", "", "")
              
              
            

              integrationCmd.AddCommand(testIntegrationCmd)
            
              testIntegrationCmd.Flags().String("integration_id", "ii", "", "Id of integration")
              cobra.MarkFlagRequired(testIntegrationCmd.Flags(), "integration_id")
              
            
  rootCmd.AddCommand(integrationCmd)

              lookCmd.AddCommand(allLooksCmd)
            
              allLooksCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookCmd.AddCommand(createLookCmd)
            
              createLookCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createLookCmd.Flags(), "body")
              

              createLookCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookCmd.AddCommand(searchLooksCmd)
            
              searchLooksCmd.Flags().String("id", "i", "", "Match look id.")
              
              

              searchLooksCmd.Flags().String("title", "t", "", "Match Look title.")
              
              

              searchLooksCmd.Flags().String("description", "d", "", "Match Look description.")
              
              

              searchLooksCmd.Flags().Int64("content_favorite_id", "cfi", 0, "Select looks with a particular content favorite id")
              
              

              searchLooksCmd.Flags().String("space_id", "si", "", "Select looks in a particular space.")
              
              

              searchLooksCmd.Flags().String("user_id", "ui", "", "Select looks created by a particular user.")
              
              

              searchLooksCmd.Flags().String("view_count", "vc", "", "Select looks with particular view_count value")
              
              

              searchLooksCmd.Flags().BoolP("deleted", "d", false, "Select soft-deleted looks")
              
              

              searchLooksCmd.Flags().Int64("query_id", "qi", 0, "Select looks that reference a particular query by query_id")
              
              

              searchLooksCmd.Flags().BoolP("curate", "c", false, "Exclude items that exist only in personal spaces other than the users")
              
              

              searchLooksCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchLooksCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              searchLooksCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              searchLooksCmd.Flags().Int64("limit", "l", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
              
              

              searchLooksCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
              
              

              searchLooksCmd.Flags().String("sorts", "s", "", "One or more fields to sort results by. Sortable fields: [:title, :user_id, :id, :created_at, :space_id, :folder_id, :description, :updated_at, :last_updater_id, :view_count, :favorite_count, :content_favorite_id, :deleted, :deleted_at, :last_viewed_at, :last_accessed_at, :query_id]")
              
              

              searchLooksCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              lookCmd.AddCommand(lookCmd652)
            
              lookCmd652.Flags().Int64("look_id", "li", 0, "Id of look")
              cobra.MarkFlagRequired(lookCmd652.Flags(), "look_id")
              

              lookCmd652.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookCmd.AddCommand(updateLookCmd)
            
              updateLookCmd.Flags().Int64("look_id", "li", 0, "Id of look")
              cobra.MarkFlagRequired(updateLookCmd.Flags(), "look_id")
              

              updateLookCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateLookCmd.Flags(), "body")
              

              updateLookCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookCmd.AddCommand(deleteLookCmd)
            
              deleteLookCmd.Flags().Int64("look_id", "li", 0, "Id of look")
              cobra.MarkFlagRequired(deleteLookCmd.Flags(), "look_id")
              
            

              lookCmd.AddCommand(runLookCmd)
            
              runLookCmd.Flags().Int64("look_id", "li", 0, "Id of look")
              cobra.MarkFlagRequired(runLookCmd.Flags(), "look_id")
              

              runLookCmd.Flags().String("result_format", "rf", "", "Format of result")
              cobra.MarkFlagRequired(runLookCmd.Flags(), "result_format")
              

              runLookCmd.Flags().Int64("limit", "l", 0, "Row limit (may override the limit in the saved query).")
              
              

              runLookCmd.Flags().BoolP("apply_formatting", "af", false, "Apply model-specified formatting to each result.")
              
              

              runLookCmd.Flags().BoolP("apply_vis", "av", false, "Apply visualization options to results.")
              
              

              runLookCmd.Flags().BoolP("cache", "c", false, "Get results from cache if available.")
              
              

              runLookCmd.Flags().Int64("image_width", "iw", 0, "Render width for image formats.")
              
              

              runLookCmd.Flags().Int64("image_height", "ih", 0, "Render height for image formats.")
              
              

              runLookCmd.Flags().BoolP("generate_drill_links", "gdl", false, "Generate drill links (only applicable to 'json_detail' format.")
              
              

              runLookCmd.Flags().BoolP("force_production", "fp", false, "Force use of production models even if the user is in development mode.")
              
              

              runLookCmd.Flags().BoolP("cache_only", "co", false, "Retrieve any results from cache even if the results have expired.")
              
              

              runLookCmd.Flags().String("path_prefix", "pp", "", "Prefix to use for drill links (url encoded).")
              
              

              runLookCmd.Flags().BoolP("rebuild_pdts", "rp", false, "Rebuild PDTS used in query.")
              
              

              runLookCmd.Flags().BoolP("server_table_calcs", "stc", false, "Perform table calculations on query results")
              
              
            
  rootCmd.AddCommand(lookCmd)

              lookmlModelCmd.AddCommand(allLookmlModelsCmd)
            
              allLookmlModelsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookmlModelCmd.AddCommand(createLookmlModelCmd)
            
              createLookmlModelCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createLookmlModelCmd.Flags(), "body")
              
            

              lookmlModelCmd.AddCommand(lookmlModelCmd6917)
            
              lookmlModelCmd6917.Flags().String("lookml_model_name", "lmn", "", "Name of lookml model.")
              cobra.MarkFlagRequired(lookmlModelCmd6917.Flags(), "lookml_model_name")
              

              lookmlModelCmd6917.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              lookmlModelCmd.AddCommand(updateLookmlModelCmd)
            
              updateLookmlModelCmd.Flags().String("lookml_model_name", "lmn", "", "Name of lookml model.")
              cobra.MarkFlagRequired(updateLookmlModelCmd.Flags(), "lookml_model_name")
              

              updateLookmlModelCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateLookmlModelCmd.Flags(), "body")
              
            

              lookmlModelCmd.AddCommand(deleteLookmlModelCmd)
            
              deleteLookmlModelCmd.Flags().String("lookml_model_name", "lmn", "", "Name of lookml model.")
              cobra.MarkFlagRequired(deleteLookmlModelCmd.Flags(), "lookml_model_name")
              
            

              lookmlModelCmd.AddCommand(lookmlModelExploreCmd)
            
              lookmlModelExploreCmd.Flags().String("lookml_model_name", "lmn", "", "Name of lookml model.")
              cobra.MarkFlagRequired(lookmlModelExploreCmd.Flags(), "lookml_model_name")
              

              lookmlModelExploreCmd.Flags().String("explore_name", "en", "", "Name of explore.")
              cobra.MarkFlagRequired(lookmlModelExploreCmd.Flags(), "explore_name")
              

              lookmlModelExploreCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(lookmlModelCmd)

              projectCmd.AddCommand(allGitBranchesCmd)
            
              allGitBranchesCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(allGitBranchesCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(gitBranchCmd)
            
              gitBranchCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(gitBranchCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(updateGitBranchCmd)
            
              updateGitBranchCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(updateGitBranchCmd.Flags(), "project_id")
              

              updateGitBranchCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateGitBranchCmd.Flags(), "body")
              
            

              projectCmd.AddCommand(createGitBranchCmd)
            
              createGitBranchCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(createGitBranchCmd.Flags(), "project_id")
              

              createGitBranchCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createGitBranchCmd.Flags(), "body")
              
            

              projectCmd.AddCommand(findGitBranchCmd)
            
              findGitBranchCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(findGitBranchCmd.Flags(), "project_id")
              

              findGitBranchCmd.Flags().String("branch_name", "bn", "", "Branch Name")
              cobra.MarkFlagRequired(findGitBranchCmd.Flags(), "branch_name")
              
            

              projectCmd.AddCommand(deleteGitBranchCmd)
            
              deleteGitBranchCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(deleteGitBranchCmd.Flags(), "project_id")
              

              deleteGitBranchCmd.Flags().String("branch_name", "bn", "", "Branch Name")
              cobra.MarkFlagRequired(deleteGitBranchCmd.Flags(), "branch_name")
              
            

              projectCmd.AddCommand(deployRefToProductionCmd)
            
              deployRefToProductionCmd.Flags().String("project_id", "pi", "", "Id of project")
              cobra.MarkFlagRequired(deployRefToProductionCmd.Flags(), "project_id")
              

              deployRefToProductionCmd.Flags().String("branch", "b", "", "Branch to deploy to production")
              
              

              deployRefToProductionCmd.Flags().String("ref", "r", "", "Ref to deploy to production")
              
              
            

              projectCmd.AddCommand(deployToProductionCmd)
            
              deployToProductionCmd.Flags().String("project_id", "pi", "", "Id of project")
              cobra.MarkFlagRequired(deployToProductionCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(resetProjectToProductionCmd)
            
              resetProjectToProductionCmd.Flags().String("project_id", "pi", "", "Id of project")
              cobra.MarkFlagRequired(resetProjectToProductionCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(resetProjectToRemoteCmd)
            
              resetProjectToRemoteCmd.Flags().String("project_id", "pi", "", "Id of project")
              cobra.MarkFlagRequired(resetProjectToRemoteCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(allProjectsCmd)
            
              allProjectsCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(createProjectCmd)
            
              createProjectCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createProjectCmd.Flags(), "body")
              
            

              projectCmd.AddCommand(projectCmd8042)
            
              projectCmd8042.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(projectCmd8042.Flags(), "project_id")
              

              projectCmd8042.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(updateProjectCmd)
            
              updateProjectCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(updateProjectCmd.Flags(), "project_id")
              

              updateProjectCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateProjectCmd.Flags(), "body")
              

              updateProjectCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(manifestCmd)
            
              manifestCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(manifestCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(gitDeployKeyCmd)
            
              gitDeployKeyCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(gitDeployKeyCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(createGitDeployKeyCmd)
            
              createGitDeployKeyCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(createGitDeployKeyCmd.Flags(), "project_id")
              
            

              projectCmd.AddCommand(projectValidationResultsCmd)
            
              projectValidationResultsCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(projectValidationResultsCmd.Flags(), "project_id")
              

              projectValidationResultsCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(validateProjectCmd)
            
              validateProjectCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(validateProjectCmd.Flags(), "project_id")
              

              validateProjectCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(projectWorkspaceCmd)
            
              projectWorkspaceCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(projectWorkspaceCmd.Flags(), "project_id")
              

              projectWorkspaceCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(allProjectFilesCmd)
            
              allProjectFilesCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(allProjectFilesCmd.Flags(), "project_id")
              

              allProjectFilesCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(projectFileCmd)
            
              projectFileCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(projectFileCmd.Flags(), "project_id")
              

              projectFileCmd.Flags().String("file_id", "fi", "", "File Id")
              cobra.MarkFlagRequired(projectFileCmd.Flags(), "file_id")
              

              projectFileCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              projectCmd.AddCommand(allGitConnectionTestsCmd)
            
              allGitConnectionTestsCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(allGitConnectionTestsCmd.Flags(), "project_id")
              

              allGitConnectionTestsCmd.Flags().String("remote_url", "ru", "", "(Optional: leave blank for root project) The remote url for remote dependency to test.")
              
              
            

              projectCmd.AddCommand(runGitConnectionTestCmd)
            
              runGitConnectionTestCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(runGitConnectionTestCmd.Flags(), "project_id")
              

              runGitConnectionTestCmd.Flags().String("test_id", "ti", "", "Test Id")
              cobra.MarkFlagRequired(runGitConnectionTestCmd.Flags(), "test_id")
              

              runGitConnectionTestCmd.Flags().String("remote_url", "ru", "", "(Optional: leave blank for root project) The remote url for remote dependency to test.")
              
              

              runGitConnectionTestCmd.Flags().String("use_production", "up", "", "(Optional: leave blank for dev credentials) Whether to use git production credentials.")
              
              
            

              projectCmd.AddCommand(allLookmlTestsCmd)
            
              allLookmlTestsCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(allLookmlTestsCmd.Flags(), "project_id")
              

              allLookmlTestsCmd.Flags().String("file_id", "fi", "", "File Id")
              
              
            

              projectCmd.AddCommand(runLookmlTestCmd)
            
              runLookmlTestCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(runLookmlTestCmd.Flags(), "project_id")
              

              runLookmlTestCmd.Flags().String("file_id", "fi", "", "File Name")
              
              

              runLookmlTestCmd.Flags().String("test", "t", "", "Test Name")
              
              

              runLookmlTestCmd.Flags().String("model", "m", "", "Model Name")
              
              
            

              projectCmd.AddCommand(tagRefCmd)
            
              tagRefCmd.Flags().String("project_id", "pi", "", "Project Id")
              cobra.MarkFlagRequired(tagRefCmd.Flags(), "project_id")
              

              tagRefCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(tagRefCmd.Flags(), "body")
              

              tagRefCmd.Flags().String("commit_sha", "cs", "", "(Optional): Commit Sha to Tag")
              
              

              tagRefCmd.Flags().String("tag_name", "tn", "", "Tag Name")
              
              

              tagRefCmd.Flags().String("tag_message", "tm", "", "(Optional): Tag Message")
              
              
            

              projectCmd.AddCommand(updateRepositoryCredentialCmd)
            
              updateRepositoryCredentialCmd.Flags().String("root_project_id", "rpi", "", "Root Project Id")
              cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "root_project_id")
              

              updateRepositoryCredentialCmd.Flags().String("credential_id", "ci", "", "Credential Id")
              cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "credential_id")
              

              updateRepositoryCredentialCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "body")
              
            

              projectCmd.AddCommand(deleteRepositoryCredentialCmd)
            
              deleteRepositoryCredentialCmd.Flags().String("root_project_id", "rpi", "", "Root Project Id")
              cobra.MarkFlagRequired(deleteRepositoryCredentialCmd.Flags(), "root_project_id")
              

              deleteRepositoryCredentialCmd.Flags().String("credential_id", "ci", "", "Credential Id")
              cobra.MarkFlagRequired(deleteRepositoryCredentialCmd.Flags(), "credential_id")
              
            

              projectCmd.AddCommand(getAllRepositoryCredentialsCmd)
            
              getAllRepositoryCredentialsCmd.Flags().String("root_project_id", "rpi", "", "Root Project Id")
              cobra.MarkFlagRequired(getAllRepositoryCredentialsCmd.Flags(), "root_project_id")
              
            
  rootCmd.AddCommand(projectCmd)

              queryCmd.AddCommand(createQueryTaskCmd)
            
              createQueryTaskCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createQueryTaskCmd.Flags(), "body")
              

              createQueryTaskCmd.Flags().Int64("limit", "l", 0, "Row limit (may override the limit in the saved query).")
              
              

              createQueryTaskCmd.Flags().BoolP("apply_formatting", "af", false, "Apply model-specified formatting to each result.")
              
              

              createQueryTaskCmd.Flags().BoolP("apply_vis", "av", false, "Apply visualization options to results.")
              
              

              createQueryTaskCmd.Flags().BoolP("cache", "c", false, "Get results from cache if available.")
              
              

              createQueryTaskCmd.Flags().Int64("image_width", "iw", 0, "Render width for image formats.")
              
              

              createQueryTaskCmd.Flags().Int64("image_height", "ih", 0, "Render height for image formats.")
              
              

              createQueryTaskCmd.Flags().BoolP("generate_drill_links", "gdl", false, "Generate drill links (only applicable to 'json_detail' format.")
              
              

              createQueryTaskCmd.Flags().BoolP("force_production", "fp", false, "Force use of production models even if the user is in development mode.")
              
              

              createQueryTaskCmd.Flags().BoolP("cache_only", "co", false, "Retrieve any results from cache even if the results have expired.")
              
              

              createQueryTaskCmd.Flags().String("path_prefix", "pp", "", "Prefix to use for drill links (url encoded).")
              
              

              createQueryTaskCmd.Flags().BoolP("rebuild_pdts", "rp", false, "Rebuild PDTS used in query.")
              
              

              createQueryTaskCmd.Flags().BoolP("server_table_calcs", "stc", false, "Perform table calculations on query results")
              
              

              createQueryTaskCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              queryCmd.AddCommand(queryTaskMultiResultsCmd)
            
              queryTaskMultiResultsCmd.Flags().String("query_task_ids", "qti", "", "List of Query Task IDs")
              cobra.MarkFlagRequired(queryTaskMultiResultsCmd.Flags(), "query_task_ids")
              
            

              queryCmd.AddCommand(queryTaskCmd)
            
              queryTaskCmd.Flags().String("query_task_id", "qti", "", "ID of the Query Task")
              cobra.MarkFlagRequired(queryTaskCmd.Flags(), "query_task_id")
              

              queryTaskCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              queryCmd.AddCommand(queryTaskResultsCmd)
            
              queryTaskResultsCmd.Flags().String("query_task_id", "qti", "", "ID of the Query Task")
              cobra.MarkFlagRequired(queryTaskResultsCmd.Flags(), "query_task_id")
              
            

              queryCmd.AddCommand(queryCmd3749)
            
              queryCmd3749.Flags().Int64("query_id", "qi", 0, "Id of query")
              cobra.MarkFlagRequired(queryCmd3749.Flags(), "query_id")
              

              queryCmd3749.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              queryCmd.AddCommand(queryForSlugCmd)
            
              queryForSlugCmd.Flags().String("slug", "s", "", "Slug of query")
              cobra.MarkFlagRequired(queryForSlugCmd.Flags(), "slug")
              

              queryForSlugCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              queryCmd.AddCommand(createQueryCmd)
            
              createQueryCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createQueryCmd.Flags(), "body")
              

              createQueryCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              queryCmd.AddCommand(runQueryCmd)
            
              runQueryCmd.Flags().Int64("query_id", "qi", 0, "Id of query")
              cobra.MarkFlagRequired(runQueryCmd.Flags(), "query_id")
              

              runQueryCmd.Flags().String("result_format", "rf", "", "Format of result")
              cobra.MarkFlagRequired(runQueryCmd.Flags(), "result_format")
              

              runQueryCmd.Flags().Int64("limit", "l", 0, "Row limit (may override the limit in the saved query).")
              
              

              runQueryCmd.Flags().BoolP("apply_formatting", "af", false, "Apply model-specified formatting to each result.")
              
              

              runQueryCmd.Flags().BoolP("apply_vis", "av", false, "Apply visualization options to results.")
              
              

              runQueryCmd.Flags().BoolP("cache", "c", false, "Get results from cache if available.")
              
              

              runQueryCmd.Flags().Int64("image_width", "iw", 0, "Render width for image formats.")
              
              

              runQueryCmd.Flags().Int64("image_height", "ih", 0, "Render height for image formats.")
              
              

              runQueryCmd.Flags().BoolP("generate_drill_links", "gdl", false, "Generate drill links (only applicable to 'json_detail' format.")
              
              

              runQueryCmd.Flags().BoolP("force_production", "fp", false, "Force use of production models even if the user is in development mode.")
              
              

              runQueryCmd.Flags().BoolP("cache_only", "co", false, "Retrieve any results from cache even if the results have expired.")
              
              

              runQueryCmd.Flags().String("path_prefix", "pp", "", "Prefix to use for drill links (url encoded).")
              
              

              runQueryCmd.Flags().BoolP("rebuild_pdts", "rp", false, "Rebuild PDTS used in query.")
              
              

              runQueryCmd.Flags().BoolP("server_table_calcs", "stc", false, "Perform table calculations on query results")
              
              
            

              queryCmd.AddCommand(runInlineQueryCmd)
            
              runInlineQueryCmd.Flags().String("result_format", "rf", "", "Format of result")
              cobra.MarkFlagRequired(runInlineQueryCmd.Flags(), "result_format")
              

              runInlineQueryCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(runInlineQueryCmd.Flags(), "body")
              

              runInlineQueryCmd.Flags().Int64("limit", "l", 0, "Row limit (may override the limit in the saved query).")
              
              

              runInlineQueryCmd.Flags().BoolP("apply_formatting", "af", false, "Apply model-specified formatting to each result.")
              
              

              runInlineQueryCmd.Flags().BoolP("apply_vis", "av", false, "Apply visualization options to results.")
              
              

              runInlineQueryCmd.Flags().BoolP("cache", "c", false, "Get results from cache if available.")
              
              

              runInlineQueryCmd.Flags().Int64("image_width", "iw", 0, "Render width for image formats.")
              
              

              runInlineQueryCmd.Flags().Int64("image_height", "ih", 0, "Render height for image formats.")
              
              

              runInlineQueryCmd.Flags().BoolP("generate_drill_links", "gdl", false, "Generate drill links (only applicable to 'json_detail' format.")
              
              

              runInlineQueryCmd.Flags().BoolP("force_production", "fp", false, "Force use of production models even if the user is in development mode.")
              
              

              runInlineQueryCmd.Flags().BoolP("cache_only", "co", false, "Retrieve any results from cache even if the results have expired.")
              
              

              runInlineQueryCmd.Flags().String("path_prefix", "pp", "", "Prefix to use for drill links (url encoded).")
              
              

              runInlineQueryCmd.Flags().BoolP("rebuild_pdts", "rp", false, "Rebuild PDTS used in query.")
              
              

              runInlineQueryCmd.Flags().BoolP("server_table_calcs", "stc", false, "Perform table calculations on query results")
              
              
            

              queryCmd.AddCommand(runUrlEncodedQueryCmd)
            
              runUrlEncodedQueryCmd.Flags().String("model_name", "mn", "", "Model name")
              cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "model_name")
              

              runUrlEncodedQueryCmd.Flags().String("view_name", "vn", "", "View name")
              cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "view_name")
              

              runUrlEncodedQueryCmd.Flags().String("result_format", "rf", "", "Format of result")
              cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "result_format")
              
            

              queryCmd.AddCommand(mergeQueryCmd)
            
              mergeQueryCmd.Flags().String("merge_query_id", "mqi", "", "Merge Query Id")
              cobra.MarkFlagRequired(mergeQueryCmd.Flags(), "merge_query_id")
              

              mergeQueryCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              queryCmd.AddCommand(createMergeQueryCmd)
            
              createMergeQueryCmd.Flags().String("body", "b", "", "")
              
              

              createMergeQueryCmd.Flags().String("fields", "f", "", "Requested fields")
              
              
            

              queryCmd.AddCommand(allRunningQueriesCmd)
            
            

              queryCmd.AddCommand(killQueryCmd)
            
              killQueryCmd.Flags().String("query_task_id", "qti", "", "Query task id.")
              cobra.MarkFlagRequired(killQueryCmd.Flags(), "query_task_id")
              
            

              queryCmd.AddCommand(sqlQueryCmd)
            
              sqlQueryCmd.Flags().String("slug", "s", "", "slug of query")
              cobra.MarkFlagRequired(sqlQueryCmd.Flags(), "slug")
              
            

              queryCmd.AddCommand(createSqlQueryCmd)
            
              createSqlQueryCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createSqlQueryCmd.Flags(), "body")
              
            

              queryCmd.AddCommand(runSqlQueryCmd)
            
              runSqlQueryCmd.Flags().String("slug", "s", "", "slug of query")
              cobra.MarkFlagRequired(runSqlQueryCmd.Flags(), "slug")
              

              runSqlQueryCmd.Flags().String("result_format", "rf", "", "Format of result, options are: ["inline_json", "json", "json_detail", "json_fe", "csv", "html", "md", "txt", "xlsx", "gsxml", "json_label"]")
              cobra.MarkFlagRequired(runSqlQueryCmd.Flags(), "result_format")
              

              runSqlQueryCmd.Flags().String("download", "d", "", "Defaults to false. If set to true, the HTTP response will have content-disposition and other headers set to make the HTTP response behave as a downloadable attachment instead of as inline content.")
              
              
            
  rootCmd.AddCommand(queryCmd)

              renderTaskCmd.AddCommand(createLookmlDashboardRenderTaskCmd)
            
              createLookmlDashboardRenderTaskCmd.Flags().String("dashboard_id", "di", "", "Id of lookml dashboard to render")
              cobra.MarkFlagRequired(createLookmlDashboardRenderTaskCmd.Flags(), "dashboard_id")
              

              createLookmlDashboardRenderTaskCmd.Flags().String("result_format", "rf", "", "Output type: pdf, png, or jpg")
              cobra.MarkFlagRequired(createLookmlDashboardRenderTaskCmd.Flags(), "result_format")
              

              createLookmlDashboardRenderTaskCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createLookmlDashboardRenderTaskCmd.Flags(), "body")
              

              createLookmlDashboardRenderTaskCmd.Flags().Int64("width", "w", 0, "Output width in pixels")
              cobra.MarkFlagRequired(createLookmlDashboardRenderTaskCmd.Flags(), "width")
              

              createLookmlDashboardRenderTaskCmd.Flags().Int64("height", "h", 0, "Output height in pixels")
              cobra.MarkFlagRequired(createLookmlDashboardRenderTaskCmd.Flags(), "height")
              

              createLookmlDashboardRenderTaskCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              createLookmlDashboardRenderTaskCmd.Flags().String("pdf_paper_size", "pps", "", "Paper size for pdf. Value can be one of: ["letter","legal","tabloid","a0","a1","a2","a3","a4","a5"]")
              
              

              createLookmlDashboardRenderTaskCmd.Flags().BoolP("pdf_landscape", "pl", false, "Whether to render pdf in landscape")
              
              
            

              renderTaskCmd.AddCommand(createLookRenderTaskCmd)
            
              createLookRenderTaskCmd.Flags().Int64("look_id", "li", 0, "Id of look to render")
              cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "look_id")
              

              createLookRenderTaskCmd.Flags().String("result_format", "rf", "", "Output type: png, or jpg")
              cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "result_format")
              

              createLookRenderTaskCmd.Flags().Int64("width", "w", 0, "Output width in pixels")
              cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "width")
              

              createLookRenderTaskCmd.Flags().Int64("height", "h", 0, "Output height in pixels")
              cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "height")
              

              createLookRenderTaskCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              renderTaskCmd.AddCommand(createQueryRenderTaskCmd)
            
              createQueryRenderTaskCmd.Flags().Int64("query_id", "qi", 0, "Id of the query to render")
              cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "query_id")
              

              createQueryRenderTaskCmd.Flags().String("result_format", "rf", "", "Output type: png or jpg")
              cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "result_format")
              

              createQueryRenderTaskCmd.Flags().Int64("width", "w", 0, "Output width in pixels")
              cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "width")
              

              createQueryRenderTaskCmd.Flags().Int64("height", "h", 0, "Output height in pixels")
              cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "height")
              

              createQueryRenderTaskCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              renderTaskCmd.AddCommand(createDashboardRenderTaskCmd)
            
              createDashboardRenderTaskCmd.Flags().Int64("dashboard_id", "di", 0, "Id of dashboard to render")
              cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "dashboard_id")
              

              createDashboardRenderTaskCmd.Flags().String("result_format", "rf", "", "Output type: pdf, png, or jpg")
              cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "result_format")
              

              createDashboardRenderTaskCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "body")
              

              createDashboardRenderTaskCmd.Flags().Int64("width", "w", 0, "Output width in pixels")
              cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "width")
              

              createDashboardRenderTaskCmd.Flags().Int64("height", "h", 0, "Output height in pixels")
              cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "height")
              

              createDashboardRenderTaskCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              createDashboardRenderTaskCmd.Flags().String("pdf_paper_size", "pps", "", "Paper size for pdf. Value can be one of: ["letter","legal","tabloid","a0","a1","a2","a3","a4","a5"]")
              
              

              createDashboardRenderTaskCmd.Flags().BoolP("pdf_landscape", "pl", false, "Whether to render pdf in landscape paper orientation")
              
              
            

              renderTaskCmd.AddCommand(renderTaskCmd4463)
            
              renderTaskCmd4463.Flags().String("render_task_id", "rti", "", "Id of render task")
              cobra.MarkFlagRequired(renderTaskCmd4463.Flags(), "render_task_id")
              

              renderTaskCmd4463.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              renderTaskCmd.AddCommand(renderTaskResultsCmd)
            
              renderTaskResultsCmd.Flags().String("render_task_id", "rti", "", "Id of render task")
              cobra.MarkFlagRequired(renderTaskResultsCmd.Flags(), "render_task_id")
              
            
  rootCmd.AddCommand(renderTaskCmd)

              roleCmd.AddCommand(searchModelSetsCmd)
            
              searchModelSetsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchModelSetsCmd.Flags().Int64("limit", "l", 0, "Number of results to return (used with `offset`).")
              
              

              searchModelSetsCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any (used with `limit`).")
              
              

              searchModelSetsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchModelSetsCmd.Flags().Int64("id", "i", 0, "Match model set id.")
              
              

              searchModelSetsCmd.Flags().String("name", "n", "", "Match model set name.")
              
              

              searchModelSetsCmd.Flags().BoolP("all_access", "aa", false, "Match model sets by all_access status.")
              
              

              searchModelSetsCmd.Flags().BoolP("built_in", "bi", false, "Match model sets by built_in status.")
              
              

              searchModelSetsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression.")
              
              
            

              roleCmd.AddCommand(modelSetCmd)
            
              modelSetCmd.Flags().Int64("model_set_id", "msi", 0, "Id of model set")
              cobra.MarkFlagRequired(modelSetCmd.Flags(), "model_set_id")
              

              modelSetCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              roleCmd.AddCommand(updateModelSetCmd)
            
              updateModelSetCmd.Flags().Int64("model_set_id", "msi", 0, "id of model set")
              cobra.MarkFlagRequired(updateModelSetCmd.Flags(), "model_set_id")
              

              updateModelSetCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateModelSetCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(deleteModelSetCmd)
            
              deleteModelSetCmd.Flags().Int64("model_set_id", "msi", 0, "id of model set")
              cobra.MarkFlagRequired(deleteModelSetCmd.Flags(), "model_set_id")
              
            

              roleCmd.AddCommand(allModelSetsCmd)
            
              allModelSetsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              roleCmd.AddCommand(createModelSetCmd)
            
              createModelSetCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createModelSetCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(allPermissionsCmd)
            
            

              roleCmd.AddCommand(searchPermissionSetsCmd)
            
              searchPermissionSetsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchPermissionSetsCmd.Flags().Int64("limit", "l", 0, "Number of results to return (used with `offset`).")
              
              

              searchPermissionSetsCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any (used with `limit`).")
              
              

              searchPermissionSetsCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchPermissionSetsCmd.Flags().Int64("id", "i", 0, "Match permission set id.")
              
              

              searchPermissionSetsCmd.Flags().String("name", "n", "", "Match permission set name.")
              
              

              searchPermissionSetsCmd.Flags().BoolP("all_access", "aa", false, "Match permission sets by all_access status.")
              
              

              searchPermissionSetsCmd.Flags().BoolP("built_in", "bi", false, "Match permission sets by built_in status.")
              
              

              searchPermissionSetsCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression.")
              
              
            

              roleCmd.AddCommand(permissionSetCmd)
            
              permissionSetCmd.Flags().Int64("permission_set_id", "psi", 0, "Id of permission set")
              cobra.MarkFlagRequired(permissionSetCmd.Flags(), "permission_set_id")
              

              permissionSetCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              roleCmd.AddCommand(updatePermissionSetCmd)
            
              updatePermissionSetCmd.Flags().Int64("permission_set_id", "psi", 0, "id of permission set")
              cobra.MarkFlagRequired(updatePermissionSetCmd.Flags(), "permission_set_id")
              

              updatePermissionSetCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updatePermissionSetCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(deletePermissionSetCmd)
            
              deletePermissionSetCmd.Flags().Int64("permission_set_id", "psi", 0, "Id of permission set")
              cobra.MarkFlagRequired(deletePermissionSetCmd.Flags(), "permission_set_id")
              
            

              roleCmd.AddCommand(allPermissionSetsCmd)
            
              allPermissionSetsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              roleCmd.AddCommand(createPermissionSetCmd)
            
              createPermissionSetCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createPermissionSetCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(allRolesCmd)
            
              allRolesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allRolesCmd.Flags().String("ids", "i", "", "Optional list of ids to get specific roles.")
              
              
            

              roleCmd.AddCommand(createRoleCmd)
            
              createRoleCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createRoleCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(searchRolesCmd)
            
              searchRolesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchRolesCmd.Flags().Int64("limit", "l", 0, "Number of results to return (used with `offset`).")
              
              

              searchRolesCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any (used with `limit`).")
              
              

              searchRolesCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchRolesCmd.Flags().Int64("id", "i", 0, "Match role id.")
              
              

              searchRolesCmd.Flags().String("name", "n", "", "Match role name.")
              
              

              searchRolesCmd.Flags().BoolP("built_in", "bi", false, "Match roles by built_in status.")
              
              

              searchRolesCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression.")
              
              
            

              roleCmd.AddCommand(roleCmd4795)
            
              roleCmd4795.Flags().Int64("role_id", "ri", 0, "id of role")
              cobra.MarkFlagRequired(roleCmd4795.Flags(), "role_id")
              
            

              roleCmd.AddCommand(updateRoleCmd)
            
              updateRoleCmd.Flags().Int64("role_id", "ri", 0, "id of role")
              cobra.MarkFlagRequired(updateRoleCmd.Flags(), "role_id")
              

              updateRoleCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateRoleCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(deleteRoleCmd)
            
              deleteRoleCmd.Flags().Int64("role_id", "ri", 0, "id of role")
              cobra.MarkFlagRequired(deleteRoleCmd.Flags(), "role_id")
              
            

              roleCmd.AddCommand(roleGroupsCmd)
            
              roleGroupsCmd.Flags().Int64("role_id", "ri", 0, "id of role")
              cobra.MarkFlagRequired(roleGroupsCmd.Flags(), "role_id")
              

              roleGroupsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              roleCmd.AddCommand(setRoleGroupsCmd)
            
              setRoleGroupsCmd.Flags().Int64("role_id", "ri", 0, "Id of Role")
              cobra.MarkFlagRequired(setRoleGroupsCmd.Flags(), "role_id")
              

              setRoleGroupsCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(setRoleGroupsCmd.Flags(), "body")
              
            

              roleCmd.AddCommand(roleUsersCmd)
            
              roleUsersCmd.Flags().Int64("role_id", "ri", 0, "id of user")
              cobra.MarkFlagRequired(roleUsersCmd.Flags(), "role_id")
              

              roleUsersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              roleUsersCmd.Flags().BoolP("direct_association_only", "dao", false, "Get only users associated directly with the role: exclude those only associated through groups.")
              
              
            

              roleCmd.AddCommand(setRoleUsersCmd)
            
              setRoleUsersCmd.Flags().Int64("role_id", "ri", 0, "id of role")
              cobra.MarkFlagRequired(setRoleUsersCmd.Flags(), "role_id")
              

              setRoleUsersCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(setRoleUsersCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(roleCmd)

              scheduledPlanCmd.AddCommand(scheduledPlansForSpaceCmd)
            
              scheduledPlansForSpaceCmd.Flags().Int64("space_id", "si", 0, "Space Id")
              cobra.MarkFlagRequired(scheduledPlansForSpaceCmd.Flags(), "space_id")
              

              scheduledPlansForSpaceCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              scheduledPlanCmd.AddCommand(scheduledPlanCmd6475)
            
              scheduledPlanCmd6475.Flags().Int64("scheduled_plan_id", "spi", 0, "Scheduled Plan Id")
              cobra.MarkFlagRequired(scheduledPlanCmd6475.Flags(), "scheduled_plan_id")
              

              scheduledPlanCmd6475.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              scheduledPlanCmd.AddCommand(updateScheduledPlanCmd)
            
              updateScheduledPlanCmd.Flags().Int64("scheduled_plan_id", "spi", 0, "Scheduled Plan Id")
              cobra.MarkFlagRequired(updateScheduledPlanCmd.Flags(), "scheduled_plan_id")
              

              updateScheduledPlanCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateScheduledPlanCmd.Flags(), "body")
              
            

              scheduledPlanCmd.AddCommand(deleteScheduledPlanCmd)
            
              deleteScheduledPlanCmd.Flags().Int64("scheduled_plan_id", "spi", 0, "Scheduled Plan Id")
              cobra.MarkFlagRequired(deleteScheduledPlanCmd.Flags(), "scheduled_plan_id")
              
            

              scheduledPlanCmd.AddCommand(allScheduledPlansCmd)
            
              allScheduledPlansCmd.Flags().Int64("user_id", "ui", 0, "Return scheduled plans belonging to this user_id. If not provided, returns scheduled plans owned by the caller.")
              
              

              allScheduledPlansCmd.Flags().String("fields", "f", "", "Comma delimited list of field names. If provided, only the fields specified will be included in the response")
              
              

              allScheduledPlansCmd.Flags().BoolP("all_users", "au", false, "Return scheduled plans belonging to all users (caller needs see_schedules permission)")
              
              
            

              scheduledPlanCmd.AddCommand(createScheduledPlanCmd)
            
              createScheduledPlanCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createScheduledPlanCmd.Flags(), "body")
              
            

              scheduledPlanCmd.AddCommand(scheduledPlanRunOnceCmd)
            
              scheduledPlanRunOnceCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(scheduledPlanRunOnceCmd.Flags(), "body")
              
            

              scheduledPlanCmd.AddCommand(scheduledPlansForLookCmd)
            
              scheduledPlansForLookCmd.Flags().Int64("look_id", "li", 0, "Look Id")
              cobra.MarkFlagRequired(scheduledPlansForLookCmd.Flags(), "look_id")
              

              scheduledPlansForLookCmd.Flags().Int64("user_id", "ui", 0, "User Id (default is requesting user if not specified)")
              
              

              scheduledPlansForLookCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              scheduledPlansForLookCmd.Flags().BoolP("all_users", "au", false, "Return scheduled plans belonging to all users for the look")
              
              
            

              scheduledPlanCmd.AddCommand(scheduledPlansForDashboardCmd)
            
              scheduledPlansForDashboardCmd.Flags().Int64("dashboard_id", "di", 0, "Dashboard Id")
              cobra.MarkFlagRequired(scheduledPlansForDashboardCmd.Flags(), "dashboard_id")
              

              scheduledPlansForDashboardCmd.Flags().Int64("user_id", "ui", 0, "User Id (default is requesting user if not specified)")
              
              

              scheduledPlansForDashboardCmd.Flags().BoolP("all_users", "au", false, "Return scheduled plans belonging to all users for the dashboard")
              
              

              scheduledPlansForDashboardCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              scheduledPlanCmd.AddCommand(scheduledPlansForLookmlDashboardCmd)
            
              scheduledPlansForLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "ldi", "", "LookML Dashboard Id")
              cobra.MarkFlagRequired(scheduledPlansForLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
              

              scheduledPlansForLookmlDashboardCmd.Flags().Int64("user_id", "ui", 0, "User Id (default is requesting user if not specified)")
              
              

              scheduledPlansForLookmlDashboardCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              scheduledPlansForLookmlDashboardCmd.Flags().BoolP("all_users", "au", false, "Return scheduled plans belonging to all users for the dashboard")
              
              
            

              scheduledPlanCmd.AddCommand(scheduledPlanRunOnceByIdCmd)
            
              scheduledPlanRunOnceByIdCmd.Flags().Int64("scheduled_plan_id", "spi", 0, "Id of schedule plan to copy and run")
              cobra.MarkFlagRequired(scheduledPlanRunOnceByIdCmd.Flags(), "scheduled_plan_id")
              

              scheduledPlanRunOnceByIdCmd.Flags().String("body", "b", "", "")
              
              
            
  rootCmd.AddCommand(scheduledPlanCmd)

              sessionCmd.AddCommand(sessionCmd9658)
            
            

              sessionCmd.AddCommand(updateSessionCmd)
            
              updateSessionCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateSessionCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(sessionCmd)

              spaceCmd.AddCommand(searchSpacesCmd)
            
              searchSpacesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchSpacesCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              searchSpacesCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              searchSpacesCmd.Flags().Int64("limit", "l", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
              
              

              searchSpacesCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
              
              

              searchSpacesCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchSpacesCmd.Flags().String("name", "n", "", "Match Space title.")
              
              

              searchSpacesCmd.Flags().Int64("id", "i", 0, "Match Space id")
              
              

              searchSpacesCmd.Flags().String("parent_id", "pi", "", "Filter on a children of a particular space.")
              
              

              searchSpacesCmd.Flags().String("creator_id", "ci", "", "Filter on spaces created by a particular user.")
              
              

              searchSpacesCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              

              searchSpacesCmd.Flags().BoolP("is_shared_root", "isr", false, "Match is shared root")
              
              
            

              spaceCmd.AddCommand(spaceCmd7986)
            
              spaceCmd7986.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceCmd7986.Flags(), "space_id")
              

              spaceCmd7986.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              spaceCmd.AddCommand(updateSpaceCmd)
            
              updateSpaceCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(updateSpaceCmd.Flags(), "space_id")
              

              updateSpaceCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateSpaceCmd.Flags(), "body")
              
            

              spaceCmd.AddCommand(deleteSpaceCmd)
            
              deleteSpaceCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(deleteSpaceCmd.Flags(), "space_id")
              
            

              spaceCmd.AddCommand(allSpacesCmd)
            
              allSpacesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              spaceCmd.AddCommand(createSpaceCmd)
            
              createSpaceCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createSpaceCmd.Flags(), "body")
              
            

              spaceCmd.AddCommand(spaceChildrenCmd)
            
              spaceChildrenCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceChildrenCmd.Flags(), "space_id")
              

              spaceChildrenCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              spaceChildrenCmd.Flags().Int64("page", "p", 0, "Requested page.")
              
              

              spaceChildrenCmd.Flags().Int64("per_page", "pp", 0, "Results per page.")
              
              

              spaceChildrenCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              
            

              spaceCmd.AddCommand(spaceChildrenSearchCmd)
            
              spaceChildrenSearchCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceChildrenSearchCmd.Flags(), "space_id")
              

              spaceChildrenSearchCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              spaceChildrenSearchCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              spaceChildrenSearchCmd.Flags().String("name", "n", "", "Match Space name.")
              
              
            

              spaceCmd.AddCommand(spaceParentCmd)
            
              spaceParentCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceParentCmd.Flags(), "space_id")
              

              spaceParentCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              spaceCmd.AddCommand(spaceAncestorsCmd)
            
              spaceAncestorsCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceAncestorsCmd.Flags(), "space_id")
              

              spaceAncestorsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              spaceCmd.AddCommand(spaceLooksCmd)
            
              spaceLooksCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceLooksCmd.Flags(), "space_id")
              

              spaceLooksCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              spaceCmd.AddCommand(spaceDashboardsCmd)
            
              spaceDashboardsCmd.Flags().String("space_id", "si", "", "Id of space")
              cobra.MarkFlagRequired(spaceDashboardsCmd.Flags(), "space_id")
              

              spaceDashboardsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            
  rootCmd.AddCommand(spaceCmd)

              themeCmd.AddCommand(allThemesCmd)
            
              allThemesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              themeCmd.AddCommand(createThemeCmd)
            
              createThemeCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createThemeCmd.Flags(), "body")
              
            

              themeCmd.AddCommand(searchThemesCmd)
            
              searchThemesCmd.Flags().Int64("id", "i", 0, "Match theme id.")
              
              

              searchThemesCmd.Flags().String("name", "n", "", "Match theme name.")
              
              

              searchThemesCmd.Flags().String("begin_at", "ba", "", "Timestamp for activation.")
              
              

              searchThemesCmd.Flags().String("end_at", "ea", "", "Timestamp for expiration.")
              
              

              searchThemesCmd.Flags().Int64("limit", "l", 0, "Number of results to return (used with `offset`).")
              
              

              searchThemesCmd.Flags().Int64("offset", "o", 0, "Number of results to skip before returning any (used with `limit`).")
              
              

              searchThemesCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchThemesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              searchThemesCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              
            

              themeCmd.AddCommand(defaultThemeCmd)
            
              defaultThemeCmd.Flags().String("ts", "t", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
              
              
            

              themeCmd.AddCommand(setDefaultThemeCmd)
            
              setDefaultThemeCmd.Flags().String("name", "n", "", "Name of theme to set as default")
              cobra.MarkFlagRequired(setDefaultThemeCmd.Flags(), "name")
              
            

              themeCmd.AddCommand(activeThemesCmd)
            
              activeThemesCmd.Flags().String("name", "n", "", "Name of theme")
              
              

              activeThemesCmd.Flags().String("ts", "t", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
              
              

              activeThemesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              themeCmd.AddCommand(themeOrDefaultCmd)
            
              themeOrDefaultCmd.Flags().String("name", "n", "", "Name of theme")
              cobra.MarkFlagRequired(themeOrDefaultCmd.Flags(), "name")
              

              themeOrDefaultCmd.Flags().String("ts", "t", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
              
              
            

              themeCmd.AddCommand(validateThemeCmd)
            
              validateThemeCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(validateThemeCmd.Flags(), "body")
              
            

              themeCmd.AddCommand(themeCmd5617)
            
              themeCmd5617.Flags().String("theme_id", "ti", "", "Id of theme")
              cobra.MarkFlagRequired(themeCmd5617.Flags(), "theme_id")
              

              themeCmd5617.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              themeCmd.AddCommand(updateThemeCmd)
            
              updateThemeCmd.Flags().String("theme_id", "ti", "", "Id of theme")
              cobra.MarkFlagRequired(updateThemeCmd.Flags(), "theme_id")
              

              updateThemeCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateThemeCmd.Flags(), "body")
              
            

              themeCmd.AddCommand(deleteThemeCmd)
            
              deleteThemeCmd.Flags().String("theme_id", "ti", "", "Id of theme")
              cobra.MarkFlagRequired(deleteThemeCmd.Flags(), "theme_id")
              
            
  rootCmd.AddCommand(themeCmd)

              userCmd.AddCommand(meCmd)
            
              meCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(allUsersCmd)
            
              allUsersCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allUsersCmd.Flags().Int64("page", "p", 0, "Return only page N of paginated results")
              
              

              allUsersCmd.Flags().Int64("per_page", "pp", 0, "Return N rows of data per page")
              
              

              allUsersCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              allUsersCmd.Flags().String("ids", "i", "", "Optional list of ids to get specific users.")
              
              
            

              userCmd.AddCommand(createUserCmd)
            
              createUserCmd.Flags().String("body", "b", "", "")
              
              

              createUserCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(searchUsersCmd)
            
              searchUsersCmd.Flags().String("fields", "f", "", "Include only these fields in the response")
              
              

              searchUsersCmd.Flags().Int64("page", "p", 0, "Return only page N of paginated results")
              
              

              searchUsersCmd.Flags().Int64("per_page", "pp", 0, "Return N rows of data per page")
              
              

              searchUsersCmd.Flags().String("sorts", "s", "", "Fields to sort by.")
              
              

              searchUsersCmd.Flags().Int64("id", "i", 0, "Match User Id.")
              
              

              searchUsersCmd.Flags().String("first_name", "fn", "", "Match First name.")
              
              

              searchUsersCmd.Flags().String("last_name", "ln", "", "Match Last name.")
              
              

              searchUsersCmd.Flags().BoolP("verified_looker_employee", "vle", false, "Search for user accounts associated with Looker employees")
              
              

              searchUsersCmd.Flags().BoolP("embed_user", "eu", false, "Search for only embed users")
              
              

              searchUsersCmd.Flags().String("email", "e", "", "Search for the user with this email address")
              
              

              searchUsersCmd.Flags().BoolP("is_disabled", "id", false, "Search for disabled user accounts")
              
              

              searchUsersCmd.Flags().BoolP("filter_or", "fo", false, "Combine given search criteria in a boolean OR expression")
              
              

              searchUsersCmd.Flags().Int64("content_metadata_id", "cmi", 0, "Search for users who have access to this content_metadata item")
              
              

              searchUsersCmd.Flags().Int64("group_id", "gi", 0, "Search for users who are direct members of this group")
              
              
            

              userCmd.AddCommand(searchUsersNamesCmd)
            
              searchUsersNamesCmd.Flags().String("pattern", "p", "", "Pattern to match")
              cobra.MarkFlagRequired(searchUsersNamesCmd.Flags(), "pattern")
              

              searchUsersNamesCmd.Flags().String("fields", "f", "", "Include only these fields in the response")
              
              

              searchUsersNamesCmd.Flags().Int64("page", "p", 0, "Return only page N of paginated results")
              
              

              searchUsersNamesCmd.Flags().Int64("per_page", "pp", 0, "Return N rows of data per page")
              
              

              searchUsersNamesCmd.Flags().String("sorts", "s", "", "Fields to sort by")
              
              

              searchUsersNamesCmd.Flags().Int64("id", "i", 0, "Match User Id")
              
              

              searchUsersNamesCmd.Flags().String("first_name", "fn", "", "Match First name")
              
              

              searchUsersNamesCmd.Flags().String("last_name", "ln", "", "Match Last name")
              
              

              searchUsersNamesCmd.Flags().BoolP("verified_looker_employee", "vle", false, "Match Verified Looker employee")
              
              

              searchUsersNamesCmd.Flags().String("email", "e", "", "Match Email Address")
              
              

              searchUsersNamesCmd.Flags().BoolP("is_disabled", "id", false, "Include or exclude disabled accounts in the results")
              
              
            

              userCmd.AddCommand(userCmd4130)
            
              userCmd4130.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(userCmd4130.Flags(), "user_id")
              

              userCmd4130.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(updateUserCmd)
            
              updateUserCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(updateUserCmd.Flags(), "user_id")
              

              updateUserCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateUserCmd.Flags(), "body")
              

              updateUserCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCmd)
            
              deleteUserCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(deleteUserCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userForCredentialCmd)
            
              userForCredentialCmd.Flags().String("credential_type", "ct", "", "Type name of credential")
              cobra.MarkFlagRequired(userForCredentialCmd.Flags(), "credential_type")
              

              userForCredentialCmd.Flags().String("credential_id", "ci", "", "Id of credential")
              cobra.MarkFlagRequired(userForCredentialCmd.Flags(), "credential_id")
              

              userForCredentialCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(userCredentialsEmailCmd)
            
              userCredentialsEmailCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsEmailCmd.Flags(), "user_id")
              

              userCredentialsEmailCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(createUserCredentialsEmailCmd)
            
              createUserCredentialsEmailCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(createUserCredentialsEmailCmd.Flags(), "user_id")
              

              createUserCredentialsEmailCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createUserCredentialsEmailCmd.Flags(), "body")
              

              createUserCredentialsEmailCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(updateUserCredentialsEmailCmd)
            
              updateUserCredentialsEmailCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(updateUserCredentialsEmailCmd.Flags(), "user_id")
              

              updateUserCredentialsEmailCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateUserCredentialsEmailCmd.Flags(), "body")
              

              updateUserCredentialsEmailCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsEmailCmd)
            
              deleteUserCredentialsEmailCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsEmailCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsTotpCmd)
            
              userCredentialsTotpCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsTotpCmd.Flags(), "user_id")
              

              userCredentialsTotpCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(createUserCredentialsTotpCmd)
            
              createUserCredentialsTotpCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(createUserCredentialsTotpCmd.Flags(), "user_id")
              

              createUserCredentialsTotpCmd.Flags().String("body", "b", "", "")
              
              

              createUserCredentialsTotpCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsTotpCmd)
            
              deleteUserCredentialsTotpCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsTotpCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsLdapCmd)
            
              userCredentialsLdapCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsLdapCmd.Flags(), "user_id")
              

              userCredentialsLdapCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsLdapCmd)
            
              deleteUserCredentialsLdapCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsLdapCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsGoogleCmd)
            
              userCredentialsGoogleCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsGoogleCmd.Flags(), "user_id")
              

              userCredentialsGoogleCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsGoogleCmd)
            
              deleteUserCredentialsGoogleCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsGoogleCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsSamlCmd)
            
              userCredentialsSamlCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsSamlCmd.Flags(), "user_id")
              

              userCredentialsSamlCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsSamlCmd)
            
              deleteUserCredentialsSamlCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsSamlCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsOidcCmd)
            
              userCredentialsOidcCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsOidcCmd.Flags(), "user_id")
              

              userCredentialsOidcCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsOidcCmd)
            
              deleteUserCredentialsOidcCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsOidcCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userCredentialsApi3Cmd)
            
              userCredentialsApi3Cmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(userCredentialsApi3Cmd.Flags(), "user_id")
              

              userCredentialsApi3Cmd.Flags().Int64("credentials_api3_id", "cai", 0, "Id of API 3 Credential")
              cobra.MarkFlagRequired(userCredentialsApi3Cmd.Flags(), "credentials_api3_id")
              

              userCredentialsApi3Cmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsApi3Cmd)
            
              deleteUserCredentialsApi3Cmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsApi3Cmd.Flags(), "user_id")
              

              deleteUserCredentialsApi3Cmd.Flags().Int64("credentials_api3_id", "cai", 0, "id of API 3 Credential")
              cobra.MarkFlagRequired(deleteUserCredentialsApi3Cmd.Flags(), "credentials_api3_id")
              
            

              userCmd.AddCommand(allUserCredentialsApi3sCmd)
            
              allUserCredentialsApi3sCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(allUserCredentialsApi3sCmd.Flags(), "user_id")
              

              allUserCredentialsApi3sCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(createUserCredentialsApi3Cmd)
            
              createUserCredentialsApi3Cmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(createUserCredentialsApi3Cmd.Flags(), "user_id")
              

              createUserCredentialsApi3Cmd.Flags().String("body", "b", "", "")
              
              

              createUserCredentialsApi3Cmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(userCredentialsEmbedCmd)
            
              userCredentialsEmbedCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(userCredentialsEmbedCmd.Flags(), "user_id")
              

              userCredentialsEmbedCmd.Flags().Int64("credentials_embed_id", "cei", 0, "Id of Embedding Credential")
              cobra.MarkFlagRequired(userCredentialsEmbedCmd.Flags(), "credentials_embed_id")
              

              userCredentialsEmbedCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsEmbedCmd)
            
              deleteUserCredentialsEmbedCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsEmbedCmd.Flags(), "user_id")
              

              deleteUserCredentialsEmbedCmd.Flags().Int64("credentials_embed_id", "cei", 0, "id of Embedding Credential")
              cobra.MarkFlagRequired(deleteUserCredentialsEmbedCmd.Flags(), "credentials_embed_id")
              
            

              userCmd.AddCommand(allUserCredentialsEmbedsCmd)
            
              allUserCredentialsEmbedsCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(allUserCredentialsEmbedsCmd.Flags(), "user_id")
              

              allUserCredentialsEmbedsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(userCredentialsLookerOpenidCmd)
            
              userCredentialsLookerOpenidCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userCredentialsLookerOpenidCmd.Flags(), "user_id")
              

              userCredentialsLookerOpenidCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserCredentialsLookerOpenidCmd)
            
              deleteUserCredentialsLookerOpenidCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserCredentialsLookerOpenidCmd.Flags(), "user_id")
              
            

              userCmd.AddCommand(userSessionCmd)
            
              userSessionCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(userSessionCmd.Flags(), "user_id")
              

              userSessionCmd.Flags().Int64("session_id", "si", 0, "Id of Web Login Session")
              cobra.MarkFlagRequired(userSessionCmd.Flags(), "session_id")
              

              userSessionCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(deleteUserSessionCmd)
            
              deleteUserSessionCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(deleteUserSessionCmd.Flags(), "user_id")
              

              deleteUserSessionCmd.Flags().Int64("session_id", "si", 0, "id of Web Login Session")
              cobra.MarkFlagRequired(deleteUserSessionCmd.Flags(), "session_id")
              
            

              userCmd.AddCommand(allUserSessionsCmd)
            
              allUserSessionsCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(allUserSessionsCmd.Flags(), "user_id")
              

              allUserSessionsCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(createUserCredentialsEmailPasswordResetCmd)
            
              createUserCredentialsEmailPasswordResetCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(createUserCredentialsEmailPasswordResetCmd.Flags(), "user_id")
              

              createUserCredentialsEmailPasswordResetCmd.Flags().BoolP("expires", "e", false, "Expiring token.")
              
              

              createUserCredentialsEmailPasswordResetCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(userRolesCmd)
            
              userRolesCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(userRolesCmd.Flags(), "user_id")
              

              userRolesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              userRolesCmd.Flags().BoolP("direct_association_only", "dao", false, "Get only roles associated directly with the user: exclude those only associated through groups.")
              
              
            

              userCmd.AddCommand(setUserRolesCmd)
            
              setUserRolesCmd.Flags().Int64("user_id", "ui", 0, "id of user")
              cobra.MarkFlagRequired(setUserRolesCmd.Flags(), "user_id")
              

              setUserRolesCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(setUserRolesCmd.Flags(), "body")
              

              setUserRolesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userCmd.AddCommand(userAttributeUserValuesCmd)
            
              userAttributeUserValuesCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(userAttributeUserValuesCmd.Flags(), "user_id")
              

              userAttributeUserValuesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              userAttributeUserValuesCmd.Flags().String("user_attribute_ids", "uai", "", "Specific user attributes to request. Omit or leave blank to request all user attributes.")
              
              

              userAttributeUserValuesCmd.Flags().BoolP("all_values", "av", false, "If true, returns all values in the search path instead of just the first value found. Useful for debugging group precedence.")
              
              

              userAttributeUserValuesCmd.Flags().BoolP("include_unset", "iu", false, "If true, returns an empty record for each requested attribute that has no user, group, or default value.")
              
              
            

              userCmd.AddCommand(setUserAttributeUserValueCmd)
            
              setUserAttributeUserValueCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "user_id")
              

              setUserAttributeUserValueCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "user_attribute_id")
              

              setUserAttributeUserValueCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "body")
              
            

              userCmd.AddCommand(deleteUserAttributeUserValueCmd)
            
              deleteUserAttributeUserValueCmd.Flags().Int64("user_id", "ui", 0, "Id of user")
              cobra.MarkFlagRequired(deleteUserAttributeUserValueCmd.Flags(), "user_id")
              

              deleteUserAttributeUserValueCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(deleteUserAttributeUserValueCmd.Flags(), "user_attribute_id")
              
            
  rootCmd.AddCommand(userCmd)

              userAttributeCmd.AddCommand(allUserAttributesCmd)
            
              allUserAttributesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              

              allUserAttributesCmd.Flags().String("sorts", "s", "", "Fields to order the results by. Sortable fields include: name, label")
              
              
            

              userAttributeCmd.AddCommand(createUserAttributeCmd)
            
              createUserAttributeCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(createUserAttributeCmd.Flags(), "body")
              

              createUserAttributeCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userAttributeCmd.AddCommand(userAttributeCmd6881)
            
              userAttributeCmd6881.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(userAttributeCmd6881.Flags(), "user_attribute_id")
              

              userAttributeCmd6881.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userAttributeCmd.AddCommand(updateUserAttributeCmd)
            
              updateUserAttributeCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(updateUserAttributeCmd.Flags(), "user_attribute_id")
              

              updateUserAttributeCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(updateUserAttributeCmd.Flags(), "body")
              

              updateUserAttributeCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userAttributeCmd.AddCommand(deleteUserAttributeCmd)
            
              deleteUserAttributeCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user_attribute")
              cobra.MarkFlagRequired(deleteUserAttributeCmd.Flags(), "user_attribute_id")
              
            

              userAttributeCmd.AddCommand(allUserAttributeGroupValuesCmd)
            
              allUserAttributeGroupValuesCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(allUserAttributeGroupValuesCmd.Flags(), "user_attribute_id")
              

              allUserAttributeGroupValuesCmd.Flags().String("fields", "f", "", "Requested fields.")
              
              
            

              userAttributeCmd.AddCommand(setUserAttributeGroupValuesCmd)
            
              setUserAttributeGroupValuesCmd.Flags().Int64("user_attribute_id", "uai", 0, "Id of user attribute")
              cobra.MarkFlagRequired(setUserAttributeGroupValuesCmd.Flags(), "user_attribute_id")
              

              setUserAttributeGroupValuesCmd.Flags().String("body", "b", "", "")
              cobra.MarkFlagRequired(setUserAttributeGroupValuesCmd.Flags(), "body")
              
            
  rootCmd.AddCommand(userAttributeCmd)

              workspaceCmd.AddCommand(allWorkspacesCmd)
            
            

              workspaceCmd.AddCommand(workspaceCmd1119)
            
              workspaceCmd1119.Flags().String("workspace_id", "wi", "", "Id of the workspace ")
              cobra.MarkFlagRequired(workspaceCmd1119.Flags(), "workspace_id")
              
            
  rootCmd.AddCommand(workspaceCmd)
}