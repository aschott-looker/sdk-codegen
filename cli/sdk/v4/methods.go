
package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

var alertCmd = &cobra.Command{
  Use:   "Alert",
  Short: "Alert",
  Long: "Alert",
}


var searchAlertsCmd = &cobra.Command{
  Use:   "searchAlerts",
  Short: "Search Alerts",
  Long: `### Search Alerts
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_alerts called")
  },
}


var getAlertCmd = &cobra.Command{
  Use:   "getAlert",
  Short: "Get an alert",
  Long: `### Get an alert by a given alert ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_alert called")
  },
}


var updateAlertCmd = &cobra.Command{
  Use:   "updateAlert",
  Short: "Update an alert",
  Long: `### Update an alert
# Required fields: 'owner_id', 'field', 'destinations', 'comparison_type', 'threshold', 'cron'
#
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_alert called")
  },
}


var updateAlertFieldCmd = &cobra.Command{
  Use:   "updateAlertField",
  Short: "Update select fields on an alert",
  Long: `### Update select alert fields
# Available fields: 'owner_id', 'is_disabled', 'disabled_reason', 'is_public', 'threshold'
#
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_alert_field called")
  },
}


var deleteAlertCmd = &cobra.Command{
  Use:   "deleteAlert",
  Short: "Delete an alert",
  Long: `### Delete an alert by a given alert ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_alert called")
  },
}


var createAlertCmd = &cobra.Command{
  Use:   "createAlert",
  Short: "Create an alert",
  Long: `### Create a new alert and return details of the newly created object

Required fields: 'field', 'destinations', 'comparison_type', 'threshold', 'cron'

Example Request:
Run alert on dashboard element '103' at 5am every day. Send an email to 'test@test.com' if inventory for Los Angeles (using dashboard filter 'Warehouse Name') is lower than 1,000
'''
{
  "cron": "0 5 * * *",
  "custom_title": "Alert when LA inventory is low",
  "dashboard_element_id": 103,
  "applied_dashboard_filters": [
    {
      "filter_title": "Warehouse Name",
      "field_name": "distribution_centers.name",
      "filter_value": "Los Angeles CA",
      "filter_description": "is Los Angeles CA"
    }
  ],
  "comparison_type": "LESS_THAN",
  "destinations": [
    {
      "destination_type": "EMAIL",
      "email_address": "test@test.com"
    }
  ],
  "field": {
    "title": "Number on Hand",
    "name": "inventory_items.number_on_hand"
  },
  "is_disabled": false,
  "is_public": true,
  "threshold": 1000
}
'''
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_alert called")
  },
}


var enqueueAlertCmd = &cobra.Command{
  Use:   "enqueueAlert",
  Short: "Enqueue an alert",
  Long: `### Enqueue an Alert by ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("enqueue_alert called")
  },
}




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
}


var createEmbedSecretCmd = &cobra.Command{
  Use:   "createEmbedSecret",
  Short: "Create Embed Secret",
  Long: `### Create an embed secret using the specified information.

The value of the 'secret' field will be set by Looker and returned.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_embed_secret called")
  },
}


var deleteEmbedSecretCmd = &cobra.Command{
  Use:   "deleteEmbedSecret",
  Short: "Delete Embed Secret",
  Long: `### Delete an embed secret.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_embed_secret called")
  },
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
    fmt.Println("create_sso_embed_url called")
  },
}


var createEmbedUrlAsMeCmd = &cobra.Command{
  Use:   "createEmbedUrlAsMe",
  Short: "Create Embed URL",
  Long: `### Create an Embed URL

Creates an embed URL that runs as the Looker user making this API call. ("Embed as me")
This embed URL can then be used to instantiate a Looker embed session in a
"Powered by Looker" (PBL) web application.

This is similar to Private Embedding (https://docs.looker.com/r/admin/embed/private-embed). Instead of
of logging into the Web UI to authenticate, the user has already authenticated against the API to be able to
make this call. However, unlike Private Embed where the user has access to any other part of the Looker UI,
the embed web session created by requesting the EmbedUrlResponse.url in a browser only has access to
content visible under the '/embed' context.

An embed URL can only be used once, and must be used within 5 minutes of being created. After it
has been used to request a page from the Looker server, the URL is invalid. Future requests using
the same URL will fail. This is to prevent 'replay attacks'.

The 'target_url' property must be a complete URL of a Looker Embedded UI page - scheme, hostname, path starting with "/embed" and query params.
To load a dashboard with id 56 and with a filter of 'Date=1 years', the looker Embed URL would look like 'https://myname.looker.com/embed/dashboards/56?Date=1%20years'.
The best way to obtain this target_url is to navigate to the desired Looker page in your web browser,
copy the URL shown in the browser address bar, insert "/embed" after the host/port, and paste it into the 'target_url' property as a quoted string value in this API request.

#### Security Note
Protect this embed URL as you would an access token or password credentials - do not write
it to disk, do not pass it to a third party, and only pass it through a secure HTTPS
encrypted transport.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_embed_url_as_me called")
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
    fmt.Println("ldap_config called")
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
    fmt.Println("update_ldap_config called")
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
    fmt.Println("test_ldap_config_connection called")
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
    fmt.Println("test_ldap_config_auth called")
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
    fmt.Println("test_ldap_config_user_info called")
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
    fmt.Println("test_ldap_config_user_auth called")
  },
}


var allOauthClientAppsCmd = &cobra.Command{
  Use:   "allOauthClientApps",
  Short: "Get All OAuth Client Apps",
  Long: `### List All OAuth Client Apps

Lists all applications registered to use OAuth2 login with this Looker instance, including
enabled and disabled apps.

Results are filtered to include only the apps that the caller (current user)
has permission to see.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_oauth_client_apps called")
  },
}


var oauthClientAppCmd = &cobra.Command{
  Use:   "oauthClientApp",
  Short: "Get OAuth Client App",
  Long: `### Get Oauth Client App

Returns the registered app client with matching client_guid.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oauth_client_app called")
  },
}


var registerOauthClientAppCmd = &cobra.Command{
  Use:   "registerOauthClientApp",
  Short: "Register OAuth App",
  Long: `### Register an OAuth2 Client App

Registers details identifying an external web app or native app as an OAuth2 login client of the Looker instance.
The app registration must provide a unique client_guid and redirect_uri that the app will present
in OAuth login requests. If the client_guid and redirect_uri parameters in the login request do not match
the app details registered with the Looker instance, the request is assumed to be a forgery and is rejected.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("register_oauth_client_app called")
  },
}


var updateOauthClientAppCmd = &cobra.Command{
  Use:   "updateOauthClientApp",
  Short: "Update OAuth App",
  Long: `### Update OAuth2 Client App Details

Modifies the details a previously registered OAuth2 login client app.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_oauth_client_app called")
  },
}


var deleteOauthClientAppCmd = &cobra.Command{
  Use:   "deleteOauthClientApp",
  Short: "Delete OAuth Client App",
  Long: `### Delete OAuth Client App

Deletes the registration info of the app with the matching client_guid.
All active sessions and tokens issued for this app will immediately become invalid.

### Note: this deletion cannot be undone.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_oauth_client_app called")
  },
}


var invalidateTokensCmd = &cobra.Command{
  Use:   "invalidateTokens",
  Short: "Invalidate Tokens",
  Long: `### Invalidate All Issued Tokens

Immediately invalidates all auth codes, sessions, access tokens and refresh tokens issued for
this app for ALL USERS of this app.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("invalidate_tokens called")
  },
}


var activateAppUserCmd = &cobra.Command{
  Use:   "activateAppUser",
  Short: "Activate OAuth App User",
  Long: `### Activate an app for a user

Activates a user for a given oauth client app. This indicates the user has been informed that
the app will have access to the user's looker data, and that the user has accepted and allowed
the app to use their Looker account.

Activating a user for an app that the user is already activated with returns a success response.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("activate_app_user called")
  },
}


var deactivateAppUserCmd = &cobra.Command{
  Use:   "deactivateAppUser",
  Short: "Deactivate OAuth App User",
  Long: `### Deactivate an app for a user

Deactivate a user for a given oauth client app. All tokens issued to the app for
this user will be invalid immediately. Before the user can use the app with their
Looker account, the user will have to read and accept an account use disclosure statement for the app.

Admin users can deactivate other users, but non-admin users can only deactivate themselves.

As with most REST DELETE operations, this endpoint does not return an error if the indicated
resource (app or user) does not exist or has already been deactivated.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deactivate_app_user called")
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
    fmt.Println("oidc_config called")
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
    fmt.Println("update_oidc_config called")
  },
}


var oidcTestConfigCmd = &cobra.Command{
  Use:   "oidcTestConfig",
  Short: "Get OIDC Test Configuration",
  Long: `### Get a OIDC test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oidc_test_config called")
  },
}


var deleteOidcTestConfigCmd = &cobra.Command{
  Use:   "deleteOidcTestConfig",
  Short: "Delete OIDC Test Configuration",
  Long: `### Delete a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_oidc_test_config called")
  },
}


var createOidcTestConfigCmd = &cobra.Command{
  Use:   "createOidcTestConfig",
  Short: "Create OIDC Test Configuration",
  Long: `### Create a OIDC test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_oidc_test_config called")
  },
}


var passwordConfigCmd = &cobra.Command{
  Use:   "passwordConfig",
  Short: "Get Password Config",
  Long: `### Get password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("password_config called")
  },
}


var updatePasswordConfigCmd = &cobra.Command{
  Use:   "updatePasswordConfig",
  Short: "Update Password Config",
  Long: `### Update password config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_password_config called")
  },
}


var forcePasswordResetAtNextLoginForAllUsersCmd = &cobra.Command{
  Use:   "forcePasswordResetAtNextLoginForAllUsers",
  Short: "Force password reset",
  Long: `### Force all credentials_email users to reset their login passwords upon their next login.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("force_password_reset_at_next_login_for_all_users called")
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
    fmt.Println("saml_config called")
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
    fmt.Println("update_saml_config called")
  },
}


var samlTestConfigCmd = &cobra.Command{
  Use:   "samlTestConfig",
  Short: "Get SAML Test Configuration",
  Long: `### Get a SAML test configuration by test_slug.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("saml_test_config called")
  },
}


var deleteSamlTestConfigCmd = &cobra.Command{
  Use:   "deleteSamlTestConfig",
  Short: "Delete SAML Test Configuration",
  Long: `### Delete a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_saml_test_config called")
  },
}


var createSamlTestConfigCmd = &cobra.Command{
  Use:   "createSamlTestConfig",
  Short: "Create SAML Test Configuration",
  Long: `### Create a SAML test configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_saml_test_config called")
  },
}


var parseSamlIdpMetadataCmd = &cobra.Command{
  Use:   "parseSamlIdpMetadata",
  Short: "Parse SAML IdP XML",
  Long: `### Parse the given xml as a SAML IdP metadata document and return the result.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("parse_saml_idp_metadata called")
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
    fmt.Println("fetch_and_parse_saml_idp_metadata called")
  },
}


var sessionConfigCmd = &cobra.Command{
  Use:   "sessionConfig",
  Short: "Get Session Config",
  Long: `### Get session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("session_config called")
  },
}


var updateSessionConfigCmd = &cobra.Command{
  Use:   "updateSessionConfig",
  Short: "Update Session Config",
  Long: `### Update session config.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_session_config called")
  },
}


var allUserLoginLockoutsCmd = &cobra.Command{
  Use:   "allUserLoginLockouts",
  Short: "Get All User Login Lockouts",
  Long: `### Get currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_login_lockouts called")
  },
}


var searchUserLoginLockoutsCmd = &cobra.Command{
  Use:   "searchUserLoginLockouts",
  Short: "Search User Login Lockouts",
  Long: `### Search currently locked-out users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_user_login_lockouts called")
  },
}


var deleteUserLoginLockoutCmd = &cobra.Command{
  Use:   "deleteUserLoginLockout",
  Short: "Delete User Login Lockout",
  Long: `### Removes login lockout for the associated user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_login_lockout called")
  },
}




var boardCmd = &cobra.Command{
  Use:   "Board",
  Short: "Manage Boards",
  Long: "Manage Boards",
}


var allBoardsCmd = &cobra.Command{
  Use:   "allBoards",
  Short: "Get All Boards",
  Long: `### Get information about all boards.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_boards called")
  },
}


var createBoardCmd = &cobra.Command{
  Use:   "createBoard",
  Short: "Create Board",
  Long: `### Create a new board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_board called")
  },
}


var searchBoardsCmd = &cobra.Command{
  Use:   "searchBoards",
  Short: "Search Boards",
  Long: `### Search Boards

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
    fmt.Println("search_boards called")
  },
}


var boardCmd7831 = &cobra.Command{
  Use:   "board",
  Short: "Get Board",
  Long: `### Get information about a board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("board called")
  },
}


var updateBoardCmd = &cobra.Command{
  Use:   "updateBoard",
  Short: "Update Board",
  Long: `### Update a board definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_board called")
  },
}


var deleteBoardCmd = &cobra.Command{
  Use:   "deleteBoard",
  Short: "Delete Board",
  Long: `### Delete a board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_board called")
  },
}


var allBoardItemsCmd = &cobra.Command{
  Use:   "allBoardItems",
  Short: "Get All Board Items",
  Long: `### Get information about all board items.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_board_items called")
  },
}


var createBoardItemCmd = &cobra.Command{
  Use:   "createBoardItem",
  Short: "Create Board Item",
  Long: `### Create a new board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_board_item called")
  },
}


var boardItemCmd = &cobra.Command{
  Use:   "boardItem",
  Short: "Get Board Item",
  Long: `### Get information about a board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("board_item called")
  },
}


var updateBoardItemCmd = &cobra.Command{
  Use:   "updateBoardItem",
  Short: "Update Board Item",
  Long: `### Update a board item definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_board_item called")
  },
}


var deleteBoardItemCmd = &cobra.Command{
  Use:   "deleteBoardItem",
  Short: "Delete Board Item",
  Long: `### Delete a board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_board_item called")
  },
}


var allBoardSectionsCmd = &cobra.Command{
  Use:   "allBoardSections",
  Short: "Get All Board sections",
  Long: `### Get information about all board sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_board_sections called")
  },
}


var createBoardSectionCmd = &cobra.Command{
  Use:   "createBoardSection",
  Short: "Create Board section",
  Long: `### Create a new board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_board_section called")
  },
}


var boardSectionCmd = &cobra.Command{
  Use:   "boardSection",
  Short: "Get Board section",
  Long: `### Get information about a board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("board_section called")
  },
}


var updateBoardSectionCmd = &cobra.Command{
  Use:   "updateBoardSection",
  Short: "Update Board section",
  Long: `### Update a board section definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_board_section called")
  },
}


var deleteBoardSectionCmd = &cobra.Command{
  Use:   "deleteBoardSection",
  Short: "Delete Board section",
  Long: `### Delete a board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_board_section called")
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
    fmt.Println("all_color_collections called")
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
    fmt.Println("create_color_collection called")
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
    fmt.Println("color_collections_custom called")
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
    fmt.Println("color_collections_standard called")
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
    fmt.Println("default_color_collection called")
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
    fmt.Println("set_default_color_collection called")
  },
}


var colorCollectionCmd9063 = &cobra.Command{
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
    fmt.Println("color_collection called")
  },
}


var updateColorCollectionCmd = &cobra.Command{
  Use:   "updateColorCollection",
  Short: "Update Custom Color collection",
  Long: `### Update a custom color collection by id.
**Note**: Only an API user with the Admin role can call this endpoint. Unauthorized requests will return 'Not Found' (404) errors.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_color_collection called")
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
    fmt.Println("delete_color_collection called")
  },
}




var commandCmd = &cobra.Command{
  Use:   "Command",
  Short: "Manage Commands",
  Long: "Manage Commands",
}


var getAllCommandsCmd = &cobra.Command{
  Use:   "getAllCommands",
  Short: "Get All Commands",
  Long: `### Get All Commands.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_all_commands called")
  },
}


var createCommandCmd = &cobra.Command{
  Use:   "createCommand",
  Short: "Create a custom command",
  Long: `### Create a new command.
# Required fields: [:name, :linked_content_id, :linked_content_type]
# 'linked_content_type' must be one of ["dashboard", "lookml_dashboard"]
#
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_command called")
  },
}


var updateCommandCmd = &cobra.Command{
  Use:   "updateCommand",
  Short: "Update a custom command",
  Long: `### Update an existing custom command.
# Optional fields: ['name', 'description']
#
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_command called")
  },
}


var deleteCommandCmd = &cobra.Command{
  Use:   "deleteCommand",
  Short: "Delete a custom command",
  Long: `### Delete an existing custom command.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_command called")
  },
}




var configCmd = &cobra.Command{
  Use:   "Config",
  Short: "Manage General Configuration",
  Long: "Manage General Configuration",
}


var cloudStorageConfigurationCmd = &cobra.Command{
  Use:   "cloudStorageConfiguration",
  Short: "Get Cloud Storage",
  Long: `Get the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("cloud_storage_configuration called")
  },
}


var updateCloudStorageConfigurationCmd = &cobra.Command{
  Use:   "updateCloudStorageConfiguration",
  Short: "Update Cloud Storage",
  Long: `Update the current Cloud Storage Configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_cloud_storage_configuration called")
  },
}


var customWelcomeEmailCmd = &cobra.Command{
  Use:   "customWelcomeEmail",
  Short: "Get Custom Welcome Email",
  Long: `### Get the current status and content of custom welcome emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("custom_welcome_email called")
  },
}


var updateCustomWelcomeEmailCmd = &cobra.Command{
  Use:   "updateCustomWelcomeEmail",
  Short: "Update Custom Welcome Email Content",
  Long: `Update custom welcome email setting and values. Optionally send a test email with the new content to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_custom_welcome_email called")
  },
}


var updateCustomWelcomeEmailTestCmd = &cobra.Command{
  Use:   "updateCustomWelcomeEmailTest",
  Short: "Send a test welcome email to the currently logged in user with the supplied content ",
  Long: `Requests to this endpoint will send a welcome email with the custom content provided in the body to the currently logged in user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_custom_welcome_email_test called")
  },
}


var digestEmailsEnabledCmd = &cobra.Command{
  Use:   "digestEmailsEnabled",
  Short: "Get Digest_emails",
  Long: `### Retrieve the value for whether or not digest emails is enabled
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("digest_emails_enabled called")
  },
}


var updateDigestEmailsEnabledCmd = &cobra.Command{
  Use:   "updateDigestEmailsEnabled",
  Short: "Update Digest_emails",
  Long: `### Update the setting for enabling/disabling digest emails
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_digest_emails_enabled called")
  },
}


var createDigestEmailSendCmd = &cobra.Command{
  Use:   "createDigestEmailSend",
  Short: "Deliver digest email contents",
  Long: `### Trigger the generation of digest email records and send them to Looker's internal system. This does not send
any actual emails, it generates records containing content which may be of interest for users who have become inactive.
Emails will be sent at a later time from Looker's internal system if the Digest Emails feature is enabled in settings.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_digest_email_send called")
  },
}


var internalHelpResourcesContentCmd = &cobra.Command{
  Use:   "internalHelpResourcesContent",
  Short: "Get Internal Help Resources Content",
  Long: `### Set the menu item name and content for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internal_help_resources_content called")
  },
}


var updateInternalHelpResourcesContentCmd = &cobra.Command{
  Use:   "updateInternalHelpResourcesContent",
  Short: "Update internal help resources content",
  Long: `Update internal help resources content
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_internal_help_resources_content called")
  },
}


var internalHelpResourcesCmd = &cobra.Command{
  Use:   "internalHelpResources",
  Short: "Get Internal Help Resources",
  Long: `### Get and set the options for internal help resources
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("internal_help_resources called")
  },
}


var updateInternalHelpResourcesCmd = &cobra.Command{
  Use:   "updateInternalHelpResources",
  Short: "Update internal help resources configuration",
  Long: `Update internal help resources settings
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_internal_help_resources called")
  },
}


var allLegacyFeaturesCmd = &cobra.Command{
  Use:   "allLegacyFeatures",
  Short: "Get All Legacy Features",
  Long: `### Get all legacy features.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_legacy_features called")
  },
}


var legacyFeatureCmd = &cobra.Command{
  Use:   "legacyFeature",
  Short: "Get Legacy Feature",
  Long: `### Get information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("legacy_feature called")
  },
}


var updateLegacyFeatureCmd = &cobra.Command{
  Use:   "updateLegacyFeature",
  Short: "Update Legacy Feature",
  Long: `### Update information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_legacy_feature called")
  },
}


var allLocalesCmd = &cobra.Command{
  Use:   "allLocales",
  Short: "Get All Locales",
  Long: `### Get a list of locales that Looker supports.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_locales called")
  },
}


var mobileSettingsCmd = &cobra.Command{
  Use:   "mobileSettings",
  Short: "Get Mobile_Settings",
  Long: `### Get all mobile settings.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("mobile_settings called")
  },
}


var getSettingCmd = &cobra.Command{
  Use:   "getSetting",
  Short: "Get Setting",
  Long: `### Get Looker Settings

Available settings are:
 - extension_framework_enabled
 - marketplace_auto_install_enabled
 - marketplace_enabled
 - whitelabel_configuration
 - custom_welcome_email

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_setting called")
  },
}


var setSettingCmd = &cobra.Command{
  Use:   "setSetting",
  Short: "Set Setting",
  Long: `### Configure Looker Settings

Available settings are:
 - extension_framework_enabled
 - marketplace_auto_install_enabled
 - marketplace_enabled
 - whitelabel_configuration
 - custom_welcome_email

See the 'Setting' type for more information on the specific values that can be configured.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_setting called")
  },
}


var allTimezonesCmd = &cobra.Command{
  Use:   "allTimezones",
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


var apiSpecCmd = &cobra.Command{
  Use:   "apiSpec",
  Short: "Get an API specification",
  Long: `### Get an API specification for this Looker instance.

The specification is returned as a JSON document in Swagger 2.x format
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("api_spec called")
  },
}


var whitelabelConfigurationCmd = &cobra.Command{
  Use:   "whitelabelConfiguration",
  Short: "Get Whitelabel configuration",
  Long: `### This feature is enabled only by special license.
### Gets the whitelabel configuration, which includes hiding documentation links, custom favicon uploading, etc.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("whitelabel_configuration called")
  },
}


var updateWhitelabelConfigurationCmd = &cobra.Command{
  Use:   "updateWhitelabelConfiguration",
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
}


var allConnectionsCmd = &cobra.Command{
  Use:   "allConnections",
  Short: "Get All Connections",
  Long: `### Get information about all connections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_connections called")
  },
}


var createConnectionCmd = &cobra.Command{
  Use:   "createConnection",
  Short: "Create Connection",
  Long: `### Create a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_connection called")
  },
}


var connectionCmd810 = &cobra.Command{
  Use:   "connection",
  Short: "Get Connection",
  Long: `### Get information about a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection called")
  },
}


var updateConnectionCmd = &cobra.Command{
  Use:   "updateConnection",
  Short: "Update Connection",
  Long: `### Update a connection using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_connection called")
  },
}


var deleteConnectionCmd = &cobra.Command{
  Use:   "deleteConnection",
  Short: "Delete Connection",
  Long: `### Delete a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_connection called")
  },
}


var deleteConnectionOverrideCmd = &cobra.Command{
  Use:   "deleteConnectionOverride",
  Short: "Delete Connection Override",
  Long: `### Delete a connection override.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_connection_override called")
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
    fmt.Println("test_connection called")
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
    fmt.Println("test_connection_config called")
  },
}


var allDialectInfosCmd = &cobra.Command{
  Use:   "allDialectInfos",
  Short: "Get All Dialect Infos",
  Long: `### Get information about all dialects.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_dialect_infos called")
  },
}


var allExternalOauthApplicationsCmd = &cobra.Command{
  Use:   "allExternalOauthApplications",
  Short: "Get All External OAuth Applications",
  Long: `### Get all External OAuth Applications.

This is an OAuth Application which Looker uses to access external systems.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_external_oauth_applications called")
  },
}


var createExternalOauthApplicationCmd = &cobra.Command{
  Use:   "createExternalOauthApplication",
  Short: "Create External OAuth Application",
  Long: `### Create an OAuth Application using the specified configuration.

This is an OAuth Application which Looker uses to access external systems.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_external_oauth_application called")
  },
}


var createOauthApplicationUserStateCmd = &cobra.Command{
  Use:   "createOauthApplicationUserState",
  Short: "Create Create OAuth user state.",
  Long: `### Create OAuth User state.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_oauth_application_user_state called")
  },
}


var allSshServersCmd = &cobra.Command{
  Use:   "allSshServers",
  Short: "Get All SSH Servers",
  Long: `### Get information about all SSH Servers.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_ssh_servers called")
  },
}


var createSshServerCmd = &cobra.Command{
  Use:   "createSshServer",
  Short: "Create SSH Server",
  Long: `### Create an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_ssh_server called")
  },
}


var sshServerCmd = &cobra.Command{
  Use:   "sshServer",
  Short: "Get SSH Server",
  Long: `### Get information about an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ssh_server called")
  },
}


var updateSshServerCmd = &cobra.Command{
  Use:   "updateSshServer",
  Short: "Update SSH Server",
  Long: `### Update an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_ssh_server called")
  },
}


var deleteSshServerCmd = &cobra.Command{
  Use:   "deleteSshServer",
  Short: "Delete SSH Server",
  Long: `### Delete an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_ssh_server called")
  },
}


var testSshServerCmd = &cobra.Command{
  Use:   "testSshServer",
  Short: "Test SSH Server",
  Long: `### Test the SSH Server
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ssh_server called")
  },
}


var allSshTunnelsCmd = &cobra.Command{
  Use:   "allSshTunnels",
  Short: "Get All SSH Tunnels",
  Long: `### Get information about all SSH Tunnels.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_ssh_tunnels called")
  },
}


var createSshTunnelCmd = &cobra.Command{
  Use:   "createSshTunnel",
  Short: "Create SSH Tunnel",
  Long: `### Create an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_ssh_tunnel called")
  },
}


var sshTunnelCmd = &cobra.Command{
  Use:   "sshTunnel",
  Short: "Get SSH Tunnel",
  Long: `### Get information about an SSH Tunnel.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ssh_tunnel called")
  },
}


var updateSshTunnelCmd = &cobra.Command{
  Use:   "updateSshTunnel",
  Short: "Update SSH Tunnel",
  Long: `### Update an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_ssh_tunnel called")
  },
}


var deleteSshTunnelCmd = &cobra.Command{
  Use:   "deleteSshTunnel",
  Short: "Delete SSH Tunnel",
  Long: `### Delete an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_ssh_tunnel called")
  },
}


var testSshTunnelCmd = &cobra.Command{
  Use:   "testSshTunnel",
  Short: "Test SSH Tunnel",
  Long: `### Test the SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("test_ssh_tunnel called")
  },
}


var sshPublicKeyCmd = &cobra.Command{
  Use:   "sshPublicKey",
  Short: "Get SSH Public Key",
  Long: `### Get the SSH public key

Get the public key created for this instance to identify itself to a remote SSH server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("ssh_public_key called")
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
    fmt.Println("search_content_favorites called")
  },
}


var contentFavoriteCmd = &cobra.Command{
  Use:   "contentFavorite",
  Short: "Get Favorite Content",
  Long: `### Get favorite content by its id`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_favorite called")
  },
}


var deleteContentFavoriteCmd = &cobra.Command{
  Use:   "deleteContentFavorite",
  Short: "Delete Favorite Content",
  Long: `### Delete favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_content_favorite called")
  },
}


var createContentFavoriteCmd = &cobra.Command{
  Use:   "createContentFavorite",
  Short: "Create Favorite Content",
  Long: `### Create favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_content_favorite called")
  },
}


var allContentMetadatasCmd = &cobra.Command{
  Use:   "allContentMetadatas",
  Short: "Get All Content Metadatas",
  Long: `### Get information about all content metadata in a space.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_content_metadatas called")
  },
}


var contentMetadataCmd = &cobra.Command{
  Use:   "contentMetadata",
  Short: "Get Content Metadata",
  Long: `### Get information about an individual content metadata record.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("content_metadata called")
  },
}


var updateContentMetadataCmd = &cobra.Command{
  Use:   "updateContentMetadata",
  Short: "Update Content Metadata",
  Long: `### Move a piece of content.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_content_metadata called")
  },
}


var allContentMetadataAccessesCmd = &cobra.Command{
  Use:   "allContentMetadataAccesses",
  Short: "Get All Content Metadata Accesses",
  Long: `### All content metadata access records for a content metadata item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_content_metadata_accesses called")
  },
}


var createContentMetadataAccessCmd = &cobra.Command{
  Use:   "createContentMetadataAccess",
  Short: "Create Content Metadata Access",
  Long: `### Create content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_content_metadata_access called")
  },
}


var updateContentMetadataAccessCmd = &cobra.Command{
  Use:   "updateContentMetadataAccess",
  Short: "Update Content Metadata Access",
  Long: `### Update type of access for content metadata.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_content_metadata_access called")
  },
}


var deleteContentMetadataAccessCmd = &cobra.Command{
  Use:   "deleteContentMetadataAccess",
  Short: "Delete Content Metadata Access",
  Long: `### Remove content metadata access.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_content_metadata_access called")
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
    fmt.Println("content_thumbnail called")
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
    fmt.Println("content_validation called")
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
    fmt.Println("search_content_views called")
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
    fmt.Println("vector_thumbnail called")
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
    fmt.Println("all_dashboards called")
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
    fmt.Println("create_dashboard called")
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
    fmt.Println("search_dashboards called")
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
    fmt.Println("import_lookml_dashboard called")
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
    fmt.Println("sync_lookml_dashboard called")
  },
}


var dashboardCmd5870 = &cobra.Command{
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
    fmt.Println("update_dashboard called")
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
    fmt.Println("delete_dashboard called")
  },
}


var dashboardAggregateTableLookmlCmd = &cobra.Command{
  Use:   "dashboardAggregateTableLookml",
  Short: "Get Aggregate Table LookML for a dashboard",
  Long: `### Get Aggregate Table LookML for Each Query on a Dahboard

Returns a JSON object that contains the dashboard id and Aggregate Table lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_aggregate_table_lookml called")
  },
}


var dashboardLookmlCmd = &cobra.Command{
  Use:   "dashboardLookml",
  Short: "Get lookml of a UDD",
  Long: `### Get lookml of a UDD

Returns a JSON object that contains the dashboard id and the full lookml

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_lookml called")
  },
}


var moveDashboardCmd = &cobra.Command{
  Use:   "moveDashboard",
  Short: "Move Dashboard",
  Long: `### Move an existing dashboard

Moves a dashboard to a specified folder, and returns the moved dashboard.

'dashboard_id' and 'folder_id' are required.
'dashboard_id' and 'folder_id' must already exist, and 'folder_id' must be different from the current 'folder_id' of the dashboard.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("move_dashboard called")
  },
}


var copyDashboardCmd = &cobra.Command{
  Use:   "copyDashboard",
  Short: "Copy Dashboard",
  Long: `### Copy an existing dashboard

Creates a copy of an existing dashboard, in a specified folder, and returns the copied dashboard.

'dashboard_id' is required, 'dashboard_id' and 'folder_id' must already exist if specified.
'folder_id' will default to the existing folder.

If a dashboard with the same title already exists in the target folder, the copy will have '(copy)'
  or '(copy <# of copies>)' appended.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("copy_dashboard called")
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
    fmt.Println("search_dashboard_elements called")
  },
}


var dashboardElementCmd = &cobra.Command{
  Use:   "dashboardElement",
  Short: "Get DashboardElement",
  Long: `### Get information about the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_element called")
  },
}


var updateDashboardElementCmd = &cobra.Command{
  Use:   "updateDashboardElement",
  Short: "Update DashboardElement",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_element called")
  },
}


var deleteDashboardElementCmd = &cobra.Command{
  Use:   "deleteDashboardElement",
  Short: "Delete DashboardElement",
  Long: `### Delete a dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_element called")
  },
}


var dashboardDashboardElementsCmd = &cobra.Command{
  Use:   "dashboardDashboardElements",
  Short: "Get All DashboardElements",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_elements called")
  },
}


var createDashboardElementCmd = &cobra.Command{
  Use:   "createDashboardElement",
  Short: "Create DashboardElement",
  Long: `### Create a dashboard element on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_element called")
  },
}


var dashboardFilterCmd = &cobra.Command{
  Use:   "dashboardFilter",
  Short: "Get Dashboard Filter",
  Long: `### Get information about the dashboard filters with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_filter called")
  },
}


var updateDashboardFilterCmd = &cobra.Command{
  Use:   "updateDashboardFilter",
  Short: "Update Dashboard Filter",
  Long: `### Update the dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_filter called")
  },
}


var deleteDashboardFilterCmd = &cobra.Command{
  Use:   "deleteDashboardFilter",
  Short: "Delete Dashboard Filter",
  Long: `### Delete a dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_filter called")
  },
}


var dashboardDashboardFiltersCmd = &cobra.Command{
  Use:   "dashboardDashboardFilters",
  Short: "Get All Dashboard Filters",
  Long: `### Get information about all the dashboard filters on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_filters called")
  },
}


var createDashboardFilterCmd = &cobra.Command{
  Use:   "createDashboardFilter",
  Short: "Create Dashboard Filter",
  Long: `### Create a dashboard filter on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_dashboard_filter called")
  },
}


var dashboardLayoutComponentCmd = &cobra.Command{
  Use:   "dashboardLayoutComponent",
  Short: "Get DashboardLayoutComponent",
  Long: `### Get information about the dashboard elements with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout_component called")
  },
}


var updateDashboardLayoutComponentCmd = &cobra.Command{
  Use:   "updateDashboardLayoutComponent",
  Short: "Update DashboardLayoutComponent",
  Long: `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_layout_component called")
  },
}


var dashboardLayoutDashboardLayoutComponentsCmd = &cobra.Command{
  Use:   "dashboardLayoutDashboardLayoutComponents",
  Short: "Get All DashboardLayoutComponents",
  Long: `### Get information about all the dashboard layout components for a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout_dashboard_layout_components called")
  },
}


var dashboardLayoutCmd = &cobra.Command{
  Use:   "dashboardLayout",
  Short: "Get DashboardLayout",
  Long: `### Get information about the dashboard layouts with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_layout called")
  },
}


var updateDashboardLayoutCmd = &cobra.Command{
  Use:   "updateDashboardLayout",
  Short: "Update DashboardLayout",
  Long: `### Update the dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_dashboard_layout called")
  },
}


var deleteDashboardLayoutCmd = &cobra.Command{
  Use:   "deleteDashboardLayout",
  Short: "Delete DashboardLayout",
  Long: `### Delete a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_dashboard_layout called")
  },
}


var dashboardDashboardLayoutsCmd = &cobra.Command{
  Use:   "dashboardDashboardLayouts",
  Short: "Get All DashboardLayouts",
  Long: `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboard_dashboard_layouts called")
  },
}


var createDashboardLayoutCmd = &cobra.Command{
  Use:   "createDashboardLayout",
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
}


var performDataActionCmd = &cobra.Command{
  Use:   "performDataAction",
  Short: "Send a Data Action",
  Long: `Perform a data action. The data action object can be obtained from query results, and used to perform an arbitrary action.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("perform_data_action called")
  },
}


var fetchRemoteDataActionFormCmd = &cobra.Command{
  Use:   "fetchRemoteDataActionForm",
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
}


var allDatagroupsCmd = &cobra.Command{
  Use:   "allDatagroups",
  Short: "Get All Datagroups",
  Long: `### Get information about all datagroups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_datagroups called")
  },
}


var datagroupCmd2032 = &cobra.Command{
  Use:   "datagroup",
  Short: "Get Datagroup",
  Long: `### Get information about a datagroup.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("datagroup called")
  },
}


var updateDatagroupCmd = &cobra.Command{
  Use:   "updateDatagroup",
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
}


var graphDerivedTablesForModelCmd = &cobra.Command{
  Use:   "graphDerivedTablesForModel",
  Short: "Get Derived Table graph for model",
  Long: `### Discover information about derived tables
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graph_derived_tables_for_model called")
  },
}


var graphDerivedTablesForViewCmd = &cobra.Command{
  Use:   "graphDerivedTablesForView",
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
}


var searchFoldersCmd = &cobra.Command{
  Use:   "searchFolders",
  Short: "Search Folders",
  Long: `Search for folders by creator id, parent id, name, etc`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("search_folders called")
  },
}


var folderCmd638 = &cobra.Command{
  Use:   "folder",
  Short: "Get Folder",
  Long: `### Get information about the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder called")
  },
}


var updateFolderCmd = &cobra.Command{
  Use:   "updateFolder",
  Short: "Update Folder",
  Long: `### Update the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_folder called")
  },
}


var deleteFolderCmd = &cobra.Command{
  Use:   "deleteFolder",
  Short: "Delete Folder",
  Long: `### Delete the folder with a specific id including any children folders.
**DANGER** this will delete all looks and dashboards in the folder.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_folder called")
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
    fmt.Println("all_folders called")
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
    fmt.Println("create_folder called")
  },
}


var folderChildrenCmd = &cobra.Command{
  Use:   "folderChildren",
  Short: "Get Folder Children",
  Long: `### Get the children of a folder.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_children called")
  },
}


var folderChildrenSearchCmd = &cobra.Command{
  Use:   "folderChildrenSearch",
  Short: "Search Folder Children",
  Long: `### Search the children of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_children_search called")
  },
}


var folderParentCmd = &cobra.Command{
  Use:   "folderParent",
  Short: "Get Folder Parent",
  Long: `### Get the parent of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_parent called")
  },
}


var folderAncestorsCmd = &cobra.Command{
  Use:   "folderAncestors",
  Short: "Get Folder Ancestors",
  Long: `### Get the ancestors of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder_ancestors called")
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
    fmt.Println("folder_looks called")
  },
}


var folderDashboardsCmd = &cobra.Command{
  Use:   "folderDashboards",
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
}


var allGroupsCmd = &cobra.Command{
  Use:   "allGroups",
  Short: "Get All Groups",
  Long: `### Get information about all groups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_groups called")
  },
}


var createGroupCmd = &cobra.Command{
  Use:   "createGroup",
  Short: "Create Group",
  Long: `### Creates a new group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_group called")
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
    fmt.Println("search_groups called")
  },
}


var searchGroupsWithRolesCmd = &cobra.Command{
  Use:   "searchGroupsWithRoles",
  Short: "Search Groups with Roles",
  Long: `### Search groups include roles

Returns all group records that match the given search criteria, and attaches any associated roles.

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
    fmt.Println("search_groups_with_roles called")
  },
}


var searchGroupsWithHierarchyCmd = &cobra.Command{
  Use:   "searchGroupsWithHierarchy",
  Short: "Search Groups with Hierarchy",
  Long: `### Search groups include hierarchy

Returns all group records that match the given search criteria, and attaches
associated role_ids and parent group_ids.

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
    fmt.Println("search_groups_with_hierarchy called")
  },
}


var groupCmd5319 = &cobra.Command{
  Use:   "group",
  Short: "Get Group",
  Long: `### Get information about a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("group called")
  },
}


var updateGroupCmd = &cobra.Command{
  Use:   "updateGroup",
  Short: "Update Group",
  Long: `### Updates the a group (admin only).`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_group called")
  },
}


var deleteGroupCmd = &cobra.Command{
  Use:   "deleteGroup",
  Short: "Delete Group",
  Long: `### Deletes a group (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group called")
  },
}


var allGroupGroupsCmd = &cobra.Command{
  Use:   "allGroupGroups",
  Short: "Get All Groups in Group",
  Long: `### Get information about all the groups in a group
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_group_groups called")
  },
}


var addGroupGroupCmd = &cobra.Command{
  Use:   "addGroupGroup",
  Short: "Add a Group to Group",
  Long: `### Adds a new group to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("add_group_group called")
  },
}


var allGroupUsersCmd = &cobra.Command{
  Use:   "allGroupUsers",
  Short: "Get All Users in Group",
  Long: `### Get information about all the users directly included in a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_group_users called")
  },
}


var addGroupUserCmd = &cobra.Command{
  Use:   "addGroupUser",
  Short: "Add a User to Group",
  Long: `### Adds a new user to a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("add_group_user called")
  },
}


var deleteGroupUserCmd = &cobra.Command{
  Use:   "deleteGroupUser",
  Short: "Remove a User from Group",
  Long: `### Removes a user from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group_user called")
  },
}


var deleteGroupFromGroupCmd = &cobra.Command{
  Use:   "deleteGroupFromGroup",
  Short: "Deletes a Group from Group",
  Long: `### Removes a group from a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_group_from_group called")
  },
}


var updateUserAttributeGroupValueCmd = &cobra.Command{
  Use:   "updateUserAttributeGroupValue",
  Short: "Set User Attribute Group Value",
  Long: `### Set the value of a user attribute for a group.

For information about how user attribute values are calculated, see [Set User Attribute Group Values](#!/UserAttribute/set_user_attribute_group_values).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_attribute_group_value called")
  },
}


var deleteUserAttributeGroupValueCmd = &cobra.Command{
  Use:   "deleteUserAttributeGroupValue",
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
}


var allPrimaryHomepageSectionsCmd = &cobra.Command{
  Use:   "allPrimaryHomepageSections",
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
}


var allIntegrationHubsCmd = &cobra.Command{
  Use:   "allIntegrationHubs",
  Short: "Get All Integration Hubs",
  Long: `### Get information about all Integration Hubs.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_integration_hubs called")
  },
}


var createIntegrationHubCmd = &cobra.Command{
  Use:   "createIntegrationHub",
  Short: "Create Integration Hub",
  Long: `### Create a new Integration Hub.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_integration_hub called")
  },
}


var integrationHubCmd = &cobra.Command{
  Use:   "integrationHub",
  Short: "Get Integration Hub",
  Long: `### Get information about a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration_hub called")
  },
}


var updateIntegrationHubCmd = &cobra.Command{
  Use:   "updateIntegrationHub",
  Short: "Update Integration Hub",
  Long: `### Update a Integration Hub definition.

This API is rate limited to prevent it from being used for SSRF attacks
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_integration_hub called")
  },
}


var deleteIntegrationHubCmd = &cobra.Command{
  Use:   "deleteIntegrationHub",
  Short: "Delete Integration Hub",
  Long: `### Delete a Integration Hub.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_integration_hub called")
  },
}


var acceptIntegrationHubLegalAgreementCmd = &cobra.Command{
  Use:   "acceptIntegrationHubLegalAgreement",
  Short: "Accept Integration Hub Legal Agreement",
  Long: `Accepts the legal agreement for a given integration hub. This only works for integration hubs that have legal_agreement_required set to true and legal_agreement_signed set to false.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("accept_integration_hub_legal_agreement called")
  },
}


var allIntegrationsCmd = &cobra.Command{
  Use:   "allIntegrations",
  Short: "Get All Integrations",
  Long: `### Get information about all Integrations.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_integrations called")
  },
}


var integrationCmd4963 = &cobra.Command{
  Use:   "integration",
  Short: "Get Integration",
  Long: `### Get information about a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration called")
  },
}


var updateIntegrationCmd = &cobra.Command{
  Use:   "updateIntegration",
  Short: "Update Integration",
  Long: `### Update parameters on a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_integration called")
  },
}


var fetchIntegrationFormCmd = &cobra.Command{
  Use:   "fetchIntegrationForm",
  Short: "Fetch Remote Integration Form",
  Long: `Returns the Integration form for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetch_integration_form called")
  },
}


var testIntegrationCmd = &cobra.Command{
  Use:   "testIntegration",
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
    fmt.Println("all_looks called")
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
    fmt.Println("create_look called")
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
    fmt.Println("search_looks called")
  },
}


var lookCmd988 = &cobra.Command{
  Use:   "look",
  Short: "Get Look",
  Long: `### Get a Look.

Returns detailed information about a Look and its associated Query.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("look called")
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
    fmt.Println("update_look called")
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
    fmt.Println("delete_look called")
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
    fmt.Println("run_look called")
  },
}


var copyLookCmd = &cobra.Command{
  Use:   "copyLook",
  Short: "Copy Look",
  Long: `### Copy an existing look

Creates a copy of an existing look, in a specified folder, and returns the copied look.

'look_id' and 'folder_id' are required.

'look_id' and 'folder_id' must already exist, and 'folder_id' must be different from the current 'folder_id' of the dashboard.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("copy_look called")
  },
}


var moveLookCmd = &cobra.Command{
  Use:   "moveLook",
  Short: "Move Look",
  Long: `### Move an existing look

Moves a look to a specified folder, and returns the moved look.

'look_id' and 'folder_id' are required.
'look_id' and 'folder_id' must already exist, and 'folder_id' must be different from the current 'folder_id' of the dashboard.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("move_look called")
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
    fmt.Println("all_lookml_models called")
  },
}


var createLookmlModelCmd = &cobra.Command{
  Use:   "createLookmlModel",
  Short: "Create LookML Model",
  Long: `### Create a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_lookml_model called")
  },
}


var lookmlModelCmd4124 = &cobra.Command{
  Use:   "lookmlModel",
  Short: "Get LookML Model",
  Long: `### Get information about a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookml_model called")
  },
}


var updateLookmlModelCmd = &cobra.Command{
  Use:   "updateLookmlModel",
  Short: "Update LookML Model",
  Long: `### Update a lookml model using the specified configuration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_lookml_model called")
  },
}


var deleteLookmlModelCmd = &cobra.Command{
  Use:   "deleteLookmlModel",
  Short: "Delete LookML Model",
  Long: `### Delete a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_lookml_model called")
  },
}


var lookmlModelExploreCmd = &cobra.Command{
  Use:   "lookmlModelExplore",
  Short: "Get LookML Model Explore",
  Long: `### Get information about a lookml model explore.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookml_model_explore called")
  },
}




var metadataCmd = &cobra.Command{
  Use:   "Metadata",
  Short: "Connection Metadata Features",
  Long: "Connection Metadata Features",
}


var modelFieldnameSuggestionsCmd = &cobra.Command{
  Use:   "modelFieldnameSuggestions",
  Short: "Model field name suggestions",
  Long: `### Field name suggestions for a model and view

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("model_fieldname_suggestions called")
  },
}


var getModelCmd = &cobra.Command{
  Use:   "getModel",
  Short: "Get a single model",
  Long: `### Get a single model

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_model called")
  },
}


var connectionDatabasesCmd = &cobra.Command{
  Use:   "connectionDatabases",
  Short: "List accessible databases to this connection",
  Long: `### List databases available to this connection

Certain dialects can support multiple databases per single connection.
If this connection supports multiple databases, the database names will be returned in an array.

Connections using dialects that do not support multiple databases will return an empty array.

**Note**: [Connection Features](#!/Metadata/connection_features) can be used to determine if a connection supports
multiple databases.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_databases called")
  },
}


var connectionFeaturesCmd = &cobra.Command{
  Use:   "connectionFeatures",
  Short: "Metadata features supported by this connection",
  Long: `### Retrieve metadata features for this connection

Returns a list of feature names with 'true' (available) or 'false' (not available)

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_features called")
  },
}


var connectionSchemasCmd = &cobra.Command{
  Use:   "connectionSchemas",
  Short: "Get schemas for a connection",
  Long: `### Get the list of schemas and tables for a connection

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_schemas called")
  },
}


var connectionTablesCmd = &cobra.Command{
  Use:   "connectionTables",
  Short: "Get tables for a connection",
  Long: `### Get the list of tables for a schema

For dialects that support multiple databases, optionally identify which to use. If not provided, the default
database for the connection will be used.

For dialects that do **not** support multiple databases, **do not use** the database parameter
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_tables called")
  },
}


var connectionColumnsCmd = &cobra.Command{
  Use:   "connectionColumns",
  Short: "Get columns for a connection",
  Long: `### Get the columns (and therefore also the tables) in a specific schema

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_columns called")
  },
}


var connectionSearchColumnsCmd = &cobra.Command{
  Use:   "connectionSearchColumns",
  Short: "Search a connection for columns",
  Long: `### Search a connection for columns matching the specified name

**Note**: 'column_name' must be a valid column name. It is not a search pattern.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_search_columns called")
  },
}


var connectionCostEstimateCmd = &cobra.Command{
  Use:   "connectionCostEstimate",
  Short: "Estimate costs for a connection",
  Long: `### Connection cost estimating

Assign a 'sql' statement to the body of the request. e.g., for Ruby, '{sql: 'select * from users'}'

**Note**: If the connection's dialect has no support for cost estimates, an error will be returned
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection_cost_estimate called")
  },
}




var projectCmd = &cobra.Command{
  Use:   "Project",
  Short: "Manage Projects",
  Long: "Manage Projects",
}


var lockAllCmd = &cobra.Command{
  Use:   "lockAll",
  Short: "Lock All",
  Long: `      ### Generate Lockfile for All LookML Dependencies

      Git must have been configured, must be in dev mode and deploy permission required

      Install_all is a two step process
      1. For each remote_dependency in a project the dependency manager will resolve any ambiguous ref.
      2. The project will then write out a lockfile including each remote_dependency with its resolved ref.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lock_all called")
  },
}


var allGitBranchesCmd = &cobra.Command{
  Use:   "allGitBranches",
  Short: "Get All Git Branches",
  Long: `### Get All Git Branches

Returns a list of git branches in the project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_git_branches called")
  },
}


var gitBranchCmd = &cobra.Command{
  Use:   "gitBranch",
  Short: "Get Active Git Branch",
  Long: `### Get the Current Git Branch

Returns the git branch currently checked out in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("git_branch called")
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
    fmt.Println("update_git_branch called")
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
    fmt.Println("create_git_branch called")
  },
}


var findGitBranchCmd = &cobra.Command{
  Use:   "findGitBranch",
  Short: "Find a Git Branch",
  Long: `### Get the specified Git Branch

Returns the git branch specified in branch_name path param if it exists in the given project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("find_git_branch called")
  },
}


var deleteGitBranchCmd = &cobra.Command{
  Use:   "deleteGitBranch",
  Short: "Delete a Git Branch",
  Long: `### Delete the specified Git Branch

Delete git branch specified in branch_name path param from local and remote of specified project repository
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_git_branch called")
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
    fmt.Println("deploy_ref_to_production called")
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
    fmt.Println("deploy_to_production called")
  },
}


var resetProjectToProductionCmd = &cobra.Command{
  Use:   "resetProjectToProduction",
  Short: "Reset To Production",
  Long: `### Reset a project to the revision of the project that is in production.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("reset_project_to_production called")
  },
}


var resetProjectToRemoteCmd = &cobra.Command{
  Use:   "resetProjectToRemote",
  Short: "Reset To Remote",
  Long: `### Reset a project development branch to the revision of the project that is on the remote.

**DANGER** this will delete any changes that have not been pushed to a remote repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("reset_project_to_remote called")
  },
}


var allProjectsCmd = &cobra.Command{
  Use:   "allProjects",
  Short: "Get All Projects",
  Long: `### Get All Projects

Returns all projects visible to the current user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_projects called")
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
    fmt.Println("create_project called")
  },
}


var projectCmd3260 = &cobra.Command{
  Use:   "project",
  Short: "Get Project",
  Long: `### Get A Project

Returns the project with the given project id
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project called")
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


var gitDeployKeyCmd = &cobra.Command{
  Use:   "gitDeployKey",
  Short: "Git Deploy Key",
  Long: `### Git Deploy Key

Returns the ssh public key previously created for a project's git repository.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("git_deploy_key called")
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
    fmt.Println("create_git_deploy_key called")
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
    fmt.Println("project_validation_results called")
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
    fmt.Println("validate_project called")
  },
}


var projectWorkspaceCmd = &cobra.Command{
  Use:   "projectWorkspace",
  Short: "Get Project Workspace",
  Long: `### Get Project Workspace

Returns information about the state of the project files in the currently selected workspace
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project_workspace called")
  },
}


var allProjectFilesCmd = &cobra.Command{
  Use:   "allProjectFiles",
  Short: "Get All Project Files",
  Long: `### Get All Project Files

Returns a list of the files in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_project_files called")
  },
}


var projectFileCmd = &cobra.Command{
  Use:   "projectFile",
  Short: "Get Project File",
  Long: `### Get Project File Info

Returns information about a file in the project
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("project_file called")
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
    fmt.Println("all_git_connection_tests called")
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
    fmt.Println("run_git_connection_test called")
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
    fmt.Println("all_lookml_tests called")
  },
}


var runLookmlTestCmd = &cobra.Command{
  Use:   "runLookmlTest",
  Short: "Run LookML Test",
  Long: `### Run LookML Tests

Runs all tests in the project, optionally filtered by file, test, and/or model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("run_lookml_test called")
  },
}


var tagRefCmd = &cobra.Command{
  Use:   "tagRef",
  Short: "Tag Ref",
  Long: `### Creates a tag for the most recent commit, or a specific ref is a SHA is provided

This is an internal-only, undocumented route.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("tag_ref called")
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
    fmt.Println("update_repository_credential called")
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
    fmt.Println("delete_repository_credential called")
  },
}


var getAllRepositoryCredentialsCmd = &cobra.Command{
  Use:   "getAllRepositoryCredentials",
  Short: "Get All Repository Credentials",
  Long: `### Get all Repository Credentials for a project

'root_project_id' is required.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("get_all_repository_credentials called")
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
    fmt.Println("create_query_task called")
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
    fmt.Println("query_task_multi_results called")
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
    fmt.Println("query_task called")
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
    fmt.Println("query_task_results called")
  },
}


var queryCmd5522 = &cobra.Command{
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
    fmt.Println("query_for_slug called")
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
    fmt.Println("create_query called")
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
    fmt.Println("run_query called")
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
    fmt.Println("run_inline_query called")
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
    fmt.Println("run_url_encoded_query called")
  },
}


var mergeQueryCmd = &cobra.Command{
  Use:   "mergeQuery",
  Short: "Get Merge Query",
  Long: `### Get Merge Query

Returns a merge query object given its id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("merge_query called")
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
    fmt.Println("create_merge_query called")
  },
}


var allRunningQueriesCmd = &cobra.Command{
  Use:   "allRunningQueries",
  Short: "Get All Running Queries",
  Long: `Get information about all running queries.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_running_queries called")
  },
}


var killQueryCmd = &cobra.Command{
  Use:   "killQuery",
  Short: "Kill Running Query",
  Long: `Kill a query with a specific query_task_id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("kill_query called")
  },
}


var sqlQueryCmd = &cobra.Command{
  Use:   "sqlQuery",
  Short: "Get SQL Runner Query",
  Long: `Get a SQL Runner query.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sql_query called")
  },
}


var createSqlQueryCmd = &cobra.Command{
  Use:   "createSqlQuery",
  Short: "Create SQL Runner Query",
  Long: `### Create a SQL Runner Query

Either the 'connection_name' or 'model_name' parameter MUST be provided.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_sql_query called")
  },
}


var runSqlQueryCmd = &cobra.Command{
  Use:   "runSqlQuery",
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
    fmt.Println("create_look_render_task called")
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
    fmt.Println("create_query_render_task called")
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
    fmt.Println("create_dashboard_render_task called")
  },
}


var renderTaskCmd1705 = &cobra.Command{
  Use:   "renderTask",
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
    fmt.Println("render_task_results called")
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
    fmt.Println("search_model_sets called")
  },
}


var modelSetCmd = &cobra.Command{
  Use:   "modelSet",
  Short: "Get Model Set",
  Long: `### Get information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("model_set called")
  },
}


var updateModelSetCmd = &cobra.Command{
  Use:   "updateModelSet",
  Short: "Update Model Set",
  Long: `### Update information about the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_model_set called")
  },
}


var deleteModelSetCmd = &cobra.Command{
  Use:   "deleteModelSet",
  Short: "Delete Model Set",
  Long: `### Delete the model set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_model_set called")
  },
}


var allModelSetsCmd = &cobra.Command{
  Use:   "allModelSets",
  Short: "Get All Model Sets",
  Long: `### Get information about all model sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_model_sets called")
  },
}


var createModelSetCmd = &cobra.Command{
  Use:   "createModelSet",
  Short: "Create Model Set",
  Long: `### Create a model set with the specified information. Model sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_model_set called")
  },
}


var allPermissionsCmd = &cobra.Command{
  Use:   "allPermissions",
  Short: "Get All Permissions",
  Long: `### Get all supported permissions.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_permissions called")
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
    fmt.Println("search_permission_sets called")
  },
}


var permissionSetCmd = &cobra.Command{
  Use:   "permissionSet",
  Short: "Get Permission Set",
  Long: `### Get information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("permission_set called")
  },
}


var updatePermissionSetCmd = &cobra.Command{
  Use:   "updatePermissionSet",
  Short: "Update Permission Set",
  Long: `### Update information about the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_permission_set called")
  },
}


var deletePermissionSetCmd = &cobra.Command{
  Use:   "deletePermissionSet",
  Short: "Delete Permission Set",
  Long: `### Delete the permission set with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_permission_set called")
  },
}


var allPermissionSetsCmd = &cobra.Command{
  Use:   "allPermissionSets",
  Short: "Get All Permission Sets",
  Long: `### Get information about all permission sets.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_permission_sets called")
  },
}


var createPermissionSetCmd = &cobra.Command{
  Use:   "createPermissionSet",
  Short: "Create Permission Set",
  Long: `### Create a permission set with the specified information. Permission sets are used by Roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_permission_set called")
  },
}


var allRolesCmd = &cobra.Command{
  Use:   "allRoles",
  Short: "Get All Roles",
  Long: `### Get information about all roles.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_roles called")
  },
}


var createRoleCmd = &cobra.Command{
  Use:   "createRole",
  Short: "Create Role",
  Long: `### Create a role with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_role called")
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
    fmt.Println("search_roles called")
  },
}


var searchRolesWithUserCountCmd = &cobra.Command{
  Use:   "searchRolesWithUserCount",
  Short: "Search Roles with User Count",
  Long: `### Search roles include user count

Returns all role records that match the given search criteria, and attaches
associated user counts.

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
    fmt.Println("search_roles_with_user_count called")
  },
}


var roleCmd2020 = &cobra.Command{
  Use:   "role",
  Short: "Get Role",
  Long: `### Get information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role called")
  },
}


var updateRoleCmd = &cobra.Command{
  Use:   "updateRole",
  Short: "Update Role",
  Long: `### Update information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_role called")
  },
}


var deleteRoleCmd = &cobra.Command{
  Use:   "deleteRole",
  Short: "Delete Role",
  Long: `### Delete the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_role called")
  },
}


var roleGroupsCmd = &cobra.Command{
  Use:   "roleGroups",
  Short: "Get Role Groups",
  Long: `### Get information about all the groups with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role_groups called")
  },
}


var setRoleGroupsCmd = &cobra.Command{
  Use:   "setRoleGroups",
  Short: "Update Role Groups",
  Long: `### Set all groups for a role, removing all existing group associations from that role.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_role_groups called")
  },
}


var roleUsersCmd = &cobra.Command{
  Use:   "roleUsers",
  Short: "Get Role Users",
  Long: `### Get information about all the users with the role that has a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role_users called")
  },
}


var setRoleUsersCmd = &cobra.Command{
  Use:   "setRoleUsers",
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
}


var scheduledPlansForSpaceCmd = &cobra.Command{
  Use:   "scheduledPlansForSpace",
  Short: "Scheduled Plans for Space",
  Long: `### Get Scheduled Plans for a Space

Returns scheduled plans owned by the caller for a given space id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plans_for_space called")
  },
}


var scheduledPlanCmd1703 = &cobra.Command{
  Use:   "scheduledPlan",
  Short: "Get Scheduled Plan",
  Long: `### Get Information About a Scheduled Plan

Admins can fetch information about other users' Scheduled Plans.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduled_plan called")
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
    fmt.Println("update_scheduled_plan called")
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
    fmt.Println("delete_scheduled_plan called")
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
    fmt.Println("all_scheduled_plans called")
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
    fmt.Println("create_scheduled_plan called")
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
    fmt.Println("scheduled_plan_run_once called")
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
    fmt.Println("scheduled_plans_for_look called")
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
    fmt.Println("scheduled_plans_for_dashboard called")
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
    fmt.Println("scheduled_plans_for_lookml_dashboard called")
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
    fmt.Println("scheduled_plan_run_once_by_id called")
  },
}




var sessionCmd = &cobra.Command{
  Use:   "Session",
  Short: "Session Information",
  Long: "Session Information",
}


var sessionCmd4 = &cobra.Command{
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
    fmt.Println("update_session called")
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
    fmt.Println("all_themes called")
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
    fmt.Println("create_theme called")
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
    fmt.Println("search_themes called")
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
    fmt.Println("default_theme called")
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
    fmt.Println("set_default_theme called")
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
    fmt.Println("active_themes called")
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
    fmt.Println("theme_or_default called")
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
    fmt.Println("validate_theme called")
  },
}


var themeCmd4597 = &cobra.Command{
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


var updateThemeCmd = &cobra.Command{
  Use:   "updateTheme",
  Short: "Update Theme",
  Long: `### Update the theme by id.

**Note**: Custom themes needs to be enabled by Looker. Unless custom themes are enabled, only the automatically generated default theme can be used. Please contact your Account Manager or help.looker.com to update your license for this feature.

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_theme called")
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
    fmt.Println("delete_theme called")
  },
}




var userCmd = &cobra.Command{
  Use:   "User",
  Short: "Manage Users",
  Long: "Manage Users",
}


var searchCredentialsEmailCmd = &cobra.Command{
  Use:   "searchCredentialsEmail",
  Short: "Search CredentialsEmail",
  Long: `### Search email credentials

Returns all credentials_email records that match the given search criteria.

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
    fmt.Println("search_credentials_email called")
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


var allUsersCmd = &cobra.Command{
  Use:   "allUsers",
  Short: "Get All Users",
  Long: `### Get information about all users.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_users called")
  },
}


var createUserCmd = &cobra.Command{
  Use:   "createUser",
  Short: "Create User",
  Long: `### Create a user with the specified information.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user called")
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
    fmt.Println("search_users called")
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
    fmt.Println("search_users_names called")
  },
}


var userCmd8023 = &cobra.Command{
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


var updateUserCmd = &cobra.Command{
  Use:   "updateUser",
  Short: "Update User",
  Long: `### Update information about the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user called")
  },
}


var deleteUserCmd = &cobra.Command{
  Use:   "deleteUser",
  Short: "Delete User",
  Long: `### Delete the user with a specific id.

**DANGER** this will delete the user and all looks and other information owned by the user.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user called")
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
    fmt.Println("user_for_credential called")
  },
}


var userCredentialsEmailCmd = &cobra.Command{
  Use:   "userCredentialsEmail",
  Short: "Get Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_email called")
  },
}


var createUserCredentialsEmailCmd = &cobra.Command{
  Use:   "createUserCredentialsEmail",
  Short: "Create Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_email called")
  },
}


var updateUserCredentialsEmailCmd = &cobra.Command{
  Use:   "updateUserCredentialsEmail",
  Short: "Update Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_credentials_email called")
  },
}


var deleteUserCredentialsEmailCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmail",
  Short: "Delete Email/Password Credential",
  Long: `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_email called")
  },
}


var userCredentialsTotpCmd = &cobra.Command{
  Use:   "userCredentialsTotp",
  Short: "Get Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_totp called")
  },
}


var createUserCredentialsTotpCmd = &cobra.Command{
  Use:   "createUserCredentialsTotp",
  Short: "Create Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_totp called")
  },
}


var deleteUserCredentialsTotpCmd = &cobra.Command{
  Use:   "deleteUserCredentialsTotp",
  Short: "Delete Two-Factor Credential",
  Long: `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_totp called")
  },
}


var userCredentialsLdapCmd = &cobra.Command{
  Use:   "userCredentialsLdap",
  Short: "Get LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_ldap called")
  },
}


var deleteUserCredentialsLdapCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLdap",
  Short: "Delete LDAP Credential",
  Long: `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_ldap called")
  },
}


var userCredentialsGoogleCmd = &cobra.Command{
  Use:   "userCredentialsGoogle",
  Short: "Get Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_google called")
  },
}


var deleteUserCredentialsGoogleCmd = &cobra.Command{
  Use:   "deleteUserCredentialsGoogle",
  Short: "Delete Google Auth Credential",
  Long: `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_google called")
  },
}


var userCredentialsSamlCmd = &cobra.Command{
  Use:   "userCredentialsSaml",
  Short: "Get Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_saml called")
  },
}


var deleteUserCredentialsSamlCmd = &cobra.Command{
  Use:   "deleteUserCredentialsSaml",
  Short: "Delete Saml Auth Credential",
  Long: `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_saml called")
  },
}


var userCredentialsOidcCmd = &cobra.Command{
  Use:   "userCredentialsOidc",
  Short: "Get OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_oidc called")
  },
}


var deleteUserCredentialsOidcCmd = &cobra.Command{
  Use:   "deleteUserCredentialsOidc",
  Short: "Delete OIDC Auth Credential",
  Long: `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_oidc called")
  },
}


var userCredentialsApi3Cmd = &cobra.Command{
  Use:   "userCredentialsApi3",
  Short: "Get API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_api3 called")
  },
}


var deleteUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "deleteUserCredentialsApi3",
  Short: "Delete API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_api3 called")
  },
}


var allUserCredentialsApi3sCmd = &cobra.Command{
  Use:   "allUserCredentialsApi3s",
  Short: "Get All API 3 Credentials",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_credentials_api3s called")
  },
}


var createUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "createUserCredentialsApi3",
  Short: "Create API 3 Credential",
  Long: `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_user_credentials_api3 called")
  },
}


var userCredentialsEmbedCmd = &cobra.Command{
  Use:   "userCredentialsEmbed",
  Short: "Get Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_embed called")
  },
}


var deleteUserCredentialsEmbedCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmbed",
  Short: "Delete Embedding Credential",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_embed called")
  },
}


var allUserCredentialsEmbedsCmd = &cobra.Command{
  Use:   "allUserCredentialsEmbeds",
  Short: "Get All Embedding Credentials",
  Long: `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_credentials_embeds called")
  },
}


var userCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "userCredentialsLookerOpenid",
  Short: "Get Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_credentials_looker_openid called")
  },
}


var deleteUserCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLookerOpenid",
  Short: "Delete Looker OpenId Credential",
  Long: `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_credentials_looker_openid called")
  },
}


var userSessionCmd = &cobra.Command{
  Use:   "userSession",
  Short: "Get Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_session called")
  },
}


var deleteUserSessionCmd = &cobra.Command{
  Use:   "deleteUserSession",
  Short: "Delete Web Login Session",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_session called")
  },
}


var allUserSessionsCmd = &cobra.Command{
  Use:   "allUserSessions",
  Short: "Get All Web Login Sessions",
  Long: `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("all_user_sessions called")
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
    fmt.Println("create_user_credentials_email_password_reset called")
  },
}


var userRolesCmd = &cobra.Command{
  Use:   "userRoles",
  Short: "Get User Roles",
  Long: `### Get information about roles of a given user
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_roles called")
  },
}


var setUserRolesCmd = &cobra.Command{
  Use:   "setUserRoles",
  Short: "Set User Roles",
  Long: `### Set roles of the user with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_user_roles called")
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
    fmt.Println("user_attribute_user_values called")
  },
}


var setUserAttributeUserValueCmd = &cobra.Command{
  Use:   "setUserAttributeUserValue",
  Short: "Set User Attribute User Value",
  Long: `### Store a custom value for a user attribute in a user's account settings.

Per-user user attribute values take precedence over group or default values.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("set_user_attribute_user_value called")
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
    fmt.Println("delete_user_attribute_user_value called")
  },
}


var sendUserCredentialsEmailPasswordResetCmd = &cobra.Command{
  Use:   "sendUserCredentialsEmailPasswordReset",
  Short: "Send Password Reset Token",
  Long: `### Send a password reset token.
This will send a password reset email to the user. If a password reset token does not already exist
for this user, it will create one and then send it.
If the user has not yet set up their account, it will send a setup email to the user.
The URL sent in the email is expressed as the 'password_reset_url' of the user's email/password credential object.
Password reset URLs will expire in 60 minutes.
This method can be called with an empty body.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("send_user_credentials_email_password_reset called")
  },
}


var wipeoutUserEmailsCmd = &cobra.Command{
  Use:   "wipeoutUserEmails",
  Short: "Wipeout User Emails",
  Long: `### Change a disabled user's email addresses

Allows the admin to change the email addresses for all the user's
associated credentials.  Will overwrite all associated email addresses with
the value supplied in the 'email' body param.
The user's 'is_disabled' status must be true.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("wipeout_user_emails called")
  },
}


var createEmbedUserCmd = &cobra.Command{
  Use:   "createEmbedUser",
  Short: "Create an embed user from an external user ID",
  Long: `Create an embed user from an external user ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("create_embed_user called")
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
    fmt.Println("all_user_attributes called")
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
    fmt.Println("create_user_attribute called")
  },
}


var userAttributeCmd9606 = &cobra.Command{
  Use:   "userAttribute",
  Short: "Get User Attribute",
  Long: `### Get information about a user attribute.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("user_attribute called")
  },
}


var updateUserAttributeCmd = &cobra.Command{
  Use:   "updateUserAttribute",
  Short: "Update User Attribute",
  Long: `### Update a user attribute definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("update_user_attribute called")
  },
}


var deleteUserAttributeCmd = &cobra.Command{
  Use:   "deleteUserAttribute",
  Short: "Delete User Attribute",
  Long: `### Delete a user attribute (admin only).
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("delete_user_attribute called")
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
    fmt.Println("all_user_attribute_group_values called")
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
    fmt.Println("set_user_attribute_group_values called")
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
    fmt.Println("all_workspaces called")
  },
}


var workspaceCmd4539 = &cobra.Command{
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

  alertCmd.AddCommand(searchAlertsCmd)
  alertCmd.AddCommand(getAlertCmd)
  alertCmd.AddCommand(updateAlertCmd)
  alertCmd.AddCommand(updateAlertFieldCmd)
  alertCmd.AddCommand(deleteAlertCmd)
  alertCmd.AddCommand(createAlertCmd)
  alertCmd.AddCommand(enqueueAlertCmd)
  rootCmd.AddCommand(alertCmd)
  apiAuthCmd.AddCommand(loginCmd)
  apiAuthCmd.AddCommand(loginUserCmd)
  apiAuthCmd.AddCommand(logoutCmd)
  rootCmd.AddCommand(apiAuthCmd)
  authCmd.AddCommand(createEmbedSecretCmd)
  authCmd.AddCommand(deleteEmbedSecretCmd)
  authCmd.AddCommand(createSsoEmbedUrlCmd)
  authCmd.AddCommand(createEmbedUrlAsMeCmd)
  authCmd.AddCommand(ldapConfigCmd)
  authCmd.AddCommand(updateLdapConfigCmd)
  authCmd.AddCommand(testLdapConfigConnectionCmd)
  authCmd.AddCommand(testLdapConfigAuthCmd)
  authCmd.AddCommand(testLdapConfigUserInfoCmd)
  authCmd.AddCommand(testLdapConfigUserAuthCmd)
  authCmd.AddCommand(allOauthClientAppsCmd)
  authCmd.AddCommand(oauthClientAppCmd)
  authCmd.AddCommand(registerOauthClientAppCmd)
  authCmd.AddCommand(updateOauthClientAppCmd)
  authCmd.AddCommand(deleteOauthClientAppCmd)
  authCmd.AddCommand(invalidateTokensCmd)
  authCmd.AddCommand(activateAppUserCmd)
  authCmd.AddCommand(deactivateAppUserCmd)
  authCmd.AddCommand(oidcConfigCmd)
  authCmd.AddCommand(updateOidcConfigCmd)
  authCmd.AddCommand(oidcTestConfigCmd)
  authCmd.AddCommand(deleteOidcTestConfigCmd)
  authCmd.AddCommand(createOidcTestConfigCmd)
  authCmd.AddCommand(passwordConfigCmd)
  authCmd.AddCommand(updatePasswordConfigCmd)
  authCmd.AddCommand(forcePasswordResetAtNextLoginForAllUsersCmd)
  authCmd.AddCommand(samlConfigCmd)
  authCmd.AddCommand(updateSamlConfigCmd)
  authCmd.AddCommand(samlTestConfigCmd)
  authCmd.AddCommand(deleteSamlTestConfigCmd)
  authCmd.AddCommand(createSamlTestConfigCmd)
  authCmd.AddCommand(parseSamlIdpMetadataCmd)
  authCmd.AddCommand(fetchAndParseSamlIdpMetadataCmd)
  authCmd.AddCommand(sessionConfigCmd)
  authCmd.AddCommand(updateSessionConfigCmd)
  authCmd.AddCommand(allUserLoginLockoutsCmd)
  authCmd.AddCommand(searchUserLoginLockoutsCmd)
  authCmd.AddCommand(deleteUserLoginLockoutCmd)
  rootCmd.AddCommand(authCmd)
  boardCmd.AddCommand(allBoardsCmd)
  boardCmd.AddCommand(createBoardCmd)
  boardCmd.AddCommand(searchBoardsCmd)
  boardCmd.AddCommand(boardCmd7831)
  boardCmd.AddCommand(updateBoardCmd)
  boardCmd.AddCommand(deleteBoardCmd)
  boardCmd.AddCommand(allBoardItemsCmd)
  boardCmd.AddCommand(createBoardItemCmd)
  boardCmd.AddCommand(boardItemCmd)
  boardCmd.AddCommand(updateBoardItemCmd)
  boardCmd.AddCommand(deleteBoardItemCmd)
  boardCmd.AddCommand(allBoardSectionsCmd)
  boardCmd.AddCommand(createBoardSectionCmd)
  boardCmd.AddCommand(boardSectionCmd)
  boardCmd.AddCommand(updateBoardSectionCmd)
  boardCmd.AddCommand(deleteBoardSectionCmd)
  rootCmd.AddCommand(boardCmd)
  colorCollectionCmd.AddCommand(allColorCollectionsCmd)
  colorCollectionCmd.AddCommand(createColorCollectionCmd)
  colorCollectionCmd.AddCommand(colorCollectionsCustomCmd)
  colorCollectionCmd.AddCommand(colorCollectionsStandardCmd)
  colorCollectionCmd.AddCommand(defaultColorCollectionCmd)
  colorCollectionCmd.AddCommand(setDefaultColorCollectionCmd)
  colorCollectionCmd.AddCommand(colorCollectionCmd9063)
  colorCollectionCmd.AddCommand(updateColorCollectionCmd)
  colorCollectionCmd.AddCommand(deleteColorCollectionCmd)
  rootCmd.AddCommand(colorCollectionCmd)
  commandCmd.AddCommand(getAllCommandsCmd)
  commandCmd.AddCommand(createCommandCmd)
  commandCmd.AddCommand(updateCommandCmd)
  commandCmd.AddCommand(deleteCommandCmd)
  rootCmd.AddCommand(commandCmd)
  configCmd.AddCommand(cloudStorageConfigurationCmd)
  configCmd.AddCommand(updateCloudStorageConfigurationCmd)
  configCmd.AddCommand(customWelcomeEmailCmd)
  configCmd.AddCommand(updateCustomWelcomeEmailCmd)
  configCmd.AddCommand(updateCustomWelcomeEmailTestCmd)
  configCmd.AddCommand(digestEmailsEnabledCmd)
  configCmd.AddCommand(updateDigestEmailsEnabledCmd)
  configCmd.AddCommand(createDigestEmailSendCmd)
  configCmd.AddCommand(internalHelpResourcesContentCmd)
  configCmd.AddCommand(updateInternalHelpResourcesContentCmd)
  configCmd.AddCommand(internalHelpResourcesCmd)
  configCmd.AddCommand(updateInternalHelpResourcesCmd)
  configCmd.AddCommand(allLegacyFeaturesCmd)
  configCmd.AddCommand(legacyFeatureCmd)
  configCmd.AddCommand(updateLegacyFeatureCmd)
  configCmd.AddCommand(allLocalesCmd)
  configCmd.AddCommand(mobileSettingsCmd)
  configCmd.AddCommand(getSettingCmd)
  configCmd.AddCommand(setSettingCmd)
  configCmd.AddCommand(allTimezonesCmd)
  configCmd.AddCommand(versionsCmd)
  configCmd.AddCommand(apiSpecCmd)
  configCmd.AddCommand(whitelabelConfigurationCmd)
  configCmd.AddCommand(updateWhitelabelConfigurationCmd)
  rootCmd.AddCommand(configCmd)
  connectionCmd.AddCommand(allConnectionsCmd)
  connectionCmd.AddCommand(createConnectionCmd)
  connectionCmd.AddCommand(connectionCmd810)
  connectionCmd.AddCommand(updateConnectionCmd)
  connectionCmd.AddCommand(deleteConnectionCmd)
  connectionCmd.AddCommand(deleteConnectionOverrideCmd)
  connectionCmd.AddCommand(testConnectionCmd)
  connectionCmd.AddCommand(testConnectionConfigCmd)
  connectionCmd.AddCommand(allDialectInfosCmd)
  connectionCmd.AddCommand(allExternalOauthApplicationsCmd)
  connectionCmd.AddCommand(createExternalOauthApplicationCmd)
  connectionCmd.AddCommand(createOauthApplicationUserStateCmd)
  connectionCmd.AddCommand(allSshServersCmd)
  connectionCmd.AddCommand(createSshServerCmd)
  connectionCmd.AddCommand(sshServerCmd)
  connectionCmd.AddCommand(updateSshServerCmd)
  connectionCmd.AddCommand(deleteSshServerCmd)
  connectionCmd.AddCommand(testSshServerCmd)
  connectionCmd.AddCommand(allSshTunnelsCmd)
  connectionCmd.AddCommand(createSshTunnelCmd)
  connectionCmd.AddCommand(sshTunnelCmd)
  connectionCmd.AddCommand(updateSshTunnelCmd)
  connectionCmd.AddCommand(deleteSshTunnelCmd)
  connectionCmd.AddCommand(testSshTunnelCmd)
  connectionCmd.AddCommand(sshPublicKeyCmd)
  rootCmd.AddCommand(connectionCmd)
  contentCmd.AddCommand(searchContentFavoritesCmd)
  contentCmd.AddCommand(contentFavoriteCmd)
  contentCmd.AddCommand(deleteContentFavoriteCmd)
  contentCmd.AddCommand(createContentFavoriteCmd)
  contentCmd.AddCommand(allContentMetadatasCmd)
  contentCmd.AddCommand(contentMetadataCmd)
  contentCmd.AddCommand(updateContentMetadataCmd)
  contentCmd.AddCommand(allContentMetadataAccessesCmd)
  contentCmd.AddCommand(createContentMetadataAccessCmd)
  contentCmd.AddCommand(updateContentMetadataAccessCmd)
  contentCmd.AddCommand(deleteContentMetadataAccessCmd)
  contentCmd.AddCommand(contentThumbnailCmd)
  contentCmd.AddCommand(contentValidationCmd)
  contentCmd.AddCommand(searchContentViewsCmd)
  contentCmd.AddCommand(vectorThumbnailCmd)
  rootCmd.AddCommand(contentCmd)
  dashboardCmd.AddCommand(allDashboardsCmd)
  dashboardCmd.AddCommand(createDashboardCmd)
  dashboardCmd.AddCommand(searchDashboardsCmd)
  dashboardCmd.AddCommand(importLookmlDashboardCmd)
  dashboardCmd.AddCommand(syncLookmlDashboardCmd)
  dashboardCmd.AddCommand(dashboardCmd5870)
  dashboardCmd.AddCommand(updateDashboardCmd)
  dashboardCmd.AddCommand(deleteDashboardCmd)
  dashboardCmd.AddCommand(dashboardAggregateTableLookmlCmd)
  dashboardCmd.AddCommand(dashboardLookmlCmd)
  dashboardCmd.AddCommand(moveDashboardCmd)
  dashboardCmd.AddCommand(copyDashboardCmd)
  dashboardCmd.AddCommand(searchDashboardElementsCmd)
  dashboardCmd.AddCommand(dashboardElementCmd)
  dashboardCmd.AddCommand(updateDashboardElementCmd)
  dashboardCmd.AddCommand(deleteDashboardElementCmd)
  dashboardCmd.AddCommand(dashboardDashboardElementsCmd)
  dashboardCmd.AddCommand(createDashboardElementCmd)
  dashboardCmd.AddCommand(dashboardFilterCmd)
  dashboardCmd.AddCommand(updateDashboardFilterCmd)
  dashboardCmd.AddCommand(deleteDashboardFilterCmd)
  dashboardCmd.AddCommand(dashboardDashboardFiltersCmd)
  dashboardCmd.AddCommand(createDashboardFilterCmd)
  dashboardCmd.AddCommand(dashboardLayoutComponentCmd)
  dashboardCmd.AddCommand(updateDashboardLayoutComponentCmd)
  dashboardCmd.AddCommand(dashboardLayoutDashboardLayoutComponentsCmd)
  dashboardCmd.AddCommand(dashboardLayoutCmd)
  dashboardCmd.AddCommand(updateDashboardLayoutCmd)
  dashboardCmd.AddCommand(deleteDashboardLayoutCmd)
  dashboardCmd.AddCommand(dashboardDashboardLayoutsCmd)
  dashboardCmd.AddCommand(createDashboardLayoutCmd)
  rootCmd.AddCommand(dashboardCmd)
  dataActionCmd.AddCommand(performDataActionCmd)
  dataActionCmd.AddCommand(fetchRemoteDataActionFormCmd)
  rootCmd.AddCommand(dataActionCmd)
  datagroupCmd.AddCommand(allDatagroupsCmd)
  datagroupCmd.AddCommand(datagroupCmd2032)
  datagroupCmd.AddCommand(updateDatagroupCmd)
  rootCmd.AddCommand(datagroupCmd)
  derivedTableCmd.AddCommand(graphDerivedTablesForModelCmd)
  derivedTableCmd.AddCommand(graphDerivedTablesForViewCmd)
  rootCmd.AddCommand(derivedTableCmd)
  folderCmd.AddCommand(searchFoldersCmd)
  folderCmd.AddCommand(folderCmd638)
  folderCmd.AddCommand(updateFolderCmd)
  folderCmd.AddCommand(deleteFolderCmd)
  folderCmd.AddCommand(allFoldersCmd)
  folderCmd.AddCommand(createFolderCmd)
  folderCmd.AddCommand(folderChildrenCmd)
  folderCmd.AddCommand(folderChildrenSearchCmd)
  folderCmd.AddCommand(folderParentCmd)
  folderCmd.AddCommand(folderAncestorsCmd)
  folderCmd.AddCommand(folderLooksCmd)
  folderCmd.AddCommand(folderDashboardsCmd)
  rootCmd.AddCommand(folderCmd)
  groupCmd.AddCommand(allGroupsCmd)
  groupCmd.AddCommand(createGroupCmd)
  groupCmd.AddCommand(searchGroupsCmd)
  groupCmd.AddCommand(searchGroupsWithRolesCmd)
  groupCmd.AddCommand(searchGroupsWithHierarchyCmd)
  groupCmd.AddCommand(groupCmd5319)
  groupCmd.AddCommand(updateGroupCmd)
  groupCmd.AddCommand(deleteGroupCmd)
  groupCmd.AddCommand(allGroupGroupsCmd)
  groupCmd.AddCommand(addGroupGroupCmd)
  groupCmd.AddCommand(allGroupUsersCmd)
  groupCmd.AddCommand(addGroupUserCmd)
  groupCmd.AddCommand(deleteGroupUserCmd)
  groupCmd.AddCommand(deleteGroupFromGroupCmd)
  groupCmd.AddCommand(updateUserAttributeGroupValueCmd)
  groupCmd.AddCommand(deleteUserAttributeGroupValueCmd)
  rootCmd.AddCommand(groupCmd)
  homepageCmd.AddCommand(allPrimaryHomepageSectionsCmd)
  rootCmd.AddCommand(homepageCmd)
  integrationCmd.AddCommand(allIntegrationHubsCmd)
  integrationCmd.AddCommand(createIntegrationHubCmd)
  integrationCmd.AddCommand(integrationHubCmd)
  integrationCmd.AddCommand(updateIntegrationHubCmd)
  integrationCmd.AddCommand(deleteIntegrationHubCmd)
  integrationCmd.AddCommand(acceptIntegrationHubLegalAgreementCmd)
  integrationCmd.AddCommand(allIntegrationsCmd)
  integrationCmd.AddCommand(integrationCmd4963)
  integrationCmd.AddCommand(updateIntegrationCmd)
  integrationCmd.AddCommand(fetchIntegrationFormCmd)
  integrationCmd.AddCommand(testIntegrationCmd)
  rootCmd.AddCommand(integrationCmd)
  lookCmd.AddCommand(allLooksCmd)
  lookCmd.AddCommand(createLookCmd)
  lookCmd.AddCommand(searchLooksCmd)
  lookCmd.AddCommand(lookCmd988)
  lookCmd.AddCommand(updateLookCmd)
  lookCmd.AddCommand(deleteLookCmd)
  lookCmd.AddCommand(runLookCmd)
  lookCmd.AddCommand(copyLookCmd)
  lookCmd.AddCommand(moveLookCmd)
  rootCmd.AddCommand(lookCmd)
  lookmlModelCmd.AddCommand(allLookmlModelsCmd)
  lookmlModelCmd.AddCommand(createLookmlModelCmd)
  lookmlModelCmd.AddCommand(lookmlModelCmd4124)
  lookmlModelCmd.AddCommand(updateLookmlModelCmd)
  lookmlModelCmd.AddCommand(deleteLookmlModelCmd)
  lookmlModelCmd.AddCommand(lookmlModelExploreCmd)
  rootCmd.AddCommand(lookmlModelCmd)
  metadataCmd.AddCommand(modelFieldnameSuggestionsCmd)
  metadataCmd.AddCommand(getModelCmd)
  metadataCmd.AddCommand(connectionDatabasesCmd)
  metadataCmd.AddCommand(connectionFeaturesCmd)
  metadataCmd.AddCommand(connectionSchemasCmd)
  metadataCmd.AddCommand(connectionTablesCmd)
  metadataCmd.AddCommand(connectionColumnsCmd)
  metadataCmd.AddCommand(connectionSearchColumnsCmd)
  metadataCmd.AddCommand(connectionCostEstimateCmd)
  rootCmd.AddCommand(metadataCmd)
  projectCmd.AddCommand(lockAllCmd)
  projectCmd.AddCommand(allGitBranchesCmd)
  projectCmd.AddCommand(gitBranchCmd)
  projectCmd.AddCommand(updateGitBranchCmd)
  projectCmd.AddCommand(createGitBranchCmd)
  projectCmd.AddCommand(findGitBranchCmd)
  projectCmd.AddCommand(deleteGitBranchCmd)
  projectCmd.AddCommand(deployRefToProductionCmd)
  projectCmd.AddCommand(deployToProductionCmd)
  projectCmd.AddCommand(resetProjectToProductionCmd)
  projectCmd.AddCommand(resetProjectToRemoteCmd)
  projectCmd.AddCommand(allProjectsCmd)
  projectCmd.AddCommand(createProjectCmd)
  projectCmd.AddCommand(projectCmd3260)
  projectCmd.AddCommand(updateProjectCmd)
  projectCmd.AddCommand(manifestCmd)
  projectCmd.AddCommand(gitDeployKeyCmd)
  projectCmd.AddCommand(createGitDeployKeyCmd)
  projectCmd.AddCommand(projectValidationResultsCmd)
  projectCmd.AddCommand(validateProjectCmd)
  projectCmd.AddCommand(projectWorkspaceCmd)
  projectCmd.AddCommand(allProjectFilesCmd)
  projectCmd.AddCommand(projectFileCmd)
  projectCmd.AddCommand(allGitConnectionTestsCmd)
  projectCmd.AddCommand(runGitConnectionTestCmd)
  projectCmd.AddCommand(allLookmlTestsCmd)
  projectCmd.AddCommand(runLookmlTestCmd)
  projectCmd.AddCommand(tagRefCmd)
  projectCmd.AddCommand(updateRepositoryCredentialCmd)
  projectCmd.AddCommand(deleteRepositoryCredentialCmd)
  projectCmd.AddCommand(getAllRepositoryCredentialsCmd)
  rootCmd.AddCommand(projectCmd)
  queryCmd.AddCommand(createQueryTaskCmd)
  queryCmd.AddCommand(queryTaskMultiResultsCmd)
  queryCmd.AddCommand(queryTaskCmd)
  queryCmd.AddCommand(queryTaskResultsCmd)
  queryCmd.AddCommand(queryCmd5522)
  queryCmd.AddCommand(queryForSlugCmd)
  queryCmd.AddCommand(createQueryCmd)
  queryCmd.AddCommand(runQueryCmd)
  queryCmd.AddCommand(runInlineQueryCmd)
  queryCmd.AddCommand(runUrlEncodedQueryCmd)
  queryCmd.AddCommand(mergeQueryCmd)
  queryCmd.AddCommand(createMergeQueryCmd)
  queryCmd.AddCommand(allRunningQueriesCmd)
  queryCmd.AddCommand(killQueryCmd)
  queryCmd.AddCommand(sqlQueryCmd)
  queryCmd.AddCommand(createSqlQueryCmd)
  queryCmd.AddCommand(runSqlQueryCmd)
  rootCmd.AddCommand(queryCmd)
  renderTaskCmd.AddCommand(createLookRenderTaskCmd)
  renderTaskCmd.AddCommand(createQueryRenderTaskCmd)
  renderTaskCmd.AddCommand(createDashboardRenderTaskCmd)
  renderTaskCmd.AddCommand(renderTaskCmd1705)
  renderTaskCmd.AddCommand(renderTaskResultsCmd)
  rootCmd.AddCommand(renderTaskCmd)
  roleCmd.AddCommand(searchModelSetsCmd)
  roleCmd.AddCommand(modelSetCmd)
  roleCmd.AddCommand(updateModelSetCmd)
  roleCmd.AddCommand(deleteModelSetCmd)
  roleCmd.AddCommand(allModelSetsCmd)
  roleCmd.AddCommand(createModelSetCmd)
  roleCmd.AddCommand(allPermissionsCmd)
  roleCmd.AddCommand(searchPermissionSetsCmd)
  roleCmd.AddCommand(permissionSetCmd)
  roleCmd.AddCommand(updatePermissionSetCmd)
  roleCmd.AddCommand(deletePermissionSetCmd)
  roleCmd.AddCommand(allPermissionSetsCmd)
  roleCmd.AddCommand(createPermissionSetCmd)
  roleCmd.AddCommand(allRolesCmd)
  roleCmd.AddCommand(createRoleCmd)
  roleCmd.AddCommand(searchRolesCmd)
  roleCmd.AddCommand(searchRolesWithUserCountCmd)
  roleCmd.AddCommand(roleCmd2020)
  roleCmd.AddCommand(updateRoleCmd)
  roleCmd.AddCommand(deleteRoleCmd)
  roleCmd.AddCommand(roleGroupsCmd)
  roleCmd.AddCommand(setRoleGroupsCmd)
  roleCmd.AddCommand(roleUsersCmd)
  roleCmd.AddCommand(setRoleUsersCmd)
  rootCmd.AddCommand(roleCmd)
  scheduledPlanCmd.AddCommand(scheduledPlansForSpaceCmd)
  scheduledPlanCmd.AddCommand(scheduledPlanCmd1703)
  scheduledPlanCmd.AddCommand(updateScheduledPlanCmd)
  scheduledPlanCmd.AddCommand(deleteScheduledPlanCmd)
  scheduledPlanCmd.AddCommand(allScheduledPlansCmd)
  scheduledPlanCmd.AddCommand(createScheduledPlanCmd)
  scheduledPlanCmd.AddCommand(scheduledPlanRunOnceCmd)
  scheduledPlanCmd.AddCommand(scheduledPlansForLookCmd)
  scheduledPlanCmd.AddCommand(scheduledPlansForDashboardCmd)
  scheduledPlanCmd.AddCommand(scheduledPlansForLookmlDashboardCmd)
  scheduledPlanCmd.AddCommand(scheduledPlanRunOnceByIdCmd)
  rootCmd.AddCommand(scheduledPlanCmd)
  sessionCmd.AddCommand(sessionCmd4)
  sessionCmd.AddCommand(updateSessionCmd)
  rootCmd.AddCommand(sessionCmd)
  themeCmd.AddCommand(allThemesCmd)
  themeCmd.AddCommand(createThemeCmd)
  themeCmd.AddCommand(searchThemesCmd)
  themeCmd.AddCommand(defaultThemeCmd)
  themeCmd.AddCommand(setDefaultThemeCmd)
  themeCmd.AddCommand(activeThemesCmd)
  themeCmd.AddCommand(themeOrDefaultCmd)
  themeCmd.AddCommand(validateThemeCmd)
  themeCmd.AddCommand(themeCmd4597)
  themeCmd.AddCommand(updateThemeCmd)
  themeCmd.AddCommand(deleteThemeCmd)
  rootCmd.AddCommand(themeCmd)
  userCmd.AddCommand(searchCredentialsEmailCmd)
  userCmd.AddCommand(meCmd)
  userCmd.AddCommand(allUsersCmd)
  userCmd.AddCommand(createUserCmd)
  userCmd.AddCommand(searchUsersCmd)
  userCmd.AddCommand(searchUsersNamesCmd)
  userCmd.AddCommand(userCmd8023)
  userCmd.AddCommand(updateUserCmd)
  userCmd.AddCommand(deleteUserCmd)
  userCmd.AddCommand(userForCredentialCmd)
  userCmd.AddCommand(userCredentialsEmailCmd)
  userCmd.AddCommand(createUserCredentialsEmailCmd)
  userCmd.AddCommand(updateUserCredentialsEmailCmd)
  userCmd.AddCommand(deleteUserCredentialsEmailCmd)
  userCmd.AddCommand(userCredentialsTotpCmd)
  userCmd.AddCommand(createUserCredentialsTotpCmd)
  userCmd.AddCommand(deleteUserCredentialsTotpCmd)
  userCmd.AddCommand(userCredentialsLdapCmd)
  userCmd.AddCommand(deleteUserCredentialsLdapCmd)
  userCmd.AddCommand(userCredentialsGoogleCmd)
  userCmd.AddCommand(deleteUserCredentialsGoogleCmd)
  userCmd.AddCommand(userCredentialsSamlCmd)
  userCmd.AddCommand(deleteUserCredentialsSamlCmd)
  userCmd.AddCommand(userCredentialsOidcCmd)
  userCmd.AddCommand(deleteUserCredentialsOidcCmd)
  userCmd.AddCommand(userCredentialsApi3Cmd)
  userCmd.AddCommand(deleteUserCredentialsApi3Cmd)
  userCmd.AddCommand(allUserCredentialsApi3sCmd)
  userCmd.AddCommand(createUserCredentialsApi3Cmd)
  userCmd.AddCommand(userCredentialsEmbedCmd)
  userCmd.AddCommand(deleteUserCredentialsEmbedCmd)
  userCmd.AddCommand(allUserCredentialsEmbedsCmd)
  userCmd.AddCommand(userCredentialsLookerOpenidCmd)
  userCmd.AddCommand(deleteUserCredentialsLookerOpenidCmd)
  userCmd.AddCommand(userSessionCmd)
  userCmd.AddCommand(deleteUserSessionCmd)
  userCmd.AddCommand(allUserSessionsCmd)
  userCmd.AddCommand(createUserCredentialsEmailPasswordResetCmd)
  userCmd.AddCommand(userRolesCmd)
  userCmd.AddCommand(setUserRolesCmd)
  userCmd.AddCommand(userAttributeUserValuesCmd)
  userCmd.AddCommand(setUserAttributeUserValueCmd)
  userCmd.AddCommand(deleteUserAttributeUserValueCmd)
  userCmd.AddCommand(sendUserCredentialsEmailPasswordResetCmd)
  userCmd.AddCommand(wipeoutUserEmailsCmd)
  userCmd.AddCommand(createEmbedUserCmd)
  rootCmd.AddCommand(userCmd)
  userAttributeCmd.AddCommand(allUserAttributesCmd)
  userAttributeCmd.AddCommand(createUserAttributeCmd)
  userAttributeCmd.AddCommand(userAttributeCmd9606)
  userAttributeCmd.AddCommand(updateUserAttributeCmd)
  userAttributeCmd.AddCommand(deleteUserAttributeCmd)
  userAttributeCmd.AddCommand(allUserAttributeGroupValuesCmd)
  userAttributeCmd.AddCommand(setUserAttributeGroupValuesCmd)
  rootCmd.AddCommand(userAttributeCmd)
  workspaceCmd.AddCommand(allWorkspacesCmd)
  workspaceCmd.AddCommand(workspaceCmd4539)
  rootCmd.AddCommand(workspaceCmd)
}