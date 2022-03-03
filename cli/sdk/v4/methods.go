// MIT License
//
// Copyright (c) 2021 Looker Data Sciences, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// 429 API methods

package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

var AlertCmd = &cobra.Command{
  Use:   "Alert",
  Short: "Alert",
  Long:  "Alert",
}

var searchAlertsCmd = &cobra.Command{
  Use:   "searchAlerts",
  Short: "Search Alerts",
  Long: `### Search Alerts
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchAlerts called")

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    group_by, _ := cmd.Flags().GetString("group_by")
    fmt.Println("group_by set to", group_by)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    disabled, _ := cmd.Flags().GetBool("disabled")
    fmt.Println("disabled set to", disabled)

    frequency, _ := cmd.Flags().GetString("frequency")
    fmt.Println("frequency set to", frequency)

    condition_met, _ := cmd.Flags().GetBool("condition_met")
    fmt.Println("condition_met set to", condition_met)

    last_run_start, _ := cmd.Flags().GetString("last_run_start")
    fmt.Println("last_run_start set to", last_run_start)

    last_run_end, _ := cmd.Flags().GetString("last_run_end")
    fmt.Println("last_run_end set to", last_run_end)

    all_owners, _ := cmd.Flags().GetBool("all_owners")
    fmt.Println("all_owners set to", all_owners)
  },
}

var getAlertCmd = &cobra.Command{
  Use:   "getAlert",
  Short: "Get an alert",
  Long: `### Get an alert by a given alert ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("getAlert called")

    alert_id, _ := cmd.Flags().GetInt64("alert_id")
    fmt.Println("alert_id set to", alert_id)
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
    fmt.Println("updateAlert called")

    alert_id, _ := cmd.Flags().GetInt64("alert_id")
    fmt.Println("alert_id set to", alert_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("updateAlertField called")

    alert_id, _ := cmd.Flags().GetInt64("alert_id")
    fmt.Println("alert_id set to", alert_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var deleteAlertCmd = &cobra.Command{
  Use:   "deleteAlert",
  Short: "Delete an alert",
  Long: `### Delete an alert by a given alert ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteAlert called")

    alert_id, _ := cmd.Flags().GetInt64("alert_id")
    fmt.Println("alert_id set to", alert_id)
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
    fmt.Println("createAlert called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var enqueueAlertCmd = &cobra.Command{
  Use:   "enqueueAlert",
  Short: "Enqueue an alert",
  Long: `### Enqueue an Alert by ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("enqueueAlert called")

    alert_id, _ := cmd.Flags().GetInt64("alert_id")
    fmt.Println("alert_id set to", alert_id)

    force, _ := cmd.Flags().GetBool("force")
    fmt.Println("force set to", force)
  },
}

var ApiAuthCmd = &cobra.Command{
  Use:   "ApiAuth",
  Short: "API Authentication",
  Long:  "API Authentication",
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
    fmt.Println("client_id set to", client_id)

    client_secret, _ := cmd.Flags().GetString("client_secret")
    fmt.Println("client_secret set to", client_secret)
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
    fmt.Println("user_id set to", user_id)

    associative, _ := cmd.Flags().GetBool("associative")
    fmt.Println("associative set to", associative)
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

var AuthCmd = &cobra.Command{
  Use:   "Auth",
  Short: "Manage User Authentication Configuration",
  Long:  "Manage User Authentication Configuration",
}

var createEmbedSecretCmd = &cobra.Command{
  Use:   "createEmbedSecret",
  Short: "Create Embed Secret",
  Long: `### Create an embed secret using the specified information.

The value of the 'secret' field will be set by Looker and returned.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createEmbedSecret called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var deleteEmbedSecretCmd = &cobra.Command{
  Use:   "deleteEmbedSecret",
  Short: "Delete Embed Secret",
  Long: `### Delete an embed secret.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteEmbedSecret called")

    embed_secret_id, _ := cmd.Flags().GetInt64("embed_secret_id")
    fmt.Println("embed_secret_id set to", embed_secret_id)
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
    fmt.Println("createSsoEmbedUrl called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("createEmbedUrlAsMe called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("allOauthClientApps called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var oauthClientAppCmd = &cobra.Command{
  Use:   "oauthClientApp",
  Short: "Get OAuth Client App",
  Long: `### Get Oauth Client App

Returns the registered app client with matching client_guid.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("oauthClientApp called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("registerOauthClientApp called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateOauthClientAppCmd = &cobra.Command{
  Use:   "updateOauthClientApp",
  Short: "Update OAuth App",
  Long: `### Update OAuth2 Client App Details

Modifies the details a previously registered OAuth2 login client app.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateOauthClientApp called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("deleteOauthClientApp called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)
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
    fmt.Println("invalidateTokens called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)
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
    fmt.Println("activateAppUser called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("deactivateAppUser called")

    client_guid, _ := cmd.Flags().GetString("client_guid")
    fmt.Println("client_guid set to", client_guid)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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
    fmt.Println("test_slug set to", test_slug)
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
    fmt.Println("test_slug set to", test_slug)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("test_slug set to", test_slug)
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
    fmt.Println("test_slug set to", test_slug)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    auth_type, _ := cmd.Flags().GetString("auth_type")
    fmt.Println("auth_type set to", auth_type)

    full_name, _ := cmd.Flags().GetString("full_name")
    fmt.Println("full_name set to", full_name)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to", email)

    remote_id, _ := cmd.Flags().GetString("remote_id")
    fmt.Println("remote_id set to", remote_id)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("key set to", key)
  },
}

var BoardCmd = &cobra.Command{
  Use:   "Board",
  Short: "Manage Boards",
  Long:  "Manage Boards",
}

var allBoardsCmd = &cobra.Command{
  Use:   "allBoards",
  Short: "Get All Boards",
  Long: `### Get information about all boards.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allBoards called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createBoardCmd = &cobra.Command{
  Use:   "createBoard",
  Short: "Create Board",
  Long: `### Create a new board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createBoard called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("searchBoards called")

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to", title)

    created_at, _ := cmd.Flags().GetString("created_at")
    fmt.Println("created_at set to", created_at)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to", last_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    favorited, _ := cmd.Flags().GetBool("favorited")
    fmt.Println("favorited set to", favorited)

    creator_id, _ := cmd.Flags().GetString("creator_id")
    fmt.Println("creator_id set to", creator_id)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
  },
}

var boardCmd = &cobra.Command{
  Use:   "board",
  Short: "Get Board",
  Long: `### Get information about a board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("board called")

    board_id, _ := cmd.Flags().GetInt64("board_id")
    fmt.Println("board_id set to", board_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateBoardCmd = &cobra.Command{
  Use:   "updateBoard",
  Short: "Update Board",
  Long: `### Update a board definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateBoard called")

    board_id, _ := cmd.Flags().GetInt64("board_id")
    fmt.Println("board_id set to", board_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteBoardCmd = &cobra.Command{
  Use:   "deleteBoard",
  Short: "Delete Board",
  Long: `### Delete a board.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteBoard called")

    board_id, _ := cmd.Flags().GetInt64("board_id")
    fmt.Println("board_id set to", board_id)
  },
}

var allBoardItemsCmd = &cobra.Command{
  Use:   "allBoardItems",
  Short: "Get All Board Items",
  Long: `### Get information about all board items.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allBoardItems called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    board_section_id, _ := cmd.Flags().GetString("board_section_id")
    fmt.Println("board_section_id set to", board_section_id)
  },
}

var createBoardItemCmd = &cobra.Command{
  Use:   "createBoardItem",
  Short: "Create Board Item",
  Long: `### Create a new board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createBoardItem called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var boardItemCmd = &cobra.Command{
  Use:   "boardItem",
  Short: "Get Board Item",
  Long: `### Get information about a board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("boardItem called")

    board_item_id, _ := cmd.Flags().GetInt64("board_item_id")
    fmt.Println("board_item_id set to", board_item_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateBoardItemCmd = &cobra.Command{
  Use:   "updateBoardItem",
  Short: "Update Board Item",
  Long: `### Update a board item definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateBoardItem called")

    board_item_id, _ := cmd.Flags().GetInt64("board_item_id")
    fmt.Println("board_item_id set to", board_item_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteBoardItemCmd = &cobra.Command{
  Use:   "deleteBoardItem",
  Short: "Delete Board Item",
  Long: `### Delete a board item.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteBoardItem called")

    board_item_id, _ := cmd.Flags().GetInt64("board_item_id")
    fmt.Println("board_item_id set to", board_item_id)
  },
}

var allBoardSectionsCmd = &cobra.Command{
  Use:   "allBoardSections",
  Short: "Get All Board sections",
  Long: `### Get information about all board sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allBoardSections called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)
  },
}

var createBoardSectionCmd = &cobra.Command{
  Use:   "createBoardSection",
  Short: "Create Board section",
  Long: `### Create a new board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createBoardSection called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var boardSectionCmd = &cobra.Command{
  Use:   "boardSection",
  Short: "Get Board section",
  Long: `### Get information about a board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("boardSection called")

    board_section_id, _ := cmd.Flags().GetInt64("board_section_id")
    fmt.Println("board_section_id set to", board_section_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateBoardSectionCmd = &cobra.Command{
  Use:   "updateBoardSection",
  Short: "Update Board section",
  Long: `### Update a board section definition.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateBoardSection called")

    board_section_id, _ := cmd.Flags().GetInt64("board_section_id")
    fmt.Println("board_section_id set to", board_section_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteBoardSectionCmd = &cobra.Command{
  Use:   "deleteBoardSection",
  Short: "Delete Board section",
  Long: `### Delete a board section.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteBoardSection called")

    board_section_id, _ := cmd.Flags().GetInt64("board_section_id")
    fmt.Println("board_section_id set to", board_section_id)
  },
}

var ColorCollectionCmd = &cobra.Command{
  Use:   "ColorCollection",
  Short: "Manage Color Collections",
  Long:  "Manage Color Collections",
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("collection_id set to", collection_id)
  },
}

var colorCollectionCmd = &cobra.Command{
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
    fmt.Println("collection_id set to", collection_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("collection_id set to", collection_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("collection_id set to", collection_id)
  },
}

var CommandCmd = &cobra.Command{
  Use:   "Command",
  Short: "Manage Commands",
  Long:  "Manage Commands",
}

var getAllCommandsCmd = &cobra.Command{
  Use:   "getAllCommands",
  Short: "Get All Commands",
  Long: `### Get All Commands.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("getAllCommands called")

    content_id, _ := cmd.Flags().GetString("content_id")
    fmt.Println("content_id set to", content_id)

    content_type, _ := cmd.Flags().GetString("content_type")
    fmt.Println("content_type set to", content_type)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)
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
    fmt.Println("createCommand called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("updateCommand called")

    command_id, _ := cmd.Flags().GetInt64("command_id")
    fmt.Println("command_id set to", command_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var deleteCommandCmd = &cobra.Command{
  Use:   "deleteCommand",
  Short: "Delete a custom command",
  Long: `### Delete an existing custom command.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteCommand called")

    command_id, _ := cmd.Flags().GetInt64("command_id")
    fmt.Println("command_id set to", command_id)
  },
}

var ConfigCmd = &cobra.Command{
  Use:   "Config",
  Short: "Manage General Configuration",
  Long:  "Manage General Configuration",
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)

    send_test_welcome_email, _ := cmd.Flags().GetBool("send_test_welcome_email")
    fmt.Println("send_test_welcome_email set to", send_test_welcome_email)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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

    legacy_feature_id, _ := cmd.Flags().GetString("legacy_feature_id")
    fmt.Println("legacy_feature_id set to", legacy_feature_id)
  },
}

var updateLegacyFeatureCmd = &cobra.Command{
  Use:   "updateLegacyFeature",
  Short: "Update Legacy Feature",
  Long: `### Update information about the legacy feature with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateLegacyFeature called")

    legacy_feature_id, _ := cmd.Flags().GetString("legacy_feature_id")
    fmt.Println("legacy_feature_id set to", legacy_feature_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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

var mobileSettingsCmd = &cobra.Command{
  Use:   "mobileSettings",
  Short: "Get Mobile_Settings",
  Long: `### Get all mobile settings.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("mobileSettings called")

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
    fmt.Println("getSetting called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("setSetting called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)
  },
}

var apiSpecCmd = &cobra.Command{
  Use:   "apiSpec",
  Short: "Get an API specification",
  Long: `### Get an API specification for this Looker instance.

The specification is returned as a JSON document in Swagger 2.x format
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("apiSpec called")

    api_version, _ := cmd.Flags().GetString("api_version")
    fmt.Println("api_version set to", api_version)

    specification, _ := cmd.Flags().GetString("specification")
    fmt.Println("specification set to", specification)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
  },
}

var ConnectionCmd = &cobra.Command{
  Use:   "Connection",
  Short: "Manage Database Connections",
  Long:  "Manage Database Connections",
}

var allConnectionsCmd = &cobra.Command{
  Use:   "allConnections",
  Short: "Get All Connections",
  Long: `### Get information about all connections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allConnections called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
  },
}

var connectionCmd = &cobra.Command{
  Use:   "connection",
  Short: "Get Connection",
  Long: `### Get information about a connection.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connection called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("connection_name set to", connection_name)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("connection_name set to", connection_name)
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
    fmt.Println("connection_name set to", connection_name)

    override_context, _ := cmd.Flags().GetString("override_context")
    fmt.Println("override_context set to", override_context)
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
    fmt.Println("connection_name set to", connection_name)

    tests, _ := cmd.Flags().GetString("tests")
    fmt.Println("tests set to", tests)
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
    fmt.Println("body set to", body)

    tests, _ := cmd.Flags().GetString("tests")
    fmt.Println("tests set to", tests)
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
    fmt.Println("fields set to", fields)
  },
}

var allExternalOauthApplicationsCmd = &cobra.Command{
  Use:   "allExternalOauthApplications",
  Short: "Get All External OAuth Applications",
  Long: `### Get all External OAuth Applications.

This is an OAuth Application which Looker uses to access external systems.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allExternalOauthApplications called")

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    client_id, _ := cmd.Flags().GetString("client_id")
    fmt.Println("client_id set to", client_id)
  },
}

var createExternalOauthApplicationCmd = &cobra.Command{
  Use:   "createExternalOauthApplication",
  Short: "Create External OAuth Application",
  Long: `### Create an OAuth Application using the specified configuration.

This is an OAuth Application which Looker uses to access external systems.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createExternalOauthApplication called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var createOauthApplicationUserStateCmd = &cobra.Command{
  Use:   "createOauthApplicationUserState",
  Short: "Create Create OAuth user state.",
  Long: `### Create OAuth User state.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createOauthApplicationUserState called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var allSshServersCmd = &cobra.Command{
  Use:   "allSshServers",
  Short: "Get All SSH Servers",
  Long: `### Get information about all SSH Servers.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allSshServers called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createSshServerCmd = &cobra.Command{
  Use:   "createSshServer",
  Short: "Create SSH Server",
  Long: `### Create an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSshServer called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var sshServerCmd = &cobra.Command{
  Use:   "sshServer",
  Short: "Get SSH Server",
  Long: `### Get information about an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sshServer called")

    ssh_server_id, _ := cmd.Flags().GetString("ssh_server_id")
    fmt.Println("ssh_server_id set to", ssh_server_id)
  },
}

var updateSshServerCmd = &cobra.Command{
  Use:   "updateSshServer",
  Short: "Update SSH Server",
  Long: `### Update an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateSshServer called")

    ssh_server_id, _ := cmd.Flags().GetString("ssh_server_id")
    fmt.Println("ssh_server_id set to", ssh_server_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var deleteSshServerCmd = &cobra.Command{
  Use:   "deleteSshServer",
  Short: "Delete SSH Server",
  Long: `### Delete an SSH Server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteSshServer called")

    ssh_server_id, _ := cmd.Flags().GetString("ssh_server_id")
    fmt.Println("ssh_server_id set to", ssh_server_id)
  },
}

var testSshServerCmd = &cobra.Command{
  Use:   "testSshServer",
  Short: "Test SSH Server",
  Long: `### Test the SSH Server
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testSshServer called")

    ssh_server_id, _ := cmd.Flags().GetString("ssh_server_id")
    fmt.Println("ssh_server_id set to", ssh_server_id)
  },
}

var allSshTunnelsCmd = &cobra.Command{
  Use:   "allSshTunnels",
  Short: "Get All SSH Tunnels",
  Long: `### Get information about all SSH Tunnels.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allSshTunnels called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createSshTunnelCmd = &cobra.Command{
  Use:   "createSshTunnel",
  Short: "Create SSH Tunnel",
  Long: `### Create an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createSshTunnel called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var sshTunnelCmd = &cobra.Command{
  Use:   "sshTunnel",
  Short: "Get SSH Tunnel",
  Long: `### Get information about an SSH Tunnel.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sshTunnel called")

    ssh_tunnel_id, _ := cmd.Flags().GetString("ssh_tunnel_id")
    fmt.Println("ssh_tunnel_id set to", ssh_tunnel_id)
  },
}

var updateSshTunnelCmd = &cobra.Command{
  Use:   "updateSshTunnel",
  Short: "Update SSH Tunnel",
  Long: `### Update an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateSshTunnel called")

    ssh_tunnel_id, _ := cmd.Flags().GetString("ssh_tunnel_id")
    fmt.Println("ssh_tunnel_id set to", ssh_tunnel_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var deleteSshTunnelCmd = &cobra.Command{
  Use:   "deleteSshTunnel",
  Short: "Delete SSH Tunnel",
  Long: `### Delete an SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteSshTunnel called")

    ssh_tunnel_id, _ := cmd.Flags().GetString("ssh_tunnel_id")
    fmt.Println("ssh_tunnel_id set to", ssh_tunnel_id)
  },
}

var testSshTunnelCmd = &cobra.Command{
  Use:   "testSshTunnel",
  Short: "Test SSH Tunnel",
  Long: `### Test the SSH Tunnel
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testSshTunnel called")

    ssh_tunnel_id, _ := cmd.Flags().GetString("ssh_tunnel_id")
    fmt.Println("ssh_tunnel_id set to", ssh_tunnel_id)
  },
}

var sshPublicKeyCmd = &cobra.Command{
  Use:   "sshPublicKey",
  Short: "Get SSH Public Key",
  Long: `### Get the SSH public key

Get the public key created for this instance to identify itself to a remote SSH server.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sshPublicKey called")

  },
}

var ContentCmd = &cobra.Command{
  Use:   "Content",
  Short: "Manage Content",
  Long:  "Manage Content",
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
    fmt.Println("id set to", id)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to", user_id)

    content_metadata_id, _ := cmd.Flags().GetString("content_metadata_id")
    fmt.Println("content_metadata_id set to", content_metadata_id)

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    board_id, _ := cmd.Flags().GetString("board_id")
    fmt.Println("board_id set to", board_id)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
  },
}

var contentFavoriteCmd = &cobra.Command{
  Use:   "contentFavorite",
  Short: "Get Favorite Content",
  Long:  `### Get favorite content by its id`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("contentFavorite called")

    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to", content_favorite_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteContentFavoriteCmd = &cobra.Command{
  Use:   "deleteContentFavorite",
  Short: "Delete Favorite Content",
  Long:  `### Delete favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteContentFavorite called")

    content_favorite_id, _ := cmd.Flags().GetInt64("content_favorite_id")
    fmt.Println("content_favorite_id set to", content_favorite_id)
  },
}

var createContentFavoriteCmd = &cobra.Command{
  Use:   "createContentFavorite",
  Short: "Create Favorite Content",
  Long:  `### Create favorite content`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createContentFavorite called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("parent_id set to", parent_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("content_metadata_id set to", content_metadata_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("content_metadata_id set to", content_metadata_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("content_metadata_id set to", content_metadata_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)

    send_boards_notification_email, _ := cmd.Flags().GetBool("send_boards_notification_email")
    fmt.Println("send_boards_notification_email set to", send_boards_notification_email)
  },
}

var updateContentMetadataAccessCmd = &cobra.Command{
  Use:   "updateContentMetadataAccess",
  Short: "Update Content Metadata Access",
  Long: `### Update type of access for content metadata.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateContentMetadataAccess called")

    content_metadata_access_id, _ := cmd.Flags().GetString("content_metadata_access_id")
    fmt.Println("content_metadata_access_id set to", content_metadata_access_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("content_metadata_access_id set to", content_metadata_access_id)
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

    _type, _ := cmd.Flags().GetString("type")
    fmt.Println("type set to", _type)

    resource_id, _ := cmd.Flags().GetString("resource_id")
    fmt.Println("resource_id set to", resource_id)

    reload, _ := cmd.Flags().GetString("reload")
    fmt.Println("reload set to", reload)

    format, _ := cmd.Flags().GetString("format")
    fmt.Println("format set to", format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to", height)
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
    fmt.Println("fields set to", fields)
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

    view_count, _ := cmd.Flags().GetString("view_count")
    fmt.Println("view_count set to", view_count)

    group_id, _ := cmd.Flags().GetString("group_id")
    fmt.Println("group_id set to", group_id)

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    content_metadata_id, _ := cmd.Flags().GetString("content_metadata_id")
    fmt.Println("content_metadata_id set to", content_metadata_id)

    start_of_week_date, _ := cmd.Flags().GetString("start_of_week_date")
    fmt.Println("start_of_week_date set to", start_of_week_date)

    all_time, _ := cmd.Flags().GetBool("all_time")
    fmt.Println("all_time set to", all_time)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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

    _type, _ := cmd.Flags().GetString("type")
    fmt.Println("type set to", _type)

    resource_id, _ := cmd.Flags().GetString("resource_id")
    fmt.Println("resource_id set to", resource_id)

    reload, _ := cmd.Flags().GetString("reload")
    fmt.Println("reload set to", reload)
  },
}

var DashboardCmd = &cobra.Command{
  Use:   "Dashboard",
  Short: "Manage Dashboards",
  Long:  "Manage Dashboards",
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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

    id, _ := cmd.Flags().GetString("id")
    fmt.Println("id set to", id)

    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to", slug)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to", title)

    description, _ := cmd.Flags().GetString("description")
    fmt.Println("description set to", description)

    content_favorite_id, _ := cmd.Flags().GetString("content_favorite_id")
    fmt.Println("content_favorite_id set to", content_favorite_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    deleted, _ := cmd.Flags().GetString("deleted")
    fmt.Println("deleted set to", deleted)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to", user_id)

    view_count, _ := cmd.Flags().GetString("view_count")
    fmt.Println("view_count set to", view_count)

    content_metadata_id, _ := cmd.Flags().GetString("content_metadata_id")
    fmt.Println("content_metadata_id set to", content_metadata_id)

    curate, _ := cmd.Flags().GetBool("curate")
    fmt.Println("curate set to", curate)

    last_viewed_at, _ := cmd.Flags().GetString("last_viewed_at")
    fmt.Println("last_viewed_at set to", last_viewed_at)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("lookml_dashboard_id set to", lookml_dashboard_id)

    space_id, _ := cmd.Flags().GetString("space_id")
    fmt.Println("space_id set to", space_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    raw_locale, _ := cmd.Flags().GetBool("raw_locale")
    fmt.Println("raw_locale set to", raw_locale)
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
    fmt.Println("lookml_dashboard_id set to", lookml_dashboard_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    raw_locale, _ := cmd.Flags().GetBool("raw_locale")
    fmt.Println("raw_locale set to", raw_locale)
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

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("dashboard_id set to", dashboard_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("dashboard_id set to", dashboard_id)
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
    fmt.Println("dashboard_id set to", dashboard_id)
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
    fmt.Println("dashboard_id set to", dashboard_id)
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
    fmt.Println("moveDashboard called")

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)
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
    fmt.Println("copyDashboard called")

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)
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
    fmt.Println("dashboard_id set to", dashboard_id)

    look_id, _ := cmd.Flags().GetInt64("look_id")
    fmt.Println("look_id set to", look_id)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to", title)

    deleted, _ := cmd.Flags().GetBool("deleted")
    fmt.Println("deleted set to", deleted)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)
  },
}

var dashboardElementCmd = &cobra.Command{
  Use:   "dashboardElement",
  Short: "Get DashboardElement",
  Long:  `### Get information about the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardElement called")

    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to", dashboard_element_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateDashboardElementCmd = &cobra.Command{
  Use:   "updateDashboardElement",
  Short: "Update DashboardElement",
  Long:  `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardElement called")

    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to", dashboard_element_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteDashboardElementCmd = &cobra.Command{
  Use:   "deleteDashboardElement",
  Short: "Delete DashboardElement",
  Long:  `### Delete a dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardElement called")

    dashboard_element_id, _ := cmd.Flags().GetString("dashboard_element_id")
    fmt.Println("dashboard_element_id set to", dashboard_element_id)
  },
}

var dashboardDashboardElementsCmd = &cobra.Command{
  Use:   "dashboardDashboardElements",
  Short: "Get All DashboardElements",
  Long:  `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardElements called")

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createDashboardElementCmd = &cobra.Command{
  Use:   "createDashboardElement",
  Short: "Create DashboardElement",
  Long:  `### Create a dashboard element on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardElement called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var dashboardFilterCmd = &cobra.Command{
  Use:   "dashboardFilter",
  Short: "Get Dashboard Filter",
  Long:  `### Get information about the dashboard filters with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardFilter called")

    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to", dashboard_filter_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateDashboardFilterCmd = &cobra.Command{
  Use:   "updateDashboardFilter",
  Short: "Update Dashboard Filter",
  Long:  `### Update the dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardFilter called")

    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to", dashboard_filter_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteDashboardFilterCmd = &cobra.Command{
  Use:   "deleteDashboardFilter",
  Short: "Delete Dashboard Filter",
  Long:  `### Delete a dashboard filter with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardFilter called")

    dashboard_filter_id, _ := cmd.Flags().GetString("dashboard_filter_id")
    fmt.Println("dashboard_filter_id set to", dashboard_filter_id)
  },
}

var dashboardDashboardFiltersCmd = &cobra.Command{
  Use:   "dashboardDashboardFilters",
  Short: "Get All Dashboard Filters",
  Long:  `### Get information about all the dashboard filters on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardFilters called")

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createDashboardFilterCmd = &cobra.Command{
  Use:   "createDashboardFilter",
  Short: "Create Dashboard Filter",
  Long:  `### Create a dashboard filter on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardFilter called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var dashboardLayoutComponentCmd = &cobra.Command{
  Use:   "dashboardLayoutComponent",
  Short: "Get DashboardLayoutComponent",
  Long:  `### Get information about the dashboard elements with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayoutComponent called")

    dashboard_layout_component_id, _ := cmd.Flags().GetString("dashboard_layout_component_id")
    fmt.Println("dashboard_layout_component_id set to", dashboard_layout_component_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateDashboardLayoutComponentCmd = &cobra.Command{
  Use:   "updateDashboardLayoutComponent",
  Short: "Update DashboardLayoutComponent",
  Long:  `### Update the dashboard element with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardLayoutComponent called")

    dashboard_layout_component_id, _ := cmd.Flags().GetString("dashboard_layout_component_id")
    fmt.Println("dashboard_layout_component_id set to", dashboard_layout_component_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var dashboardLayoutDashboardLayoutComponentsCmd = &cobra.Command{
  Use:   "dashboardLayoutDashboardLayoutComponents",
  Short: "Get All DashboardLayoutComponents",
  Long:  `### Get information about all the dashboard layout components for a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayoutDashboardLayoutComponents called")

    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to", dashboard_layout_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var dashboardLayoutCmd = &cobra.Command{
  Use:   "dashboardLayout",
  Short: "Get DashboardLayout",
  Long:  `### Get information about the dashboard layouts with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardLayout called")

    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to", dashboard_layout_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateDashboardLayoutCmd = &cobra.Command{
  Use:   "updateDashboardLayout",
  Short: "Update DashboardLayout",
  Long:  `### Update the dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDashboardLayout called")

    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to", dashboard_layout_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteDashboardLayoutCmd = &cobra.Command{
  Use:   "deleteDashboardLayout",
  Short: "Delete DashboardLayout",
  Long:  `### Delete a dashboard layout with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteDashboardLayout called")

    dashboard_layout_id, _ := cmd.Flags().GetString("dashboard_layout_id")
    fmt.Println("dashboard_layout_id set to", dashboard_layout_id)
  },
}

var dashboardDashboardLayoutsCmd = &cobra.Command{
  Use:   "dashboardDashboardLayouts",
  Short: "Get All DashboardLayouts",
  Long:  `### Get information about all the dashboard elements on a dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("dashboardDashboardLayouts called")

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createDashboardLayoutCmd = &cobra.Command{
  Use:   "createDashboardLayout",
  Short: "Create DashboardLayout",
  Long:  `### Create a dashboard layout on the dashboard with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createDashboardLayout called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var DataActionCmd = &cobra.Command{
  Use:   "DataAction",
  Short: "Run Data Actions",
  Long:  "Run Data Actions",
}

var performDataActionCmd = &cobra.Command{
  Use:   "performDataAction",
  Short: "Send a Data Action",
  Long:  `Perform a data action. The data action object can be obtained from query results, and used to perform an arbitrary action.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("performDataAction called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var fetchRemoteDataActionFormCmd = &cobra.Command{
  Use:   "fetchRemoteDataActionForm",
  Short: "Fetch Remote Data Action Form",
  Long:  `For some data actions, the remote server may supply a form requesting further user input. This endpoint takes a data action, asks the remote server to generate a form for it, and returns that form to you for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetchRemoteDataActionForm called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var DatagroupCmd = &cobra.Command{
  Use:   "Datagroup",
  Short: "Manage Datagroups",
  Long:  "Manage Datagroups",
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

var datagroupCmd = &cobra.Command{
  Use:   "datagroup",
  Short: "Get Datagroup",
  Long: `### Get information about a datagroup.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("datagroup called")

    datagroup_id, _ := cmd.Flags().GetInt64("datagroup_id")
    fmt.Println("datagroup_id set to", datagroup_id)
  },
}

var updateDatagroupCmd = &cobra.Command{
  Use:   "updateDatagroup",
  Short: "Update Datagroup",
  Long: `### Update a datagroup using the specified params.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateDatagroup called")

    datagroup_id, _ := cmd.Flags().GetInt64("datagroup_id")
    fmt.Println("datagroup_id set to", datagroup_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var DerivedTableCmd = &cobra.Command{
  Use:   "DerivedTable",
  Short: "View Derived Table graphs",
  Long:  "View Derived Table graphs",
}

var graphDerivedTablesForModelCmd = &cobra.Command{
  Use:   "graphDerivedTablesForModel",
  Short: "Get Derived Table graph for model",
  Long: `### Discover information about derived tables
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("graphDerivedTablesForModel called")

    model, _ := cmd.Flags().GetString("model")
    fmt.Println("model set to", model)

    format, _ := cmd.Flags().GetString("format")
    fmt.Println("format set to", format)

    color, _ := cmd.Flags().GetString("color")
    fmt.Println("color set to", color)
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
    fmt.Println("view set to", view)

    models, _ := cmd.Flags().GetString("models")
    fmt.Println("models set to", models)

    workspace, _ := cmd.Flags().GetString("workspace")
    fmt.Println("workspace set to", workspace)
  },
}

var FolderCmd = &cobra.Command{
  Use:   "Folder",
  Short: "Manage Folders",
  Long:  "Manage Folders",
}

var searchFoldersCmd = &cobra.Command{
  Use:   "searchFolders",
  Short: "Search Folders",
  Long:  `Search for folders by creator id, parent id, name, etc`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("searchFolders called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    parent_id, _ := cmd.Flags().GetString("parent_id")
    fmt.Println("parent_id set to", parent_id)

    creator_id, _ := cmd.Flags().GetString("creator_id")
    fmt.Println("creator_id set to", creator_id)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    is_shared_root, _ := cmd.Flags().GetBool("is_shared_root")
    fmt.Println("is_shared_root set to", is_shared_root)
  },
}

var folderCmd = &cobra.Command{
  Use:   "folder",
  Short: "Get Folder",
  Long:  `### Get information about the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folder called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateFolderCmd = &cobra.Command{
  Use:   "updateFolder",
  Short: "Update Folder",
  Long:  `### Update the folder with a specific id.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateFolder called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("folder_id set to", folder_id)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
  },
}

var folderChildrenCmd = &cobra.Command{
  Use:   "folderChildren",
  Short: "Get Folder Children",
  Long:  `### Get the children of a folder.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderChildren called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)
  },
}

var folderChildrenSearchCmd = &cobra.Command{
  Use:   "folderChildrenSearch",
  Short: "Search Folder Children",
  Long:  `### Search the children of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderChildrenSearch called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)
  },
}

var folderParentCmd = &cobra.Command{
  Use:   "folderParent",
  Short: "Get Folder Parent",
  Long:  `### Get the parent of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderParent called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var folderAncestorsCmd = &cobra.Command{
  Use:   "folderAncestors",
  Short: "Get Folder Ancestors",
  Long:  `### Get the ancestors of a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderAncestors called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var folderDashboardsCmd = &cobra.Command{
  Use:   "folderDashboards",
  Short: "Get Folder Dashboards",
  Long:  `### Get the dashboards in a folder`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("folderDashboards called")

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var GroupCmd = &cobra.Command{
  Use:   "Group",
  Short: "Manage Groups",
  Long:  "Manage Groups",
}

var allGroupsCmd = &cobra.Command{
  Use:   "allGroups",
  Short: "Get All Groups",
  Long: `### Get information about all groups.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allGroups called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to", ids)

    content_metadata_id, _ := cmd.Flags().GetInt64("content_metadata_id")
    fmt.Println("content_metadata_id set to", content_metadata_id)

    can_add_to_content_metadata, _ := cmd.Flags().GetBool("can_add_to_content_metadata")
    fmt.Println("can_add_to_content_metadata set to", can_add_to_content_metadata)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    external_group_id, _ := cmd.Flags().GetString("external_group_id")
    fmt.Println("external_group_id set to", external_group_id)

    externally_managed, _ := cmd.Flags().GetBool("externally_managed")
    fmt.Println("externally_managed set to", externally_managed)

    externally_orphaned, _ := cmd.Flags().GetBool("externally_orphaned")
    fmt.Println("externally_orphaned set to", externally_orphaned)
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
    fmt.Println("searchGroupsWithRoles called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    external_group_id, _ := cmd.Flags().GetString("external_group_id")
    fmt.Println("external_group_id set to", external_group_id)

    externally_managed, _ := cmd.Flags().GetBool("externally_managed")
    fmt.Println("externally_managed set to", externally_managed)

    externally_orphaned, _ := cmd.Flags().GetBool("externally_orphaned")
    fmt.Println("externally_orphaned set to", externally_orphaned)
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
    fmt.Println("searchGroupsWithHierarchy called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    external_group_id, _ := cmd.Flags().GetString("external_group_id")
    fmt.Println("external_group_id set to", external_group_id)

    externally_managed, _ := cmd.Flags().GetBool("externally_managed")
    fmt.Println("externally_managed set to", externally_managed)

    externally_orphaned, _ := cmd.Flags().GetBool("externally_orphaned")
    fmt.Println("externally_orphaned set to", externally_orphaned)
  },
}

var groupCmd = &cobra.Command{
  Use:   "group",
  Short: "Get Group",
  Long: `### Get information about a group.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("group called")

    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateGroupCmd = &cobra.Command{
  Use:   "updateGroup",
  Short: "Update Group",
  Long:  `### Updates the a group (admin only).`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateGroup called")

    group_id, _ := cmd.Flags().GetInt64("group_id")
    fmt.Println("group_id set to", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("group_id set to", group_id)
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
    fmt.Println("group_id set to", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("group_id set to", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("group_id set to", group_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)
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
    fmt.Println("group_id set to", group_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("group_id set to", group_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
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
    fmt.Println("group_id set to", group_id)

    deleting_group_id, _ := cmd.Flags().GetInt64("deleting_group_id")
    fmt.Println("deleting_group_id set to", deleting_group_id)
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
    fmt.Println("group_id set to", group_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("group_id set to", group_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to", user_attribute_id)
  },
}

var HomepageCmd = &cobra.Command{
  Use:   "Homepage",
  Short: "Manage Homepage",
  Long:  "Manage Homepage",
}

var allPrimaryHomepageSectionsCmd = &cobra.Command{
  Use:   "allPrimaryHomepageSections",
  Short: "Get All Primary homepage sections",
  Long: `### Get information about the primary homepage's sections.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allPrimaryHomepageSections called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var IntegrationCmd = &cobra.Command{
  Use:   "Integration",
  Short: "Manage Integrations",
  Long:  "Manage Integrations",
}

var allIntegrationHubsCmd = &cobra.Command{
  Use:   "allIntegrationHubs",
  Short: "Get All Integration Hubs",
  Long: `### Get information about all Integration Hubs.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allIntegrationHubs called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("integration_hub_id set to", integration_hub_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("integration_hub_id set to", integration_hub_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("integration_hub_id set to", integration_hub_id)
  },
}

var acceptIntegrationHubLegalAgreementCmd = &cobra.Command{
  Use:   "acceptIntegrationHubLegalAgreement",
  Short: "Accept Integration Hub Legal Agreement",
  Long:  `Accepts the legal agreement for a given integration hub. This only works for integration hubs that have legal_agreement_required set to true and legal_agreement_signed set to false.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("acceptIntegrationHubLegalAgreement called")

    integration_hub_id, _ := cmd.Flags().GetInt64("integration_hub_id")
    fmt.Println("integration_hub_id set to", integration_hub_id)
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
    fmt.Println("fields set to", fields)

    integration_hub_id, _ := cmd.Flags().GetString("integration_hub_id")
    fmt.Println("integration_hub_id set to", integration_hub_id)
  },
}

var integrationCmd = &cobra.Command{
  Use:   "integration",
  Short: "Get Integration",
  Long: `### Get information about a Integration.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("integration called")

    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to", integration_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("integration_id set to", integration_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var fetchIntegrationFormCmd = &cobra.Command{
  Use:   "fetchIntegrationForm",
  Short: "Fetch Remote Integration Form",
  Long:  `Returns the Integration form for presentation to the user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("fetchIntegrationForm called")

    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to", integration_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var testIntegrationCmd = &cobra.Command{
  Use:   "testIntegration",
  Short: "Test integration",
  Long:  `Tests the integration to make sure all the settings are working.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("testIntegration called")

    integration_id, _ := cmd.Flags().GetString("integration_id")
    fmt.Println("integration_id set to", integration_id)
  },
}

var LookCmd = &cobra.Command{
  Use:   "Look",
  Short: "Run and Manage Looks",
  Long:  "Run and Manage Looks",
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("id set to", id)

    title, _ := cmd.Flags().GetString("title")
    fmt.Println("title set to", title)

    description, _ := cmd.Flags().GetString("description")
    fmt.Println("description set to", description)

    content_favorite_id, _ := cmd.Flags().GetString("content_favorite_id")
    fmt.Println("content_favorite_id set to", content_favorite_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)

    user_id, _ := cmd.Flags().GetString("user_id")
    fmt.Println("user_id set to", user_id)

    view_count, _ := cmd.Flags().GetString("view_count")
    fmt.Println("view_count set to", view_count)

    deleted, _ := cmd.Flags().GetBool("deleted")
    fmt.Println("deleted set to", deleted)

    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to", query_id)

    curate, _ := cmd.Flags().GetBool("curate")
    fmt.Println("curate set to", curate)

    last_viewed_at, _ := cmd.Flags().GetString("last_viewed_at")
    fmt.Println("last_viewed_at set to", last_viewed_at)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)
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

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to", server_table_calcs)
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
    fmt.Println("copyLook called")

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)
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
    fmt.Println("moveLook called")

    look_id, _ := cmd.Flags().GetString("look_id")
    fmt.Println("look_id set to", look_id)

    folder_id, _ := cmd.Flags().GetString("folder_id")
    fmt.Println("folder_id set to", folder_id)
  },
}

var LookmlModelCmd = &cobra.Command{
  Use:   "LookmlModel",
  Short: "Manage LookML Models",
  Long:  "Manage LookML Models",
}

var allLookmlModelsCmd = &cobra.Command{
  Use:   "allLookmlModels",
  Short: "Get All LookML Models",
  Long: `### Get information about all lookml models.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allLookmlModels called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)
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
    fmt.Println("body set to", body)
  },
}

var lookmlModelCmd = &cobra.Command{
  Use:   "lookmlModel",
  Short: "Get LookML Model",
  Long: `### Get information about a lookml model.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("lookmlModel called")

    lookml_model_name, _ := cmd.Flags().GetString("lookml_model_name")
    fmt.Println("lookml_model_name set to", lookml_model_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("lookml_model_name set to", lookml_model_name)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("lookml_model_name set to", lookml_model_name)
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
    fmt.Println("lookml_model_name set to", lookml_model_name)

    explore_name, _ := cmd.Flags().GetString("explore_name")
    fmt.Println("explore_name set to", explore_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var MetadataCmd = &cobra.Command{
  Use:   "Metadata",
  Short: "Connection Metadata Features",
  Long:  "Connection Metadata Features",
}

var modelFieldnameSuggestionsCmd = &cobra.Command{
  Use:   "modelFieldnameSuggestions",
  Short: "Model field name suggestions",
  Long: `### Field name suggestions for a model and view

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("modelFieldnameSuggestions called")

    model_name, _ := cmd.Flags().GetString("model_name")
    fmt.Println("model_name set to", model_name)

    view_name, _ := cmd.Flags().GetString("view_name")
    fmt.Println("view_name set to", view_name)

    field_name, _ := cmd.Flags().GetString("field_name")
    fmt.Println("field_name set to", field_name)

    term, _ := cmd.Flags().GetString("term")
    fmt.Println("term set to", term)

    filters, _ := cmd.Flags().GetString("filters")
    fmt.Println("filters set to", filters)
  },
}

var getModelCmd = &cobra.Command{
  Use:   "getModel",
  Short: "Get a single model",
  Long: `### Get a single model

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("getModel called")

    model_name, _ := cmd.Flags().GetString("model_name")
    fmt.Println("model_name set to", model_name)
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
    fmt.Println("connectionDatabases called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)
  },
}

var connectionFeaturesCmd = &cobra.Command{
  Use:   "connectionFeatures",
  Short: "Metadata features supported by this connection",
  Long: `### Retrieve metadata features for this connection

Returns a list of feature names with 'true' (available) or 'false' (not available)

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connectionFeatures called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var connectionSchemasCmd = &cobra.Command{
  Use:   "connectionSchemas",
  Short: "Get schemas for a connection",
  Long: `### Get the list of schemas and tables for a connection

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connectionSchemas called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    database, _ := cmd.Flags().GetString("database")
    fmt.Println("database set to", database)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("connectionTables called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    database, _ := cmd.Flags().GetString("database")
    fmt.Println("database set to", database)

    schema_name, _ := cmd.Flags().GetString("schema_name")
    fmt.Println("schema_name set to", schema_name)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var connectionColumnsCmd = &cobra.Command{
  Use:   "connectionColumns",
  Short: "Get columns for a connection",
  Long: `### Get the columns (and therefore also the tables) in a specific schema

`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connectionColumns called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    database, _ := cmd.Flags().GetString("database")
    fmt.Println("database set to", database)

    schema_name, _ := cmd.Flags().GetString("schema_name")
    fmt.Println("schema_name set to", schema_name)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    table_limit, _ := cmd.Flags().GetInt64("table_limit")
    fmt.Println("table_limit set to", table_limit)

    table_names, _ := cmd.Flags().GetString("table_names")
    fmt.Println("table_names set to", table_names)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var connectionSearchColumnsCmd = &cobra.Command{
  Use:   "connectionSearchColumns",
  Short: "Search a connection for columns",
  Long: `### Search a connection for columns matching the specified name

**Note**: 'column_name' must be a valid column name. It is not a search pattern.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("connectionSearchColumns called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    column_name, _ := cmd.Flags().GetString("column_name")
    fmt.Println("column_name set to", column_name)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("connectionCostEstimate called")

    connection_name, _ := cmd.Flags().GetString("connection_name")
    fmt.Println("connection_name set to", connection_name)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var ProjectCmd = &cobra.Command{
  Use:   "Project",
  Short: "Manage Projects",
  Long:  "Manage Projects",
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
    fmt.Println("lockAll called")

    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("project_id set to", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("project_id set to", project_id)

    branch_name, _ := cmd.Flags().GetString("branch_name")
    fmt.Println("branch_name set to", branch_name)
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
    fmt.Println("project_id set to", project_id)

    branch_name, _ := cmd.Flags().GetString("branch_name")
    fmt.Println("branch_name set to", branch_name)
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
    fmt.Println("project_id set to", project_id)

    branch, _ := cmd.Flags().GetString("branch")
    fmt.Println("branch set to", branch)

    ref, _ := cmd.Flags().GetString("ref")
    fmt.Println("ref set to", ref)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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

    project_id, _ := cmd.Flags().GetString("project_id")
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)
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
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to", file_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("project_id set to", project_id)

    remote_url, _ := cmd.Flags().GetString("remote_url")
    fmt.Println("remote_url set to", remote_url)
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
    fmt.Println("project_id set to", project_id)

    test_id, _ := cmd.Flags().GetString("test_id")
    fmt.Println("test_id set to", test_id)

    remote_url, _ := cmd.Flags().GetString("remote_url")
    fmt.Println("remote_url set to", remote_url)

    use_production, _ := cmd.Flags().GetString("use_production")
    fmt.Println("use_production set to", use_production)
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
    fmt.Println("project_id set to", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to", file_id)
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
    fmt.Println("project_id set to", project_id)

    file_id, _ := cmd.Flags().GetString("file_id")
    fmt.Println("file_id set to", file_id)

    test, _ := cmd.Flags().GetString("test")
    fmt.Println("test set to", test)

    model, _ := cmd.Flags().GetString("model")
    fmt.Println("model set to", model)
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
    fmt.Println("project_id set to", project_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    commit_sha, _ := cmd.Flags().GetString("commit_sha")
    fmt.Println("commit_sha set to", commit_sha)

    tag_name, _ := cmd.Flags().GetString("tag_name")
    fmt.Println("tag_name set to", tag_name)

    tag_message, _ := cmd.Flags().GetString("tag_message")
    fmt.Println("tag_message set to", tag_message)
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
    fmt.Println("root_project_id set to", root_project_id)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to", credential_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("root_project_id set to", root_project_id)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to", credential_id)
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
    fmt.Println("root_project_id set to", root_project_id)
  },
}

var QueryCmd = &cobra.Command{
  Use:   "Query",
  Short: "Run and Manage Queries",
  Long:  "Run and Manage Queries",
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
    fmt.Println("body set to", body)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to", server_table_calcs)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("query_task_ids set to", query_task_ids)
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
    fmt.Println("query_task_id set to", query_task_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("query_task_id set to", query_task_id)
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

    query_id, _ := cmd.Flags().GetInt64("query_id")
    fmt.Println("query_id set to", query_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("slug set to", slug)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("query_id set to", query_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to", server_table_calcs)

    source, _ := cmd.Flags().GetString("source")
    fmt.Println("source set to", source)
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
    fmt.Println("result_format set to", result_format)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    apply_formatting, _ := cmd.Flags().GetBool("apply_formatting")
    fmt.Println("apply_formatting set to", apply_formatting)

    apply_vis, _ := cmd.Flags().GetBool("apply_vis")
    fmt.Println("apply_vis set to", apply_vis)

    cache, _ := cmd.Flags().GetBool("cache")
    fmt.Println("cache set to", cache)

    image_width, _ := cmd.Flags().GetInt64("image_width")
    fmt.Println("image_width set to", image_width)

    image_height, _ := cmd.Flags().GetInt64("image_height")
    fmt.Println("image_height set to", image_height)

    generate_drill_links, _ := cmd.Flags().GetBool("generate_drill_links")
    fmt.Println("generate_drill_links set to", generate_drill_links)

    force_production, _ := cmd.Flags().GetBool("force_production")
    fmt.Println("force_production set to", force_production)

    cache_only, _ := cmd.Flags().GetBool("cache_only")
    fmt.Println("cache_only set to", cache_only)

    path_prefix, _ := cmd.Flags().GetString("path_prefix")
    fmt.Println("path_prefix set to", path_prefix)

    rebuild_pdts, _ := cmd.Flags().GetBool("rebuild_pdts")
    fmt.Println("rebuild_pdts set to", rebuild_pdts)

    server_table_calcs, _ := cmd.Flags().GetBool("server_table_calcs")
    fmt.Println("server_table_calcs set to", server_table_calcs)
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
    fmt.Println("model_name set to", model_name)

    view_name, _ := cmd.Flags().GetString("view_name")
    fmt.Println("view_name set to", view_name)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)
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
    fmt.Println("merge_query_id set to", merge_query_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("query_task_id set to", query_task_id)
  },
}

var sqlQueryCmd = &cobra.Command{
  Use:   "sqlQuery",
  Short: "Get SQL Runner Query",
  Long:  `Get a SQL Runner query.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("sqlQuery called")

    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to", slug)
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
    fmt.Println("body set to", body)
  },
}

var runSqlQueryCmd = &cobra.Command{
  Use:   "runSqlQuery",
  Short: "Run SQL Runner Query",
  Long:  `Execute a SQL Runner query in a given result_format.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("runSqlQuery called")

    slug, _ := cmd.Flags().GetString("slug")
    fmt.Println("slug set to", slug)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    download, _ := cmd.Flags().GetString("download")
    fmt.Println("download set to", download)
  },
}

var RenderTaskCmd = &cobra.Command{
  Use:   "RenderTask",
  Short: "Manage Render Tasks",
  Long:  "Manage Render Tasks",
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
    fmt.Println("look_id set to", look_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("query_id set to", query_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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

    dashboard_id, _ := cmd.Flags().GetString("dashboard_id")
    fmt.Println("dashboard_id set to", dashboard_id)

    result_format, _ := cmd.Flags().GetString("result_format")
    fmt.Println("result_format set to", result_format)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    width, _ := cmd.Flags().GetInt64("width")
    fmt.Println("width set to", width)

    height, _ := cmd.Flags().GetInt64("height")
    fmt.Println("height set to", height)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    pdf_paper_size, _ := cmd.Flags().GetString("pdf_paper_size")
    fmt.Println("pdf_paper_size set to", pdf_paper_size)

    pdf_landscape, _ := cmd.Flags().GetBool("pdf_landscape")
    fmt.Println("pdf_landscape set to", pdf_landscape)

    long_tables, _ := cmd.Flags().GetBool("long_tables")
    fmt.Println("long_tables set to", long_tables)
  },
}

var renderTaskCmd = &cobra.Command{
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
    fmt.Println("render_task_id set to", render_task_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("render_task_id set to", render_task_id)
  },
}

var RoleCmd = &cobra.Command{
  Use:   "Role",
  Short: "Manage Roles",
  Long:  "Manage Roles",
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
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    all_access, _ := cmd.Flags().GetBool("all_access")
    fmt.Println("all_access set to", all_access)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("model_set_id set to", model_set_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("model_set_id set to", model_set_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("model_set_id set to", model_set_id)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    all_access, _ := cmd.Flags().GetBool("all_access")
    fmt.Println("all_access set to", all_access)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("permission_set_id set to", permission_set_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("permission_set_id set to", permission_set_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("permission_set_id set to", permission_set_id)
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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
    fmt.Println("fields set to", fields)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to", ids)
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
    fmt.Println("body set to", body)
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
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("searchRolesWithUserCount called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    built_in, _ := cmd.Flags().GetBool("built_in")
    fmt.Println("built_in set to", built_in)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
  },
}

var roleCmd = &cobra.Command{
  Use:   "role",
  Short: "Get Role",
  Long: `### Get information about the role with a specific id.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("role called")

    role_id, _ := cmd.Flags().GetInt64("role_id")
    fmt.Println("role_id set to", role_id)
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
    fmt.Println("role_id set to", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("role_id set to", role_id)
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
    fmt.Println("role_id set to", role_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("role_id set to", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("role_id set to", role_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    direct_association_only, _ := cmd.Flags().GetBool("direct_association_only")
    fmt.Println("direct_association_only set to", direct_association_only)
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
    fmt.Println("role_id set to", role_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var ScheduledPlanCmd = &cobra.Command{
  Use:   "ScheduledPlan",
  Short: "Manage Scheduled Plans",
  Long:  "Manage Scheduled Plans",
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
    fmt.Println("space_id set to", space_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var scheduledPlanCmd = &cobra.Command{
  Use:   "scheduledPlan",
  Short: "Get Scheduled Plan",
  Long: `### Get Information About a Scheduled Plan

Admins can fetch information about other users' Scheduled Plans.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("scheduledPlan called")

    scheduled_plan_id, _ := cmd.Flags().GetInt64("scheduled_plan_id")
    fmt.Println("scheduled_plan_id set to", scheduled_plan_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("scheduled_plan_id set to", scheduled_plan_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("scheduled_plan_id set to", scheduled_plan_id)
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
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to", all_users)
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
    fmt.Println("body set to", body)
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
    fmt.Println("body set to", body)
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
    fmt.Println("look_id set to", look_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to", all_users)
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
    fmt.Println("dashboard_id set to", dashboard_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to", all_users)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("lookml_dashboard_id set to", lookml_dashboard_id)

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    all_users, _ := cmd.Flags().GetBool("all_users")
    fmt.Println("all_users set to", all_users)
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
    fmt.Println("scheduled_plan_id set to", scheduled_plan_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var SessionCmd = &cobra.Command{
  Use:   "Session",
  Short: "Session Information",
  Long:  "Session Information",
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
    fmt.Println("body set to", body)
  },
}

var ThemeCmd = &cobra.Command{
  Use:   "Theme",
  Short: "Manage Themes",
  Long:  "Manage Themes",
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
    fmt.Println("fields set to", fields)
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
    fmt.Println("body set to", body)
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
    fmt.Println("id set to", id)

    name, _ := cmd.Flags().GetString("name")
    fmt.Println("name set to", name)

    begin_at, _ := cmd.Flags().GetString("begin_at")
    fmt.Println("begin_at set to", begin_at)

    end_at, _ := cmd.Flags().GetString("end_at")
    fmt.Println("end_at set to", end_at)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
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
    fmt.Println("ts set to", ts)
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
    fmt.Println("name set to", name)
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
    fmt.Println("name set to", name)

    ts, _ := cmd.Flags().GetString("ts")
    fmt.Println("ts set to", ts)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("name set to", name)

    ts, _ := cmd.Flags().GetString("ts")
    fmt.Println("ts set to", ts)
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
    fmt.Println("body set to", body)
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

    theme_id, _ := cmd.Flags().GetInt64("theme_id")
    fmt.Println("theme_id set to", theme_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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

    theme_id, _ := cmd.Flags().GetInt64("theme_id")
    fmt.Println("theme_id set to", theme_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("theme_id set to", theme_id)
  },
}

var UserCmd = &cobra.Command{
  Use:   "User",
  Short: "Manage Users",
  Long:  "Manage Users",
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
    fmt.Println("searchCredentialsEmail called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to", email)

    emails, _ := cmd.Flags().GetString("emails")
    fmt.Println("emails set to", emails)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)
  },
}

var meCmd = &cobra.Command{
  Use:   "me",
  Short: "Get Current User",
  Long: `### Get information about the current user; i.e. the user account currently calling the API.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("me called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    ids, _ := cmd.Flags().GetString("ids")
    fmt.Println("ids set to", ids)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetString("id")
    fmt.Println("id set to", id)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to", last_name)

    verified_looker_employee, _ := cmd.Flags().GetBool("verified_looker_employee")
    fmt.Println("verified_looker_employee set to", verified_looker_employee)

    embed_user, _ := cmd.Flags().GetBool("embed_user")
    fmt.Println("embed_user set to", embed_user)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to", email)

    is_disabled, _ := cmd.Flags().GetBool("is_disabled")
    fmt.Println("is_disabled set to", is_disabled)

    filter_or, _ := cmd.Flags().GetBool("filter_or")
    fmt.Println("filter_or set to", filter_or)

    content_metadata_id, _ := cmd.Flags().GetString("content_metadata_id")
    fmt.Println("content_metadata_id set to", content_metadata_id)

    group_id, _ := cmd.Flags().GetString("group_id")
    fmt.Println("group_id set to", group_id)
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
    fmt.Println("pattern set to", pattern)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    page, _ := cmd.Flags().GetInt64("page")
    fmt.Println("page set to", page)

    per_page, _ := cmd.Flags().GetInt64("per_page")
    fmt.Println("per_page set to", per_page)

    limit, _ := cmd.Flags().GetInt64("limit")
    fmt.Println("limit set to", limit)

    offset, _ := cmd.Flags().GetInt64("offset")
    fmt.Println("offset set to", offset)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)

    id, _ := cmd.Flags().GetInt64("id")
    fmt.Println("id set to", id)

    first_name, _ := cmd.Flags().GetString("first_name")
    fmt.Println("first_name set to", first_name)

    last_name, _ := cmd.Flags().GetString("last_name")
    fmt.Println("last_name set to", last_name)

    verified_looker_employee, _ := cmd.Flags().GetBool("verified_looker_employee")
    fmt.Println("verified_looker_employee set to", verified_looker_employee)

    email, _ := cmd.Flags().GetString("email")
    fmt.Println("email set to", email)

    is_disabled, _ := cmd.Flags().GetBool("is_disabled")
    fmt.Println("is_disabled set to", is_disabled)
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

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_id set to", user_id)
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
    fmt.Println("credential_type set to", credential_type)

    credential_id, _ := cmd.Flags().GetString("credential_id")
    fmt.Println("credential_id set to", credential_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var userCredentialsEmailCmd = &cobra.Command{
  Use:   "userCredentialsEmail",
  Short: "Get Email/Password Credential",
  Long:  `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsEmail called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createUserCredentialsEmailCmd = &cobra.Command{
  Use:   "createUserCredentialsEmail",
  Short: "Create Email/Password Credential",
  Long:  `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsEmail called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var updateUserCredentialsEmailCmd = &cobra.Command{
  Use:   "updateUserCredentialsEmail",
  Short: "Update Email/Password Credential",
  Long:  `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("updateUserCredentialsEmail called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsEmailCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmail",
  Short: "Delete Email/Password Credential",
  Long:  `### Email/password login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsEmail called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsTotpCmd = &cobra.Command{
  Use:   "userCredentialsTotp",
  Short: "Get Two-Factor Credential",
  Long:  `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsTotp called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createUserCredentialsTotpCmd = &cobra.Command{
  Use:   "createUserCredentialsTotp",
  Short: "Create Two-Factor Credential",
  Long:  `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsTotp called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsTotpCmd = &cobra.Command{
  Use:   "deleteUserCredentialsTotp",
  Short: "Delete Two-Factor Credential",
  Long:  `### Two-factor login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsTotp called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsLdapCmd = &cobra.Command{
  Use:   "userCredentialsLdap",
  Short: "Get LDAP Credential",
  Long:  `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsLdap called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsLdapCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLdap",
  Short: "Delete LDAP Credential",
  Long:  `### LDAP login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsLdap called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsGoogleCmd = &cobra.Command{
  Use:   "userCredentialsGoogle",
  Short: "Get Google Auth Credential",
  Long:  `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsGoogle called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsGoogleCmd = &cobra.Command{
  Use:   "deleteUserCredentialsGoogle",
  Short: "Delete Google Auth Credential",
  Long:  `### Google authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsGoogle called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsSamlCmd = &cobra.Command{
  Use:   "userCredentialsSaml",
  Short: "Get Saml Auth Credential",
  Long:  `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsSaml called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsSamlCmd = &cobra.Command{
  Use:   "deleteUserCredentialsSaml",
  Short: "Delete Saml Auth Credential",
  Long:  `### Saml authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsSaml called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsOidcCmd = &cobra.Command{
  Use:   "userCredentialsOidc",
  Short: "Get OIDC Auth Credential",
  Long:  `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsOidc called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsOidcCmd = &cobra.Command{
  Use:   "deleteUserCredentialsOidc",
  Short: "Delete OIDC Auth Credential",
  Long:  `### OpenID Connect (OIDC) authentication login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsOidc called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userCredentialsApi3Cmd = &cobra.Command{
  Use:   "userCredentialsApi3",
  Short: "Get API 3 Credential",
  Long:  `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsApi3 called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    credentials_api3_id, _ := cmd.Flags().GetInt64("credentials_api3_id")
    fmt.Println("credentials_api3_id set to", credentials_api3_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "deleteUserCredentialsApi3",
  Short: "Delete API 3 Credential",
  Long:  `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsApi3 called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    credentials_api3_id, _ := cmd.Flags().GetInt64("credentials_api3_id")
    fmt.Println("credentials_api3_id set to", credentials_api3_id)
  },
}

var allUserCredentialsApi3sCmd = &cobra.Command{
  Use:   "allUserCredentialsApi3s",
  Short: "Get All API 3 Credentials",
  Long:  `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserCredentialsApi3s called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createUserCredentialsApi3Cmd = &cobra.Command{
  Use:   "createUserCredentialsApi3",
  Short: "Create API 3 Credential",
  Long:  `### API 3 login information for the specified user. This is for the newer API keys that can be added for any user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createUserCredentialsApi3 called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var userCredentialsEmbedCmd = &cobra.Command{
  Use:   "userCredentialsEmbed",
  Short: "Get Embedding Credential",
  Long:  `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsEmbed called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    credentials_embed_id, _ := cmd.Flags().GetInt64("credentials_embed_id")
    fmt.Println("credentials_embed_id set to", credentials_embed_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsEmbedCmd = &cobra.Command{
  Use:   "deleteUserCredentialsEmbed",
  Short: "Delete Embedding Credential",
  Long:  `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsEmbed called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    credentials_embed_id, _ := cmd.Flags().GetInt64("credentials_embed_id")
    fmt.Println("credentials_embed_id set to", credentials_embed_id)
  },
}

var allUserCredentialsEmbedsCmd = &cobra.Command{
  Use:   "allUserCredentialsEmbeds",
  Short: "Get All Embedding Credentials",
  Long:  `### Embed login information for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserCredentialsEmbeds called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var userCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "userCredentialsLookerOpenid",
  Short: "Get Looker OpenId Credential",
  Long:  `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userCredentialsLookerOpenid called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserCredentialsLookerOpenidCmd = &cobra.Command{
  Use:   "deleteUserCredentialsLookerOpenid",
  Short: "Delete Looker OpenId Credential",
  Long:  `### Looker Openid login information for the specified user. Used by Looker Analysts.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserCredentialsLookerOpenid called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)
  },
}

var userSessionCmd = &cobra.Command{
  Use:   "userSession",
  Short: "Get Web Login Session",
  Long:  `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userSession called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    session_id, _ := cmd.Flags().GetInt64("session_id")
    fmt.Println("session_id set to", session_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var deleteUserSessionCmd = &cobra.Command{
  Use:   "deleteUserSession",
  Short: "Delete Web Login Session",
  Long:  `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("deleteUserSession called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    session_id, _ := cmd.Flags().GetInt64("session_id")
    fmt.Println("session_id set to", session_id)
  },
}

var allUserSessionsCmd = &cobra.Command{
  Use:   "allUserSessions",
  Short: "Get All Web Login Sessions",
  Long:  `### Web login session for the specified user.`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserSessions called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_id set to", user_id)

    expires, _ := cmd.Flags().GetBool("expires")
    fmt.Println("expires set to", expires)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    direct_association_only, _ := cmd.Flags().GetBool("direct_association_only")
    fmt.Println("direct_association_only set to", direct_association_only)
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
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    user_attribute_ids, _ := cmd.Flags().GetString("user_attribute_ids")
    fmt.Println("user_attribute_ids set to", user_attribute_ids)

    all_values, _ := cmd.Flags().GetBool("all_values")
    fmt.Println("all_values set to", all_values)

    include_unset, _ := cmd.Flags().GetBool("include_unset")
    fmt.Println("include_unset set to", include_unset)
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
    fmt.Println("user_id set to", user_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
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
    fmt.Println("user_id set to", user_id)

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to", user_attribute_id)
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
    fmt.Println("sendUserCredentialsEmailPasswordReset called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("wipeoutUserEmails called")

    user_id, _ := cmd.Flags().GetInt64("user_id")
    fmt.Println("user_id set to", user_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var createEmbedUserCmd = &cobra.Command{
  Use:   "createEmbedUser",
  Short: "Create an embed user from an external user ID",
  Long: `Create an embed user from an external user ID
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("createEmbedUser called")

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var UserAttributeCmd = &cobra.Command{
  Use:   "UserAttribute",
  Short: "Manage User Attributes",
  Long:  "Manage User Attributes",
}

var allUserAttributesCmd = &cobra.Command{
  Use:   "allUserAttributes",
  Short: "Get All User Attributes",
  Long: `### Get information about all user attributes.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("allUserAttributes called")

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)

    sorts, _ := cmd.Flags().GetString("sorts")
    fmt.Println("sorts set to", sorts)
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
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
  },
}

var userAttributeCmd = &cobra.Command{
  Use:   "userAttribute",
  Short: "Get User Attribute",
  Long: `### Get information about a user attribute.
`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("userAttribute called")

    user_attribute_id, _ := cmd.Flags().GetInt64("user_attribute_id")
    fmt.Println("user_attribute_id set to", user_attribute_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_attribute_id set to", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_attribute_id set to", user_attribute_id)
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
    fmt.Println("user_attribute_id set to", user_attribute_id)

    fields, _ := cmd.Flags().GetString("fields")
    fmt.Println("fields set to", fields)
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
    fmt.Println("user_attribute_id set to", user_attribute_id)

    body, _ := cmd.Flags().GetString("body")
    fmt.Println("body set to", body)
  },
}

var WorkspaceCmd = &cobra.Command{
  Use:   "Workspace",
  Short: "Manage Workspaces",
  Long:  "Manage Workspaces",
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

    workspace_id, _ := cmd.Flags().GetString("workspace_id")
    fmt.Println("workspace_id set to", workspace_id)
  },
}

func init() {
  AlertCmd.AddCommand(searchAlertsCmd)
  searchAlertsCmd.Flags().Int64("limit", 0, "(Optional) Number of results to return (used with `offset`).")
  searchAlertsCmd.Flags().Int64("offset", 0, "(Optional) Number of results to skip before returning any (used with `limit`).")
  searchAlertsCmd.Flags().String("group_by", "", "(Optional) Dimension by which to order the results(`dashboard` | `owner`)")
  searchAlertsCmd.Flags().String("fields", "", "(Optional) Requested fields.")
  searchAlertsCmd.Flags().Bool("disabled", false, "(Optional) Filter on returning only enabled or disabled alerts.")
  searchAlertsCmd.Flags().String("frequency", "", "(Optional) Filter on alert frequency, such as: monthly, weekly, daily, hourly, minutes")
  searchAlertsCmd.Flags().Bool("condition_met", false, "(Optional) Filter on whether the alert has met its condition when it last executed")
  searchAlertsCmd.Flags().String("last_run_start", "", "(Optional) Filter on the start range of the last time the alerts were run. Example: 2021-01-01T01:01:01-08:00.")
  searchAlertsCmd.Flags().String("last_run_end", "", "(Optional) Filter on the start range of the last time the alerts were run. Example: 2021-01-01T01:01:01-08:00.")
  searchAlertsCmd.Flags().Bool("all_owners", false, "(Admin only) (Optional) Filter for all owners.")
  AlertCmd.AddCommand(getAlertCmd)
  getAlertCmd.Flags().Int64("alert_id", 0, "ID of an alert")
  cobra.MarkFlagRequired(getAlertCmd.Flags(), "alert_id")
  AlertCmd.AddCommand(updateAlertCmd)
  updateAlertCmd.Flags().Int64("alert_id", 0, "ID of an alert")
  cobra.MarkFlagRequired(updateAlertCmd.Flags(), "alert_id")
  updateAlertCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateAlertCmd.Flags(), "body")
  AlertCmd.AddCommand(updateAlertFieldCmd)
  updateAlertFieldCmd.Flags().Int64("alert_id", 0, "ID of an alert")
  cobra.MarkFlagRequired(updateAlertFieldCmd.Flags(), "alert_id")
  updateAlertFieldCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateAlertFieldCmd.Flags(), "body")
  AlertCmd.AddCommand(deleteAlertCmd)
  deleteAlertCmd.Flags().Int64("alert_id", 0, "ID of an alert")
  cobra.MarkFlagRequired(deleteAlertCmd.Flags(), "alert_id")
  AlertCmd.AddCommand(createAlertCmd)
  createAlertCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createAlertCmd.Flags(), "body")
  AlertCmd.AddCommand(enqueueAlertCmd)
  enqueueAlertCmd.Flags().Int64("alert_id", 0, "ID of an alert")
  cobra.MarkFlagRequired(enqueueAlertCmd.Flags(), "alert_id")
  enqueueAlertCmd.Flags().Bool("force", false, "Whether to enqueue an alert again if its already running.")
  rootCmd.AddCommand(AlertCmd)
  ApiAuthCmd.AddCommand(loginCmd)
  loginCmd.Flags().String("client_id", "", "client_id part of API3 Key.")
  loginCmd.Flags().String("client_secret", "", "client_secret part of API3 Key.")
  ApiAuthCmd.AddCommand(loginUserCmd)
  loginUserCmd.Flags().Int64("user_id", 0, "Id of user.")
  cobra.MarkFlagRequired(loginUserCmd.Flags(), "user_id")
  loginUserCmd.Flags().Bool("associative", false, "When true (default), API calls using the returned access_token are attributed to the admin user who created the access_token. When false, API activity is attributed to the user the access_token runs as. False requires a looker license.")
  ApiAuthCmd.AddCommand(logoutCmd)
  rootCmd.AddCommand(ApiAuthCmd)
  AuthCmd.AddCommand(createEmbedSecretCmd)
  createEmbedSecretCmd.Flags().String("body", "", "")
  AuthCmd.AddCommand(deleteEmbedSecretCmd)
  deleteEmbedSecretCmd.Flags().Int64("embed_secret_id", 0, "Id of Embed Secret")
  cobra.MarkFlagRequired(deleteEmbedSecretCmd.Flags(), "embed_secret_id")
  AuthCmd.AddCommand(createSsoEmbedUrlCmd)
  createSsoEmbedUrlCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createSsoEmbedUrlCmd.Flags(), "body")
  AuthCmd.AddCommand(createEmbedUrlAsMeCmd)
  createEmbedUrlAsMeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createEmbedUrlAsMeCmd.Flags(), "body")
  AuthCmd.AddCommand(ldapConfigCmd)
  AuthCmd.AddCommand(updateLdapConfigCmd)
  updateLdapConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateLdapConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(testLdapConfigConnectionCmd)
  testLdapConfigConnectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(testLdapConfigConnectionCmd.Flags(), "body")
  AuthCmd.AddCommand(testLdapConfigAuthCmd)
  testLdapConfigAuthCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(testLdapConfigAuthCmd.Flags(), "body")
  AuthCmd.AddCommand(testLdapConfigUserInfoCmd)
  testLdapConfigUserInfoCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(testLdapConfigUserInfoCmd.Flags(), "body")
  AuthCmd.AddCommand(testLdapConfigUserAuthCmd)
  testLdapConfigUserAuthCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(testLdapConfigUserAuthCmd.Flags(), "body")
  AuthCmd.AddCommand(allOauthClientAppsCmd)
  allOauthClientAppsCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(oauthClientAppCmd)
  oauthClientAppCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(oauthClientAppCmd.Flags(), "client_guid")
  oauthClientAppCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(registerOauthClientAppCmd)
  registerOauthClientAppCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(registerOauthClientAppCmd.Flags(), "client_guid")
  registerOauthClientAppCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(registerOauthClientAppCmd.Flags(), "body")
  registerOauthClientAppCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(updateOauthClientAppCmd)
  updateOauthClientAppCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(updateOauthClientAppCmd.Flags(), "client_guid")
  updateOauthClientAppCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateOauthClientAppCmd.Flags(), "body")
  updateOauthClientAppCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(deleteOauthClientAppCmd)
  deleteOauthClientAppCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(deleteOauthClientAppCmd.Flags(), "client_guid")
  AuthCmd.AddCommand(invalidateTokensCmd)
  invalidateTokensCmd.Flags().String("client_guid", "", "The unique id of the application")
  cobra.MarkFlagRequired(invalidateTokensCmd.Flags(), "client_guid")
  AuthCmd.AddCommand(activateAppUserCmd)
  activateAppUserCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(activateAppUserCmd.Flags(), "client_guid")
  activateAppUserCmd.Flags().Int64("user_id", 0, "The id of the user to enable use of this app")
  cobra.MarkFlagRequired(activateAppUserCmd.Flags(), "user_id")
  activateAppUserCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(deactivateAppUserCmd)
  deactivateAppUserCmd.Flags().String("client_guid", "", "The unique id of this application")
  cobra.MarkFlagRequired(deactivateAppUserCmd.Flags(), "client_guid")
  deactivateAppUserCmd.Flags().Int64("user_id", 0, "The id of the user to enable use of this app")
  cobra.MarkFlagRequired(deactivateAppUserCmd.Flags(), "user_id")
  deactivateAppUserCmd.Flags().String("fields", "", "Requested fields.")
  AuthCmd.AddCommand(oidcConfigCmd)
  AuthCmd.AddCommand(updateOidcConfigCmd)
  updateOidcConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateOidcConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(oidcTestConfigCmd)
  oidcTestConfigCmd.Flags().String("test_slug", "", "Slug of test config")
  cobra.MarkFlagRequired(oidcTestConfigCmd.Flags(), "test_slug")
  AuthCmd.AddCommand(deleteOidcTestConfigCmd)
  deleteOidcTestConfigCmd.Flags().String("test_slug", "", "Slug of test config")
  cobra.MarkFlagRequired(deleteOidcTestConfigCmd.Flags(), "test_slug")
  AuthCmd.AddCommand(createOidcTestConfigCmd)
  createOidcTestConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createOidcTestConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(passwordConfigCmd)
  AuthCmd.AddCommand(updatePasswordConfigCmd)
  updatePasswordConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updatePasswordConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(forcePasswordResetAtNextLoginForAllUsersCmd)
  AuthCmd.AddCommand(samlConfigCmd)
  AuthCmd.AddCommand(updateSamlConfigCmd)
  updateSamlConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateSamlConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(samlTestConfigCmd)
  samlTestConfigCmd.Flags().String("test_slug", "", "Slug of test config")
  cobra.MarkFlagRequired(samlTestConfigCmd.Flags(), "test_slug")
  AuthCmd.AddCommand(deleteSamlTestConfigCmd)
  deleteSamlTestConfigCmd.Flags().String("test_slug", "", "Slug of test config")
  cobra.MarkFlagRequired(deleteSamlTestConfigCmd.Flags(), "test_slug")
  AuthCmd.AddCommand(createSamlTestConfigCmd)
  createSamlTestConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createSamlTestConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(parseSamlIdpMetadataCmd)
  parseSamlIdpMetadataCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(parseSamlIdpMetadataCmd.Flags(), "body")
  AuthCmd.AddCommand(fetchAndParseSamlIdpMetadataCmd)
  fetchAndParseSamlIdpMetadataCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(fetchAndParseSamlIdpMetadataCmd.Flags(), "body")
  AuthCmd.AddCommand(sessionConfigCmd)
  AuthCmd.AddCommand(updateSessionConfigCmd)
  updateSessionConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateSessionConfigCmd.Flags(), "body")
  AuthCmd.AddCommand(allUserLoginLockoutsCmd)
  allUserLoginLockoutsCmd.Flags().String("fields", "", "Include only these fields in the response")
  AuthCmd.AddCommand(searchUserLoginLockoutsCmd)
  searchUserLoginLockoutsCmd.Flags().String("fields", "", "Include only these fields in the response")
  searchUserLoginLockoutsCmd.Flags().Int64("page", 0, "Return only page N of paginated results")
  searchUserLoginLockoutsCmd.Flags().Int64("per_page", 0, "Return N rows of data per page")
  searchUserLoginLockoutsCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchUserLoginLockoutsCmd.Flags().String("auth_type", "", "Auth type user is locked out for (email, ldap, totp, api)")
  searchUserLoginLockoutsCmd.Flags().String("full_name", "", "Match name")
  searchUserLoginLockoutsCmd.Flags().String("email", "", "Match email")
  searchUserLoginLockoutsCmd.Flags().String("remote_id", "", "Match remote LDAP ID")
  searchUserLoginLockoutsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  AuthCmd.AddCommand(deleteUserLoginLockoutCmd)
  deleteUserLoginLockoutCmd.Flags().String("key", "", "The key associated with the locked user")
  cobra.MarkFlagRequired(deleteUserLoginLockoutCmd.Flags(), "key")
  rootCmd.AddCommand(AuthCmd)
  BoardCmd.AddCommand(allBoardsCmd)
  allBoardsCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(createBoardCmd)
  createBoardCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createBoardCmd.Flags(), "body")
  createBoardCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(searchBoardsCmd)
  searchBoardsCmd.Flags().String("title", "", "Matches board title.")
  searchBoardsCmd.Flags().String("created_at", "", "Matches the timestamp for when the board was created.")
  searchBoardsCmd.Flags().String("first_name", "", "The first name of the user who created this board.")
  searchBoardsCmd.Flags().String("last_name", "", "The last name of the user who created this board.")
  searchBoardsCmd.Flags().String("fields", "", "Requested fields.")
  searchBoardsCmd.Flags().Bool("favorited", false, "Return favorited boards when true.")
  searchBoardsCmd.Flags().String("creator_id", "", "Filter on boards created by a particular user.")
  searchBoardsCmd.Flags().String("sorts", "", "The fields to sort the results by")
  searchBoardsCmd.Flags().Int64("page", 0, "The page to return.")
  searchBoardsCmd.Flags().Int64("per_page", 0, "The number of items in the returned page.")
  searchBoardsCmd.Flags().Int64("offset", 0, "The number of items to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchBoardsCmd.Flags().Int64("limit", 0, "The maximum number of items to return. (used with offset and takes priority over page and per_page)")
  searchBoardsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  BoardCmd.AddCommand(boardCmd)
  boardCmd.Flags().Int64("board_id", 0, "Id of board")
  cobra.MarkFlagRequired(boardCmd.Flags(), "board_id")
  boardCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(updateBoardCmd)
  updateBoardCmd.Flags().Int64("board_id", 0, "Id of board")
  cobra.MarkFlagRequired(updateBoardCmd.Flags(), "board_id")
  updateBoardCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateBoardCmd.Flags(), "body")
  updateBoardCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(deleteBoardCmd)
  deleteBoardCmd.Flags().Int64("board_id", 0, "Id of board")
  cobra.MarkFlagRequired(deleteBoardCmd.Flags(), "board_id")
  BoardCmd.AddCommand(allBoardItemsCmd)
  allBoardItemsCmd.Flags().String("fields", "", "Requested fields.")
  allBoardItemsCmd.Flags().String("sorts", "", "Fields to sort by.")
  allBoardItemsCmd.Flags().String("board_section_id", "", "Filter to a specific board section")
  BoardCmd.AddCommand(createBoardItemCmd)
  createBoardItemCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createBoardItemCmd.Flags(), "body")
  createBoardItemCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(boardItemCmd)
  boardItemCmd.Flags().Int64("board_item_id", 0, "Id of board item")
  cobra.MarkFlagRequired(boardItemCmd.Flags(), "board_item_id")
  boardItemCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(updateBoardItemCmd)
  updateBoardItemCmd.Flags().Int64("board_item_id", 0, "Id of board item")
  cobra.MarkFlagRequired(updateBoardItemCmd.Flags(), "board_item_id")
  updateBoardItemCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateBoardItemCmd.Flags(), "body")
  updateBoardItemCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(deleteBoardItemCmd)
  deleteBoardItemCmd.Flags().Int64("board_item_id", 0, "Id of board_item")
  cobra.MarkFlagRequired(deleteBoardItemCmd.Flags(), "board_item_id")
  BoardCmd.AddCommand(allBoardSectionsCmd)
  allBoardSectionsCmd.Flags().String("fields", "", "Requested fields.")
  allBoardSectionsCmd.Flags().String("sorts", "", "Fields to sort by.")
  BoardCmd.AddCommand(createBoardSectionCmd)
  createBoardSectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createBoardSectionCmd.Flags(), "body")
  createBoardSectionCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(boardSectionCmd)
  boardSectionCmd.Flags().Int64("board_section_id", 0, "Id of board section")
  cobra.MarkFlagRequired(boardSectionCmd.Flags(), "board_section_id")
  boardSectionCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(updateBoardSectionCmd)
  updateBoardSectionCmd.Flags().Int64("board_section_id", 0, "Id of board section")
  cobra.MarkFlagRequired(updateBoardSectionCmd.Flags(), "board_section_id")
  updateBoardSectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateBoardSectionCmd.Flags(), "body")
  updateBoardSectionCmd.Flags().String("fields", "", "Requested fields.")
  BoardCmd.AddCommand(deleteBoardSectionCmd)
  deleteBoardSectionCmd.Flags().Int64("board_section_id", 0, "Id of board section")
  cobra.MarkFlagRequired(deleteBoardSectionCmd.Flags(), "board_section_id")
  rootCmd.AddCommand(BoardCmd)
  ColorCollectionCmd.AddCommand(allColorCollectionsCmd)
  allColorCollectionsCmd.Flags().String("fields", "", "Requested fields.")
  ColorCollectionCmd.AddCommand(createColorCollectionCmd)
  createColorCollectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createColorCollectionCmd.Flags(), "body")
  ColorCollectionCmd.AddCommand(colorCollectionsCustomCmd)
  colorCollectionsCustomCmd.Flags().String("fields", "", "Requested fields.")
  ColorCollectionCmd.AddCommand(colorCollectionsStandardCmd)
  colorCollectionsStandardCmd.Flags().String("fields", "", "Requested fields.")
  ColorCollectionCmd.AddCommand(defaultColorCollectionCmd)
  ColorCollectionCmd.AddCommand(setDefaultColorCollectionCmd)
  setDefaultColorCollectionCmd.Flags().String("collection_id", "", "ID of color collection to set as default")
  cobra.MarkFlagRequired(setDefaultColorCollectionCmd.Flags(), "collection_id")
  ColorCollectionCmd.AddCommand(colorCollectionCmd)
  colorCollectionCmd.Flags().String("collection_id", "", "Id of Color Collection")
  cobra.MarkFlagRequired(colorCollectionCmd.Flags(), "collection_id")
  colorCollectionCmd.Flags().String("fields", "", "Requested fields.")
  ColorCollectionCmd.AddCommand(updateColorCollectionCmd)
  updateColorCollectionCmd.Flags().String("collection_id", "", "Id of Custom Color Collection")
  cobra.MarkFlagRequired(updateColorCollectionCmd.Flags(), "collection_id")
  updateColorCollectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateColorCollectionCmd.Flags(), "body")
  ColorCollectionCmd.AddCommand(deleteColorCollectionCmd)
  deleteColorCollectionCmd.Flags().String("collection_id", "", "Id of Color Collection")
  cobra.MarkFlagRequired(deleteColorCollectionCmd.Flags(), "collection_id")
  rootCmd.AddCommand(ColorCollectionCmd)
  CommandCmd.AddCommand(getAllCommandsCmd)
  getAllCommandsCmd.Flags().String("content_id", "", "Id of the associated content. This must be accompanied with content_type.")
  getAllCommandsCmd.Flags().String("content_type", "", "Type of the associated content. This must be accompanied with content_id.")
  getAllCommandsCmd.Flags().Int64("limit", 0, "Number of results to return.")
  CommandCmd.AddCommand(createCommandCmd)
  createCommandCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createCommandCmd.Flags(), "body")
  CommandCmd.AddCommand(updateCommandCmd)
  updateCommandCmd.Flags().Int64("command_id", 0, "ID of a command")
  cobra.MarkFlagRequired(updateCommandCmd.Flags(), "command_id")
  updateCommandCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateCommandCmd.Flags(), "body")
  CommandCmd.AddCommand(deleteCommandCmd)
  deleteCommandCmd.Flags().Int64("command_id", 0, "ID of a command")
  cobra.MarkFlagRequired(deleteCommandCmd.Flags(), "command_id")
  rootCmd.AddCommand(CommandCmd)
  ConfigCmd.AddCommand(cloudStorageConfigurationCmd)
  ConfigCmd.AddCommand(updateCloudStorageConfigurationCmd)
  updateCloudStorageConfigurationCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateCloudStorageConfigurationCmd.Flags(), "body")
  ConfigCmd.AddCommand(customWelcomeEmailCmd)
  ConfigCmd.AddCommand(updateCustomWelcomeEmailCmd)
  updateCustomWelcomeEmailCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateCustomWelcomeEmailCmd.Flags(), "body")
  updateCustomWelcomeEmailCmd.Flags().Bool("send_test_welcome_email", false, "If true a test email with the content from the request will be sent to the current user after saving")
  ConfigCmd.AddCommand(updateCustomWelcomeEmailTestCmd)
  updateCustomWelcomeEmailTestCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateCustomWelcomeEmailTestCmd.Flags(), "body")
  ConfigCmd.AddCommand(digestEmailsEnabledCmd)
  ConfigCmd.AddCommand(updateDigestEmailsEnabledCmd)
  updateDigestEmailsEnabledCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDigestEmailsEnabledCmd.Flags(), "body")
  ConfigCmd.AddCommand(createDigestEmailSendCmd)
  ConfigCmd.AddCommand(internalHelpResourcesContentCmd)
  ConfigCmd.AddCommand(updateInternalHelpResourcesContentCmd)
  updateInternalHelpResourcesContentCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateInternalHelpResourcesContentCmd.Flags(), "body")
  ConfigCmd.AddCommand(internalHelpResourcesCmd)
  ConfigCmd.AddCommand(updateInternalHelpResourcesCmd)
  updateInternalHelpResourcesCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateInternalHelpResourcesCmd.Flags(), "body")
  ConfigCmd.AddCommand(allLegacyFeaturesCmd)
  ConfigCmd.AddCommand(legacyFeatureCmd)
  legacyFeatureCmd.Flags().String("legacy_feature_id", "", "id of legacy feature")
  cobra.MarkFlagRequired(legacyFeatureCmd.Flags(), "legacy_feature_id")
  ConfigCmd.AddCommand(updateLegacyFeatureCmd)
  updateLegacyFeatureCmd.Flags().String("legacy_feature_id", "", "id of legacy feature")
  cobra.MarkFlagRequired(updateLegacyFeatureCmd.Flags(), "legacy_feature_id")
  updateLegacyFeatureCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateLegacyFeatureCmd.Flags(), "body")
  ConfigCmd.AddCommand(allLocalesCmd)
  ConfigCmd.AddCommand(mobileSettingsCmd)
  ConfigCmd.AddCommand(getSettingCmd)
  getSettingCmd.Flags().String("fields", "", "Requested fields")
  ConfigCmd.AddCommand(setSettingCmd)
  setSettingCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setSettingCmd.Flags(), "body")
  setSettingCmd.Flags().String("fields", "", "Requested fields")
  ConfigCmd.AddCommand(allTimezonesCmd)
  ConfigCmd.AddCommand(versionsCmd)
  versionsCmd.Flags().String("fields", "", "Requested fields.")
  ConfigCmd.AddCommand(apiSpecCmd)
  apiSpecCmd.Flags().String("api_version", "", "API version")
  cobra.MarkFlagRequired(apiSpecCmd.Flags(), "api_version")
  apiSpecCmd.Flags().String("specification", "", "Specification name. Typically, this is \"swagger.json\"")
  cobra.MarkFlagRequired(apiSpecCmd.Flags(), "specification")
  ConfigCmd.AddCommand(whitelabelConfigurationCmd)
  whitelabelConfigurationCmd.Flags().String("fields", "", "Requested fields.")
  ConfigCmd.AddCommand(updateWhitelabelConfigurationCmd)
  updateWhitelabelConfigurationCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateWhitelabelConfigurationCmd.Flags(), "body")
  rootCmd.AddCommand(ConfigCmd)
  ConnectionCmd.AddCommand(allConnectionsCmd)
  allConnectionsCmd.Flags().String("fields", "", "Requested fields.")
  ConnectionCmd.AddCommand(createConnectionCmd)
  createConnectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createConnectionCmd.Flags(), "body")
  ConnectionCmd.AddCommand(connectionCmd)
  connectionCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionCmd.Flags(), "connection_name")
  connectionCmd.Flags().String("fields", "", "Requested fields.")
  ConnectionCmd.AddCommand(updateConnectionCmd)
  updateConnectionCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(updateConnectionCmd.Flags(), "connection_name")
  updateConnectionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateConnectionCmd.Flags(), "body")
  ConnectionCmd.AddCommand(deleteConnectionCmd)
  deleteConnectionCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(deleteConnectionCmd.Flags(), "connection_name")
  ConnectionCmd.AddCommand(deleteConnectionOverrideCmd)
  deleteConnectionOverrideCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(deleteConnectionOverrideCmd.Flags(), "connection_name")
  deleteConnectionOverrideCmd.Flags().String("override_context", "", "Context of connection override")
  cobra.MarkFlagRequired(deleteConnectionOverrideCmd.Flags(), "override_context")
  ConnectionCmd.AddCommand(testConnectionCmd)
  testConnectionCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(testConnectionCmd.Flags(), "connection_name")
  testConnectionCmd.Flags().String("tests", "", "Array of names of tests to run")
  ConnectionCmd.AddCommand(testConnectionConfigCmd)
  testConnectionConfigCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(testConnectionConfigCmd.Flags(), "body")
  testConnectionConfigCmd.Flags().String("tests", "", "Array of names of tests to run")
  ConnectionCmd.AddCommand(allDialectInfosCmd)
  allDialectInfosCmd.Flags().String("fields", "", "Requested fields.")
  ConnectionCmd.AddCommand(allExternalOauthApplicationsCmd)
  allExternalOauthApplicationsCmd.Flags().String("name", "", "Application name")
  allExternalOauthApplicationsCmd.Flags().String("client_id", "", "Application Client ID")
  ConnectionCmd.AddCommand(createExternalOauthApplicationCmd)
  createExternalOauthApplicationCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createExternalOauthApplicationCmd.Flags(), "body")
  ConnectionCmd.AddCommand(createOauthApplicationUserStateCmd)
  createOauthApplicationUserStateCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createOauthApplicationUserStateCmd.Flags(), "body")
  ConnectionCmd.AddCommand(allSshServersCmd)
  allSshServersCmd.Flags().String("fields", "", "Requested fields.")
  ConnectionCmd.AddCommand(createSshServerCmd)
  createSshServerCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createSshServerCmd.Flags(), "body")
  ConnectionCmd.AddCommand(sshServerCmd)
  sshServerCmd.Flags().String("ssh_server_id", "", "Id of SSH Server")
  cobra.MarkFlagRequired(sshServerCmd.Flags(), "ssh_server_id")
  ConnectionCmd.AddCommand(updateSshServerCmd)
  updateSshServerCmd.Flags().String("ssh_server_id", "", "Id of SSH Server")
  cobra.MarkFlagRequired(updateSshServerCmd.Flags(), "ssh_server_id")
  updateSshServerCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateSshServerCmd.Flags(), "body")
  ConnectionCmd.AddCommand(deleteSshServerCmd)
  deleteSshServerCmd.Flags().String("ssh_server_id", "", "Id of SSH Server")
  cobra.MarkFlagRequired(deleteSshServerCmd.Flags(), "ssh_server_id")
  ConnectionCmd.AddCommand(testSshServerCmd)
  testSshServerCmd.Flags().String("ssh_server_id", "", "Id of SSH Server")
  cobra.MarkFlagRequired(testSshServerCmd.Flags(), "ssh_server_id")
  ConnectionCmd.AddCommand(allSshTunnelsCmd)
  allSshTunnelsCmd.Flags().String("fields", "", "Requested fields.")
  ConnectionCmd.AddCommand(createSshTunnelCmd)
  createSshTunnelCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createSshTunnelCmd.Flags(), "body")
  ConnectionCmd.AddCommand(sshTunnelCmd)
  sshTunnelCmd.Flags().String("ssh_tunnel_id", "", "Id of SSH Tunnel")
  cobra.MarkFlagRequired(sshTunnelCmd.Flags(), "ssh_tunnel_id")
  ConnectionCmd.AddCommand(updateSshTunnelCmd)
  updateSshTunnelCmd.Flags().String("ssh_tunnel_id", "", "Id of SSH Tunnel")
  cobra.MarkFlagRequired(updateSshTunnelCmd.Flags(), "ssh_tunnel_id")
  updateSshTunnelCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateSshTunnelCmd.Flags(), "body")
  ConnectionCmd.AddCommand(deleteSshTunnelCmd)
  deleteSshTunnelCmd.Flags().String("ssh_tunnel_id", "", "Id of SSH Tunnel")
  cobra.MarkFlagRequired(deleteSshTunnelCmd.Flags(), "ssh_tunnel_id")
  ConnectionCmd.AddCommand(testSshTunnelCmd)
  testSshTunnelCmd.Flags().String("ssh_tunnel_id", "", "Id of SSH Tunnel")
  cobra.MarkFlagRequired(testSshTunnelCmd.Flags(), "ssh_tunnel_id")
  ConnectionCmd.AddCommand(sshPublicKeyCmd)
  rootCmd.AddCommand(ConnectionCmd)
  ContentCmd.AddCommand(searchContentFavoritesCmd)
  searchContentFavoritesCmd.Flags().Int64("id", 0, "Match content favorite id(s)")
  searchContentFavoritesCmd.Flags().String("user_id", "", "Match user id(s).To create a list of multiple ids, use commas as separators")
  searchContentFavoritesCmd.Flags().String("content_metadata_id", "", "Match content metadata id(s).To create a list of multiple ids, use commas as separators")
  searchContentFavoritesCmd.Flags().String("dashboard_id", "", "Match dashboard id(s).To create a list of multiple ids, use commas as separators")
  searchContentFavoritesCmd.Flags().String("look_id", "", "Match look id(s).To create a list of multiple ids, use commas as separators")
  searchContentFavoritesCmd.Flags().String("board_id", "", "Match board id(s).To create a list of multiple ids, use commas as separators")
  searchContentFavoritesCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset)")
  searchContentFavoritesCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit)")
  searchContentFavoritesCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchContentFavoritesCmd.Flags().String("fields", "", "Requested fields.")
  searchContentFavoritesCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  ContentCmd.AddCommand(contentFavoriteCmd)
  contentFavoriteCmd.Flags().Int64("content_favorite_id", 0, "Id of favorite content")
  cobra.MarkFlagRequired(contentFavoriteCmd.Flags(), "content_favorite_id")
  contentFavoriteCmd.Flags().String("fields", "", "Requested fields.")
  ContentCmd.AddCommand(deleteContentFavoriteCmd)
  deleteContentFavoriteCmd.Flags().Int64("content_favorite_id", 0, "Id of favorite content")
  cobra.MarkFlagRequired(deleteContentFavoriteCmd.Flags(), "content_favorite_id")
  ContentCmd.AddCommand(createContentFavoriteCmd)
  createContentFavoriteCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createContentFavoriteCmd.Flags(), "body")
  ContentCmd.AddCommand(allContentMetadatasCmd)
  allContentMetadatasCmd.Flags().Int64("parent_id", 0, "Parent space of content.")
  cobra.MarkFlagRequired(allContentMetadatasCmd.Flags(), "parent_id")
  allContentMetadatasCmd.Flags().String("fields", "", "Requested fields.")
  ContentCmd.AddCommand(contentMetadataCmd)
  contentMetadataCmd.Flags().Int64("content_metadata_id", 0, "Id of content metadata")
  cobra.MarkFlagRequired(contentMetadataCmd.Flags(), "content_metadata_id")
  contentMetadataCmd.Flags().String("fields", "", "Requested fields.")
  ContentCmd.AddCommand(updateContentMetadataCmd)
  updateContentMetadataCmd.Flags().Int64("content_metadata_id", 0, "Id of content metadata")
  cobra.MarkFlagRequired(updateContentMetadataCmd.Flags(), "content_metadata_id")
  updateContentMetadataCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateContentMetadataCmd.Flags(), "body")
  ContentCmd.AddCommand(allContentMetadataAccessesCmd)
  allContentMetadataAccessesCmd.Flags().Int64("content_metadata_id", 0, "Id of content metadata")
  cobra.MarkFlagRequired(allContentMetadataAccessesCmd.Flags(), "content_metadata_id")
  allContentMetadataAccessesCmd.Flags().String("fields", "", "Requested fields.")
  ContentCmd.AddCommand(createContentMetadataAccessCmd)
  createContentMetadataAccessCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createContentMetadataAccessCmd.Flags(), "body")
  createContentMetadataAccessCmd.Flags().Bool("send_boards_notification_email", false, "Optionally sends notification email when granting access to a board.")
  ContentCmd.AddCommand(updateContentMetadataAccessCmd)
  updateContentMetadataAccessCmd.Flags().String("content_metadata_access_id", "", "Id of content metadata access")
  cobra.MarkFlagRequired(updateContentMetadataAccessCmd.Flags(), "content_metadata_access_id")
  updateContentMetadataAccessCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateContentMetadataAccessCmd.Flags(), "body")
  ContentCmd.AddCommand(deleteContentMetadataAccessCmd)
  deleteContentMetadataAccessCmd.Flags().Int64("content_metadata_access_id", 0, "Id of content metadata access")
  cobra.MarkFlagRequired(deleteContentMetadataAccessCmd.Flags(), "content_metadata_access_id")
  ContentCmd.AddCommand(contentThumbnailCmd)
  contentThumbnailCmd.Flags().String("type", "", "Either dashboard or look")
  cobra.MarkFlagRequired(contentThumbnailCmd.Flags(), "type")
  contentThumbnailCmd.Flags().String("resource_id", "", "ID of the dashboard or look to render")
  cobra.MarkFlagRequired(contentThumbnailCmd.Flags(), "resource_id")
  contentThumbnailCmd.Flags().String("reload", "", "Whether or not to refresh the rendered image with the latest content")
  contentThumbnailCmd.Flags().String("format", "", "A value of png produces a thumbnail in PNG format instead of SVG (default)")
  contentThumbnailCmd.Flags().Int64("width", 0, "The width of the image if format is supplied")
  contentThumbnailCmd.Flags().Int64("height", 0, "The height of the image if format is supplied")
  ContentCmd.AddCommand(contentValidationCmd)
  contentValidationCmd.Flags().String("fields", "", "Requested fields.")
  ContentCmd.AddCommand(searchContentViewsCmd)
  searchContentViewsCmd.Flags().String("view_count", "", "Match view count")
  searchContentViewsCmd.Flags().String("group_id", "", "Match Group Id")
  searchContentViewsCmd.Flags().String("look_id", "", "Match look_id")
  searchContentViewsCmd.Flags().String("dashboard_id", "", "Match dashboard_id")
  searchContentViewsCmd.Flags().String("content_metadata_id", "", "Match content metadata id")
  searchContentViewsCmd.Flags().String("start_of_week_date", "", "Match start of week date (format is \"YYYY-MM-DD\")")
  searchContentViewsCmd.Flags().Bool("all_time", false, "True if only all time view records should be returned")
  searchContentViewsCmd.Flags().String("user_id", "", "Match user id")
  searchContentViewsCmd.Flags().String("fields", "", "Requested fields")
  searchContentViewsCmd.Flags().Int64("limit", 0, "Number of results to return. Use with `offset` to manage pagination of results")
  searchContentViewsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning data")
  searchContentViewsCmd.Flags().String("sorts", "", "Fields to sort by")
  searchContentViewsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  ContentCmd.AddCommand(vectorThumbnailCmd)
  vectorThumbnailCmd.Flags().String("type", "", "Either dashboard or look")
  cobra.MarkFlagRequired(vectorThumbnailCmd.Flags(), "type")
  vectorThumbnailCmd.Flags().String("resource_id", "", "ID of the dashboard or look to render")
  cobra.MarkFlagRequired(vectorThumbnailCmd.Flags(), "resource_id")
  vectorThumbnailCmd.Flags().String("reload", "", "Whether or not to refresh the rendered image with the latest content")
  rootCmd.AddCommand(ContentCmd)
  DashboardCmd.AddCommand(allDashboardsCmd)
  allDashboardsCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(createDashboardCmd)
  createDashboardCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createDashboardCmd.Flags(), "body")
  DashboardCmd.AddCommand(searchDashboardsCmd)
  searchDashboardsCmd.Flags().String("id", "", "Match dashboard id.")
  searchDashboardsCmd.Flags().String("slug", "", "Match dashboard slug.")
  searchDashboardsCmd.Flags().String("title", "", "Match Dashboard title.")
  searchDashboardsCmd.Flags().String("description", "", "Match Dashboard description.")
  searchDashboardsCmd.Flags().String("content_favorite_id", "", "Filter on a content favorite id.")
  searchDashboardsCmd.Flags().String("folder_id", "", "Filter on a particular space.")
  searchDashboardsCmd.Flags().String("deleted", "", "Filter on dashboards deleted status.")
  searchDashboardsCmd.Flags().String("user_id", "", "Filter on dashboards created by a particular user.")
  searchDashboardsCmd.Flags().String("view_count", "", "Filter on a particular value of view_count")
  searchDashboardsCmd.Flags().String("content_metadata_id", "", "Filter on a content favorite id.")
  searchDashboardsCmd.Flags().Bool("curate", false, "Exclude items that exist only in personal spaces other than the users")
  searchDashboardsCmd.Flags().String("last_viewed_at", "", "Select dashboards based on when they were last viewed")
  searchDashboardsCmd.Flags().String("fields", "", "Requested fields.")
  searchDashboardsCmd.Flags().Int64("page", 0, "Requested page.")
  searchDashboardsCmd.Flags().Int64("per_page", 0, "Results per page.")
  searchDashboardsCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  searchDashboardsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchDashboardsCmd.Flags().String("sorts", "", "One or more fields to sort by. Sortable fields: [:title, :user_id, :id, :created_at, :space_id, :folder_id, :description, :view_count, :favorite_count, :slug, :content_favorite_id, :content_metadata_id, :deleted, :deleted_at, :last_viewed_at, :last_accessed_at]")
  searchDashboardsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  DashboardCmd.AddCommand(importLookmlDashboardCmd)
  importLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "", "Id of LookML dashboard")
  cobra.MarkFlagRequired(importLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
  importLookmlDashboardCmd.Flags().String("space_id", "", "Id of space to import the dashboard to")
  cobra.MarkFlagRequired(importLookmlDashboardCmd.Flags(), "space_id")
  importLookmlDashboardCmd.Flags().String("body", "", "")
  importLookmlDashboardCmd.Flags().Bool("raw_locale", false, "If true, and this dashboard is localized, export it with the raw keys, not localized.")
  DashboardCmd.AddCommand(syncLookmlDashboardCmd)
  syncLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "", "Id of LookML dashboard, in the form 'model::dashboardname'")
  cobra.MarkFlagRequired(syncLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
  syncLookmlDashboardCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(syncLookmlDashboardCmd.Flags(), "body")
  syncLookmlDashboardCmd.Flags().Bool("raw_locale", false, "If true, and this dashboard is localized, export it with the raw keys, not localized.")
  DashboardCmd.AddCommand(dashboardCmd)
  dashboardCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardCmd.Flags(), "dashboard_id")
  dashboardCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(updateDashboardCmd)
  updateDashboardCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(updateDashboardCmd.Flags(), "dashboard_id")
  updateDashboardCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDashboardCmd.Flags(), "body")
  DashboardCmd.AddCommand(deleteDashboardCmd)
  deleteDashboardCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(deleteDashboardCmd.Flags(), "dashboard_id")
  DashboardCmd.AddCommand(dashboardAggregateTableLookmlCmd)
  dashboardAggregateTableLookmlCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardAggregateTableLookmlCmd.Flags(), "dashboard_id")
  DashboardCmd.AddCommand(dashboardLookmlCmd)
  dashboardLookmlCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardLookmlCmd.Flags(), "dashboard_id")
  DashboardCmd.AddCommand(moveDashboardCmd)
  moveDashboardCmd.Flags().String("dashboard_id", "", "Dashboard id to move.")
  cobra.MarkFlagRequired(moveDashboardCmd.Flags(), "dashboard_id")
  moveDashboardCmd.Flags().String("folder_id", "", "Folder id to move to.")
  cobra.MarkFlagRequired(moveDashboardCmd.Flags(), "folder_id")
  DashboardCmd.AddCommand(copyDashboardCmd)
  copyDashboardCmd.Flags().String("dashboard_id", "", "Dashboard id to copy.")
  cobra.MarkFlagRequired(copyDashboardCmd.Flags(), "dashboard_id")
  copyDashboardCmd.Flags().String("folder_id", "", "Folder id to copy to.")
  DashboardCmd.AddCommand(searchDashboardElementsCmd)
  searchDashboardElementsCmd.Flags().Int64("dashboard_id", 0, "Select elements that refer to a given dashboard id")
  searchDashboardElementsCmd.Flags().Int64("look_id", 0, "Select elements that refer to a given look id")
  searchDashboardElementsCmd.Flags().String("title", "", "Match the title of element")
  searchDashboardElementsCmd.Flags().Bool("deleted", false, "Select soft-deleted dashboard elements")
  searchDashboardElementsCmd.Flags().String("fields", "", "Requested fields.")
  searchDashboardElementsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchDashboardElementsCmd.Flags().String("sorts", "", "Fields to sort by. Sortable fields: [:look_id, :dashboard_id, :deleted, :title]")
  DashboardCmd.AddCommand(dashboardElementCmd)
  dashboardElementCmd.Flags().String("dashboard_element_id", "", "Id of dashboard element")
  cobra.MarkFlagRequired(dashboardElementCmd.Flags(), "dashboard_element_id")
  dashboardElementCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(updateDashboardElementCmd)
  updateDashboardElementCmd.Flags().String("dashboard_element_id", "", "Id of dashboard element")
  cobra.MarkFlagRequired(updateDashboardElementCmd.Flags(), "dashboard_element_id")
  updateDashboardElementCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDashboardElementCmd.Flags(), "body")
  updateDashboardElementCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(deleteDashboardElementCmd)
  deleteDashboardElementCmd.Flags().String("dashboard_element_id", "", "Id of dashboard element")
  cobra.MarkFlagRequired(deleteDashboardElementCmd.Flags(), "dashboard_element_id")
  DashboardCmd.AddCommand(dashboardDashboardElementsCmd)
  dashboardDashboardElementsCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardDashboardElementsCmd.Flags(), "dashboard_id")
  dashboardDashboardElementsCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(createDashboardElementCmd)
  createDashboardElementCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createDashboardElementCmd.Flags(), "body")
  createDashboardElementCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(dashboardFilterCmd)
  dashboardFilterCmd.Flags().String("dashboard_filter_id", "", "Id of dashboard filters")
  cobra.MarkFlagRequired(dashboardFilterCmd.Flags(), "dashboard_filter_id")
  dashboardFilterCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(updateDashboardFilterCmd)
  updateDashboardFilterCmd.Flags().String("dashboard_filter_id", "", "Id of dashboard filter")
  cobra.MarkFlagRequired(updateDashboardFilterCmd.Flags(), "dashboard_filter_id")
  updateDashboardFilterCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDashboardFilterCmd.Flags(), "body")
  updateDashboardFilterCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(deleteDashboardFilterCmd)
  deleteDashboardFilterCmd.Flags().String("dashboard_filter_id", "", "Id of dashboard filter")
  cobra.MarkFlagRequired(deleteDashboardFilterCmd.Flags(), "dashboard_filter_id")
  DashboardCmd.AddCommand(dashboardDashboardFiltersCmd)
  dashboardDashboardFiltersCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardDashboardFiltersCmd.Flags(), "dashboard_id")
  dashboardDashboardFiltersCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(createDashboardFilterCmd)
  createDashboardFilterCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createDashboardFilterCmd.Flags(), "body")
  createDashboardFilterCmd.Flags().String("fields", "", "Requested fields")
  DashboardCmd.AddCommand(dashboardLayoutComponentCmd)
  dashboardLayoutComponentCmd.Flags().String("dashboard_layout_component_id", "", "Id of dashboard layout component")
  cobra.MarkFlagRequired(dashboardLayoutComponentCmd.Flags(), "dashboard_layout_component_id")
  dashboardLayoutComponentCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(updateDashboardLayoutComponentCmd)
  updateDashboardLayoutComponentCmd.Flags().String("dashboard_layout_component_id", "", "Id of dashboard layout component")
  cobra.MarkFlagRequired(updateDashboardLayoutComponentCmd.Flags(), "dashboard_layout_component_id")
  updateDashboardLayoutComponentCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDashboardLayoutComponentCmd.Flags(), "body")
  updateDashboardLayoutComponentCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(dashboardLayoutDashboardLayoutComponentsCmd)
  dashboardLayoutDashboardLayoutComponentsCmd.Flags().String("dashboard_layout_id", "", "Id of dashboard layout component")
  cobra.MarkFlagRequired(dashboardLayoutDashboardLayoutComponentsCmd.Flags(), "dashboard_layout_id")
  dashboardLayoutDashboardLayoutComponentsCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(dashboardLayoutCmd)
  dashboardLayoutCmd.Flags().String("dashboard_layout_id", "", "Id of dashboard layouts")
  cobra.MarkFlagRequired(dashboardLayoutCmd.Flags(), "dashboard_layout_id")
  dashboardLayoutCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(updateDashboardLayoutCmd)
  updateDashboardLayoutCmd.Flags().String("dashboard_layout_id", "", "Id of dashboard layout")
  cobra.MarkFlagRequired(updateDashboardLayoutCmd.Flags(), "dashboard_layout_id")
  updateDashboardLayoutCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDashboardLayoutCmd.Flags(), "body")
  updateDashboardLayoutCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(deleteDashboardLayoutCmd)
  deleteDashboardLayoutCmd.Flags().String("dashboard_layout_id", "", "Id of dashboard layout")
  cobra.MarkFlagRequired(deleteDashboardLayoutCmd.Flags(), "dashboard_layout_id")
  DashboardCmd.AddCommand(dashboardDashboardLayoutsCmd)
  dashboardDashboardLayoutsCmd.Flags().String("dashboard_id", "", "Id of dashboard")
  cobra.MarkFlagRequired(dashboardDashboardLayoutsCmd.Flags(), "dashboard_id")
  dashboardDashboardLayoutsCmd.Flags().String("fields", "", "Requested fields.")
  DashboardCmd.AddCommand(createDashboardLayoutCmd)
  createDashboardLayoutCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createDashboardLayoutCmd.Flags(), "body")
  createDashboardLayoutCmd.Flags().String("fields", "", "Requested fields.")
  rootCmd.AddCommand(DashboardCmd)
  DataActionCmd.AddCommand(performDataActionCmd)
  performDataActionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(performDataActionCmd.Flags(), "body")
  DataActionCmd.AddCommand(fetchRemoteDataActionFormCmd)
  fetchRemoteDataActionFormCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(fetchRemoteDataActionFormCmd.Flags(), "body")
  rootCmd.AddCommand(DataActionCmd)
  DatagroupCmd.AddCommand(allDatagroupsCmd)
  DatagroupCmd.AddCommand(datagroupCmd)
  datagroupCmd.Flags().Int64("datagroup_id", 0, "ID of datagroup.")
  cobra.MarkFlagRequired(datagroupCmd.Flags(), "datagroup_id")
  DatagroupCmd.AddCommand(updateDatagroupCmd)
  updateDatagroupCmd.Flags().Int64("datagroup_id", 0, "ID of datagroup.")
  cobra.MarkFlagRequired(updateDatagroupCmd.Flags(), "datagroup_id")
  updateDatagroupCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateDatagroupCmd.Flags(), "body")
  rootCmd.AddCommand(DatagroupCmd)
  DerivedTableCmd.AddCommand(graphDerivedTablesForModelCmd)
  graphDerivedTablesForModelCmd.Flags().String("model", "", "The name of the Lookml model.")
  cobra.MarkFlagRequired(graphDerivedTablesForModelCmd.Flags(), "model")
  graphDerivedTablesForModelCmd.Flags().String("format", "", "The format of the graph. Valid values are [dot]. Default is `dot`")
  graphDerivedTablesForModelCmd.Flags().String("color", "", "Color denoting the build status of the graph. Grey = not built, green = built, yellow = building, red = error.")
  DerivedTableCmd.AddCommand(graphDerivedTablesForViewCmd)
  graphDerivedTablesForViewCmd.Flags().String("view", "", "The derived table's view name.")
  cobra.MarkFlagRequired(graphDerivedTablesForViewCmd.Flags(), "view")
  graphDerivedTablesForViewCmd.Flags().String("models", "", "The models where this derived table is defined.")
  graphDerivedTablesForViewCmd.Flags().String("workspace", "", "The model directory to look in, either `dev` or `production`.")
  rootCmd.AddCommand(DerivedTableCmd)
  FolderCmd.AddCommand(searchFoldersCmd)
  searchFoldersCmd.Flags().String("fields", "", "Requested fields.")
  searchFoldersCmd.Flags().Int64("page", 0, "Requested page.")
  searchFoldersCmd.Flags().Int64("per_page", 0, "Results per page.")
  searchFoldersCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  searchFoldersCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchFoldersCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchFoldersCmd.Flags().String("name", "", "Match Space title.")
  searchFoldersCmd.Flags().Int64("id", 0, "Match Space id")
  searchFoldersCmd.Flags().String("parent_id", "", "Filter on a children of a particular folder.")
  searchFoldersCmd.Flags().String("creator_id", "", "Filter on folder created by a particular user.")
  searchFoldersCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchFoldersCmd.Flags().Bool("is_shared_root", false, "Match is shared root")
  FolderCmd.AddCommand(folderCmd)
  folderCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderCmd.Flags(), "folder_id")
  folderCmd.Flags().String("fields", "", "Requested fields.")
  FolderCmd.AddCommand(updateFolderCmd)
  updateFolderCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(updateFolderCmd.Flags(), "folder_id")
  updateFolderCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateFolderCmd.Flags(), "body")
  FolderCmd.AddCommand(deleteFolderCmd)
  deleteFolderCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(deleteFolderCmd.Flags(), "folder_id")
  FolderCmd.AddCommand(allFoldersCmd)
  allFoldersCmd.Flags().String("fields", "", "Requested fields.")
  FolderCmd.AddCommand(createFolderCmd)
  createFolderCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createFolderCmd.Flags(), "body")
  FolderCmd.AddCommand(folderChildrenCmd)
  folderChildrenCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderChildrenCmd.Flags(), "folder_id")
  folderChildrenCmd.Flags().String("fields", "", "Requested fields.")
  folderChildrenCmd.Flags().Int64("page", 0, "Requested page.")
  folderChildrenCmd.Flags().Int64("per_page", 0, "Results per page.")
  folderChildrenCmd.Flags().String("sorts", "", "Fields to sort by.")
  FolderCmd.AddCommand(folderChildrenSearchCmd)
  folderChildrenSearchCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderChildrenSearchCmd.Flags(), "folder_id")
  folderChildrenSearchCmd.Flags().String("fields", "", "Requested fields.")
  folderChildrenSearchCmd.Flags().String("sorts", "", "Fields to sort by.")
  folderChildrenSearchCmd.Flags().String("name", "", "Match folder name.")
  FolderCmd.AddCommand(folderParentCmd)
  folderParentCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderParentCmd.Flags(), "folder_id")
  folderParentCmd.Flags().String("fields", "", "Requested fields.")
  FolderCmd.AddCommand(folderAncestorsCmd)
  folderAncestorsCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderAncestorsCmd.Flags(), "folder_id")
  folderAncestorsCmd.Flags().String("fields", "", "Requested fields.")
  FolderCmd.AddCommand(folderLooksCmd)
  folderLooksCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderLooksCmd.Flags(), "folder_id")
  folderLooksCmd.Flags().String("fields", "", "Requested fields.")
  FolderCmd.AddCommand(folderDashboardsCmd)
  folderDashboardsCmd.Flags().String("folder_id", "", "Id of folder")
  cobra.MarkFlagRequired(folderDashboardsCmd.Flags(), "folder_id")
  folderDashboardsCmd.Flags().String("fields", "", "Requested fields.")
  rootCmd.AddCommand(FolderCmd)
  GroupCmd.AddCommand(allGroupsCmd)
  allGroupsCmd.Flags().String("fields", "", "Requested fields.")
  allGroupsCmd.Flags().Int64("page", 0, "Requested page.")
  allGroupsCmd.Flags().Int64("per_page", 0, "Results per page.")
  allGroupsCmd.Flags().String("sorts", "", "Fields to sort by.")
  allGroupsCmd.Flags().String("ids", "", "Optional of ids to get specific groups.")
  allGroupsCmd.Flags().Int64("content_metadata_id", 0, "Id of content metadata to which groups must have access.")
  allGroupsCmd.Flags().Bool("can_add_to_content_metadata", false, "Select only groups that either can/cannot be given access to content.")
  GroupCmd.AddCommand(createGroupCmd)
  createGroupCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createGroupCmd.Flags(), "body")
  createGroupCmd.Flags().String("fields", "", "Requested fields.")
  GroupCmd.AddCommand(searchGroupsCmd)
  searchGroupsCmd.Flags().String("fields", "", "Requested fields.")
  searchGroupsCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchGroupsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchGroupsCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchGroupsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchGroupsCmd.Flags().Int64("id", 0, "Match group id.")
  searchGroupsCmd.Flags().String("name", "", "Match group name.")
  searchGroupsCmd.Flags().String("external_group_id", "", "Match group external_group_id.")
  searchGroupsCmd.Flags().Bool("externally_managed", false, "Match group externally_managed.")
  searchGroupsCmd.Flags().Bool("externally_orphaned", false, "Match group externally_orphaned.")
  GroupCmd.AddCommand(searchGroupsWithRolesCmd)
  searchGroupsWithRolesCmd.Flags().String("fields", "", "Requested fields.")
  searchGroupsWithRolesCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchGroupsWithRolesCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchGroupsWithRolesCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchGroupsWithRolesCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchGroupsWithRolesCmd.Flags().Int64("id", 0, "Match group id.")
  searchGroupsWithRolesCmd.Flags().String("name", "", "Match group name.")
  searchGroupsWithRolesCmd.Flags().String("external_group_id", "", "Match group external_group_id.")
  searchGroupsWithRolesCmd.Flags().Bool("externally_managed", false, "Match group externally_managed.")
  searchGroupsWithRolesCmd.Flags().Bool("externally_orphaned", false, "Match group externally_orphaned.")
  GroupCmd.AddCommand(searchGroupsWithHierarchyCmd)
  searchGroupsWithHierarchyCmd.Flags().String("fields", "", "Requested fields.")
  searchGroupsWithHierarchyCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchGroupsWithHierarchyCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchGroupsWithHierarchyCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchGroupsWithHierarchyCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchGroupsWithHierarchyCmd.Flags().Int64("id", 0, "Match group id.")
  searchGroupsWithHierarchyCmd.Flags().String("name", "", "Match group name.")
  searchGroupsWithHierarchyCmd.Flags().String("external_group_id", "", "Match group external_group_id.")
  searchGroupsWithHierarchyCmd.Flags().Bool("externally_managed", false, "Match group externally_managed.")
  searchGroupsWithHierarchyCmd.Flags().Bool("externally_orphaned", false, "Match group externally_orphaned.")
  GroupCmd.AddCommand(groupCmd)
  groupCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(groupCmd.Flags(), "group_id")
  groupCmd.Flags().String("fields", "", "Requested fields.")
  GroupCmd.AddCommand(updateGroupCmd)
  updateGroupCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(updateGroupCmd.Flags(), "group_id")
  updateGroupCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateGroupCmd.Flags(), "body")
  updateGroupCmd.Flags().String("fields", "", "Requested fields.")
  GroupCmd.AddCommand(deleteGroupCmd)
  deleteGroupCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(deleteGroupCmd.Flags(), "group_id")
  GroupCmd.AddCommand(allGroupGroupsCmd)
  allGroupGroupsCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(allGroupGroupsCmd.Flags(), "group_id")
  allGroupGroupsCmd.Flags().String("fields", "", "Requested fields.")
  GroupCmd.AddCommand(addGroupGroupCmd)
  addGroupGroupCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(addGroupGroupCmd.Flags(), "group_id")
  addGroupGroupCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(addGroupGroupCmd.Flags(), "body")
  GroupCmd.AddCommand(allGroupUsersCmd)
  allGroupUsersCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(allGroupUsersCmd.Flags(), "group_id")
  allGroupUsersCmd.Flags().String("fields", "", "Requested fields.")
  allGroupUsersCmd.Flags().Int64("page", 0, "Requested page.")
  allGroupUsersCmd.Flags().Int64("per_page", 0, "Results per page.")
  allGroupUsersCmd.Flags().String("sorts", "", "Fields to sort by.")
  GroupCmd.AddCommand(addGroupUserCmd)
  addGroupUserCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(addGroupUserCmd.Flags(), "group_id")
  addGroupUserCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(addGroupUserCmd.Flags(), "body")
  GroupCmd.AddCommand(deleteGroupUserCmd)
  deleteGroupUserCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(deleteGroupUserCmd.Flags(), "group_id")
  deleteGroupUserCmd.Flags().Int64("user_id", 0, "Id of user to remove from group")
  cobra.MarkFlagRequired(deleteGroupUserCmd.Flags(), "user_id")
  GroupCmd.AddCommand(deleteGroupFromGroupCmd)
  deleteGroupFromGroupCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(deleteGroupFromGroupCmd.Flags(), "group_id")
  deleteGroupFromGroupCmd.Flags().Int64("deleting_group_id", 0, "Id of group to delete")
  cobra.MarkFlagRequired(deleteGroupFromGroupCmd.Flags(), "deleting_group_id")
  GroupCmd.AddCommand(updateUserAttributeGroupValueCmd)
  updateUserAttributeGroupValueCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "group_id")
  updateUserAttributeGroupValueCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "user_attribute_id")
  updateUserAttributeGroupValueCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateUserAttributeGroupValueCmd.Flags(), "body")
  GroupCmd.AddCommand(deleteUserAttributeGroupValueCmd)
  deleteUserAttributeGroupValueCmd.Flags().Int64("group_id", 0, "Id of group")
  cobra.MarkFlagRequired(deleteUserAttributeGroupValueCmd.Flags(), "group_id")
  deleteUserAttributeGroupValueCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(deleteUserAttributeGroupValueCmd.Flags(), "user_attribute_id")
  rootCmd.AddCommand(GroupCmd)
  HomepageCmd.AddCommand(allPrimaryHomepageSectionsCmd)
  allPrimaryHomepageSectionsCmd.Flags().String("fields", "", "Requested fields.")
  rootCmd.AddCommand(HomepageCmd)
  IntegrationCmd.AddCommand(allIntegrationHubsCmd)
  allIntegrationHubsCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(createIntegrationHubCmd)
  createIntegrationHubCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createIntegrationHubCmd.Flags(), "body")
  createIntegrationHubCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(integrationHubCmd)
  integrationHubCmd.Flags().Int64("integration_hub_id", 0, "Id of Integration Hub")
  cobra.MarkFlagRequired(integrationHubCmd.Flags(), "integration_hub_id")
  integrationHubCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(updateIntegrationHubCmd)
  updateIntegrationHubCmd.Flags().Int64("integration_hub_id", 0, "Id of Integration Hub")
  cobra.MarkFlagRequired(updateIntegrationHubCmd.Flags(), "integration_hub_id")
  updateIntegrationHubCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateIntegrationHubCmd.Flags(), "body")
  updateIntegrationHubCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(deleteIntegrationHubCmd)
  deleteIntegrationHubCmd.Flags().Int64("integration_hub_id", 0, "Id of integration_hub")
  cobra.MarkFlagRequired(deleteIntegrationHubCmd.Flags(), "integration_hub_id")
  IntegrationCmd.AddCommand(acceptIntegrationHubLegalAgreementCmd)
  acceptIntegrationHubLegalAgreementCmd.Flags().Int64("integration_hub_id", 0, "Id of integration_hub")
  cobra.MarkFlagRequired(acceptIntegrationHubLegalAgreementCmd.Flags(), "integration_hub_id")
  IntegrationCmd.AddCommand(allIntegrationsCmd)
  allIntegrationsCmd.Flags().String("fields", "", "Requested fields.")
  allIntegrationsCmd.Flags().String("integration_hub_id", "", "Filter to a specific provider")
  IntegrationCmd.AddCommand(integrationCmd)
  integrationCmd.Flags().String("integration_id", "", "Id of integration")
  cobra.MarkFlagRequired(integrationCmd.Flags(), "integration_id")
  integrationCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(updateIntegrationCmd)
  updateIntegrationCmd.Flags().String("integration_id", "", "Id of integration")
  cobra.MarkFlagRequired(updateIntegrationCmd.Flags(), "integration_id")
  updateIntegrationCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateIntegrationCmd.Flags(), "body")
  updateIntegrationCmd.Flags().String("fields", "", "Requested fields.")
  IntegrationCmd.AddCommand(fetchIntegrationFormCmd)
  fetchIntegrationFormCmd.Flags().String("integration_id", "", "Id of integration")
  cobra.MarkFlagRequired(fetchIntegrationFormCmd.Flags(), "integration_id")
  fetchIntegrationFormCmd.Flags().String("body", "", "")
  IntegrationCmd.AddCommand(testIntegrationCmd)
  testIntegrationCmd.Flags().String("integration_id", "", "Id of integration")
  cobra.MarkFlagRequired(testIntegrationCmd.Flags(), "integration_id")
  rootCmd.AddCommand(IntegrationCmd)
  LookCmd.AddCommand(allLooksCmd)
  allLooksCmd.Flags().String("fields", "", "Requested fields.")
  LookCmd.AddCommand(createLookCmd)
  createLookCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createLookCmd.Flags(), "body")
  createLookCmd.Flags().String("fields", "", "Requested fields.")
  LookCmd.AddCommand(searchLooksCmd)
  searchLooksCmd.Flags().String("id", "", "Match look id.")
  searchLooksCmd.Flags().String("title", "", "Match Look title.")
  searchLooksCmd.Flags().String("description", "", "Match Look description.")
  searchLooksCmd.Flags().String("content_favorite_id", "", "Select looks with a particular content favorite id")
  searchLooksCmd.Flags().String("folder_id", "", "Select looks in a particular folder.")
  searchLooksCmd.Flags().String("user_id", "", "Select looks created by a particular user.")
  searchLooksCmd.Flags().String("view_count", "", "Select looks with particular view_count value")
  searchLooksCmd.Flags().Bool("deleted", false, "Select soft-deleted looks")
  searchLooksCmd.Flags().Int64("query_id", 0, "Select looks that reference a particular query by query_id")
  searchLooksCmd.Flags().Bool("curate", false, "Exclude items that exist only in personal spaces other than the users")
  searchLooksCmd.Flags().String("last_viewed_at", "", "Select looks based on when they were last viewed")
  searchLooksCmd.Flags().String("fields", "", "Requested fields.")
  searchLooksCmd.Flags().Int64("page", 0, "Requested page.")
  searchLooksCmd.Flags().Int64("per_page", 0, "Results per page.")
  searchLooksCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  searchLooksCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchLooksCmd.Flags().String("sorts", "", "One or more fields to sort results by. Sortable fields: [:title, :user_id, :id, :created_at, :space_id, :folder_id, :description, :updated_at, :last_updater_id, :view_count, :favorite_count, :content_favorite_id, :deleted, :deleted_at, :last_viewed_at, :last_accessed_at, :query_id]")
  searchLooksCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  LookCmd.AddCommand(lookCmd)
  lookCmd.Flags().String("look_id", "", "Id of look")
  cobra.MarkFlagRequired(lookCmd.Flags(), "look_id")
  lookCmd.Flags().String("fields", "", "Requested fields.")
  LookCmd.AddCommand(updateLookCmd)
  updateLookCmd.Flags().String("look_id", "", "Id of look")
  cobra.MarkFlagRequired(updateLookCmd.Flags(), "look_id")
  updateLookCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateLookCmd.Flags(), "body")
  updateLookCmd.Flags().String("fields", "", "Requested fields.")
  LookCmd.AddCommand(deleteLookCmd)
  deleteLookCmd.Flags().String("look_id", "", "Id of look")
  cobra.MarkFlagRequired(deleteLookCmd.Flags(), "look_id")
  LookCmd.AddCommand(runLookCmd)
  runLookCmd.Flags().String("look_id", "", "Id of look")
  cobra.MarkFlagRequired(runLookCmd.Flags(), "look_id")
  runLookCmd.Flags().String("result_format", "", "Format of result")
  cobra.MarkFlagRequired(runLookCmd.Flags(), "result_format")
  runLookCmd.Flags().Int64("limit", 0, "Row limit (may override the limit in the saved query).")
  runLookCmd.Flags().Bool("apply_formatting", false, "Apply model-specified formatting to each result.")
  runLookCmd.Flags().Bool("apply_vis", false, "Apply visualization options to results.")
  runLookCmd.Flags().Bool("cache", false, "Get results from cache if available.")
  runLookCmd.Flags().Int64("image_width", 0, "Render width for image formats.")
  runLookCmd.Flags().Int64("image_height", 0, "Render height for image formats.")
  runLookCmd.Flags().Bool("generate_drill_links", false, "Generate drill links (only applicable to 'json_detail' format.")
  runLookCmd.Flags().Bool("force_production", false, "Force use of production models even if the user is in development mode.")
  runLookCmd.Flags().Bool("cache_only", false, "Retrieve any results from cache even if the results have expired.")
  runLookCmd.Flags().String("path_prefix", "", "Prefix to use for drill links (url encoded).")
  runLookCmd.Flags().Bool("rebuild_pdts", false, "Rebuild PDTS used in query.")
  runLookCmd.Flags().Bool("server_table_calcs", false, "Perform table calculations on query results")
  LookCmd.AddCommand(copyLookCmd)
  copyLookCmd.Flags().String("look_id", "", "Look id to copy.")
  cobra.MarkFlagRequired(copyLookCmd.Flags(), "look_id")
  copyLookCmd.Flags().String("folder_id", "", "Folder id to copy to.")
  LookCmd.AddCommand(moveLookCmd)
  moveLookCmd.Flags().String("look_id", "", "Look id to move.")
  cobra.MarkFlagRequired(moveLookCmd.Flags(), "look_id")
  moveLookCmd.Flags().String("folder_id", "", "Folder id to move to.")
  cobra.MarkFlagRequired(moveLookCmd.Flags(), "folder_id")
  rootCmd.AddCommand(LookCmd)
  LookmlModelCmd.AddCommand(allLookmlModelsCmd)
  allLookmlModelsCmd.Flags().String("fields", "", "Requested fields.")
  allLookmlModelsCmd.Flags().Int64("limit", 0, "Number of results to return. (can be used with offset)")
  allLookmlModelsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (Defaults to 0 if not set when limit is used)")
  LookmlModelCmd.AddCommand(createLookmlModelCmd)
  createLookmlModelCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createLookmlModelCmd.Flags(), "body")
  LookmlModelCmd.AddCommand(lookmlModelCmd)
  lookmlModelCmd.Flags().String("lookml_model_name", "", "Name of lookml model.")
  cobra.MarkFlagRequired(lookmlModelCmd.Flags(), "lookml_model_name")
  lookmlModelCmd.Flags().String("fields", "", "Requested fields.")
  LookmlModelCmd.AddCommand(updateLookmlModelCmd)
  updateLookmlModelCmd.Flags().String("lookml_model_name", "", "Name of lookml model.")
  cobra.MarkFlagRequired(updateLookmlModelCmd.Flags(), "lookml_model_name")
  updateLookmlModelCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateLookmlModelCmd.Flags(), "body")
  LookmlModelCmd.AddCommand(deleteLookmlModelCmd)
  deleteLookmlModelCmd.Flags().String("lookml_model_name", "", "Name of lookml model.")
  cobra.MarkFlagRequired(deleteLookmlModelCmd.Flags(), "lookml_model_name")
  LookmlModelCmd.AddCommand(lookmlModelExploreCmd)
  lookmlModelExploreCmd.Flags().String("lookml_model_name", "", "Name of lookml model.")
  cobra.MarkFlagRequired(lookmlModelExploreCmd.Flags(), "lookml_model_name")
  lookmlModelExploreCmd.Flags().String("explore_name", "", "Name of explore.")
  cobra.MarkFlagRequired(lookmlModelExploreCmd.Flags(), "explore_name")
  lookmlModelExploreCmd.Flags().String("fields", "", "Requested fields.")
  rootCmd.AddCommand(LookmlModelCmd)
  MetadataCmd.AddCommand(modelFieldnameSuggestionsCmd)
  modelFieldnameSuggestionsCmd.Flags().String("model_name", "", "Name of model")
  cobra.MarkFlagRequired(modelFieldnameSuggestionsCmd.Flags(), "model_name")
  modelFieldnameSuggestionsCmd.Flags().String("view_name", "", "Name of view")
  cobra.MarkFlagRequired(modelFieldnameSuggestionsCmd.Flags(), "view_name")
  modelFieldnameSuggestionsCmd.Flags().String("field_name", "", "Name of field to use for suggestions")
  cobra.MarkFlagRequired(modelFieldnameSuggestionsCmd.Flags(), "field_name")
  modelFieldnameSuggestionsCmd.Flags().String("term", "", "Search term")
  modelFieldnameSuggestionsCmd.Flags().String("filters", "", "Suggestion filters")
  MetadataCmd.AddCommand(getModelCmd)
  getModelCmd.Flags().String("model_name", "", "Name of model")
  cobra.MarkFlagRequired(getModelCmd.Flags(), "model_name")
  MetadataCmd.AddCommand(connectionDatabasesCmd)
  connectionDatabasesCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionDatabasesCmd.Flags(), "connection_name")
  MetadataCmd.AddCommand(connectionFeaturesCmd)
  connectionFeaturesCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionFeaturesCmd.Flags(), "connection_name")
  connectionFeaturesCmd.Flags().String("fields", "", "Requested fields.")
  MetadataCmd.AddCommand(connectionSchemasCmd)
  connectionSchemasCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionSchemasCmd.Flags(), "connection_name")
  connectionSchemasCmd.Flags().String("database", "", "For dialects that support multiple databases, optionally identify which to use")
  connectionSchemasCmd.Flags().Bool("cache", false, "True to use fetch from cache, false to load fresh")
  connectionSchemasCmd.Flags().String("fields", "", "Requested fields.")
  MetadataCmd.AddCommand(connectionTablesCmd)
  connectionTablesCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionTablesCmd.Flags(), "connection_name")
  connectionTablesCmd.Flags().String("database", "", "Optional. Name of database to use for the query, only if applicable")
  connectionTablesCmd.Flags().String("schema_name", "", "Optional. Return only tables for this schema")
  connectionTablesCmd.Flags().Bool("cache", false, "True to fetch from cache, false to load fresh")
  connectionTablesCmd.Flags().String("fields", "", "Requested fields.")
  MetadataCmd.AddCommand(connectionColumnsCmd)
  connectionColumnsCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionColumnsCmd.Flags(), "connection_name")
  connectionColumnsCmd.Flags().String("database", "", "For dialects that support multiple databases, optionally identify which to use")
  connectionColumnsCmd.Flags().String("schema_name", "", "Name of schema to use.")
  connectionColumnsCmd.Flags().Bool("cache", false, "True to fetch from cache, false to load fresh")
  connectionColumnsCmd.Flags().Int64("table_limit", 0, "limits the tables per schema returned")
  connectionColumnsCmd.Flags().String("table_names", "", "only fetch columns for a given (comma-separated) list of tables")
  connectionColumnsCmd.Flags().String("fields", "", "Requested fields.")
  MetadataCmd.AddCommand(connectionSearchColumnsCmd)
  connectionSearchColumnsCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionSearchColumnsCmd.Flags(), "connection_name")
  connectionSearchColumnsCmd.Flags().String("column_name", "", "Column name to find")
  connectionSearchColumnsCmd.Flags().String("fields", "", "Requested fields.")
  MetadataCmd.AddCommand(connectionCostEstimateCmd)
  connectionCostEstimateCmd.Flags().String("connection_name", "", "Name of connection")
  cobra.MarkFlagRequired(connectionCostEstimateCmd.Flags(), "connection_name")
  connectionCostEstimateCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(connectionCostEstimateCmd.Flags(), "body")
  connectionCostEstimateCmd.Flags().String("fields", "", "Requested fields.")
  rootCmd.AddCommand(MetadataCmd)
  ProjectCmd.AddCommand(lockAllCmd)
  lockAllCmd.Flags().String("project_id", "", "Id of project")
  cobra.MarkFlagRequired(lockAllCmd.Flags(), "project_id")
  lockAllCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(allGitBranchesCmd)
  allGitBranchesCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(allGitBranchesCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(gitBranchCmd)
  gitBranchCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(gitBranchCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(updateGitBranchCmd)
  updateGitBranchCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(updateGitBranchCmd.Flags(), "project_id")
  updateGitBranchCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateGitBranchCmd.Flags(), "body")
  ProjectCmd.AddCommand(createGitBranchCmd)
  createGitBranchCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(createGitBranchCmd.Flags(), "project_id")
  createGitBranchCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createGitBranchCmd.Flags(), "body")
  ProjectCmd.AddCommand(findGitBranchCmd)
  findGitBranchCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(findGitBranchCmd.Flags(), "project_id")
  findGitBranchCmd.Flags().String("branch_name", "", "Branch Name")
  cobra.MarkFlagRequired(findGitBranchCmd.Flags(), "branch_name")
  ProjectCmd.AddCommand(deleteGitBranchCmd)
  deleteGitBranchCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(deleteGitBranchCmd.Flags(), "project_id")
  deleteGitBranchCmd.Flags().String("branch_name", "", "Branch Name")
  cobra.MarkFlagRequired(deleteGitBranchCmd.Flags(), "branch_name")
  ProjectCmd.AddCommand(deployRefToProductionCmd)
  deployRefToProductionCmd.Flags().String("project_id", "", "Id of project")
  cobra.MarkFlagRequired(deployRefToProductionCmd.Flags(), "project_id")
  deployRefToProductionCmd.Flags().String("branch", "", "Branch to deploy to production")
  deployRefToProductionCmd.Flags().String("ref", "", "Ref to deploy to production")
  ProjectCmd.AddCommand(deployToProductionCmd)
  deployToProductionCmd.Flags().String("project_id", "", "Id of project")
  cobra.MarkFlagRequired(deployToProductionCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(resetProjectToProductionCmd)
  resetProjectToProductionCmd.Flags().String("project_id", "", "Id of project")
  cobra.MarkFlagRequired(resetProjectToProductionCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(resetProjectToRemoteCmd)
  resetProjectToRemoteCmd.Flags().String("project_id", "", "Id of project")
  cobra.MarkFlagRequired(resetProjectToRemoteCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(allProjectsCmd)
  allProjectsCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(createProjectCmd)
  createProjectCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createProjectCmd.Flags(), "body")
  ProjectCmd.AddCommand(projectCmd)
  projectCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(projectCmd.Flags(), "project_id")
  projectCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(updateProjectCmd)
  updateProjectCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(updateProjectCmd.Flags(), "project_id")
  updateProjectCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateProjectCmd.Flags(), "body")
  updateProjectCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(manifestCmd)
  manifestCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(manifestCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(gitDeployKeyCmd)
  gitDeployKeyCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(gitDeployKeyCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(createGitDeployKeyCmd)
  createGitDeployKeyCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(createGitDeployKeyCmd.Flags(), "project_id")
  ProjectCmd.AddCommand(projectValidationResultsCmd)
  projectValidationResultsCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(projectValidationResultsCmd.Flags(), "project_id")
  projectValidationResultsCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(validateProjectCmd)
  validateProjectCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(validateProjectCmd.Flags(), "project_id")
  validateProjectCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(projectWorkspaceCmd)
  projectWorkspaceCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(projectWorkspaceCmd.Flags(), "project_id")
  projectWorkspaceCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(allProjectFilesCmd)
  allProjectFilesCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(allProjectFilesCmd.Flags(), "project_id")
  allProjectFilesCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(projectFileCmd)
  projectFileCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(projectFileCmd.Flags(), "project_id")
  projectFileCmd.Flags().String("file_id", "", "File Id")
  cobra.MarkFlagRequired(projectFileCmd.Flags(), "file_id")
  projectFileCmd.Flags().String("fields", "", "Requested fields")
  ProjectCmd.AddCommand(allGitConnectionTestsCmd)
  allGitConnectionTestsCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(allGitConnectionTestsCmd.Flags(), "project_id")
  allGitConnectionTestsCmd.Flags().String("remote_url", "", "(Optional: leave blank for root project) The remote url for remote dependency to test.")
  ProjectCmd.AddCommand(runGitConnectionTestCmd)
  runGitConnectionTestCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(runGitConnectionTestCmd.Flags(), "project_id")
  runGitConnectionTestCmd.Flags().String("test_id", "", "Test Id")
  cobra.MarkFlagRequired(runGitConnectionTestCmd.Flags(), "test_id")
  runGitConnectionTestCmd.Flags().String("remote_url", "", "(Optional: leave blank for root project) The remote url for remote dependency to test.")
  runGitConnectionTestCmd.Flags().String("use_production", "", "(Optional: leave blank for dev credentials) Whether to use git production credentials.")
  ProjectCmd.AddCommand(allLookmlTestsCmd)
  allLookmlTestsCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(allLookmlTestsCmd.Flags(), "project_id")
  allLookmlTestsCmd.Flags().String("file_id", "", "File Id")
  ProjectCmd.AddCommand(runLookmlTestCmd)
  runLookmlTestCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(runLookmlTestCmd.Flags(), "project_id")
  runLookmlTestCmd.Flags().String("file_id", "", "File Name")
  runLookmlTestCmd.Flags().String("test", "", "Test Name")
  runLookmlTestCmd.Flags().String("model", "", "Model Name")
  ProjectCmd.AddCommand(tagRefCmd)
  tagRefCmd.Flags().String("project_id", "", "Project Id")
  cobra.MarkFlagRequired(tagRefCmd.Flags(), "project_id")
  tagRefCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(tagRefCmd.Flags(), "body")
  tagRefCmd.Flags().String("commit_sha", "", "(Optional): Commit Sha to Tag")
  tagRefCmd.Flags().String("tag_name", "", "Tag Name")
  tagRefCmd.Flags().String("tag_message", "", "(Optional): Tag Message")
  ProjectCmd.AddCommand(updateRepositoryCredentialCmd)
  updateRepositoryCredentialCmd.Flags().String("root_project_id", "", "Root Project Id")
  cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "root_project_id")
  updateRepositoryCredentialCmd.Flags().String("credential_id", "", "Credential Id")
  cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "credential_id")
  updateRepositoryCredentialCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateRepositoryCredentialCmd.Flags(), "body")
  ProjectCmd.AddCommand(deleteRepositoryCredentialCmd)
  deleteRepositoryCredentialCmd.Flags().String("root_project_id", "", "Root Project Id")
  cobra.MarkFlagRequired(deleteRepositoryCredentialCmd.Flags(), "root_project_id")
  deleteRepositoryCredentialCmd.Flags().String("credential_id", "", "Credential Id")
  cobra.MarkFlagRequired(deleteRepositoryCredentialCmd.Flags(), "credential_id")
  ProjectCmd.AddCommand(getAllRepositoryCredentialsCmd)
  getAllRepositoryCredentialsCmd.Flags().String("root_project_id", "", "Root Project Id")
  cobra.MarkFlagRequired(getAllRepositoryCredentialsCmd.Flags(), "root_project_id")
  rootCmd.AddCommand(ProjectCmd)
  QueryCmd.AddCommand(createQueryTaskCmd)
  createQueryTaskCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createQueryTaskCmd.Flags(), "body")
  createQueryTaskCmd.Flags().Int64("limit", 0, "Row limit (may override the limit in the saved query).")
  createQueryTaskCmd.Flags().Bool("apply_formatting", false, "Apply model-specified formatting to each result.")
  createQueryTaskCmd.Flags().Bool("apply_vis", false, "Apply visualization options to results.")
  createQueryTaskCmd.Flags().Bool("cache", false, "Get results from cache if available.")
  createQueryTaskCmd.Flags().Int64("image_width", 0, "Render width for image formats.")
  createQueryTaskCmd.Flags().Int64("image_height", 0, "Render height for image formats.")
  createQueryTaskCmd.Flags().Bool("generate_drill_links", false, "Generate drill links (only applicable to 'json_detail' format.")
  createQueryTaskCmd.Flags().Bool("force_production", false, "Force use of production models even if the user is in development mode.")
  createQueryTaskCmd.Flags().Bool("cache_only", false, "Retrieve any results from cache even if the results have expired.")
  createQueryTaskCmd.Flags().String("path_prefix", "", "Prefix to use for drill links (url encoded).")
  createQueryTaskCmd.Flags().Bool("rebuild_pdts", false, "Rebuild PDTS used in query.")
  createQueryTaskCmd.Flags().Bool("server_table_calcs", false, "Perform table calculations on query results")
  createQueryTaskCmd.Flags().String("fields", "", "Requested fields")
  QueryCmd.AddCommand(queryTaskMultiResultsCmd)
  queryTaskMultiResultsCmd.Flags().String("query_task_ids", "", "List of Query Task IDs")
  cobra.MarkFlagRequired(queryTaskMultiResultsCmd.Flags(), "query_task_ids")
  QueryCmd.AddCommand(queryTaskCmd)
  queryTaskCmd.Flags().String("query_task_id", "", "ID of the Query Task")
  cobra.MarkFlagRequired(queryTaskCmd.Flags(), "query_task_id")
  queryTaskCmd.Flags().String("fields", "", "Requested fields.")
  QueryCmd.AddCommand(queryTaskResultsCmd)
  queryTaskResultsCmd.Flags().String("query_task_id", "", "ID of the Query Task")
  cobra.MarkFlagRequired(queryTaskResultsCmd.Flags(), "query_task_id")
  QueryCmd.AddCommand(queryCmd)
  queryCmd.Flags().Int64("query_id", 0, "Id of query")
  cobra.MarkFlagRequired(queryCmd.Flags(), "query_id")
  queryCmd.Flags().String("fields", "", "Requested fields.")
  QueryCmd.AddCommand(queryForSlugCmd)
  queryForSlugCmd.Flags().String("slug", "", "Slug of query")
  cobra.MarkFlagRequired(queryForSlugCmd.Flags(), "slug")
  queryForSlugCmd.Flags().String("fields", "", "Requested fields.")
  QueryCmd.AddCommand(createQueryCmd)
  createQueryCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createQueryCmd.Flags(), "body")
  createQueryCmd.Flags().String("fields", "", "Requested fields.")
  QueryCmd.AddCommand(runQueryCmd)
  runQueryCmd.Flags().Int64("query_id", 0, "Id of query")
  cobra.MarkFlagRequired(runQueryCmd.Flags(), "query_id")
  runQueryCmd.Flags().String("result_format", "", "Format of result")
  cobra.MarkFlagRequired(runQueryCmd.Flags(), "result_format")
  runQueryCmd.Flags().Int64("limit", 0, "Row limit (may override the limit in the saved query).")
  runQueryCmd.Flags().Bool("apply_formatting", false, "Apply model-specified formatting to each result.")
  runQueryCmd.Flags().Bool("apply_vis", false, "Apply visualization options to results.")
  runQueryCmd.Flags().Bool("cache", false, "Get results from cache if available.")
  runQueryCmd.Flags().Int64("image_width", 0, "Render width for image formats.")
  runQueryCmd.Flags().Int64("image_height", 0, "Render height for image formats.")
  runQueryCmd.Flags().Bool("generate_drill_links", false, "Generate drill links (only applicable to 'json_detail' format.")
  runQueryCmd.Flags().Bool("force_production", false, "Force use of production models even if the user is in development mode.")
  runQueryCmd.Flags().Bool("cache_only", false, "Retrieve any results from cache even if the results have expired.")
  runQueryCmd.Flags().String("path_prefix", "", "Prefix to use for drill links (url encoded).")
  runQueryCmd.Flags().Bool("rebuild_pdts", false, "Rebuild PDTS used in query.")
  runQueryCmd.Flags().Bool("server_table_calcs", false, "Perform table calculations on query results")
  runQueryCmd.Flags().String("source", "", "Specifies the source of this call.")
  QueryCmd.AddCommand(runInlineQueryCmd)
  runInlineQueryCmd.Flags().String("result_format", "", "Format of result")
  cobra.MarkFlagRequired(runInlineQueryCmd.Flags(), "result_format")
  runInlineQueryCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(runInlineQueryCmd.Flags(), "body")
  runInlineQueryCmd.Flags().Int64("limit", 0, "Row limit (may override the limit in the saved query).")
  runInlineQueryCmd.Flags().Bool("apply_formatting", false, "Apply model-specified formatting to each result.")
  runInlineQueryCmd.Flags().Bool("apply_vis", false, "Apply visualization options to results.")
  runInlineQueryCmd.Flags().Bool("cache", false, "Get results from cache if available.")
  runInlineQueryCmd.Flags().Int64("image_width", 0, "Render width for image formats.")
  runInlineQueryCmd.Flags().Int64("image_height", 0, "Render height for image formats.")
  runInlineQueryCmd.Flags().Bool("generate_drill_links", false, "Generate drill links (only applicable to 'json_detail' format.")
  runInlineQueryCmd.Flags().Bool("force_production", false, "Force use of production models even if the user is in development mode.")
  runInlineQueryCmd.Flags().Bool("cache_only", false, "Retrieve any results from cache even if the results have expired.")
  runInlineQueryCmd.Flags().String("path_prefix", "", "Prefix to use for drill links (url encoded).")
  runInlineQueryCmd.Flags().Bool("rebuild_pdts", false, "Rebuild PDTS used in query.")
  runInlineQueryCmd.Flags().Bool("server_table_calcs", false, "Perform table calculations on query results")
  QueryCmd.AddCommand(runUrlEncodedQueryCmd)
  runUrlEncodedQueryCmd.Flags().String("model_name", "", "Model name")
  cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "model_name")
  runUrlEncodedQueryCmd.Flags().String("view_name", "", "View name")
  cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "view_name")
  runUrlEncodedQueryCmd.Flags().String("result_format", "", "Format of result")
  cobra.MarkFlagRequired(runUrlEncodedQueryCmd.Flags(), "result_format")
  QueryCmd.AddCommand(mergeQueryCmd)
  mergeQueryCmd.Flags().String("merge_query_id", "", "Merge Query Id")
  cobra.MarkFlagRequired(mergeQueryCmd.Flags(), "merge_query_id")
  mergeQueryCmd.Flags().String("fields", "", "Requested fields")
  QueryCmd.AddCommand(createMergeQueryCmd)
  createMergeQueryCmd.Flags().String("body", "", "")
  createMergeQueryCmd.Flags().String("fields", "", "Requested fields")
  QueryCmd.AddCommand(allRunningQueriesCmd)
  QueryCmd.AddCommand(killQueryCmd)
  killQueryCmd.Flags().String("query_task_id", "", "Query task id.")
  cobra.MarkFlagRequired(killQueryCmd.Flags(), "query_task_id")
  QueryCmd.AddCommand(sqlQueryCmd)
  sqlQueryCmd.Flags().String("slug", "", "slug of query")
  cobra.MarkFlagRequired(sqlQueryCmd.Flags(), "slug")
  QueryCmd.AddCommand(createSqlQueryCmd)
  createSqlQueryCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createSqlQueryCmd.Flags(), "body")
  QueryCmd.AddCommand(runSqlQueryCmd)
  runSqlQueryCmd.Flags().String("slug", "", "slug of query")
  cobra.MarkFlagRequired(runSqlQueryCmd.Flags(), "slug")
  runSqlQueryCmd.Flags().String("result_format", "", "Format of result, options are: [\"inline_json\", \"json\", \"json_detail\", \"json_fe\", \"csv\", \"html\", \"md\", \"txt\", \"xlsx\", \"gsxml\", \"json_label\"]")
  cobra.MarkFlagRequired(runSqlQueryCmd.Flags(), "result_format")
  runSqlQueryCmd.Flags().String("download", "", "Defaults to false. If set to true, the HTTP response will have content-disposition and other headers set to make the HTTP response behave as a downloadable attachment instead of as inline content.")
  rootCmd.AddCommand(QueryCmd)
  RenderTaskCmd.AddCommand(createLookRenderTaskCmd)
  createLookRenderTaskCmd.Flags().Int64("look_id", 0, "Id of look to render")
  cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "look_id")
  createLookRenderTaskCmd.Flags().String("result_format", "", "Output type: png, or jpg")
  cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "result_format")
  createLookRenderTaskCmd.Flags().Int64("width", 0, "Output width in pixels")
  cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "width")
  createLookRenderTaskCmd.Flags().Int64("height", 0, "Output height in pixels")
  cobra.MarkFlagRequired(createLookRenderTaskCmd.Flags(), "height")
  createLookRenderTaskCmd.Flags().String("fields", "", "Requested fields.")
  RenderTaskCmd.AddCommand(createQueryRenderTaskCmd)
  createQueryRenderTaskCmd.Flags().Int64("query_id", 0, "Id of the query to render")
  cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "query_id")
  createQueryRenderTaskCmd.Flags().String("result_format", "", "Output type: png or jpg")
  cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "result_format")
  createQueryRenderTaskCmd.Flags().Int64("width", 0, "Output width in pixels")
  cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "width")
  createQueryRenderTaskCmd.Flags().Int64("height", 0, "Output height in pixels")
  cobra.MarkFlagRequired(createQueryRenderTaskCmd.Flags(), "height")
  createQueryRenderTaskCmd.Flags().String("fields", "", "Requested fields.")
  RenderTaskCmd.AddCommand(createDashboardRenderTaskCmd)
  createDashboardRenderTaskCmd.Flags().String("dashboard_id", "", "Id of dashboard to render. The ID can be a LookML dashboard also.")
  cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "dashboard_id")
  createDashboardRenderTaskCmd.Flags().String("result_format", "", "Output type: pdf, png, or jpg")
  cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "result_format")
  createDashboardRenderTaskCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "body")
  createDashboardRenderTaskCmd.Flags().Int64("width", 0, "Output width in pixels")
  cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "width")
  createDashboardRenderTaskCmd.Flags().Int64("height", 0, "Output height in pixels")
  cobra.MarkFlagRequired(createDashboardRenderTaskCmd.Flags(), "height")
  createDashboardRenderTaskCmd.Flags().String("fields", "", "Requested fields.")
  createDashboardRenderTaskCmd.Flags().String("pdf_paper_size", "", "Paper size for pdf. Value can be one of: [\"letter\",\"legal\",\"tabloid\",\"a0\",\"a1\",\"a2\",\"a3\",\"a4\",\"a5\"]")
  createDashboardRenderTaskCmd.Flags().Bool("pdf_landscape", false, "Whether to render pdf in landscape paper orientation")
  createDashboardRenderTaskCmd.Flags().Bool("long_tables", false, "Whether or not to expand table vis to full length")
  RenderTaskCmd.AddCommand(renderTaskCmd)
  renderTaskCmd.Flags().String("render_task_id", "", "Id of render task")
  cobra.MarkFlagRequired(renderTaskCmd.Flags(), "render_task_id")
  renderTaskCmd.Flags().String("fields", "", "Requested fields.")
  RenderTaskCmd.AddCommand(renderTaskResultsCmd)
  renderTaskResultsCmd.Flags().String("render_task_id", "", "Id of render task")
  cobra.MarkFlagRequired(renderTaskResultsCmd.Flags(), "render_task_id")
  rootCmd.AddCommand(RenderTaskCmd)
  RoleCmd.AddCommand(searchModelSetsCmd)
  searchModelSetsCmd.Flags().String("fields", "", "Requested fields.")
  searchModelSetsCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchModelSetsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchModelSetsCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchModelSetsCmd.Flags().Int64("id", 0, "Match model set id.")
  searchModelSetsCmd.Flags().String("name", "", "Match model set name.")
  searchModelSetsCmd.Flags().Bool("all_access", false, "Match model sets by all_access status.")
  searchModelSetsCmd.Flags().Bool("built_in", false, "Match model sets by built_in status.")
  searchModelSetsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression.")
  RoleCmd.AddCommand(modelSetCmd)
  modelSetCmd.Flags().Int64("model_set_id", 0, "Id of model set")
  cobra.MarkFlagRequired(modelSetCmd.Flags(), "model_set_id")
  modelSetCmd.Flags().String("fields", "", "Requested fields.")
  RoleCmd.AddCommand(updateModelSetCmd)
  updateModelSetCmd.Flags().Int64("model_set_id", 0, "id of model set")
  cobra.MarkFlagRequired(updateModelSetCmd.Flags(), "model_set_id")
  updateModelSetCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateModelSetCmd.Flags(), "body")
  RoleCmd.AddCommand(deleteModelSetCmd)
  deleteModelSetCmd.Flags().Int64("model_set_id", 0, "id of model set")
  cobra.MarkFlagRequired(deleteModelSetCmd.Flags(), "model_set_id")
  RoleCmd.AddCommand(allModelSetsCmd)
  allModelSetsCmd.Flags().String("fields", "", "Requested fields.")
  RoleCmd.AddCommand(createModelSetCmd)
  createModelSetCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createModelSetCmd.Flags(), "body")
  RoleCmd.AddCommand(allPermissionsCmd)
  RoleCmd.AddCommand(searchPermissionSetsCmd)
  searchPermissionSetsCmd.Flags().String("fields", "", "Requested fields.")
  searchPermissionSetsCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchPermissionSetsCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchPermissionSetsCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchPermissionSetsCmd.Flags().Int64("id", 0, "Match permission set id.")
  searchPermissionSetsCmd.Flags().String("name", "", "Match permission set name.")
  searchPermissionSetsCmd.Flags().Bool("all_access", false, "Match permission sets by all_access status.")
  searchPermissionSetsCmd.Flags().Bool("built_in", false, "Match permission sets by built_in status.")
  searchPermissionSetsCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression.")
  RoleCmd.AddCommand(permissionSetCmd)
  permissionSetCmd.Flags().Int64("permission_set_id", 0, "Id of permission set")
  cobra.MarkFlagRequired(permissionSetCmd.Flags(), "permission_set_id")
  permissionSetCmd.Flags().String("fields", "", "Requested fields.")
  RoleCmd.AddCommand(updatePermissionSetCmd)
  updatePermissionSetCmd.Flags().Int64("permission_set_id", 0, "id of permission set")
  cobra.MarkFlagRequired(updatePermissionSetCmd.Flags(), "permission_set_id")
  updatePermissionSetCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updatePermissionSetCmd.Flags(), "body")
  RoleCmd.AddCommand(deletePermissionSetCmd)
  deletePermissionSetCmd.Flags().Int64("permission_set_id", 0, "Id of permission set")
  cobra.MarkFlagRequired(deletePermissionSetCmd.Flags(), "permission_set_id")
  RoleCmd.AddCommand(allPermissionSetsCmd)
  allPermissionSetsCmd.Flags().String("fields", "", "Requested fields.")
  RoleCmd.AddCommand(createPermissionSetCmd)
  createPermissionSetCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createPermissionSetCmd.Flags(), "body")
  RoleCmd.AddCommand(allRolesCmd)
  allRolesCmd.Flags().String("fields", "", "Requested fields.")
  allRolesCmd.Flags().String("ids", "", "Optional list of ids to get specific roles.")
  RoleCmd.AddCommand(createRoleCmd)
  createRoleCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createRoleCmd.Flags(), "body")
  RoleCmd.AddCommand(searchRolesCmd)
  searchRolesCmd.Flags().String("fields", "", "Requested fields.")
  searchRolesCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchRolesCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchRolesCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchRolesCmd.Flags().Int64("id", 0, "Match role id.")
  searchRolesCmd.Flags().String("name", "", "Match role name.")
  searchRolesCmd.Flags().Bool("built_in", false, "Match roles by built_in status.")
  searchRolesCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression.")
  RoleCmd.AddCommand(searchRolesWithUserCountCmd)
  searchRolesWithUserCountCmd.Flags().String("fields", "", "Requested fields.")
  searchRolesWithUserCountCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchRolesWithUserCountCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchRolesWithUserCountCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchRolesWithUserCountCmd.Flags().Int64("id", 0, "Match role id.")
  searchRolesWithUserCountCmd.Flags().String("name", "", "Match role name.")
  searchRolesWithUserCountCmd.Flags().Bool("built_in", false, "Match roles by built_in status.")
  searchRolesWithUserCountCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression.")
  RoleCmd.AddCommand(roleCmd)
  roleCmd.Flags().Int64("role_id", 0, "id of role")
  cobra.MarkFlagRequired(roleCmd.Flags(), "role_id")
  RoleCmd.AddCommand(updateRoleCmd)
  updateRoleCmd.Flags().Int64("role_id", 0, "id of role")
  cobra.MarkFlagRequired(updateRoleCmd.Flags(), "role_id")
  updateRoleCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateRoleCmd.Flags(), "body")
  RoleCmd.AddCommand(deleteRoleCmd)
  deleteRoleCmd.Flags().Int64("role_id", 0, "id of role")
  cobra.MarkFlagRequired(deleteRoleCmd.Flags(), "role_id")
  RoleCmd.AddCommand(roleGroupsCmd)
  roleGroupsCmd.Flags().Int64("role_id", 0, "id of role")
  cobra.MarkFlagRequired(roleGroupsCmd.Flags(), "role_id")
  roleGroupsCmd.Flags().String("fields", "", "Requested fields.")
  RoleCmd.AddCommand(setRoleGroupsCmd)
  setRoleGroupsCmd.Flags().Int64("role_id", 0, "Id of Role")
  cobra.MarkFlagRequired(setRoleGroupsCmd.Flags(), "role_id")
  setRoleGroupsCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setRoleGroupsCmd.Flags(), "body")
  RoleCmd.AddCommand(roleUsersCmd)
  roleUsersCmd.Flags().Int64("role_id", 0, "id of user")
  cobra.MarkFlagRequired(roleUsersCmd.Flags(), "role_id")
  roleUsersCmd.Flags().String("fields", "", "Requested fields.")
  roleUsersCmd.Flags().Bool("direct_association_only", false, "Get only users associated directly with the role: exclude those only associated through groups.")
  RoleCmd.AddCommand(setRoleUsersCmd)
  setRoleUsersCmd.Flags().Int64("role_id", 0, "id of role")
  cobra.MarkFlagRequired(setRoleUsersCmd.Flags(), "role_id")
  setRoleUsersCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setRoleUsersCmd.Flags(), "body")
  rootCmd.AddCommand(RoleCmd)
  ScheduledPlanCmd.AddCommand(scheduledPlansForSpaceCmd)
  scheduledPlansForSpaceCmd.Flags().Int64("space_id", 0, "Space Id")
  cobra.MarkFlagRequired(scheduledPlansForSpaceCmd.Flags(), "space_id")
  scheduledPlansForSpaceCmd.Flags().String("fields", "", "Requested fields.")
  ScheduledPlanCmd.AddCommand(scheduledPlanCmd)
  scheduledPlanCmd.Flags().Int64("scheduled_plan_id", 0, "Scheduled Plan Id")
  cobra.MarkFlagRequired(scheduledPlanCmd.Flags(), "scheduled_plan_id")
  scheduledPlanCmd.Flags().String("fields", "", "Requested fields.")
  ScheduledPlanCmd.AddCommand(updateScheduledPlanCmd)
  updateScheduledPlanCmd.Flags().Int64("scheduled_plan_id", 0, "Scheduled Plan Id")
  cobra.MarkFlagRequired(updateScheduledPlanCmd.Flags(), "scheduled_plan_id")
  updateScheduledPlanCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateScheduledPlanCmd.Flags(), "body")
  ScheduledPlanCmd.AddCommand(deleteScheduledPlanCmd)
  deleteScheduledPlanCmd.Flags().Int64("scheduled_plan_id", 0, "Scheduled Plan Id")
  cobra.MarkFlagRequired(deleteScheduledPlanCmd.Flags(), "scheduled_plan_id")
  ScheduledPlanCmd.AddCommand(allScheduledPlansCmd)
  allScheduledPlansCmd.Flags().Int64("user_id", 0, "Return scheduled plans belonging to this user_id. If not provided, returns scheduled plans owned by the caller.")
  allScheduledPlansCmd.Flags().String("fields", "", "Comma delimited list of field names. If provided, only the fields specified will be included in the response")
  allScheduledPlansCmd.Flags().Bool("all_users", false, "Return scheduled plans belonging to all users (caller needs see_schedules permission)")
  ScheduledPlanCmd.AddCommand(createScheduledPlanCmd)
  createScheduledPlanCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createScheduledPlanCmd.Flags(), "body")
  ScheduledPlanCmd.AddCommand(scheduledPlanRunOnceCmd)
  scheduledPlanRunOnceCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(scheduledPlanRunOnceCmd.Flags(), "body")
  ScheduledPlanCmd.AddCommand(scheduledPlansForLookCmd)
  scheduledPlansForLookCmd.Flags().Int64("look_id", 0, "Look Id")
  cobra.MarkFlagRequired(scheduledPlansForLookCmd.Flags(), "look_id")
  scheduledPlansForLookCmd.Flags().Int64("user_id", 0, "User Id (default is requesting user if not specified)")
  scheduledPlansForLookCmd.Flags().String("fields", "", "Requested fields.")
  scheduledPlansForLookCmd.Flags().Bool("all_users", false, "Return scheduled plans belonging to all users for the look")
  ScheduledPlanCmd.AddCommand(scheduledPlansForDashboardCmd)
  scheduledPlansForDashboardCmd.Flags().Int64("dashboard_id", 0, "Dashboard Id")
  cobra.MarkFlagRequired(scheduledPlansForDashboardCmd.Flags(), "dashboard_id")
  scheduledPlansForDashboardCmd.Flags().Int64("user_id", 0, "User Id (default is requesting user if not specified)")
  scheduledPlansForDashboardCmd.Flags().Bool("all_users", false, "Return scheduled plans belonging to all users for the dashboard")
  scheduledPlansForDashboardCmd.Flags().String("fields", "", "Requested fields.")
  ScheduledPlanCmd.AddCommand(scheduledPlansForLookmlDashboardCmd)
  scheduledPlansForLookmlDashboardCmd.Flags().String("lookml_dashboard_id", "", "LookML Dashboard Id")
  cobra.MarkFlagRequired(scheduledPlansForLookmlDashboardCmd.Flags(), "lookml_dashboard_id")
  scheduledPlansForLookmlDashboardCmd.Flags().Int64("user_id", 0, "User Id (default is requesting user if not specified)")
  scheduledPlansForLookmlDashboardCmd.Flags().String("fields", "", "Requested fields.")
  scheduledPlansForLookmlDashboardCmd.Flags().Bool("all_users", false, "Return scheduled plans belonging to all users for the dashboard")
  ScheduledPlanCmd.AddCommand(scheduledPlanRunOnceByIdCmd)
  scheduledPlanRunOnceByIdCmd.Flags().Int64("scheduled_plan_id", 0, "Id of schedule plan to copy and run")
  cobra.MarkFlagRequired(scheduledPlanRunOnceByIdCmd.Flags(), "scheduled_plan_id")
  scheduledPlanRunOnceByIdCmd.Flags().String("body", "", "")
  rootCmd.AddCommand(ScheduledPlanCmd)
  SessionCmd.AddCommand(sessionCmd)
  SessionCmd.AddCommand(updateSessionCmd)
  updateSessionCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateSessionCmd.Flags(), "body")
  rootCmd.AddCommand(SessionCmd)
  ThemeCmd.AddCommand(allThemesCmd)
  allThemesCmd.Flags().String("fields", "", "Requested fields.")
  ThemeCmd.AddCommand(createThemeCmd)
  createThemeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createThemeCmd.Flags(), "body")
  ThemeCmd.AddCommand(searchThemesCmd)
  searchThemesCmd.Flags().Int64("id", 0, "Match theme id.")
  searchThemesCmd.Flags().String("name", "", "Match theme name.")
  searchThemesCmd.Flags().String("begin_at", "", "Timestamp for activation.")
  searchThemesCmd.Flags().String("end_at", "", "Timestamp for expiration.")
  searchThemesCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchThemesCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchThemesCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchThemesCmd.Flags().String("fields", "", "Requested fields.")
  searchThemesCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  ThemeCmd.AddCommand(defaultThemeCmd)
  defaultThemeCmd.Flags().String("ts", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
  ThemeCmd.AddCommand(setDefaultThemeCmd)
  setDefaultThemeCmd.Flags().String("name", "", "Name of theme to set as default")
  cobra.MarkFlagRequired(setDefaultThemeCmd.Flags(), "name")
  ThemeCmd.AddCommand(activeThemesCmd)
  activeThemesCmd.Flags().String("name", "", "Name of theme")
  activeThemesCmd.Flags().String("ts", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
  activeThemesCmd.Flags().String("fields", "", "Requested fields.")
  ThemeCmd.AddCommand(themeOrDefaultCmd)
  themeOrDefaultCmd.Flags().String("name", "", "Name of theme")
  cobra.MarkFlagRequired(themeOrDefaultCmd.Flags(), "name")
  themeOrDefaultCmd.Flags().String("ts", "", "Timestamp representing the target datetime for the active period. Defaults to 'now'")
  ThemeCmd.AddCommand(validateThemeCmd)
  validateThemeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(validateThemeCmd.Flags(), "body")
  ThemeCmd.AddCommand(themeCmd)
  themeCmd.Flags().Int64("theme_id", 0, "Id of theme")
  cobra.MarkFlagRequired(themeCmd.Flags(), "theme_id")
  themeCmd.Flags().String("fields", "", "Requested fields.")
  ThemeCmd.AddCommand(updateThemeCmd)
  updateThemeCmd.Flags().Int64("theme_id", 0, "Id of theme")
  cobra.MarkFlagRequired(updateThemeCmd.Flags(), "theme_id")
  updateThemeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateThemeCmd.Flags(), "body")
  ThemeCmd.AddCommand(deleteThemeCmd)
  deleteThemeCmd.Flags().String("theme_id", "", "Id of theme")
  cobra.MarkFlagRequired(deleteThemeCmd.Flags(), "theme_id")
  rootCmd.AddCommand(ThemeCmd)
  UserCmd.AddCommand(searchCredentialsEmailCmd)
  searchCredentialsEmailCmd.Flags().String("fields", "", "Requested fields.")
  searchCredentialsEmailCmd.Flags().Int64("limit", 0, "Number of results to return (used with `offset`).")
  searchCredentialsEmailCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any (used with `limit`).")
  searchCredentialsEmailCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchCredentialsEmailCmd.Flags().Int64("id", 0, "Match credentials_email id.")
  searchCredentialsEmailCmd.Flags().String("email", "", "Match credentials_email email.")
  searchCredentialsEmailCmd.Flags().String("emails", "", "Find credentials_email that match given emails.")
  searchCredentialsEmailCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression.")
  UserCmd.AddCommand(meCmd)
  meCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(allUsersCmd)
  allUsersCmd.Flags().String("fields", "", "Requested fields.")
  allUsersCmd.Flags().Int64("page", 0, "DEPRECATED. Use limit and offset instead. Return only page N of paginated results")
  allUsersCmd.Flags().Int64("per_page", 0, "DEPRECATED. Use limit and offset instead. Return N rows of data per page")
  allUsersCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  allUsersCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  allUsersCmd.Flags().String("sorts", "", "Fields to sort by.")
  allUsersCmd.Flags().String("ids", "", "Optional list of ids to get specific users.")
  UserCmd.AddCommand(createUserCmd)
  createUserCmd.Flags().String("body", "", "")
  createUserCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(searchUsersCmd)
  searchUsersCmd.Flags().String("fields", "", "Include only these fields in the response")
  searchUsersCmd.Flags().Int64("page", 0, "DEPRECATED. Use limit and offset instead. Return only page N of paginated results")
  searchUsersCmd.Flags().Int64("per_page", 0, "DEPRECATED. Use limit and offset instead. Return N rows of data per page")
  searchUsersCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  searchUsersCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchUsersCmd.Flags().String("sorts", "", "Fields to sort by.")
  searchUsersCmd.Flags().String("id", "", "Match User Id.")
  searchUsersCmd.Flags().String("first_name", "", "Match First name.")
  searchUsersCmd.Flags().String("last_name", "", "Match Last name.")
  searchUsersCmd.Flags().Bool("verified_looker_employee", false, "Search for user accounts associated with Looker employees")
  searchUsersCmd.Flags().Bool("embed_user", false, "Search for only embed users")
  searchUsersCmd.Flags().String("email", "", "Search for the user with this email address")
  searchUsersCmd.Flags().Bool("is_disabled", false, "Search for disabled user accounts")
  searchUsersCmd.Flags().Bool("filter_or", false, "Combine given search criteria in a boolean OR expression")
  searchUsersCmd.Flags().String("content_metadata_id", "", "Search for users who have access to this content_metadata item")
  searchUsersCmd.Flags().String("group_id", "", "Search for users who are direct members of this group")
  UserCmd.AddCommand(searchUsersNamesCmd)
  searchUsersNamesCmd.Flags().String("pattern", "", "Pattern to match")
  cobra.MarkFlagRequired(searchUsersNamesCmd.Flags(), "pattern")
  searchUsersNamesCmd.Flags().String("fields", "", "Include only these fields in the response")
  searchUsersNamesCmd.Flags().Int64("page", 0, "DEPRECATED. Use limit and offset instead. Return only page N of paginated results")
  searchUsersNamesCmd.Flags().Int64("per_page", 0, "DEPRECATED. Use limit and offset instead. Return N rows of data per page")
  searchUsersNamesCmd.Flags().Int64("limit", 0, "Number of results to return. (used with offset and takes priority over page and per_page)")
  searchUsersNamesCmd.Flags().Int64("offset", 0, "Number of results to skip before returning any. (used with limit and takes priority over page and per_page)")
  searchUsersNamesCmd.Flags().String("sorts", "", "Fields to sort by")
  searchUsersNamesCmd.Flags().Int64("id", 0, "Match User Id")
  searchUsersNamesCmd.Flags().String("first_name", "", "Match First name")
  searchUsersNamesCmd.Flags().String("last_name", "", "Match Last name")
  searchUsersNamesCmd.Flags().Bool("verified_looker_employee", false, "Match Verified Looker employee")
  searchUsersNamesCmd.Flags().String("email", "", "Match Email Address")
  searchUsersNamesCmd.Flags().Bool("is_disabled", false, "Include or exclude disabled accounts in the results")
  UserCmd.AddCommand(userCmd)
  userCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(userCmd.Flags(), "user_id")
  userCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(updateUserCmd)
  updateUserCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(updateUserCmd.Flags(), "user_id")
  updateUserCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateUserCmd.Flags(), "body")
  updateUserCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCmd)
  deleteUserCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(deleteUserCmd.Flags(), "user_id")
  UserCmd.AddCommand(userForCredentialCmd)
  userForCredentialCmd.Flags().String("credential_type", "", "Type name of credential")
  cobra.MarkFlagRequired(userForCredentialCmd.Flags(), "credential_type")
  userForCredentialCmd.Flags().String("credential_id", "", "Id of credential")
  cobra.MarkFlagRequired(userForCredentialCmd.Flags(), "credential_id")
  userForCredentialCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(userCredentialsEmailCmd)
  userCredentialsEmailCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsEmailCmd.Flags(), "user_id")
  userCredentialsEmailCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(createUserCredentialsEmailCmd)
  createUserCredentialsEmailCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(createUserCredentialsEmailCmd.Flags(), "user_id")
  createUserCredentialsEmailCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createUserCredentialsEmailCmd.Flags(), "body")
  createUserCredentialsEmailCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(updateUserCredentialsEmailCmd)
  updateUserCredentialsEmailCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(updateUserCredentialsEmailCmd.Flags(), "user_id")
  updateUserCredentialsEmailCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateUserCredentialsEmailCmd.Flags(), "body")
  updateUserCredentialsEmailCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsEmailCmd)
  deleteUserCredentialsEmailCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsEmailCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsTotpCmd)
  userCredentialsTotpCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsTotpCmd.Flags(), "user_id")
  userCredentialsTotpCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(createUserCredentialsTotpCmd)
  createUserCredentialsTotpCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(createUserCredentialsTotpCmd.Flags(), "user_id")
  createUserCredentialsTotpCmd.Flags().String("body", "", "")
  createUserCredentialsTotpCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsTotpCmd)
  deleteUserCredentialsTotpCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsTotpCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsLdapCmd)
  userCredentialsLdapCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsLdapCmd.Flags(), "user_id")
  userCredentialsLdapCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsLdapCmd)
  deleteUserCredentialsLdapCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsLdapCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsGoogleCmd)
  userCredentialsGoogleCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsGoogleCmd.Flags(), "user_id")
  userCredentialsGoogleCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsGoogleCmd)
  deleteUserCredentialsGoogleCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsGoogleCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsSamlCmd)
  userCredentialsSamlCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsSamlCmd.Flags(), "user_id")
  userCredentialsSamlCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsSamlCmd)
  deleteUserCredentialsSamlCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsSamlCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsOidcCmd)
  userCredentialsOidcCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsOidcCmd.Flags(), "user_id")
  userCredentialsOidcCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsOidcCmd)
  deleteUserCredentialsOidcCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsOidcCmd.Flags(), "user_id")
  UserCmd.AddCommand(userCredentialsApi3Cmd)
  userCredentialsApi3Cmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(userCredentialsApi3Cmd.Flags(), "user_id")
  userCredentialsApi3Cmd.Flags().Int64("credentials_api3_id", 0, "Id of API 3 Credential")
  cobra.MarkFlagRequired(userCredentialsApi3Cmd.Flags(), "credentials_api3_id")
  userCredentialsApi3Cmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsApi3Cmd)
  deleteUserCredentialsApi3Cmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsApi3Cmd.Flags(), "user_id")
  deleteUserCredentialsApi3Cmd.Flags().Int64("credentials_api3_id", 0, "id of API 3 Credential")
  cobra.MarkFlagRequired(deleteUserCredentialsApi3Cmd.Flags(), "credentials_api3_id")
  UserCmd.AddCommand(allUserCredentialsApi3sCmd)
  allUserCredentialsApi3sCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(allUserCredentialsApi3sCmd.Flags(), "user_id")
  allUserCredentialsApi3sCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(createUserCredentialsApi3Cmd)
  createUserCredentialsApi3Cmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(createUserCredentialsApi3Cmd.Flags(), "user_id")
  createUserCredentialsApi3Cmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(userCredentialsEmbedCmd)
  userCredentialsEmbedCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(userCredentialsEmbedCmd.Flags(), "user_id")
  userCredentialsEmbedCmd.Flags().Int64("credentials_embed_id", 0, "Id of Embedding Credential")
  cobra.MarkFlagRequired(userCredentialsEmbedCmd.Flags(), "credentials_embed_id")
  userCredentialsEmbedCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsEmbedCmd)
  deleteUserCredentialsEmbedCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsEmbedCmd.Flags(), "user_id")
  deleteUserCredentialsEmbedCmd.Flags().Int64("credentials_embed_id", 0, "id of Embedding Credential")
  cobra.MarkFlagRequired(deleteUserCredentialsEmbedCmd.Flags(), "credentials_embed_id")
  UserCmd.AddCommand(allUserCredentialsEmbedsCmd)
  allUserCredentialsEmbedsCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(allUserCredentialsEmbedsCmd.Flags(), "user_id")
  allUserCredentialsEmbedsCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(userCredentialsLookerOpenidCmd)
  userCredentialsLookerOpenidCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userCredentialsLookerOpenidCmd.Flags(), "user_id")
  userCredentialsLookerOpenidCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserCredentialsLookerOpenidCmd)
  deleteUserCredentialsLookerOpenidCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserCredentialsLookerOpenidCmd.Flags(), "user_id")
  UserCmd.AddCommand(userSessionCmd)
  userSessionCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(userSessionCmd.Flags(), "user_id")
  userSessionCmd.Flags().Int64("session_id", 0, "Id of Web Login Session")
  cobra.MarkFlagRequired(userSessionCmd.Flags(), "session_id")
  userSessionCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(deleteUserSessionCmd)
  deleteUserSessionCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(deleteUserSessionCmd.Flags(), "user_id")
  deleteUserSessionCmd.Flags().Int64("session_id", 0, "id of Web Login Session")
  cobra.MarkFlagRequired(deleteUserSessionCmd.Flags(), "session_id")
  UserCmd.AddCommand(allUserSessionsCmd)
  allUserSessionsCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(allUserSessionsCmd.Flags(), "user_id")
  allUserSessionsCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(createUserCredentialsEmailPasswordResetCmd)
  createUserCredentialsEmailPasswordResetCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(createUserCredentialsEmailPasswordResetCmd.Flags(), "user_id")
  createUserCredentialsEmailPasswordResetCmd.Flags().Bool("expires", false, "Expiring token.")
  createUserCredentialsEmailPasswordResetCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(userRolesCmd)
  userRolesCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(userRolesCmd.Flags(), "user_id")
  userRolesCmd.Flags().String("fields", "", "Requested fields.")
  userRolesCmd.Flags().Bool("direct_association_only", false, "Get only roles associated directly with the user: exclude those only associated through groups.")
  UserCmd.AddCommand(setUserRolesCmd)
  setUserRolesCmd.Flags().Int64("user_id", 0, "id of user")
  cobra.MarkFlagRequired(setUserRolesCmd.Flags(), "user_id")
  setUserRolesCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setUserRolesCmd.Flags(), "body")
  setUserRolesCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(userAttributeUserValuesCmd)
  userAttributeUserValuesCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(userAttributeUserValuesCmd.Flags(), "user_id")
  userAttributeUserValuesCmd.Flags().String("fields", "", "Requested fields.")
  userAttributeUserValuesCmd.Flags().String("user_attribute_ids", "", "Specific user attributes to request. Omit or leave blank to request all user attributes.")
  userAttributeUserValuesCmd.Flags().Bool("all_values", false, "If true, returns all values in the search path instead of just the first value found. Useful for debugging group precedence.")
  userAttributeUserValuesCmd.Flags().Bool("include_unset", false, "If true, returns an empty record for each requested attribute that has no user, group, or default value.")
  UserCmd.AddCommand(setUserAttributeUserValueCmd)
  setUserAttributeUserValueCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "user_id")
  setUserAttributeUserValueCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "user_attribute_id")
  setUserAttributeUserValueCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setUserAttributeUserValueCmd.Flags(), "body")
  UserCmd.AddCommand(deleteUserAttributeUserValueCmd)
  deleteUserAttributeUserValueCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(deleteUserAttributeUserValueCmd.Flags(), "user_id")
  deleteUserAttributeUserValueCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(deleteUserAttributeUserValueCmd.Flags(), "user_attribute_id")
  UserCmd.AddCommand(sendUserCredentialsEmailPasswordResetCmd)
  sendUserCredentialsEmailPasswordResetCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(sendUserCredentialsEmailPasswordResetCmd.Flags(), "user_id")
  sendUserCredentialsEmailPasswordResetCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(wipeoutUserEmailsCmd)
  wipeoutUserEmailsCmd.Flags().Int64("user_id", 0, "Id of user")
  cobra.MarkFlagRequired(wipeoutUserEmailsCmd.Flags(), "user_id")
  wipeoutUserEmailsCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(wipeoutUserEmailsCmd.Flags(), "body")
  wipeoutUserEmailsCmd.Flags().String("fields", "", "Requested fields.")
  UserCmd.AddCommand(createEmbedUserCmd)
  createEmbedUserCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createEmbedUserCmd.Flags(), "body")
  rootCmd.AddCommand(UserCmd)
  UserAttributeCmd.AddCommand(allUserAttributesCmd)
  allUserAttributesCmd.Flags().String("fields", "", "Requested fields.")
  allUserAttributesCmd.Flags().String("sorts", "", "Fields to order the results by. Sortable fields include: name, label")
  UserAttributeCmd.AddCommand(createUserAttributeCmd)
  createUserAttributeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(createUserAttributeCmd.Flags(), "body")
  createUserAttributeCmd.Flags().String("fields", "", "Requested fields.")
  UserAttributeCmd.AddCommand(userAttributeCmd)
  userAttributeCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(userAttributeCmd.Flags(), "user_attribute_id")
  userAttributeCmd.Flags().String("fields", "", "Requested fields.")
  UserAttributeCmd.AddCommand(updateUserAttributeCmd)
  updateUserAttributeCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(updateUserAttributeCmd.Flags(), "user_attribute_id")
  updateUserAttributeCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(updateUserAttributeCmd.Flags(), "body")
  updateUserAttributeCmd.Flags().String("fields", "", "Requested fields.")
  UserAttributeCmd.AddCommand(deleteUserAttributeCmd)
  deleteUserAttributeCmd.Flags().Int64("user_attribute_id", 0, "Id of user_attribute")
  cobra.MarkFlagRequired(deleteUserAttributeCmd.Flags(), "user_attribute_id")
  UserAttributeCmd.AddCommand(allUserAttributeGroupValuesCmd)
  allUserAttributeGroupValuesCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(allUserAttributeGroupValuesCmd.Flags(), "user_attribute_id")
  allUserAttributeGroupValuesCmd.Flags().String("fields", "", "Requested fields.")
  UserAttributeCmd.AddCommand(setUserAttributeGroupValuesCmd)
  setUserAttributeGroupValuesCmd.Flags().Int64("user_attribute_id", 0, "Id of user attribute")
  cobra.MarkFlagRequired(setUserAttributeGroupValuesCmd.Flags(), "user_attribute_id")
  setUserAttributeGroupValuesCmd.Flags().String("body", "", "")
  cobra.MarkFlagRequired(setUserAttributeGroupValuesCmd.Flags(), "body")
  rootCmd.AddCommand(UserAttributeCmd)
  WorkspaceCmd.AddCommand(allWorkspacesCmd)
  WorkspaceCmd.AddCommand(workspaceCmd)
  workspaceCmd.Flags().String("workspace_id", "", "Id of the workspace ")
  cobra.MarkFlagRequired(workspaceCmd.Flags(), "workspace_id")
  rootCmd.AddCommand(WorkspaceCmd)
}
