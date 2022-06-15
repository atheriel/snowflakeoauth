#' Connect to a Snowflake Database via OAuth
#'
#' @description Wraps [DBI::dbConnect()] using the Snowflake ODBC driver but
#'   uses the local OAuth token for authentication instead of a username and
#'   password.
#'
#' @param account The Snowflake account identifier, e.g. `myaccount` or
#'   `myaccount.snowflakecomputing.com`.
#' @param driver The name of the Snowflake ODBC driver.
#' @param ... Further arguments passed to the Snowflake driver via
#'   [DBI::dbConnect()], such as `Database` or `Warehouse`.
#' @returns A `DBIConnection`.
#' @export
snowflake_conn <- function(account, driver = "snowflake", ...) {
  account <- normalise_account(account)
  token <- .tokens[[account]]
  if (is.null(token)) {
    stop("no existing token found, did you call snowflake_auth()?")
  }
  token <- maybe_refresh_token(token$token)
  DBI::dbConnect(
    odbc::odbc(),
    driver = driver, server = account, authenticator = "OAuth",
    token = token$access_token, ...
  )
}

#' Authenticate to Snowflake via OAuth
#'
#' @description Authenticate with Snowflake via OAuth and cache the token
#'   locally so it can be used in calls to [snowflake_conn()].
#'
#' @param account The Snowflake account identifier, e.g. `myaccount` or
#'   `myaccount.snowflakecomputing.com`.
#' @param client_id The OAuth client ID to use for authorization.
#' @param client_secret The OAuth client secret, which is required for *most*
#'   authorization flows.
#' @param role The role to request. When `NULL`, accept the user's default.
#' @param auth_url The OAuth URL for authorization. This is only required when
#'   using an external OAuth provider instead of Snowflake's built-in one.
#' @param token_url The OAuth URL for retrieving tokens. This is only required
#'   when using an external OAuth provider instead of Snowflake's built-in one.
#' @param scope Additional (non-role) OAuth scopes, if any.
#' @param offline_access When `TRUE`, request "offline access" -- that is, allow
#'   tokens to be refreshed automatically, if possible.
#' @param client_args Further arguments passed to [httr2::oauth_client()].
#' @returns An [httr2::oauth_token], invisibly.
#' @importFrom rlang !!!
#' @export
snowflake_auth <- function(account, client_id, client_secret = NULL, role = NULL,
                           auth_url = NULL, token_url = NULL, scope = NULL,
                           offline_access = TRUE,
                           ## username = NULL, password = NULL,
                           client_args = list()) {
  account <- normalise_account(account)
  # Assume Snowflake's own OAuth implementation by default.
  internal <- is.null(auth_url)
  ## if (internal && (!is.null(username) || !is.null(password))) {
  ##   stop("`username` and `password` should only be used with external OAuth providers")
  ## }
  if (internal) {
    auth_url <- sprintf("https://%s/oauth/authorize", account)
    token_url <- sprintf("https://%s/oauth/token-request", account)
    role_scope <- sprintf("session:role:%s", role)
    # Snowflake's OAuth uses a non-standard scope for offline access,
    # "refresh_token".
    #
    # TODO: Maybe issue an error that other scopes are being ignored?
    scope <- if (offline_access) "refresh_token" else NULL
  } else {
    # FIXME: Is this always the correct format for external IdPs?
    if (!is.null(role)) {
      role_scope <- sprintf("https://%s/session:role:%s", account, role)
    } else {
      role_scope <- sprintf("https://%s/session:role-any", account)
    }
  }
  scope <- paste(c(scope, role_scope), collapse = " ")
  # Note: Snowflake's docs erroneously state that only header-based client auth
  # is supported, but testing shows this is not the case, so we can use httr2's
  # default of body-based client auth.
  client_args$id <- client_id
  client_args$token_url <- token_url
  client_args$secret <- client_secret
  client <- rlang::inject(httr2::oauth_client(!!!client_args))
  token <- httr2::oauth_flow_auth_code(
    client, auth_url, scope = scope, port = 1410
  )
  # Keep a reference to the client for later token refresh.
  .tokens[[account]] <- list(token = token, client = client)
  invisible(.tokens[[account]])
}

normalise_account <- function(account) {
  if (startsWith(account, "https")) {
    stop("`account` must not be a complete URL")
  }
  if (!endsWith(account, "snowflakecomputing.com")) {
    sprintf("%s.snowflakecomputing.com", account)
  } else {
    account
  }
}

maybe_refresh_token <- function(token) {
  if (!token_has_expired(token)) {
    return(token)
  }
  if (is.null(token$refresh_token) || is.null(token$client)) {
    stop("token has expired and cannot be automatically refreshed")
  }
  token <- httr2::oauth_flow_refresh(token$client, token$refresh_token)
  token
}

token_has_expired <- function(token) {
  # Allow for the recommended 5 seconds of clock skew.
  !is.null(token$expires_at) && token$expires_at < as.integer(Sys.time()) + 5
}

# Internal token cache.
.tokens <- new.env()
