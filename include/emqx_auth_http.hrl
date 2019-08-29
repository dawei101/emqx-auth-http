
-define(APP, emqx_auth_http).

-record(http_request, {method = post, url, params, cache_time, appids}).

