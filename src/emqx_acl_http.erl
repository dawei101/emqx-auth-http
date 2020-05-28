%% Copyright (c) 2013-2019 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(emqx_acl_http).

-include("emqx_auth_http.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-import(emqx_auth_http_cli,
        [ request/5
        , feedvar/2
        ]).

%% ACL callbacks
-export([ register_metrics/0
        , check_acl/5
        , reload_acl/1
        , description/0
        ]).

register_metrics() ->
    [emqx_metrics:new(MetricName) || MetricName <- ['acl.http.allow', 'acl.http.deny', 'acl.http.ignore']].

%%------------------------------------------------------------------------------
%% ACL callbacks
%%------------------------------------------------------------------------------

check_acl(Credentials = #{username := Username, client_id := ClientId}, PubSub, Topic, AclResult, State = #{acl_req := AclReq}) ->
	case check_roobo_acl(Credentials, Topic, AclReq) of
		ok -> emqx_metrics:inc('acl.http.ignore'), ok;
		{ok, false} ->
			?LOG(info, "[Auth http] check acl deny client:~s username:~s", [ClientId, Username]),
			case do_check_acl(Credentials, PubSub, Topic, AclResult, State) of
				ok -> emqx_metrics:inc('acl.http.ignore'), ok;
				{stop, allow} -> emqx_metrics:inc('acl.http.allow'), {stop, allow};
				{stop, deny} -> emqx_metrics:inc('acl.http.deny'), {stop, deny}
			end;
		{ok, true} ->
			emqx_metrics:inc('acl.http.allow'),
%% 			?LOG(info, "[Auth http] check acl allow client:~s username:~s", [ClientId, Username]),
			{stop, allow}
	end.

check_roobo_acl(#{username := <<$$, _/binary>>}, _Topic, _AclReq) ->
	ok;

check_roobo_acl(#{username := Username, client_id := ClientId}, Topic, #http_request{appids = AppIds}) ->
	?LOG(debug, "[Auth http] acl super appIds:~p", [AppIds]),
	UsernameStr = get_str(Username),
	ClientIdStr = get_str(ClientId),
	case string:chr(UsernameStr, $@) of
		0 ->
			?LOG(info, "[Auth http] acl username:~s invalid", [Username]),
			{ok, false};
		_ ->
			UserNameArray = string:tokens(UsernameStr, "@"),
			AppId = lists:nth(2, UserNameArray),
			case lists:member(AppId, AppIds) of
				true ->
					?LOG(info, "[Auth http] acl username:~s is super user", [Username]),
					{ok, true};
				_ ->
					case string:equal(lists:nth(1, UserNameArray), ClientIdStr) of
						false ->
							{ok, false};
						true ->
							%% check topic
							case string:equal(get_str(get_clientid_by_topic(Topic)), ClientIdStr) of
								true ->
									{ok, true};
								false ->
									{ok, false}
							end
					end
			end
	end.

get_clientid_by_topic(Topic) ->
	S = binary:split(Topic, <<$/>>, [global, trim]),
	Size = array:size(array:from_list(S)),
	if
		Size >= 4 ->
			lists:nth(4, S);
		true ->
			<<"">>
	end.

get_str(P) ->
	if
		is_binary(P) ->
			binary:bin_to_list(P);
		is_list(P) ->
			P;
		true ->
			""
	end.

do_check_acl(#{username := <<$$, _/binary>>}, _PubSub, _Topic, _AclResult, _Config) ->
    ok;
do_check_acl(Credentials, PubSub, Topic, _AclResult, #{acl_req := AclReq,
                                                       http_opts := HttpOpts,
                                                       retry_opts := RetryOpts}) ->
    Credentials1 = Credentials#{access => access(PubSub), topic => Topic},
    case check_acl_request(AclReq, Credentials1, HttpOpts, RetryOpts) of
        {ok, 200, "ignore"} -> ok;
        {ok, 200, _Body}    -> {stop, allow};
        {ok, _Code, _Body}  -> {stop, deny};
        {error, Error}      ->
            ?LOG(error, "[ACL http] do_check_acl url ~s Error: ~p", [AclReq#http_request.url, Error]),
            ok
    end.

reload_acl(_State) -> ok.

description() -> "ACL with HTTP API".

%%------------------------------------------------------------------------------
%% Interval functions
%%------------------------------------------------------------------------------

check_acl_request(#http_request{method = Method, url = Url, params = Params}, Credentials, HttpOpts, RetryOpts) ->
    request(Method, Url, feedvar(Params, Credentials), HttpOpts, RetryOpts).

access(subscribe) -> 1;
access(publish)   -> 2.

