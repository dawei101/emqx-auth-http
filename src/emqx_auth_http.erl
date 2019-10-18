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

-module(emqx_auth_http).

-include("emqx_auth_http.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").
-import(emqx_auth_http_cli,
        [ request/5
        , feedvar/2
        ]).

%% Callbacks
-export([ register_metrics/0
        , check/2
        , description/0
        ]).

register_metrics() ->
    [emqx_metrics:new(MetricName) || MetricName <- ['auth.http.success', 'auth.http.failure', 'auth.http.ignore']].

check(Credentials, #{auth_req := AuthReq,
                     super_req := SuperReq,
					 config_req := ConfigReq,
                     http_opts := HttpOpts,
                     retry_opts := RetryOpts}) ->
	?LOG(info, "[Auth http] start auth"),
    case authenticate(AuthReq, ConfigReq, Credentials, HttpOpts, RetryOpts) of
        {ok, 200, "ignore"} ->
            emqx_metrics:inc('auth.http.ignore'), ok;
        {ok, 200, Body}  ->
            emqx_metrics:inc('auth.http.success'),
			process_success_client(Credentials, Body),
            {stop, Credentials#{is_superuser => is_superuser(SuperReq, Credentials, HttpOpts, RetryOpts),
                                auth_result => success,
                                anonymous => false,
                                mountpoint  => mountpoint(Body, Credentials)}};
		{ok, 403, _Msg} ->
            emqx_metrics:inc('auth.http.failure'),
			process_failed_client(Credentials, AuthReq),
			?LOG(info, "[Auth http] block by blacklist"),
            {stop, Credentials#{auth_result => 403, anonymous => false}};
        {ok, Code, _Body} ->
            emqx_metrics:inc('auth.http.failure'),
			process_failed_client(Credentials, AuthReq),
			?LOG(info, "[Auth http] check_auth Code: ~p", [Code]),
            {stop, Credentials#{auth_result => Code, anonymous => false}};
        {error, Error} ->
            ?LOG(error, "[Auth http] check_auth Url: ~p Error: ~p", [AuthReq#http_request.url, Error]),
            emqx_metrics:inc('auth.http.failure'),
            {stop, Credentials#{auth_result => Error, anonymous => false}}
    end.

description() -> "Authentication by HTTP API".

%%--------------------------------------------------------------------
%% Requests
%%--------------------------------------------------------------------

authenticate(#http_request{method = Method, url = Url, params = Params}, ConfigReq, Credentials, HttpOpts, RetryOpts) ->
	case pre_process_by_config(ConfigReq, Credentials, HttpOpts, RetryOpts) of
		{ok, true, _} ->
			{ok, 403, "blocked by black list"};
		{ok, false, true} ->
			{ok, 200, "access by white list"};
		{ok, _, _} ->
			request(Method, Url, feedvar(Params, Credentials), HttpOpts, RetryOpts)
	end.

process_failed_client(_Credentials = #{client_id := ClientId}, #http_request{limit_config = LimitConfig})->
	case lookup_ets(blocked_client, ClientId) of
		0 ->
			Now = timestamp(),
			case lookup_ets(failed_client, ClientId) of
				0 ->
					?LOG(info, "[Auth http] ClientId:~s do not have config!", [ClientId]),
					ets:insert(failed_client, {ClientId, {1, Now, Now}});
				{Times, StartFailedTs, EndFailedTs} ->
					Gap = Now - StartFailedTs,
					Rate = list_to_integer(proplists:get_value("rate", LimitConfig)),
					Time = list_to_integer(proplists:get_value("time", LimitConfig)),
					Sleep = list_to_integer(proplists:get_value("sleep", LimitConfig)),
					if
						Gap =< Time ->
						   if
							   Times >= Rate - 1 ->
								  ?LOG(warning, "[Auth http] hit rate. should add block list:~s", [ClientId]),
								  ets:insert(blocked_client, {ClientId, Now}),
								  timer:sleep(Sleep * 1000);
							   true ->
								  ets:insert(failed_client, {ClientId, {Times+1, StartFailedTs, Now}}),
								  ?LOG(info, "[Auth http] in gap add times:~s", [integer_to_list(Times+1)])
						   end;
					   true ->
						   ?LOG(info, "[Auth http] out gap:~s clear time", [ClientId]),
						   ets:insert(failed_client, {ClientId, {1, Now, Now}})
					end,
					?LOG(debug, "[Auth http] Rate:~p Time:~p Sleep:~p", [Rate, Time, Sleep])
			end;
		LastBlockTs ->
			Sleep = list_to_integer(proplists:get_value("sleep", LimitConfig)),
			timer:sleep(Sleep * 1000),
			?LOG(info, "[Auth http] in blocked_client:~s sleep:~p", [ClientId, Sleep])
	end.

process_success_client(_Credentials = #{client_id := ClientId}, Body)->
	ets:delete(failed_client, ClientId),
	ets:delete(blocked_client, ClientId),
	?LOG(info, "[Auth http] client:~s connect success! body:~s", [ClientId, Body]),
	ok.

get_app_id(Username)->
	if is_binary(Username) ->
		    UsernameStr = binary:bin_to_list(Username);
	   is_list(Username) ->
			UsernameStr = Username;
	   true -> 
		    UsernameStr = ""
	end,
	Position = string:chr(UsernameStr, $@),
	case Position of
		0->	
			?LOG(debug, "[Auth http] username:~s invalid", [Username]),
			"";
		_->
			lists:nth(2, string:tokens(UsernameStr, "@"))
	end.

timestamp() ->
    {M, S, _} = os:timestamp(),
    M * 1000000 + S.

lookup_ets(Table, Key)->
	case ets:lookup(Table, Key) of
		[] -> 0;
		Result -> proplists:get_value(Key, Result)
	end.

check_local_config(CacheTime, Method, Url, Params, HttpOpts, RetryOpts) ->
	TimesGap = timestamp() - lookup_ets(auth_config, last_timestamp),
	if
		TimesGap > CacheTime ->
			case request(Method, Url, Params, HttpOpts, RetryOpts) of
				{ok, 200, Body}  ->
					?LOG(info, "[Auth http] auth config respnose ok ~s", [Body]),
					Result = jsx:decode(list_to_binary(Body)),
					case proplists:get_value(<<"result">>, Result) of
						0 ->
							DataResult = proplists:get_value(<<"data">>, Result),
							ConfigResult = proplists:get_value(<<"config">>, DataResult),
							AppIdBlackList = proplists:get_value(<<"app_id_blacklist">>, ConfigResult),
							ClientIdBlackList = proplists:get_value(<<"client_id_blacklist">>, ConfigResult),
							AppIdWhiteList = proplists:get_value(<<"app_id_whitelist">>, ConfigResult),
							ClientIdWhiteList = proplists:get_value(<<"client_id_whitelist">>, ConfigResult),
							ets:insert(auth_config, {app_id_blacklist, AppIdBlackList}),
							ets:insert(auth_config, {client_id_blacklist, ClientIdBlackList}),
							ets:insert(auth_config, {app_id_whitelist, AppIdWhiteList}),
							ets:insert(auth_config, {client_id_whitelist, ClientIdWhiteList}),
							ets:insert(auth_config, {last_timestamp, timestamp()}),
							?LOG(info, "[Auth http] auth config save to ets success!");
						_Result ->
							?LOG(error, "[Auth http] auth config result error:~s", [integer_to_list(_Result)])
					end;
				{ok, Code, Body} ->
					?LOG(error, "[Auth http] auth config error! code:~s body:~s", [integer_to_list(Code), Body]);
		        {error, Error} ->
					?LOG(error, "[Auth http] auth config error Url: ~p Error: ~p", [Url, Error])
			end;
		true ->
			?LOG(debug, "[Auth http] auth config in cache time:~p do not need update!", [CacheTime])
	end.

check_blacklist_auth(AppId, ClientId) ->
	AppIdBlackList= lookup_ets(auth_config, app_id_blacklist),
	ClientIdBlackList = lookup_ets(auth_config, client_id_blacklist),
	if
		AppIdBlackList == 0 ->
			{ok, false};
		ClientIdBlackList ==0 ->
			{ok, false};
		true ->
			{ok, check_auth_list(AppIdBlackList, ClientIdBlackList, AppId, ClientId)}
	end.

check_whitelist_auth(AppId, ClientId) ->
	AppIdWhiteList= lookup_ets(auth_config, app_id_whitelist),
	ClientIdWhiteList = lookup_ets(auth_config, client_id_whitelist),
	if
		AppIdWhiteList == 0 ->
			{ok, false};
		ClientIdWhiteList ==0 ->
			{ok, false};
		true ->
			{ok, check_auth_list(AppIdWhiteList, ClientIdWhiteList, AppId, ClientId)}
	end.

check_auth_list(AppIdConfigList, ClientIdConfigList, AppId, ClientId)->
	if 
		AppIdConfigList == undefined ->
			Success = false;
		true ->
			AppIdList = string:tokens(binary:bin_to_list(AppIdConfigList), ";"),
			Success = lists:member(AppId, AppIdList)
	end,
	if 
		Success == false ->
			if 
				ClientIdConfigList == undefined ->
					false;
				true ->
					ClientIdList = string:tokens(binary:bin_to_list(ClientIdConfigList), ";"),
					Success1 = lists:member(binary:bin_to_list(ClientId), ClientIdList),
					Success1
			end;
		true ->
			true
	end.

pre_process_by_config(#http_request{method = Method, url = Url, params = Params, cache_time = CacheTime}, 
					  _Credentials = #{username := Username, client_id := ClientId}, HttpOpts, RetryOpts) ->
	AppId = get_app_id(Username),
	%% update the local config
	check_local_config(CacheTime, Method, Url, list_to_binary(Params), HttpOpts, RetryOpts),
	%% check black list first
	{ok, BlackResult} = check_blacklist_auth(AppId, ClientId),
	if
		BlackResult == false ->
			%% check white list
			{ok, WhiteResult} = check_whitelist_auth(AppId, ClientId),
			{ok, BlackResult, WhiteResult};
		BlackResult == true ->
			{ok, BlackResult, false};
		true ->
			{ok, false, false}
	end.
			
-spec(is_superuser(undefined | #http_request{}, emqx_types:credetials(), list(), list()) -> boolean()).
is_superuser(undefined, _Credetials, _HttpOpts, _RetryOpts) ->
    false;
is_superuser(#http_request{method = Method, url = Url, params = Params, appids = AppIds}, Credetials= #{username := Username}, HttpOpts, RetryOpts) ->
 	AppId = get_app_id(Username),
	case AppIds of 
		undefined -> 
			false;
		_ ->
			lists:member(AppId, AppIds)
	end.
%% 	false.
%% 	if 
%% 		Enable =< 0 ->
%% 			false;
%% 		true ->
%% 			case request(Method, Url, feedvar(Params, Credetials), HttpOpts, RetryOpts) of
%% 		        {ok, 200, _Body}   -> 
%% 					true;
%% 		        {ok, _Code, _Body} ->
%% 					false;
%% 		        {error, Error}     -> ?LOG(error, "[Auth HTTP] is_superuser ~s Error: ~p", [Url, Error]),
%% 		                              false
%% 		    end
%% 	end.

mountpoint(Body, Credetials) when is_list(Body) ->
    mountpoint(list_to_binary(Body), Credetials);

mountpoint(Body, #{mountpoint := Mountpoint}) ->
    case emqx_json:safe_decode(Body, [return_maps]) of
        {error, _} -> Mountpoint;
        {ok, Json} when is_map(Json) ->
            maps:get(<<"mountpoint">>, Json, Mountpoint);
        {ok, _NotMap} ->
            Mountpoint
    end.

