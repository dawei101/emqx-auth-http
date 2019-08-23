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
    case authenticate(AuthReq,ConfigReq, Credentials, HttpOpts, RetryOpts) of
        {ok, 200, "ignore"} ->
            emqx_metrics:inc('auth.http.ignore'), ok;
        {ok, 200, Body}  ->
            emqx_metrics:inc('auth.http.success'),
            {stop, Credentials#{is_superuser => is_superuser(SuperReq, Credentials, HttpOpts, RetryOpts),
                                auth_result => success,
                                anonymous => false,
                                mountpoint  => mountpoint(Body, Credentials)}};
		{ok, 403, _Msg} ->
            emqx_metrics:inc('auth.http.failure'),
			?LOG(error, "block by blacklist Credentials: ~p", [Credentials]),
            {stop, Credentials#{auth_result => 403, anonymous => false}};
        {ok, Code, _Body} ->
            emqx_metrics:inc('auth.http.failure'),
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
	Blocked = block_by_blacklist(ConfigReq,Credentials,HttpOpts,RetryOpts),
%% 	?LOG(error, "[Auth blacklist] blocked:~s", [Blocked]),
	case Blocked of
		true ->
			{ok, 403, "blocked by black list"};
		_ -> request(Method, Url, feedvar(Params, Credentials), HttpOpts, RetryOpts)
	end.

get_app_id(Username)->
	if is_binary(Username) ->
		    UsernameStr = binary:bin_to_list(Username);
	   is_list(Username) ->
			UsernameStr = Username;
	   true -> 
		    UsernameStr = ""
	end,
	Position = string:chr(UsernameStr,$@),
	case Position of
		0->	
			?LOG(error, "[Auth blacklist] username:~s invalid", [Username]),
			"";
		_->
			lists:nth(2,string:tokens(UsernameStr,"@"))
	end.

timestamp() ->
    {M, S, _} = os:timestamp(),
    M * 1000000 + S.

lookup_ets(Key)->
	case ets:lookup(blacklist,Key) of
		[] -> 0;
		Result -> proplists:get_value(Key,Result)
	end.

check_blacklist_auth_by_ets(AppId,ClientId,CacheTime)->
	TimesGap = timestamp()-lookup_ets(last_timestamp),
%% 	?LOG(error, "time gap:~s cacheTime:~s",[TimesGap,CacheTime]),
	if 
		TimesGap > CacheTime ->
			{false,false};
		true ->
			AppIdBlackList= lookup_ets(app_id_blacklist),
			ClientIdBlackList = lookup_ets(client_id_blacklist),
			if 
				AppIdBlackList == 0 -> {false,false};
				ClientIdBlackList ==0 -> {false,false};
				true ->
					{ok,check_blacklist_auth(AppIdBlackList,ClientIdBlackList,AppId,ClientId)}
			end
	end.

check_blacklist_auth_by_net(AppId,ClientId,Method,Url,Params,HttpOpts,RetryOpts)->
	case request(Method, Url, Params, HttpOpts, RetryOpts) of
		{ok, 200, Body}  ->
			?LOG(debug, "blacklist respnose ok ~s",[Body]),
			Result = jsx:decode(list_to_binary(Body)),
			DataResult = proplists:get_value(<<"data">>, Result),
			ConfigResult = proplists:get_value(<<"config">>, DataResult),
			AppIdBlackList = proplists:get_value(<<"app_id_blacklist">>,ConfigResult),
			ClientIdBlackList = proplists:get_value(<<"client_id_blacklist">>,ConfigResult),
			ets:insert(blacklist,{app_id_blacklist,AppIdBlackList}),
			ets:insert(blacklist,{client_id_blacklist,ClientIdBlackList}),
			ets:insert(blacklist,{last_timestamp,timestamp()}),
			check_blacklist_auth(AppIdBlackList,ClientIdBlackList,AppId,ClientId);
		{ok, _Code, _Body} ->
            false;
        {error, _Error} ->
            false
	end.

check_blacklist_auth(AppIdBlackList,ClientIdBlackList,AppId,ClientId)->
	if 
		AppIdBlackList == undefined ->
			Blocked = false;
%% 			?LOG(error, "appId black list is null");
		true ->
%% 			?LOG(error, "appId black list is not null:~s",[AppIdBlackList]),
			AppIdList = string:tokens(binary:bin_to_list(AppIdBlackList), ";"),
%% 			?LOG(error, "appId black list:~p",[AppIdList]),
			Blocked = lists:member(AppId,AppIdList)
	end,
%% 	?LOG(error, "appId block result:~s",[Blocked]),
	if 
		Blocked == false ->
			if 
				ClientIdBlackList == undefined ->
%% 					?LOG(error, "clientId black list is null");
					false;
				true ->
%% 					?LOG(error, "clientId black list is not null:~s",[ClientIdBlackList]),
					ClientIdList = string:tokens(binary:bin_to_list(ClientIdBlackList), ";"),
%% 					?LOG(error, "clientId black list:~p",[ClientIdList]),
					Blocked1 = lists:member(binary:bin_to_list(ClientId),ClientIdList),
%% 					?LOG(error, "clientId block result:~s",[Blocked1]),
					Blocked1
			end;
		true ->
			true
	end.

block_by_blacklist(#http_request{method = Method, url = Url, params = Params,cache_time=CacheTime},
				   _Credentials = #{ username := Username, client_id := ClientId}, HttpOpts, RetryOpts) ->
	AppId = get_app_id(Username),
%% 	?LOG(error,"appId ~s clientId ~s",[AppId,ClientId]),
	case check_blacklist_auth_by_ets(AppId,ClientId,CacheTime) of
		{false , _} ->
			check_blacklist_auth_by_net(AppId,ClientId,Method,Url,Params,HttpOpts,RetryOpts);
		{ok, Result} -> Result
	end.
			
															
														

-spec(is_superuser(undefined | #http_request{}, emqx_types:credetials(), list(), list()) -> boolean()).
is_superuser(undefined, _Credetials, _HttpOpts, _RetryOpts) ->
    false;
is_superuser(#http_request{method = Method, url = Url, params = Params, enable = Enable}, Credetials, HttpOpts, RetryOpts) ->
	if 
		Enable =< 0 ->
			false;
		true ->
			case request(Method, Url, feedvar(Params, Credetials), HttpOpts, RetryOpts) of
		        {ok, 200, _Body}   -> 
					true;
		        {ok, _Code, _Body} ->
					false;
		        {error, Error}     -> ?LOG(error, "[Auth HTTP] is_superuser ~s Error: ~p", [Url, Error]),
		                              false
		    end
	end.

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

