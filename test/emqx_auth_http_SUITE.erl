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

-module(emqx_auth_http_SUITE).

-compile(export_all).

-include_lib("emqx/include/emqx.hrl").

-include_lib("common_test/include/ct.hrl").

-include_lib("eunit/include/eunit.hrl").

-define(APP, emqx_auth_http).

-define(USER(ClientId, Username, Sockname, Peername, Zone),
        #{client_id => ClientId, username => Username, sockname => Sockname, peername => Peername, zone => Zone}).

-define(USER(ClientId, Username, Sockname, Peername, Zone, Mountpoint),
        #{client_id => ClientId, username => Username, sockname => Sockname, peername => Peername, zone => Zone, mountpoint => Mountpoint}).
all() ->
    [{group, http},
     {group, https}].

groups() ->
    [{http, [sequence],
      [ 
	   %%t_check_acl, 
	   t_check_auth
      , t_sub_pub
      , t_comment_config]},
     {https, [sequence],
      [ t_check_acl
      , t_check_auth
      , t_sub_pub]}
    ].

init_per_group(http, Config) ->
    http_auth_server:start_http(),
    emqx_ct_helpers:start_apps([emqx_auth_http], fun http_speical_configs/1),
    Config;
init_per_group(https, Config) ->
    http_auth_server:start_https(),
    emqx_ct_helpers:start_apps([emqx_auth_http], fun https_special_configs/1),
    Config.

end_per_group(http, _Config) ->
    http_auth_server:stop_http(),
    emqx_ct_helpers:stop_apps([emqx_auth_http, emqx]);
end_per_group(https, _Config) ->
    http_auth_server:stop_https(),
    emqx_ct_helpers:stop_apps([emqx_auth_http, emqx]).

http_speical_configs(App) ->
    set_special_configs(App, http).

https_special_configs(App) ->
    set_special_configs(App, https).

set_special_configs(emqx, _Grp) ->
    application:set_env(emqx, allow_anonymous, false),
	application:set_env(emqx, logger_level, debug),
    application:set_env(emqx, enable_acl_cache, false),
    LoadedPluginPath = filename:join(["test", "emqx_SUITE_data", "loaded_plugins"]),
    application:set_env(emqx, plugins_loaded_file,
                        emqx_ct_helpers:deps_path(emqx, LoadedPluginPath));

set_special_configs(emqx_auth_http, Grp) ->
    AuthReq = maps:from_list(application:get_env(emqx_auth_http, auth_req, [])),
    SuprReq = maps:from_list(application:get_env(emqx_auth_http, super_req, [])),
    AclReq  = maps:from_list(application:get_env(emqx_auth_http, acl_req, [])),
    {AuthReq1, SuprReq1, AclReq1} =
        case Grp of
            http ->
                {AuthReq#{method := get},
                 SuprReq#{method := get},
                 AclReq #{method := get}};
            https ->
                set_https_client_opts(),
                {AuthReq#{method := get, url := "https://127.0.0.1:8991/mqtt/auth"},
                 SuprReq#{method := get, url := "https://127.0.0.1:8991/mqtt/superuser"},
                 AclReq #{method := get, url := "https://127.0.0.1:8991/mqtt/acl"}}
        end,
    application:set_env(emqx_auth_http, auth_req, maps:to_list(AuthReq1)),
    application:set_env(emqx_auth_http, super_req, maps:to_list(SuprReq1)),
    application:set_env(emqx_auth_http, acl_req, maps:to_list(AclReq1));

set_special_configs(_App, _Grp) ->
    ok.

%% @private
set_https_client_opts() ->
    HttpOpts = maps:from_list(application:get_env(emqx_auth_http, http_opts, [])),
    HttpOpts1 = HttpOpts#{ssl => emqx_ct_helpers:client_ssl_twoway()},
    application:set_env(emqx_auth_http, http_opts, maps:to_list(HttpOpts1)).

%%------------------------------------------------------------------------------
%% Testcases
%%------------------------------------------------------------------------------

t_check_acl(_) ->
    SuperUser = ?USER(<<"superclient">>, <<"superclient1@superuser">>, {{127,0,0,1}, 1883}, {{127, 0, 0, 1}, 2982}, external),

    allow = emqx_access_control:check_acl(SuperUser, subscribe, <<"users/testuser/1">>),
%%     deny = emqx_access_control:check_acl(SuperUser, publish, <<"anytopic">>),

    User1 = ?USER(<<"client1">>, <<"client1@testuser">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, external),
    UnIpUser1 = ?USER(<<"client1">>, <<"testuser">>, {{127,0,0,1}, 1883}, {{192,168,0,4}, 2981}, external),
    UnClientIdUser1 = ?USER(<<"unkonwc">>, <<"testuser">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, external),
    UnnameUser1= ?USER(<<"client1">>, <<"unuser">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, external),
    allow = emqx_access_control:check_acl(User1, subscribe, <<"/{appId}/clients/client1/command">>),
%%     allow = emqx_access_control:check_acl(User1, publish, <<"users/testuser/1">>),
    deny = emqx_access_control:check_acl(UnIpUser1, subscribe, <<"users/testuser/1">>),
    deny = emqx_access_control:check_acl(UnClientIdUser1, subscribe, <<"users/testuser/1">>),
    deny  = emqx_access_control:check_acl(UnnameUser1, subscribe, <<"$SYS/testuser/1">>).

%%     User2 = ?USER(<<"client2">>, <<"xyz">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2982}, external),
%%     UserC = ?USER(<<"client2">>, <<"xyz">>, {{127,0,0,1}, 1883}, {{192,168,1,3}, 2983}, external),
%%     allow = emqx_access_control:check_acl(UserC, publish, <<"a/b/c">>),
%%     deny = emqx_access_control:check_acl(User2, publish, <<"a/b/c">>),
%%     deny  = emqx_access_control:check_acl(User2, subscribe, <<"$SYS/testuser/1">>).

t_check_auth(_) ->
    User1 = ?USER(<<"client1">>, <<"client1@testuser1">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, external, undefined),
    User2 = ?USER(<<"client2">>, <<"client2@testuser2">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2982}, exteneral, undefined),
    User3 = ?USER(<<"client3">>, undefined, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2983}, exteneral, undefined),
	
	User4 = ?USER(<<"client4">>, <<"client4@blackappId">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, exteneral, undefined),
	User5 = ?USER(<<"blackclientId">>, <<"blackclientId@test">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, exteneral, undefined),
	User6 = ?USER(<<"whiteclientid">>, <<"whiteclientid@test">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, exteneral, undefined),
	User7 = ?USER(<<"whiteclientid2">>, <<"whiteclientid2@whiteappid">>, {{127,0,0,1}, 1883}, {{127,0,0,1}, 2981}, exteneral, undefined),
    {ok, #{auth_result := success,
           anonymous := false,
           is_superuser := false}} = emqx_access_control:authenticate(User1#{password => <<"pass1">>}),

	{ok, #{auth_result := success,
           anonymous := false,
           is_superuser := false}} = emqx_access_control:authenticate(User6#{password => <<"pass1">>}),
	{ok, #{auth_result := success,
           anonymous := false,
           is_superuser := false}} = emqx_access_control:authenticate(User7#{password => <<"pass1">>}),
    {error, 404} = emqx_access_control:authenticate(User1#{password => <<"pass">>}),
    {error, 404} = emqx_access_control:authenticate(User1#{password => <<>>}),
	{ok, #{auth_result := success,
           anonymous := false,
           is_superuser := false}} = emqx_access_control:authenticate(User1#{password => <<"pass1">>}),
	{error, 404} = emqx_access_control:authenticate(User1#{password => <<>>}),
    {ok, #{is_superuser := false}} = emqx_access_control:authenticate(User2#{password => <<"pass2">>}),
    {error, 404} = emqx_access_control:authenticate(User2#{password => <<>>}),
    {error, 404} = emqx_access_control:authenticate(User2#{password => <<"errorpwd">>}),
    {error, 404} = emqx_access_control:authenticate(User3#{password => <<"pwd">>}),
	{error, 403} = emqx_access_control:authenticate(User4#{password => <<"errorpwd">>}),
	{error, 403} = emqx_access_control:authenticate(User5#{password => <<"errorpwd">>}),
	{error, 403} = emqx_access_control:authenticate(User5#{password => <<"errorpwd">>}),
	{error, 403} = emqx_access_control:authenticate(User5#{password => <<"errorpwd">>}).


t_sub_pub(_) ->
    ct:pal("start client"),
    {ok, T1} = emqx_client:start_link([{host, "localhost"},
                                       {client_id, <<"client1">>},
                                       {username, <<"client1@testuser1">>},
                                       {password, <<"pass1">>}]),
    {ok, _} = emqx_client:connect(T1),
    emqx_client:publish(T1, <<"topic">>, <<"body">>, [{qos, 0}, {retain, true}]),
    timer:sleep(1000),
    {ok, T2} = emqx_client:start_link([{host, "localhost"},
                                       {client_id, <<"client2">>},
                                       {username, <<"client2@testuser2">>},
                                       {password, <<"pass2">>}]),
    {ok, _} = emqx_client:connect(T2),
    emqx_client:subscribe(T2, <<"topic">>),
    receive
        {publish, _Topic, Payload} ->
            ?assertEqual(<<"body">>, Payload)
        after 1000 -> false end,
    emqx_client:disconnect(T1),
    emqx_client:disconnect(T2).

t_comment_config(_) ->
    AuthCount = length(emqx_hooks:lookup('client.authenticate')),
    AclCount = length(emqx_hooks:lookup('client.check_acl')),
    application:stop(?APP),
    [application:unset_env(?APP, Par) || Par <- [acl_req, auth_req]],
    application:start(?APP),
    ?assertEqual([], emqx_hooks:lookup('client.authenticate')),
    ?assertEqual(AuthCount - 1, length(emqx_hooks:lookup('client.authenticate'))),
    ?assertEqual(AclCount - 1, length(emqx_hooks:lookup('client.check_acl'))).

