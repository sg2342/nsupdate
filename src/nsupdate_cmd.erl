-module(nsupdate_cmd).

-export([do/1, do/0]).

line() -> line(">> ").

line(Prompt) ->
    L = string:trim(io:get_line(standard_io, Prompt), trailing, "\n"),
    Tokens = lists:map(fun erlang:list_to_binary/1, string:tokens(L, " ")),
    line1(Tokens, erlang:list_to_binary(L)).

line1([], _) -> send;
line1([<<"send">>], _) -> send;
line1([<<"update">> | T], L) -> line1(T,L);
line1([<<"add">>, Name, Ttl, Type| _], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, leading, " "),
    {add, Name, erlang:binary_to_integer(Ttl), <<"IN">>, Type, Data};
line1([<<"delete">>, Name], _) -> {delete, Name};
line1([<<"delete">>, Name, Type], _) -> {delete, Name, <<"ANY">>, Type};
line1([<<"delete">>, Name, Type |_], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, leading, " "),
    {delete, Name, <<"IN">>, Type, Data};
line1([<<"key">>, Name, Secret], _) -> {key, Name, Secret};
line1([<<"local">>, Addr, Port], _) ->
    {ok, A} = inet_parse:strict_address(erlang:binary_to_list(Addr)),
    {local, A, erlang:binary_to_integer(Port)};
line1([<<"local">>, Addr], _) ->
    {ok, A} = inet_parse:strict_address(erlang:binary_to_list(Addr)),
    {local, A, 0};
line1([<<"zone">>, Zone], _) -> {zone, Zone};
line1([<<"server">>, Host], _) -> {server, erlang:binary_to_list(Host)};
line1([<<"server">>, Host, Port], _) ->
    {server, {erlang:binary_to_list(Host), erlang:binary_to_integer(Port)}}.


do(Key) ->
    do(line(), #{ key => Key
		, timeout => timer:seconds(300)
		, protocol => tcp
		, local => {any, 0}
		, updates => [] }).

do() ->
    do(line(), #{ timeout => timer:seconds(300)
		, protocol => tcp
		, local => {any, 0}
		, updates => [] }).


do(send, #{ key := Key, updates := Updates, zone := Zone, server := Server}) ->
    nsupdate_impl:query(Server, Key, Zone, lists:reverse(Updates));
do(send, _) -> {error, missing_input};
do({zone, Zone}, #{ } = D) -> do(line(), D#{ zone => Zone });
do({server, Server}, #{ } = D) -> do(line(), D#{ server => Server});
do({local, Addr, Port}, #{ } = D) -> do(line(), D#{ local => {Addr, Port}});
do({key, Name, Secret}, #{ } = D) ->
    K = base64:decode(Secret),
    Alg = case size(K) of
	      64 -> <<"hmac-sha512">>;
	      48 -> <<"hmac-sha384">>;
	      32 -> <<"hmac-sha256">>;
	      28 -> <<"hmac-sha225">>;
	      20 -> <<"hmac-sha1">>;
	      16 -> <<"hmac-md5.sig-alg.reg.int">> end,
    do(line(), D#{ key => {Name, Alg, K}});
do(U, #{ updates := Updates } = D) ->
    do(line(), D#{ updates => [U|Updates]}).

