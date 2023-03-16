-module(nsupdate_cmd).

-export([do/1, do/2]).
-export([parse_key/1]).

line(standard_io) -> line(standard_io, ">> ");
line(Fd) -> line(Fd, "").

line(Fd, Prompt) ->
    L = string:trim(io:get_line(Fd, Prompt), trailing, "\n"),
    Tokens = lists:map(fun erlang:list_to_binary/1, string:tokens(L, " ")),
    line1(Tokens, erlang:list_to_binary(L)).

line1([], _) ->
    send;
line1([<<"send">>], _) ->
    send;
line1([<<"update">> | T], L) ->
    line1(T, L);
line1([<<"add">>, Name, Ttl, <<"IN">>, Type | T], L) ->
    line1([<<"add">>, Name, Ttl, Type | T], L);
line1([<<"add">>, Name, Ttl, Type | _], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, leading, " "),
    {add, Name, erlang:binary_to_integer(Ttl), <<"IN">>, Type, Data};
line1([<<"delete">> | T], L) ->
    line1([<<"del">> | T], L);
line1([<<"del">>, Name, <<X:8/integer, _/binary>> | T], L) when
    X >= $0, X =< $9
->
    line1([<<"del">>, Name | T], L);
line1([<<"del">>, Name, <<"IN">> | T], L) ->
    line1([<<"del">>, Name | T], L);
line1([<<"del">>, Name], _) ->
    {delete, Name, <<"IN">>};
line1([<<"del">>, Name, Type], _) ->
    {delete, Name, <<"IN">>, Type};
line1([<<"del">>, Name, Type | _], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, both, " "),
    {delete, Name, <<"IN">>, Type, Data};
line1([<<"key">>, Name, Secret], _) ->
    {key, Name, Secret};
line1([<<"local">>, Addr, Port], _) ->
    {ok, A} = inet_parse:strict_address(erlang:binary_to_list(Addr)),
    {local, A, erlang:binary_to_integer(Port)};
line1([<<"local">>, Addr], _) ->
    {ok, A} = inet_parse:strict_address(erlang:binary_to_list(Addr)),
    {local, A, 0};
line1([<<"zone">>, Zone], _) ->
    {zone, Zone};
line1([<<"server">>, Host], _) ->
    {server, erlang:binary_to_list(Host)};
line1([<<"server">>, Host, Port], _) ->
    {server, {erlang:binary_to_list(Host), erlang:binary_to_integer(Port)}}.

parse_key(Bin) when is_binary(Bin) ->
    [Name | L] = string:split(string:trim(Bin), <<" ">>, all),
    [Secret | _] = lists:reverse(L),
    {Alg, K} = parse_key1(Secret),
    {Name, Alg, K}.

parse_key1(Secret) ->
    K = base64:decode(Secret),
    Alg =
        case size(K) of
            64 -> <<"hmac-sha512">>;
            48 -> <<"hmac-sha384">>;
            32 -> <<"hmac-sha256">>;
            28 -> <<"hmac-sha225">>;
            20 -> <<"hmac-sha1">>;
            16 -> <<"hmac-md5.sig-alg.reg.int">>
        end,
    {Alg, K}.

do(Fd, Key) ->
    do1(line(Fd), #{
        key => Key,
        timeout => timer:seconds(300),
        protocol => tcp,
        fd => Fd,
        local => {any, 0},
        updates => []
    }).

do(Fd) ->
    do1(line(Fd), #{
        timeout => timer:seconds(300),
        protocol => tcp,
        fd => Fd,
        local => {any, 0},
        updates => []
    }).

do1(send, #{key := Key, updates := Updates, zone := Zone, server := Server}) ->
    nsupdate_impl:query(Server, Key, Zone, lists:reverse(Updates));
do1(send, _) ->
    {error, missing_input};
do1({zone, Zone}, #{fd := Fd} = D) ->
    do1(line(Fd), D#{zone => Zone});
do1({server, Server}, #{fd := Fd} = D) ->
    do1(line(Fd), D#{server => Server});
do1({local, Addr, Port}, #{fd := Fd} = D) ->
    do1(line(Fd), D#{local => {Addr, Port}});
do1({key, Name, Secret}, #{fd := Fd} = D) ->
    {Alg, K} = parse_key1(Secret),
    do1(line(Fd), D#{key => {Name, Alg, K}});
do1(U, #{updates := Updates, fd := Fd} = D) ->
    do1(line(Fd), D#{updates => [U | Updates]}).
