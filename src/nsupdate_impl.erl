-module(nsupdate_impl).

-export([query/1, query/4]).

-include_lib("dns_erlang/include/dns.hrl").

query(Server, Key, Zone, Updates) ->
    query(#{
        zone => Zone,
        key => Key,
        updates => Updates,
        server => Server,
        timeout => timer:seconds(300),
        protocol => tcp,
        local => {any, 0}
    }).

query(#{
    key := {KeyName, Alg, Secret},
    zone := Zone,
    updates := Updates,
    server := {ServerName, Port},
    local := Local,
    timeout := Timeout,
    protocol := Proto
}) ->
    Msg0 = update_msg(Zone, Updates),
    Msg = dns:add_tsig(Msg0, Alg, KeyName, Secret, 0),
    Packet = dns:encode_message(Msg),
    query1({Proto, ServerName, Port}, Timeout, Local, Packet).

query1({udp, Host, Port}, Timeout, {LocalAddr, LocalPort}, Packet) ->
    {ok, Socket} = gen_udp:open(
        LocalPort,
        [binary, {active, false}, {ip, LocalAddr}]
    ),
    MaybeOk = gen_udp:send(Socket, Host, Port, Packet),
    R = query2(MaybeOk, gen_udp, Socket, Host, Timeout),
    gen_udp:close(Socket),
    R;
query1({tcp, Host, Port}, Timeout, {LocalAddr, LocalPort}, Packet) ->
    {ok, Socket} = gen_tcp:connect(
        Host,
        Port,
        [
            binary,
            {active, false},
            {packet, 2},
            {ip, LocalAddr},
            {port, LocalPort}
        ]
    ),
    MaybeOk = gen_tcp:send(Socket, Packet),
    R = query2(MaybeOk, gen_tcp, Socket, Host, Timeout),
    gen_tcp:close(Socket),
    R.

query2(ok, gen_udp, Socket, Host, Timeout) ->
    case gen_udp:recv(Socket, 65535, Timeout) of
        {ok, {Host, _Port, M}} -> qresult(dns:decode_message(M));
        Res -> Res
    end;
query2(ok, gen_tcp, Socket, _Host, Timeout) ->
    case gen_tcp:recv(Socket, 0, Timeout) of
        {ok, M} -> qresult(dns:decode_message(M));
        Res -> Res
    end;
query2(Error, _Mod, _Socket, _Host, _Timeout) ->
    Error.

qresult(#dns_message{rc = ?DNS_RCODE_NOERROR}) -> ok;
qresult(#dns_message{rc = Rc}) -> {error, dns:rcode_name(Rc)};
qresult(R) -> {error, R}.

update_msg(Zone, Updates) ->
    Authority = lists:map(fun update_msg1/1, Updates),
    AUC = length(Authority),
    #dns_message{
        qr = false,
        oc = ?DNS_OPCODE_UPDATE,
        aa = false,
        tc = false,
        rd = false,
        ra = false,
        ad = false,
        cd = false,
        rc = 0,
        qc = 1,
        anc = 0,
        auc = AUC,
        questions =
            [
                #dns_query{
                    name = Zone,
                    class = ?DNS_CLASS_IN,
                    type = ?DNS_TYPE_SOA
                }
            ],
        answers = [],
        authority = Authority
    }.

update_msg1({delete, Name, Class, Type, Data}) ->
    T = nsupdate_bstr:type(Type),
    #dns_rr{
        name = Name,
        class = nsupdate_bstr:class(Class),
        ttl = 0,
        type = T,
        data = update_msg2(T, Data)
    };
update_msg1({delete, Name, _Class, Type}) ->
    T = nsupdate_bstr:type(Type),
    #dns_rr{
        name = Name,
        class = nsupdate_bstr:class(<<"ANY">>),
        ttl = 0,
        type = T,
        data = <<>>
    };
update_msg1({delete, Name, _Class}) ->
    #dns_rr{
        name = Name,
        class = nsupdate_bstr:class(<<"ANY">>),
        ttl = 0,
        type = ?DNS_TYPE_ANY,
        data = <<>>
    };
update_msg1({add, Name, Ttl, Class, Type, Data}) ->
    T = nsupdate_bstr:type(Type),
    #dns_rr{
        name = Name,
        class = nsupdate_bstr:class(Class),
        ttl = Ttl,
        type = T,
        data = update_msg2(T, Data)
    }.

update_msg2(?DNS_TYPE_MX, Data) ->
    [PreferenceB, Exchange] = binary:split(Data, <<" ">>, [trim_all, global]),
    Preference = erlang:binary_to_integer(PreferenceB),
    #dns_rrdata_mx{preference = Preference, exchange = Exchange};
update_msg2(?DNS_TYPE_A, {_, _, _, _} = A) ->
    #dns_rrdata_a{ip = A};
update_msg2(?DNS_TYPE_A, B) ->
    {ok, {_, _, _, _} = A} =
        inet_parse:strict_address(
            string:trim(erlang:binary_to_list(B), both, " ")
        ),
    #dns_rrdata_a{ip = A};
update_msg2(?DNS_TYPE_AAAA, {_, _, _, _, _, _, _, _} = AAAA) ->
    #dns_rrdata_aaaa{ip = AAAA};
update_msg2(?DNS_TYPE_AAAA, B) ->
    {ok, {_, _, _, _, _, _, _, _} = AAAA} =
        inet_parse:strict_address(
            string:trim(erlang:binary_to_list(B), both, " ")
        ),
    #dns_rrdata_aaaa{ip = AAAA};
update_msg2(?DNS_TYPE_CNAME, Dname) ->
    #dns_rrdata_cname{dname = string:trim(Dname, both, " ")};
update_msg2(?DNS_TYPE_TXT, Txt) ->
    #dns_rrdata_txt{txt = string_list(Txt)}.

string_list(Bin) ->
    {ok, R} = re:compile("(\".*?\"|[^\" \\s]+)(?=\\s* |\\s*$)"),
    {match, Matches} = re:run(Bin, R, [{capture, [1], list}, global]),
    [string:trim(M, both, "\"") || [M] <- Matches].
