-module(nsupdate).
-compile(export_all).

-include_lib("dns_erlang/include/dns.hrl").

line() -> line(">> ").

line(Prompt) ->
    L = string:trim(io:get_line(standard_io, Prompt), trailing, "\n"),
    Tokens = lists:map(fun erlang:list_to_binary/1, string:tokens(L, " ")),
    line1(Tokens, erlang:list_to_binary(L)).

line1([], _) -> send;
line1([<<"send">>], _) -> send;
line1([<<"update">>, <<"add">>, Name, Ttl, Type| _], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, leading, " "),
    {add, Name, erlang:binary_to_integer(Ttl), Type, Data};
line1([<<"update">>, <<"delete">>, Name], _) -> {delete, Name};
line1([<<"update">>, <<"delete">>, Name, Type], _) -> {delete, Name, Type};
line1([<<"update">>, <<"delete">>, Name, Type |_], L) ->
    [_, Data0] = string:split(L, Type, leading),
    Data = string:trim(Data0, leading, " "),
    {delete, Name, Type, Data};
line1([<<"zone">>, Zone], _) -> {zone, Zone};
line1([<<"server">>, Host], _) -> {server, erlang:binary_to_list(Host)};
line1([<<"server">>, Host, Port], _) ->
    {server, {erlang:binary_to_list(Host), erlang:binary_to_integer(Port)}}.


do(Key) -> do(line(), #{ key => Key, updates => [] }).

do(send, #{ key := Key, updates := Updates, zone := Zone, server := Server}) ->
    do(Server, Key, Zone, lists:reverse(Updates));
do(send, _) -> {error, missing_input};
do({zone, Zone}, #{ } = D) -> do(line(), D#{ zone => Zone });
do({server, Server}, #{ } = D) -> do(line(), D#{ server => Server});
do(U, #{ updates := Updates } = D) ->
    do(line(), D#{ updates => [U|Updates]}).



do(ProtoHostPort, {KeyName, Alg, Secret}, Zone, Updates) ->
    Msg0 = update_msg(Zone, Updates),
    Msg = dns:add_tsig(Msg0, Alg, KeyName, Secret, 0),
    self() ! Msg,
    Packet = dns:encode_message(Msg),
    query(ProtoHostPort, Packet).

query(ProtoHostPort, Packet) -> query2(query1(ProtoHostPort), Packet).

query1({tcp, Host}) -> {tcp, Host, 53};
query1({udp, Host}) -> {udp, Host, 53};
query1({Host, Port}) -> {tcp, Host, Port};
query1(Host)  when is_list(Host) -> {tcp, Host, 53};
query1({_,_,_,_} = Host) ->  {tcp, Host, 53};
query1({_,_,_,_,_,_,_,_} = Host) ->  {tcp, Host, 53};
query1({udp, Host, Port}) -> {upd, Host, Port};
query1({tcp, Host, Port}) -> {tcp, Host, Port}.


query2({udp, Host, Port}, Packet) ->
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    gen_udp:send(Socket, Host, Port, Packet),
    R = case gen_udp:recv(Socket, 65535, 12000) of
	    {ok, {Host, _Port, Reply}} -> query3(dns:decode_message(Reply));
	    Response -> Response end,
    gen_udp:close(Socket),
    R;
query2({tcp, Host, Port}, Packet) ->
    {ok, Socket} = gen_tcp:connect(Host, Port,
				   [binary, {active, false}, {packet,2}]),
    gen_tcp:send(Socket, Packet),
    R = case gen_tcp:recv(Socket, 0, 12000) of
	    {ok, Reply} -> query3(dns:decode_message(Reply));
	    Response -> Response end,
    gen_tcp:close(Socket),
    R.

query3(#dns_message{ rc = ?DNS_RCODE_NOERROR}) -> ok;
query3(#dns_message{ rc = Rc}) -> {error, dns:rcode_name(Rc)};
query3(R) -> {error, R}.

update_msg(Zone, Updates) ->
    Authority = lists:map(fun update_msg1/1, Updates),
    AUC = length(Authority),
    #dns_message{ qr = false
		, oc = ?DNS_OPCODE_UPDATE
		, aa = false
		, tc = false
		, rd = false
		, ra = false
		, ad = false
		, cd = false
		, rc = 0
		, qc = 1
		, anc = 0
		, auc = AUC
		, questions =
		      [#dns_query{ name = Zone
				 , class = ?DNS_CLASS_IN
				 , type = ?DNS_TYPE_SOA }]
		, answers = []
		, authority = Authority }.

update_msg1({delete, Name, Type, Data}) ->
    T = bstr_to_type(Type),
    #dns_rr{ name = Name
	   , class = ?DNS_CLASS_ANY
	   , ttl = 0
	   , type = T
	   , data = update_msg2(T, Data)};
update_msg1({delete, Name, Type}) ->
    T = bstr_to_type(Type),
    #dns_rr{ name = Name
	   , class = ?DNS_CLASS_ANY
	   , ttl = 0
	   , type = T
	   , data = <<>>};
update_msg1({delete, Name}) ->
    #dns_rr{ name = Name
	   , class = ?DNS_CLASS_ANY
	   , ttl = 0
	   , type = ?DNS_TYPE_ANY
	   , data = <<>>};
update_msg1({add, Name, Ttl, Type, Data}) ->
    T = bstr_to_type(Type),
    #dns_rr{ name = Name
	   , class = ?DNS_CLASS_IN
	   , ttl = Ttl
	   , type = T
	   , data = update_msg2(T, Data)}.

update_msg2(?DNS_TYPE_A, {_,_,_,_} = A) -> #dns_rrdata_a{ip = A};
update_msg2(?DNS_TYPE_A, B) ->
    {ok, {_,_,_,_} = A} =
	inet_parse:strict_address(
	  string:trim(erlang:binary_to_list(B), both, " ")),
    #dns_rrdata_a{ip = A};
update_msg2(?DNS_TYPE_AAAA, {_,_,_,_,_,_,_,_} = A) ->
    #dns_rrdata_aaaa{ip = A};
update_msg2(?DNS_TYPE_AAAA, B) ->
    {ok, {_,_,_,_,_,_,_,_} = A} =
	inet_parse:strict_address(
	  string:trim(erlang:binary_to_list(B), both, " ")),
    #dns_rrdata_a{ip = A};
update_msg2(?DNS_TYPE_CNAME, Dname) ->
    #dns_rrdata_cname{dname = string:trim(Dname, both, " ")};
update_msg2(?DNS_TYPE_TXT, Txt) -> #dns_rrdata_txt{txt = Txt}.


bstr_to_type(B) ->
    case B of
	?DNS_TYPE_A_BSTR -> ?DNS_TYPE_A_NUMBER;
	?DNS_TYPE_NS_BSTR -> ?DNS_TYPE_NS_NUMBER;
	?DNS_TYPE_MD_BSTR -> ?DNS_TYPE_MD_NUMBER;
	?DNS_TYPE_MF_BSTR -> ?DNS_TYPE_MF_NUMBER;
	?DNS_TYPE_CNAME_BSTR -> ?DNS_TYPE_CNAME_NUMBER;
	?DNS_TYPE_SOA_BSTR -> ?DNS_TYPE_SOA_NUMBER;
	?DNS_TYPE_MB_BSTR -> ?DNS_TYPE_MB_NUMBER;
	?DNS_TYPE_MG_BSTR -> ?DNS_TYPE_MG_NUMBER;
	?DNS_TYPE_MR_BSTR -> ?DNS_TYPE_MR_NUMBER;
	?DNS_TYPE_NULL_BSTR -> ?DNS_TYPE_NULL_NUMBER;
	?DNS_TYPE_WKS_BSTR -> ?DNS_TYPE_WKS_NUMBER;
	?DNS_TYPE_PTR_BSTR -> ?DNS_TYPE_PTR_NUMBER;
	?DNS_TYPE_HINFO_BSTR -> ?DNS_TYPE_HINFO_NUMBER;
	?DNS_TYPE_MINFO_BSTR -> ?DNS_TYPE_MINFO_NUMBER;
	?DNS_TYPE_MX_BSTR -> ?DNS_TYPE_MX_NUMBER;
	?DNS_TYPE_TXT_BSTR -> ?DNS_TYPE_TXT_NUMBER;
	?DNS_TYPE_RP_BSTR -> ?DNS_TYPE_RP_NUMBER;
	?DNS_TYPE_AFSDB_BSTR -> ?DNS_TYPE_AFSDB_NUMBER;
	?DNS_TYPE_X25_BSTR -> ?DNS_TYPE_X25_NUMBER;
	?DNS_TYPE_ISDN_BSTR -> ?DNS_TYPE_ISDN_NUMBER;
	?DNS_TYPE_RT_BSTR -> ?DNS_TYPE_RT_NUMBER;
	?DNS_TYPE_NSAP_BSTR -> ?DNS_TYPE_NSAP_NUMBER;
	?DNS_TYPE_SIG_BSTR -> ?DNS_TYPE_SIG_NUMBER;
	?DNS_TYPE_KEY_BSTR -> ?DNS_TYPE_KEY_NUMBER;
	?DNS_TYPE_PX_BSTR -> ?DNS_TYPE_PX_NUMBER;
	?DNS_TYPE_GPOS_BSTR -> ?DNS_TYPE_GPOS_NUMBER;
	?DNS_TYPE_AAAA_BSTR -> ?DNS_TYPE_AAAA_NUMBER;
	?DNS_TYPE_LOC_BSTR -> ?DNS_TYPE_LOC_NUMBER;
	?DNS_TYPE_NXT_BSTR -> ?DNS_TYPE_NXT_NUMBER;
	?DNS_TYPE_EID_BSTR -> ?DNS_TYPE_EID_NUMBER;
	?DNS_TYPE_NIMLOC_BSTR -> ?DNS_TYPE_NIMLOC_NUMBER;
	?DNS_TYPE_SRV_BSTR -> ?DNS_TYPE_SRV_NUMBER;
	?DNS_TYPE_ATMA_BSTR -> ?DNS_TYPE_ATMA_NUMBER;
	?DNS_TYPE_NAPTR_BSTR -> ?DNS_TYPE_NAPTR_NUMBER;
	?DNS_TYPE_KX_BSTR -> ?DNS_TYPE_KX_NUMBER;
	?DNS_TYPE_CERT_BSTR -> ?DNS_TYPE_CERT_NUMBER;
	?DNS_TYPE_DNAME_BSTR -> ?DNS_TYPE_DNAME_NUMBER;
	?DNS_TYPE_SINK_BSTR -> ?DNS_TYPE_SINK_NUMBER;
	?DNS_TYPE_OPT_BSTR -> ?DNS_TYPE_OPT_NUMBER;
	?DNS_TYPE_APL_BSTR -> ?DNS_TYPE_APL_NUMBER;
	?DNS_TYPE_DS_BSTR -> ?DNS_TYPE_DS_NUMBER;
	?DNS_TYPE_CDS_BSTR -> ?DNS_TYPE_CDS_NUMBER;
	?DNS_TYPE_SSHFP_BSTR -> ?DNS_TYPE_SSHFP_NUMBER;
        ?DNS_TYPE_CAA_BSTR -> ?DNS_TYPE_CAA_NUMBER;
	?DNS_TYPE_IPSECKEY_BSTR -> ?DNS_TYPE_IPSECKEY_NUMBER;
	?DNS_TYPE_RRSIG_BSTR -> ?DNS_TYPE_RRSIG_NUMBER;
	?DNS_TYPE_NSEC_BSTR -> ?DNS_TYPE_NSEC_NUMBER;
	?DNS_TYPE_DNSKEY_BSTR -> ?DNS_TYPE_DNSKEY_NUMBER;
	?DNS_TYPE_CDNSKEY_BSTR -> ?DNS_TYPE_CDNSKEY_NUMBER;
	?DNS_TYPE_NSEC3_BSTR -> ?DNS_TYPE_NSEC3_NUMBER;
	?DNS_TYPE_NSEC3PARAM_BSTR -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
	?DNS_TYPE_DHCID_BSTR -> ?DNS_TYPE_DHCID_NUMBER;
	?DNS_TYPE_HIP_BSTR -> ?DNS_TYPE_HIP_NUMBER;
	?DNS_TYPE_NINFO_BSTR -> ?DNS_TYPE_NINFO_NUMBER;
	?DNS_TYPE_RKEY_BSTR -> ?DNS_TYPE_RKEY_NUMBER;
	?DNS_TYPE_TALINK_BSTR -> ?DNS_TYPE_TALINK_NUMBER;
	?DNS_TYPE_SPF_BSTR -> ?DNS_TYPE_SPF_NUMBER;
	?DNS_TYPE_UINFO_BSTR -> ?DNS_TYPE_UINFO_NUMBER;
	?DNS_TYPE_UID_BSTR -> ?DNS_TYPE_UID_NUMBER;
	?DNS_TYPE_GID_BSTR -> ?DNS_TYPE_GID_NUMBER;
	?DNS_TYPE_UNSPEC_BSTR -> ?DNS_TYPE_UNSPEC_NUMBER;
	?DNS_TYPE_TKEY_BSTR -> ?DNS_TYPE_TKEY_NUMBER;
	?DNS_TYPE_TSIG_BSTR -> ?DNS_TYPE_TSIG_NUMBER;
	?DNS_TYPE_IXFR_BSTR -> ?DNS_TYPE_IXFR_NUMBER;
	?DNS_TYPE_AXFR_BSTR -> ?DNS_TYPE_AXFR_NUMBER;
	?DNS_TYPE_MAILB_BSTR -> ?DNS_TYPE_MAILB_NUMBER;
	?DNS_TYPE_MAILA_BSTR -> ?DNS_TYPE_MAILA_NUMBER;
	?DNS_TYPE_ANY_BSTR -> ?DNS_TYPE_ANY_NUMBER;
	?DNS_TYPE_DLV_BSTR -> ?DNS_TYPE_DLV_NUMBER;
	_ -> undefined
    end.
