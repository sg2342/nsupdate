-module(nsupdate).
-export([main/1]).

main([]) ->
    result(try nsupdate_cmd:do(standard_io)
	   catch error:function_clause -> {error, invalid_input} end);
main(["-k", KeyFile]) ->
    {ok, B} = file:read_file(KeyFile),
    result(try nsupdate_cmd:do(standard_io, nsupdate_cmd:parse_key(B))
	   catch error:function_clause -> {error, invalid_input} end);
main([FileName]) ->
    {ok, Fd} = file:open(FileName, [read]),
    result(try nsupdate_cmd:do(Fd)
	   catch error:function_clause -> {error, invalid_input} end);
main(["-k", KeyFile, FileName]) ->
    {ok, B} = file:read_file(KeyFile),
    {ok, Fd} = file:open(FileName, [read]),
    result(try nsupdate_cmd:do(Fd, nsupdate_cmd:parse_key(B))
	   catch error:function_clause -> {error, invalid_input} end);
main(_) ->
    Sn = filename:basename(escript:script_name()),
    io:format("usage: ~s [ -k keyfile] [filename]~n~n",[Sn]),
    halt(1).

result(ok) -> ok;
result({error, _} = E) ->
    io:format("~n~n!!! ~p !!!~n~n",[E]),
    halt(1).
