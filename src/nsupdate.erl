-module(nsupdate).
-export([main/1]).

main([]) ->
    result(try nsupdate_cmd:do()
	   catch error:function_clause -> {error, invalid_input} end);
main(["-k", KeyFile]) ->
    {ok, B} = file:read_file(KeyFile),
    result(try nsupdate_cmd:do(nsupdate_cmd:parse_key(B))
	   catch error:function_clause -> {error, invalid_input} end).


result(ok) -> ok;
result({error, _} = E) ->
    io:format("~n~n!!! ~p !!!~n~n",[E]),
    halt(1).
