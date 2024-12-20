-module(nsupdate).
-export([main/1]).

main(Args) ->
    Cmd = #{
        arguments => [
            #{
                name => keyfile,
                short => $k,
                required => false,
                help => "keyfile"
            },
            #{
                name => filename,
                required => false,
                help => "filename"
            }
        ],
        handler => fun(A) -> result(handle(A)) end
    },
    argparse:run(Args, Cmd, #{progname => filename:basename(escript:script_name())}).

handle(#{keyfile := KeyFile, filename := FileName}) ->
    maybe
        {ok, B} ?= file:read_file(KeyFile),
        {ok, Fd} ?= file:open(FileName, [read]),
        try
            nsupdate_cmd:do(Fd, nsupdate_cmd:parse_key(B))
        catch
            error:function_clause -> {error, invalid_input}
        end
    end;
handle(#{keyfile := KeyFile}) ->
    maybe
        {ok, B} ?= file:read_file(KeyFile),
        try
            nsupdate_cmd:do(standard_io, nsupdate_cmd:parse_key(B))
        catch
            error:function_clause -> {error, invalid_input}
        end
    end;
handle(#{filename := FileName}) ->
    maybe
        {ok, Fd} ?= file:open(FileName, [read]),
        try
            nsupdate_cmd:do(Fd)
        catch
            error:function_clause ->
                {error, invalid_input}
        end
    end;
handle(_) ->
    try
        nsupdate_cmd:do(standard_io)
    catch
        error:function_clause ->
            {error, invalid_input}
    end.

result(ok) ->
    ok;
result({error, _} = E) ->
    io:format(standard_error, "~n~n!!! ~p !!!~n~n", [E]),
    halt(1).
