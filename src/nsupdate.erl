-module(nsupdate).
-export([main/1]).

main([]) ->
    nsupdate_cmd:do().
