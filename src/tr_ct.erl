-module(tr_ct).

-export([ with_trace/3 ]).

-export([ trace_checkpoint/2
        , set_activation_checkpoint/2 ]).

-define(SPEC, tr_ct_spec).
-define(TR_ACTIVATE_AT, tr_activate_at).
-define(TR_START, start).

with_trace(Fun, Config0, Spec) ->
    ct:log("with_trace (Spec = ~p)...", [Spec]),
    Config = [{?SPEC, Spec} | Config0],
    trace_checkpoint(?TR_START, Config),
    Res = try Fun(Config)
          catch Error:R:Stack ->
                    case Error of
                        error ->
                            ct:pal("Error ~p~nStack = ~p", [R, Stack]),
                            ttb_stop(),
                            error(R);
                        exit ->
                            ct:pal("Exit ~p~nStack = ~p", [R, Stack]),
                            ttb_stop(),
                            exit(R);
                        throw ->
                            ct:pal("Caught throw:~p", [R]),
                            throw(R)
                    end
          end,
    ct:log("Res = ~p", [Res]),
    case get_spec(collect, Config, on_error) of
        on_error ->
            ct:log("Discarding trace", []),
            tr_ttb:stop_nofetch();
        always ->
            ttb_stop()
    end,
    Res.

set_activation_checkpoint(Checkpoint, Config) ->
    [{tr_activate_at, Checkpoint} | Config].

trace_checkpoint(Checkpoint, Config) ->
    case trace_is_active(Config) of
        true ->
            case proplists:get_value(?TR_ACTIVATE_AT, Config, ?TR_START) of
                Checkpoint ->
                    Dest = get_destination(Config),
                    Spec0 = get_spec(Config),
                    Spec = Spec0#{info => #{checkpoint => Checkpoint}},
                    TTBRes = tr_ttb:on_nodes(get_nodes(Config), Dest, Spec),
                    ct:log("Trace set up at checkpoint ~p: ~p",
                           [Checkpoint, TTBRes]);
                _ ->
                    ok
            end;
        false ->
            ok
    end.

trace_is_active(Config) ->
    lists:keymember(?SPEC, 1, Config).

ttb_stop() ->
    Dir = tr_ttb:stop(),
    Out = filename:join(filename:dirname(Dir), filename:basename(Dir) ++ ".txt"),
    case tr_ttb:format(Dir, Out, #{limit => 10000}) of
        {error, Reason} ->
            ct:pal("TTB formatting error: ~p", [Reason]);
        _ ->
            ok
    end,
    ct:pal("Formatted trace log in ~s~n", [Out]).

get_destination(Config) ->
    case get_spec(destination, Config) of
        undefined ->
            LogBase = log_base_name(Config),
            fstring("~s.tr_ct", [LogBase]);
        D ->
            D
    end.

get_nodes(Config) ->
    get_spec(nodes, Config, [node()]).

get_spec(Key, Config) ->
    get_spec(Key, Config, undefined).

get_spec(Key, Config, Default) ->
    tr_ttb:cfg(get_spec(Config), Key, Default).

get_spec(Config) ->
    case proplists:get_value(?SPEC, Config) of
        undefined ->
            #{};
        Map when is_map(Map) ->
            Map
    end.

log_base_name(Config) ->
    {_, LF} = lists:keyfind(tc_logfile, 1, Config),
    [Base, []] = re:split(LF, <<"\\.html">>, [{return, list}]),
    Base.

fstring(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).
