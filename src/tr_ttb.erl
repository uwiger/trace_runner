%% -*- mode: erlang; indent-tabs-mode: nil; -*-
%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%
%% Copyright (C) 2016 Ulf Wiger. All rights reserved.
%%
%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
%%---- END COPYRIGHT ---------------------------------------------------------
-module(tr_ttb).

-export([ event/1 ]).

-export([ dbg_tracer/0
        , dbg_tracer/1
        , dbg_stop/0 ]).

-export([
         on_nodes/2,
         on_nodes/3,
         on_nodes/4,
         default_patterns/0,
         default_flags/0,
         stop/0,
         stop_nofetch/0,
         format/1,
         format/2,
         format/3,
         format_opts/0,
         format_opts/1,
         handler/4,
         pp/3,
         pp_term/2,           %% (Term, Module | F((T) -> {yes, T1} | no)) -> Term1
         pp_custom/3,         %% (Term, Tag, Fmt((X) -> X1)) -> Term1
         record_print_fun/1
        ]).

-export([ cfg/3 ]).

-export([ shell_records_tab/0 ]).

-export_type([ flag/0, flags/0,
               pattern/0, patterns/0,
               proc/0 ]).

-type trace_pat() :: any().
-type pattern() :: {module(), atom(), arity(), trace_pat()}.
-type patterns() :: [pattern()].

-type proc() :: pid() | port() | atom() | {global,any()}
              | all | processes | ports | existing | existing_processes
              | existing_ports | new | new_processes | new_ports.
-type procs() :: proc() | [proc()].

-type flag() :: clear | all
              | m | s | r | c | call | p | sos | sol | sofs | sofl
              | send | 'receive' | call | procs | ports | garbage_collection
              | running | set_on_spawn | set_on_first_spawn | set_on_link
              | set_on_first_link | timestamp | monotonic_timestamp
              | strict_monotonic_timestamp | arity | return_to | silent
              | running_procs | running_ports | exiting.
-type flags() :: flag() | [flag()].

-callback flags() -> {procs(), flags()}.
-callback patterns() -> [pattern()].

-define(EVENT(E, S), event(?LINE, E, S)).

%% This function is also traced. Can be used to insert markers in the trace
%% log.
event(E) ->
    event(?LINE, E, none).

event(_, _, _) ->
    ok.

dbg_tracer() ->
    dbg_tracer(#{}).

dbg_tracer(Opts) when is_map(Opts) ->
    St0 = init_state(maps:merge(#{ fd => group_leader()
                                 , print_header => false }, Opts)),
    dbg:tracer(process, {fun dhandler/2, St0}).

dbg_stop() ->
    await_traces(),
    dbg:stop().

shell_records_tab() ->
    case find_shell_process() of
        ShellPid when is_pid(ShellPid) ->
            case [T || T <- ets:all(),
                       ets:info(T, owner) == ShellPid
                           andalso ets:info(T, name) == shell_records] of
                [RecTab] ->
                    RecTab;
                [] ->
                    undefined
            end;
        _ ->
            undefined
    end.

find_shell_process() ->
    find_shell_process(group_leader()).

find_shell_process(GL) ->
    case lists:keyfind(shell, 1, pi(GL, dictionary)) of
        {_, Pid} ->
            Pid;
        false ->
            case pi(GL, group_leader) of
                GL  -> undefined;
                GL1 -> find_shell_process(GL1)
            end
    end.

pi(P, Key) when is_pid(P) ->
    {_, I} = process_info(P, Key),
    I.

await_traces() ->
    case dbg:get_tracer() of
        {ok, Tracer} ->
            await_tracer(process_info(Tracer, message_queue_len), Tracer);
        {error, _} ->
            ok
    end.

await_tracer({message_queue_len, L}, Tracer) when L > 3 ->
    timer:sleep(10),
    await_tracer(process_info(Tracer, message_queue_len), Tracer);
await_tracer(_, _) ->
    ok.


on_nodes(Ns, File) ->
    on_nodes(Ns, default_patterns(), default_flags(), [{file, File}]).

on_nodes(Ns, File, Spec) ->
    on_nodes(Ns,
                cfg(Spec, patterns, default_patterns()),
                cfg(Spec, flags, default_flags()),
                [ {file, File}
                , {tr_ttb_info, cfg(Spec, info, undefined)}]).

-spec on_nodes([node()], [pattern()], {procs(), flags()}, list()) ->
                      {ok,list()} | {error, any()}.
on_nodes(Ns, Patterns0, Flags, Opts0) ->
    Opts = lists:keydelete(tr_ttb_info, 1, Opts0),
    Patterns = expand_patterns(Patterns0),
    Res = ttb_start_trace(Ns, Patterns, Flags, Opts),
    ?EVENT(ttb_started, maybe_info(#{ nodes => Ns
                                    , patterns => Patterns
                                    , flags    => Flags }, Opts0)),
    Res.

maybe_info(Map, Opts) ->
    case lists:keyfind(tr_ttb_info, 1, Opts) of
        {_, Info} when Info =/= undefined ->
            Map#{info => Info};
        _ ->
            Map
    end.

ttb_start_trace(Ns, Patterns, Flags, Opts) ->
    Start = maps:get(start, Patterns, []),
    Res = ttb:start_trace(Ns, Start, Flags, Opts),
    maps:fold(
        fun(Op, Pats, _) when Op==tp; Op==tpl->
                [ttb:Op(M,F,A,MS) || {M,F,A,MS} <- Pats];
            (Op, Pats, _) when Op==ctp; Op==ctpl; Op==ctpg ->
                [ttb:Op(M,F,A) || {M,F,A} <- Pats];
            (tpe, Pats, _) ->
                [dbg:tpe(E, MS) || {E, MS} <- Pats];
            (ctpe, Pats, _) ->
                [dbg:ctpe(E) || E <- Pats]
        end, ok, maps:without([start], Patterns)),
    Res.

expand_patterns(Patterns) when is_map(Patterns) ->
    maps:merge(Patterns,
                maps:map(fun(_K, V) when is_list(V) ->
                            [expand_pat(P) || P <- V];
                            (_, V) -> V
                         end,
                         maps:with([start,tp,tpl], Patterns)));
expand_patterns(Patterns) when is_list(Patterns) ->
    #{start => [expand_pat(P) || P <- Patterns]}.

expand_pat(P) when is_tuple(P) ->
    Sz = tuple_size(P),
    case element(Sz, P) of
        x ->
            setelement(Sz, P, [{'_',[],[{exception_trace}]}]);
        _ ->
            P
    end;
expand_pat(P) ->
    P.

-spec default_patterns() -> [pattern()].
default_patterns() ->
    [{?MODULE     , event, 3, []}].

-spec default_flags() -> {procs(), flags()}.
default_flags() ->
    {all, call}.

stop() ->
    {stopped, Dir} = ttb:stop([return_fetch_dir]),
    Dir.

stop_nofetch() ->
    ttb:stop([nofetch]).

format(Dir) ->
    format(Dir, standard_io).

format(Dir, OutFile) ->
    format(Dir, OutFile, #{}).

format(Dir, OutFile, Opts) ->
    try ttb:format(Dir, format_opts(OutFile, Opts))
    catch
        error:exceeded_limit = Reason ->
            {error, Reason};
        error:Other:ST ->
            {error, {Other, ST}}
    end.

format_opts() ->
    format_opts(standard_io).

format_opts(Outfile) ->
    format_opts(Outfile, #{}).

format_opts(OutFile, Opts0) ->
    Opts = maps:merge(#{limit => 10000}, Opts0),
    [{out, OutFile}, {handler, {fun handler/4, init_state(Opts)}}].

init_state(Opts0) ->
    Opts = maps:merge(#{ ts    => 0
                       , diff  => 0
                       , limit => infinity
                       , sofar => 0
                       , opts  => Opts0 }, Opts0),
    case Opts of
        #{shell_records := true, shell_records_tab := _} ->
            Opts;
        #{shell_records := true} ->
            case shell_records_tab() of
                undefined ->
                    maps:without([shell_records, shell_records_tab], Opts);
                Tab ->
                    Opts#{shell_records_tab => Tab}
            end;
        _ ->
            Opts
    end.

%% Real-time handler (see dbg_tracer/1
dhandler(end_of_trace, St) ->
    St;
dhandler(Trace, #{fd := Fd} = St) ->
    handler(Fd, Trace, [], St).

handler(Fd, Trace, TI, #{delay := D} = Acc) ->
    timer:sleep(D),
    handler(Fd, Trace, TI, maps:remove(delay, Acc));
handler(_, _, _, #{limit_exceeded := true} = Acc) ->
    Acc;
handler(Fd, Trace, TI, Acc) ->
    try Res = handler_(Fd, Trace, TI, Acc),
         Res
    catch
        error:limit_exceeded ->
            Acc#{limit_exceeded => true};
        Caught:E:ST ->
            fwrite(user, "CAUGHT ~p:~p:~p~nTrace=~p", [Caught, E, ST, Trace]),
            Acc
    end.

handler_(Fd, Trace, _, #{ts := TSp, diff := Diff, sofar := Sofar} = Acc) ->
    TS = ts(Trace, TSp),
    L0 = case {TSp,Diff} of {0,0} ->
                 case maps:get(print_header, Acc, true) of
                     true ->
                         io:fwrite(Fd, "%% -*- erlang -*-~n", []),
                         io:put_chars(Fd, format_time(TS)),
                         2;
                     _ ->
                         0
                 end;
             _ -> 0
         end,
    Tdiff = tdiff(TS, TSp, time_resolution(Acc)),
    Diff1 = Diff + Tdiff,
    Sofar1 = Sofar + L0,
    Acc1 = Acc#{sofar => Sofar1, ts => TS, diff => Diff1},
    check_limit_exceeded(Acc1),
    Lines =
        case Trace of
            {trace_ts, From, call, {Mod, Fun, Args}, TS} ->
                {Pid, Node} = pid_and_node(From),
                print_call(Fd, Pid, Node, Mod, Fun, Args, Diff1, Acc);
            {trace_ts, From, Type, {Mod, Fun, Arity}, Info, TS}
              when Type =:= return_from; Type =:= exception_from ->
                {Pid, Node} = pid_and_node(From),
                print_return(Fd, Type, Pid, Node, Mod, Fun, Arity, Info, Diff1, Acc);
            {trace_ts, From, Type, Info, TS} ->
                {Pid, Node} = pid_and_node(From),
                print_other(Fd, #{type => Type}, Pid, Node, Info, Diff1, Acc);
            {trace_ts, From, Type, Arg, Info, TS} ->
                {Pid, Node} = pid_and_node(From),
                print_other(Fd, #{type => Type, arg => Arg}, Pid, Node, Info, Diff1, Acc);
            TraceTS when element(1, TraceTS) == trace_ts ->
                fwrite(Fd, "~p~n", [Trace]);
            _ ->
                fwrite(Fd, "~p~n", [Trace])
        end,
    Acc1#{sofar => Sofar1 + Lines}.

pid_and_node({Pid, _, Node}) ->
    {Pid, Node};
pid_and_node(Pid) when is_pid(Pid); is_port(Pid) ->
    {Pid, local}.

fwrite(Fd, Fmt, Args) ->
    io_reqs(Fd, [{put_chars, fwrite(Fmt, Args)}]).

io_reqs(Fd, Rs) ->
    Lines = count_lines(Rs),
    io:requests(Fd, Rs),
    Lines.

count_lines(Rs) ->
    lists:foldl(
      fun(nl, Acc) -> Acc+1;
         ({put_chars, Cs}, Acc) ->
              count_newlines(Cs) + Acc;
         ({put_chars, unicode, Cs}, Acc) ->
              count_newlines(Cs) + Acc
      end, 0, Rs).

count_newlines(Cs) ->
    case re:run(Cs, <<"\\v">>, [global]) of
        {match, Ms} ->
            length(Ms);
        nomatch ->
            0
    end.


check_limit_exceeded(#{sofar := Sofar, limit := Limit}) ->
    if Sofar > Limit ->
            error(limit_exceeded);
       true ->
            ok
    end.

ts(Trace, _TSp) when element(1, Trace) == trace_ts ->
    Sz = tuple_size(Trace),
    element(Sz, Trace);
ts(_, 0) ->
    erlang:timestamp();
ts(_, TSp) ->
    TSp.

print_call(Fd, Pid, Node, Mod, Fun, Args, Diff, Acc) ->
    case {Fun, Args} of
        {event, [Line, Evt, State]} when is_integer(Line) ->
            Lines = print_evt(Fd, Pid, Node, Mod, Line, Evt, State, Diff, Acc),
            case get_pids({Evt, State}) of
                [] -> Lines;
                Pids ->
                    Lines1 = fwrite(Fd, "    Nodes = ~p~n", [Pids]),
                    Lines + Lines1
            end;
        _ ->
            print_call_(Fd, Pid, Node, Mod, Fun, Args, Diff, Acc)
    end.

print_return(Fd, Type, Pid, Node, Mod, Fun, Arity, Info, T, Acc) ->
    Tstr = fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3 + 4,
    Head = print_return_head(Type, Pid, Node, Mod, Fun, Arity),
    Line1Len = iolist_size([Tstr, Head]),
    InfoPP = pp(Info, 1, Mod, Acc),
    Res = case fits_on_line(InfoPP, Line1Len, 79) of  %% minus space
              true  -> [" ", InfoPP];
              false ->
                  ["\n", indent(Indent), pp(Info, Indent, Mod, Acc)]
          end,
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, Res]}, nl]).

print_other(Fd, Type, Pid, Node, Info, T, Acc) ->
    Tstr = fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3 + 4,
    Head = print_other_head(Pid, Node, Type),
    Line1Len = iolist_size([Tstr, Head]),
    Mod = guess_mod(Type, Info),
    InfoPP = pp(Info, 1, Mod, Acc),
    Res = case fits_on_line(InfoPP, Line1Len, 79) of
              true -> [" ", InfoPP];
              false ->
                  ["\n", indent(Indent), pp(Info, Indent, Mod, Acc)]
          end,
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, Res]}, nl]).

typestr(return_from   ) -> "->";
typestr(exception_from) -> "xx~~>".

guess_mod(Type, Info) ->
    guess_mod(Type, Info, ?MODULE).

guess_mod(#{type := exit}, {_, [{Mod, _, _}|_]}, Default) when is_atom(Mod) ->
    case erlang:function_exported(Mod, module_info, 0) of
        true -> Mod;
        false -> Default
    end;
guess_mod(_, {erlang, apply, [Mod|_]}, _) when is_atom(Mod) ->
    Mod;
guess_mod(_, {erlang, apply, [F|_]}, _) when is_function(F) ->
    {_, Mod} = erlang:fun_info(F, module),
    Mod;
guess_mod(_, _, Default) ->
    Default.

-define(CHAR_MAX, 60).

print_evt(Fd, Pid, N, Mod, L, E, St, T, Acc) ->
    Tstr = fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3,
    Head = case N of
               local -> fwrite(" - ~w|~w/~w: "  , [Pid, Mod, L]);
               _     -> fwrite(" - ~w~w|~w/~w: ", [Pid, N, Mod, L])
           end,
    EvtCol = iolist_size(Head) + 1,
    EvtCs = pp(E, EvtCol, Mod, Acc),
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, EvtCs]}, nl
                 | print_tail(St, Mod, Indent, Acc)]).

print_call_(Fd, Pid, N, Mod, Fun, Args, T, Acc) ->
    Tstr = fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3 + 4,
    Head = print_call_head(Pid, N, Mod, Fun),
    Line1Len = iolist_size([Tstr, Head]),
    PlainArgs = pp_args(Args, 1, Mod, Acc),
    Rest = case fits_on_line(PlainArgs, Line1Len, 79) of %% minus )
               true -> [PlainArgs, ")"];
               false ->
                   ["\n", indent(Indent),
                    pp_args(Args, Indent, Mod, Acc), ")"]
           end,
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, Rest]}, nl]).

print_call_head(Pid, N, Mod, Fun) ->
    case N of
        local -> fwrite(" - ~w|~w:~w("  , [Pid, Mod, Fun]);
        _     -> fwrite(" - ~w~w|~w:~w(", [Pid, N, Mod, Fun])
    end.

print_other_head(Pid, N, #{type := Type, arg := Arg}) ->
    case N of
        local -> fwrite(" - ~w|~w[~w]:", [Pid, Type, Arg]);
        _     -> fwrite(" - ~w~w|~w[~w]:", [Pid, N, Type, Arg])
    end;
print_other_head(Pid, N, #{type := Type}) ->
    case N of
        local -> fwrite(" - ~w|~w:", [Pid, Type]);
        _     -> fwrite(" - ~w~w|~w", [Pid, N, Type])
    end.

print_return_head(Type, Pid, Node, Mod, Fun, Arity) ->
    case Node of
        local -> fwrite(" - ~w|~w:~w/~w "   ++ typestr(Type), [Pid, Mod, Fun, Arity]);
        _     -> fwrite(" - ~w~w|~w:~w/~w " ++ typestr(Type), [Pid, Node, Mod, Fun, Arity])
    end.

fwrite(Fmt, Args) ->
    io_lib:fwrite(Fmt, Args).

indent(N) ->
    lists:duplicate(N, $\s).

rm_braces(Str) ->
    %% allow for whitespace (incl vertical) before and after
    B = iolist_to_binary(Str),
    Sz = byte_size(B),
    {Open,1} = binary:match(B, [<<"{">>]),
    {Close,1} = lists:last(
                  binary:matches(B, [<<"}">>])),
    SzA = Open + 1,
    SzB = Sz-Close,
    SzMid = Sz - SzA - SzB,
    <<_:SzA/unit:8,Mid:SzMid/binary,_/binary>> = B,
    Mid.

fits_on_line(IOList, Len, LineLen) ->
    iolist_size(IOList) + Len =< LineLen
        andalso has_no_line_breaks(IOList).

has_no_line_breaks(IOL) ->
    nomatch =:= re:run(IOL, <<"\\v">>).


print_tail(none, _, _Col, _Acc) -> [];
print_tail(St, Mod, Col, Acc) ->
    Cs = pp(St, Col+1, Mod, Acc),
    [{put_chars, unicode, [lists:duplicate(Col,$\s), Cs]}, nl].

%% Pretty-printing the args list as a list, may trigger the 'string' interpretation
%% of the list. We want to remove the brackets anyway, so convert to tuple, then remove the braces
pp_args(Args, Col, Mod, Acc) ->
    rm_braces(pp(list_to_tuple(Args), Col, Mod, Acc)).

pp(Term, Col, Mod) ->
    pp(Term, Col, Mod, #{}).

pp(Term, Col, Mod, Acc) ->
    Out = pp_term(Term, Mod),
    io_lib_pretty:print(Out,
                        [{column, Col},
                         {line_length, 80},
                         {depth, -1},
                         {max_chars, ?CHAR_MAX},
                         {record_print_fun, record_print_fun(Mod, Acc)}]).

pp_term(T, M) when is_atom(M) ->
    pp_term(T, fun M:pp_term/1);
pp_term(T, F) when is_function(F, 1) ->
    try F(T) of
        {yes, Out} -> Out;
        no         -> pp_term_(T, F)
    catch
        error:_ ->
            pp_term_(T, F)
    end.

pp_term_(D, _) when element(1, D) == dict ->
    pp_custom(D, '$dict', fun dict_to_list/1);
pp_term_(T, M) when is_tuple(T) ->
    list_to_tuple([pp_term(Trm, M) || Trm <- tuple_to_list(T)]);
pp_term_(L, M) when is_list(L) ->
    %% Could be an improper list
    lmap(L, fun(T) -> pp_term(T, M) end);
pp_term_(T, _) ->
    T.

lmap([H|T], F) when is_list(T) ->
    [F(H)|lmap(T,F)];
lmap([H|X], F) ->
    [F(H)|F(X)];
lmap([], _) ->
    [].

pp_custom(X, Tag, F) ->
    try {Tag, F(X)}
    catch
        error:_ ->
            {'ERROR-CUSTOM', Tag, X}
    end.

tdiff(_, 0, _) -> 0;
tdiff(TS, T0, Res) ->
    case Res of
        millisecond ->
            timer:now_diff(TS, T0) div 1000;
        microsecond ->
            timer:now_diff(TS, T0)
    end.

time_resolution(Opts) ->
    maps:get(time_resolution, Opts, millisecond).

record_print_fun(Mod) ->
    record_print_fun(Mod, #{}).

record_print_fun(Mod, Acc) ->
    fun(Tag, NoFields) ->
            record_print_fun_(Mod, Tag, NoFields, [], Acc)
    end.

record_print_fun_(Mod, Tag, NoFields, V, Acc) ->
    case shell_record_print(Tag, NoFields, Acc) of
        Fields when is_list(Fields) ->
            Fields;
        _ ->
            try Mod:record_fields(Tag) of
                Fields when is_list(Fields) ->
                    case length(Fields) of
                        NoFields -> Fields;
                        _ -> no
                    end;
                {check_mods, Mods} when is_list(Mods) ->
                    check_mods(Mods, Tag, NoFields, V, Acc);
                no -> no
            catch
                _:_ ->
                    no
            end
    end.

%% code copied and slightly modified from shell:record_print_fun/1
shell_record_print(Tag, NoFields, #{shell_records_tab := RT}) ->
    try ets:lookup(RT, Tag) of
        [{_,{attribute,_,record,{Tag,Fields}}}]
          when length(Fields) =:= NoFields ->
            record_fields(Fields);
        _ ->
            no
    catch
        error:_ ->
            no
    end;
shell_record_print(_, _, _) ->
    no.

record_fields([{record_field,_,{atom,_,Field}} | Fs]) ->
    [Field | record_fields(Fs)];
record_fields([{record_field,_,{atom,_,Field},_} | Fs]) ->
    [Field | record_fields(Fs)];
record_fields([{typed_record_field,Field,_Type} | Fs]) ->
    record_fields([Field | Fs]);
record_fields([]) ->
    [].


check_mods([], _, _, _, _) ->
    no;
check_mods([M|Mods], Tag, NoFields, V, Acc) ->
    Cont = fun(V1) -> check_mods(Mods, Tag, NoFields, V1, Acc) end,
    case lists:member(M, V) of
        true ->
            Cont(V);
        false ->
            V1 = [M|V],
            try record_print_fun_(M, Tag, NoFields, V1, Acc) of
                Fields when is_list(Fields) ->
                    Fields;
                no ->
                    Cont(V1)
            catch
                _:_ ->
                    Cont(V1)
            end
    end.

get_pids(Term) ->
    Pids = dict:to_list(get_pids(Term, dict:new())),
    [{node_prefix(P), N} || {N, P} <- Pids].

get_pids(T, Acc) when is_tuple(T) ->
    get_pids(tuple_to_list(T), Acc);
get_pids(L, Acc) when is_list(L) ->
    get_pids_(L, Acc);
get_pids(P, Acc) when is_pid(P) ->
    try ets:lookup(ttb, P) of
        [{_, _, Node}] ->
            dict:store(Node, P, Acc);
        _ ->
            Acc
    catch
        error:_ -> Acc
    end;
get_pids(_, Acc) ->
    Acc.

get_pids_([H|T], Acc) ->
    get_pids_(T, get_pids(H, Acc));
get_pids_(_, Acc) ->
    Acc.


node_prefix(P) ->
    case re:run(pid_to_list(P), "[^<\\.]+", [{capture,first,list}]) of
        {match, [Pfx]} ->
            Pfx;
        _ ->
            P
    end.

cfg(Mod, Key, Default) when is_atom(Mod) ->
    try_callback(Mod, Key, [], Default);
cfg(Spec, Key, Default) when is_map(Spec) ->
    case maps:find(Key, Spec) of
        {ok, Res} -> Res;
        error ->
            case maps:get(module, Spec, undefined) of
                undefined -> Default;
                Mod ->
                    try_callback(Mod, Key, [], Default)
            end
    end.

try_callback(Mod, Key, Args, Default) ->
    ensure_loaded(Mod),
    case erlang:function_exported(Mod, Key, length(Args)) of
        true ->
            apply(Mod, Key, Args);
        false ->
            Default
    end.

ensure_loaded(Mod) ->
    case code:ensure_loaded(Mod) of
        {module, _} ->
            true;
        {error, _} ->
            false
    end.

%% -dialyzer(no_opaque).
-dialyzer([{nowarn_function, dict_to_list/1}, no_opaque]).
dict_to_list(D) when element(1, D) == dict ->
    dict:to_list(D).

-dialyzer({nowarn_function, format_time_/1}).
%% ==================================================================
%% Copied from lager_default_formatter.erl, lager_util.erl

format_time(Now) ->
    {Date, Time} = format_time_(maybe_utc(localtime_ms(Now))),
    ["=== Start time: ", Date, " ", Time, " ===\n"].

format_time_({utc, {{Y, M, D}, {H, Mi, S, Ms}}}) ->
    {[integer_to_list(Y), $-, i2l(M), $-, i2l(D)],
     [i2l(H), $:, i2l(Mi), $:, i2l(S), $., i3l(Ms), $ , $U, $T, $C]};
format_time_({{Y, M, D}, {H, Mi, S, Ms}}) ->
    {[integer_to_list(Y), $-, i2l(M), $-, i2l(D)],
     [i2l(H), $:, i2l(Mi), $:, i2l(S), $., i3l(Ms)]};
format_time_({utc, {{Y, M, D}, {H, Mi, S}}}) ->
    {[integer_to_list(Y), $-, i2l(M), $-, i2l(D)],
     [i2l(H), $:, i2l(Mi), $:, i2l(S), $ , $U, $T, $C]};
format_time_({{Y, M, D}, {H, Mi, S}}) ->
    {[integer_to_list(Y), $-, i2l(M), $-, i2l(D)],
     [i2l(H), $:, i2l(Mi), $:, i2l(S)]}.

i2l(I) when I < 10  -> [$0, $0+I];
i2l(I)              -> integer_to_list(I).
i3l(I) when I < 100 -> [$0 | i2l(I)];
i3l(I)              -> integer_to_list(I).

localtime_ms(Now) ->
    {_, _, Micro} = Now,
    {Date, {Hours, Minutes, Seconds}} = calendar:now_to_local_time(Now),
    {Date, {Hours, Minutes, Seconds, Micro div 1000 rem 1000}}.

maybe_utc({Date, {H, M, S, Ms}}) ->
    case maybe_utc_({Date, {H, M, S}}) of
        {utc, {Date1, {H1, M1, S1}}} ->
            {utc, {Date1, {H1, M1, S1, Ms}}};
        {Date1, {H1, M1, S1}} ->
            {Date1, {H1, M1, S1, Ms}}
    end.

maybe_utc_(Time) ->
    UTC = case application:get_env(sasl, utc_log) of
        {ok, Val} ->
            Val;
        undefined ->
            %% Backwards compatible:
            application:get_env(stdlib, utc_log, false)
    end,
    if
        UTC =:= true ->
            UTCTime = case calendar:local_time_to_universal_time_dst(Time) of
                []     -> calendar:local_time();
                [T0|_] -> T0
            end,
            {utc, UTCTime};
        true ->
            Time
    end.

%% ==================================================================
