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
         record_print_fun/1
        ]).

-type trace_pat() :: any().
-type pattern() :: {module(), atom(), arity(), trace_pat()}.

-callback flags() -> [{atom(), any()}].
-callback patterns() -> [pattern()].


%% This function is also traced. Can be used to insert markers in the trace
%% log.
event(E) ->
    event(?LINE, E, none).

event(_, _, _) ->
    ok.

on_nodes(Ns, File) ->
    on_nodes(Ns, default_patterns(), default_flags(), [{file, File}]).

on_nodes(Ns, File, Mod) ->
    on_nodes(Ns,
                cb(Mod, patterns, [], default_patterns()),
                cb(Mod, flags, [], default_flags()),
                [{mod, Mod}, {file, File}]).

on_nodes(Ns, Patterns, Flags, Opts) ->
    ttb:start_trace(Ns, Patterns, Flags, lists:keydelete(mod, 1, Opts)).

default_patterns() ->
    [{?MODULE     , event, 3, []}].

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
    format(Dir, OutFile, default_opts()).

format(Dir, OutFile, Opts) ->
    try ttb:format(Dir, format_opts(OutFile, Opts))
    catch
        error:exceeded_limit = Reason ->
            {error, Reason};
        error:Other ->
            {error, {Other, erlang:get_stacktrace()}}
    end.

format_opts() ->
    format_opts(standard_io).

format_opts(Outfile) ->
    format_opts(Outfile, default_opts()).

format_opts(OutFile, Opts) ->
    Limit = maps:get(limit, Opts, infinity),
    [{out, OutFile}, {handler, {fun handler/4, #{ts => 0,
                                                 diff => 0,
                                                 sofar => 0,
                                                 limit => Limit,
                                                 opts => Opts}}}].

default_opts() ->
    #{limit => 10000}.



handler(Fd, Trace, _, #{ts := TSp, diff := Diff, sofar := Sofar} = Acc) ->
    TS = ts(Trace, TSp),
    L0 = case {TSp,Diff} of {0,0} ->
                 io:fwrite(Fd, "%% -*- erlang -*-~n", []),
                 io:put_chars(Fd, format_time(TS)),
                 2;
             _ -> 0
         end,
    Tdiff = tdiff(TS, TSp),
    Diff1 = Diff + Tdiff,
    Sofar1 = Sofar + L0,
    Acc1 = Acc#{sofar => Sofar1, ts => TS, diff => Diff1},
    check_limit_exceeded(Acc1),
    Lines =
        case Trace of
            {trace_ts,{Pid, _, Node}, call, {Mod, Fun, Args}, TS} ->
                print_call(Fd, Pid, Node, Mod, Fun, Args, Diff1);
            {trace_ts,{Pid, _, Node}, Type, {Mod, Fun, Arity}, Info, TS}
              when Type =:= return_from; Type =:= exception_from ->
                print_return(Fd, Type, Pid, Node, Mod, Fun, Arity, Info, Diff1);
            TraceTS when element(1, TraceTS) == trace_ts ->
                fwrite(Fd, "~p~n", [Trace]);
            _ ->
                fwrite(Fd, "~p~n", [Trace])
        end,
    Acc1#{sofar => Sofar1 + Lines}.

fwrite(Fd, Fmt, Args) ->
    io_reqs(Fd, [{put_chars, io_lib:fwrite(Fmt, Args)}]).

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
ts(_, TSp) ->
    TSp.



print_call(Fd, Pid, Node, Mod, Fun, Args, Diff) ->
    case {Fun, Args} of
        {event, [Line, Evt, State]} when is_integer(Line) ->
            Lines = print_evt(Fd, Pid, Node, Mod, Line, Evt, State, Diff),
            case get_pids({Evt, State}) of
                [] -> Lines;
                Pids ->
                    Lines1 = fwrite(Fd, "    Nodes = ~p~n", [Pids]),
                    Lines + Lines1
            end;
        _ ->
            print_call_(Fd, Pid, Node, Mod, Fun, Args, Diff)
    end.

print_return(Fd, Type, Pid, Node, Mod, Fun, Arity, Info, T) ->
    Tstr = io_lib:fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3 + 4,
    Head = io_lib:fwrite(" - ~w~w|~w:~w/~w " ++ typestr(Type),
                         [Pid, Node, Mod, Fun, Arity]),
    Line1Len = iolist_size([Tstr, Head]),
    InfoPP = pp(Info, 1, Mod),
    Res = case fits_on_line(InfoPP, Line1Len, 79) of  %% minus space
              true  -> [" ", InfoPP];
              false ->
                  ["\n", indent(Indent), pp(Info, Indent, Mod)]
          end,
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, Res]}, nl]).

typestr(return_from   ) -> "->";
typestr(exception_from) -> "xx~~>".


-define(CHAR_MAX, 60).

print_evt(Fd, Pid, N, Mod, L, E, St, T) ->
    Tstr = io_lib:fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3,
    Head = io_lib:fwrite(" - ~w~w|~w/~w: ", [Pid, N, Mod, L]),
    EvtCol = iolist_size(Head) + 1,
    EvtCs = pp(E, EvtCol, Mod),
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, EvtCs]}, nl
                 | print_tail(St, Mod, Indent)]).

print_call_(Fd, Pid, N, Mod, Fun, Args, T) ->
    Tstr = io_lib:fwrite("~w", [T]),
    Indent = iolist_size(Tstr) + 3 + 4,
        %% + (iolist_size(io_lib:fwrite("~w", [N])) div 2),
    Head = io_lib:fwrite(" - ~w~w|~w:~w(", [Pid, N, Mod, Fun]),
    Line1Len = iolist_size([Tstr, Head]),
    PlainArgs = rm_brackets(pp(Args, 1, Mod)),
    Rest = case fits_on_line(PlainArgs, Line1Len, 79) of %% minus )
               true -> [PlainArgs, ")"];
               false ->
                   ["\n", indent(Indent),
                    rm_brackets(pp(Args, Indent, Mod)), ")"]
           end,
    io_reqs(Fd, [{put_chars, unicode, [Tstr, Head, Rest]}, nl]).

indent(N) ->
    lists:duplicate(N, $\s).

rm_brackets(Str) ->
    %% allow for whitespace (incl vertical) before and after
    B = iolist_to_binary(Str),
    Sz = byte_size(B),
    {Open,1} = binary:match(B, [<<"[">>]),
    {Close,1} = lists:last(
                  binary:matches(B, [<<"]">>])),
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


print_tail(none, _, _Col) -> [];
print_tail(St, Mod, Col) ->
    Cs = pp(St, Col+1, Mod),
    [{put_chars, unicode, [lists:duplicate(Col,$\s), Cs]}, nl].

pp(Term, Col, Mod) ->
    io_lib_pretty:print(pp_term(Term),
                        [{column, Col},
                         {line_length, 80},
                         {depth, -1},
                         {max_chars, ?CHAR_MAX},
                         {record_print_fun, record_print_fun(Mod)}]).

pp_term(D) when element(1,D) == dict ->
    try {'$dict', dict:to_list(D)}
    catch
        error:_ ->
            list_to_tuple([pp_term(T) || T <- tuple_to_list(D)])
    end;
pp_term(T) when is_tuple(T) ->
    list_to_tuple([pp_term(Trm) || Trm <- tuple_to_list(T)]);
pp_term(L) when is_list(L) ->
    [pp_term(T) || T <- L];
pp_term(T) ->
    T.

tdiff(_, 0) -> 0;
tdiff(TS, T0) ->
    %% time difference in milliseconds
    timer:now_diff(TS, T0) div 1000.

record_print_fun(Mod) ->
    fun(Tag, NoFields) ->
            record_print_fun_(Mod, Tag, NoFields, [])
    end.

record_print_fun_(Mod, Tag, NoFields, V) ->
    try Mod:record_fields(Tag) of
        Fields when is_list(Fields) ->
            case length(Fields) of
                NoFields -> Fields;
                _ -> no
            end;
        {check_mods, Mods} when is_list(Mods) ->
            check_mods(Mods, Tag, NoFields, V);
        no -> no
    catch
        _:_ ->
            no
    end.

check_mods([], _, _, _) ->
    no;
check_mods([M|Mods], Tag, NoFields, V) ->
    Cont = fun(V1) -> check_mods(Mods, Tag, NoFields, V1) end,
    case lists:member(M, V) of
        true ->
            Cont(V);
        false ->
            V1 = [M|V],
            try record_print_fun_(M, Tag, NoFields, V1) of
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

cb(Mod, F, Args, Default) ->
    ensure_loaded(Mod),
    case erlang:function_exported(Mod, F, length(Args)) of
        true ->
            apply(Mod, F, Args);
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
