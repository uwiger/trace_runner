# trace_runner
A wrapper for tracing test runs using TTB.

This component is based on [locks_ttb](https://github.com/uwiger/locks/blob/master/src/locks_ttb.erl), whose main purpose was to be used in complicated
multi-node test cases: a wrapper around the test case sets up a multi-node
trace using ttb; if the test case succeeds, the traces are discarded, but
if it fails, the logs are fetched, merged and formatted for 'easy' viewing.

The idea is complemented with the notion of using an `event()` function,
whose only purpose is to be traced. This can serve as extremely lightweight
runtime debugging statements. Since the `event()` function only returns
`ok`, the whole operation is cheaper than any runtime test for debug level
could be. the `include/trace_runner.hrl` include file defines `?event`
macros that can be used, including one that tests whether the `event()`
function is traced, before evaluating the argument expression. This can
be used to 'pretty-print' the arguments to the `event()` function without
incurring overhead when not tracing (obviously there is *some* overhead in
checking the trace status).

Example (from https://github.com/PDXOstc/rvi_core, although at the time of writing, the trace_runner support hasn't yet been merged)

First, we create a callback module for the `tr_ttb` behavior, which
lets us specify trace patterns and trace flags.

```erlang
patterns() ->
    [{authorize_rpc        , event, 3, []},
     {service_edge_rpc     , event, 3, []},
     {service_discovery_rpc, event, 3, []},
     {dlink_tcp_rpc        , event, 3, []},
     {connection           , event, 3, []},
     {dlink_tls_rpc        , event, 3, []},
     {dlink_tls_conn       , event, 3, []},
     {dlink_bt_rpc         , event, 3, []},
     {bt_connection        , event, 3, []},
     {dlink_sms_rpc        , event, 3, []},
     {schedule_rpc         , event, 3, []},
     {proto_json_rpc       , event, 3, []},
     {proto_msgpack_rpc    , event, 3, []},
     {rvi_common           , event, 3, []},
     {?MODULE              , event, 3, []}
     | tr_ttb:default_patterns()].

flags() ->
    {all, call}.
```

Then, we instrument our test suite(s):

```erlang
t_multicall_sota_service(Config) ->
    with_trace(fun t_multicall_sota_service_/1, Config,
     	       "t_multicall_sota_service").

t_multicall_sota_service_(_Config) ->
    %% the actual test case
    Data = <<"abc">>,
    ...
```

In the wrapper, we determine which nodes to include in the trace,
give the trace a name, then call the test case within a try ... catch.
If the test succeeds, we call `stop_nofetch()`, discarding the trace,
otherwise, we fetch the trace logs and merge them, pretty-printing
the result.

```erlang
with_trace(F, Config, File) ->
    Nodes = [N || {N,_} <- get_nodes()],
    rvi_ttb:on_nodes([node()|Nodes], File),
    try F(Config)
    catch
	error:R ->
	    Stack = erlang:get_stacktrace(),
	    ttb_stop(),
	    ct:log("Error ~p; Stack = ~p", [R, Stack]),
	    erlang:error(R);
	exit:R ->
	    ttb_stop(),
	    exit(R)
    end,
    rvi_ttb:stop_nofetch(),
    ok.

ttb_stop() ->
    Dir = rvi_ttb:stop(),
    Out = filename:join(filename:dirname(Dir),
			filename:basename(Dir) ++ ".txt"),
    rvi_ttb:format(Dir, Out),
    ct:log("Formatted trace log in ~s~n", [Out]).
```

On test failure, this would result in the following output in the CT log:

<img src="doc/images/ttb-log-snap-1.png" alt="trace log snapshot 2" style="width:800">

The formatted text log has an emacs erlang-mode header, so is best
viewed in emacs.

<img src="doc/images/ttb-log-snap.png" alt="trace log snapshot" style="width:800">

Note that the log formatter prefixes each message with the relative time
(in ms) since the start of the trace, the name of the node where the
trace event originated and the module/line of the traced call.
It also tries to pretty-print records, looking for a
`record_fields(RecName)` callback in the module named in the call trace.

<img src="doc/images/ttb-log-snap-2.png" alt="trace log snapshot 2" style="width:800">

A `record_fields/1` function might look like this:

```erlang
record_fields(service_entry)	-> record_info(fields, service_entry);
record_fields(st           )	-> record_info(fields, st);
record_fields(component_spec)	-> record_info(fields, component_spec);
record_fields(_)		-> no.
```

## Custom formatting of terms

The pretty-printer allows terms to be custom-formatted using a `pp_term(Term)` callback,
optionally exported from the callback module. The semantics of the callback is:

```erlang
pp_term(Term) -> {yes, Term1} | no.
```

The custom formatting function can call on subsequent `pp_term/1` callbacks using
the `trace_runner` helper function `tr_ttb:pp_term(Term, Mod) -> Term1`.
The helper unwraps any `{yes, ...}` tuples etc., returning either a modified term
or the original term.

Instead of a callback module, `tr_ttb:pp_term/2` can take a fun as second argument.
Technically, the implementation is:

```erlang
pp_term(T, M) when is_atom(M) ->
    pp_term(T, fun M:pp_term/1);
pp_term(T, F) when is_function(F, 1) ->
    try F(T) of
        {yes, Out} ->
            Out;
        no         -> pp_term_(T, F)
    catch
        error:_ ->
            pp_term_(T, F)
    end.
```

... where `pp_term_/2` traverses the term, looking for opportunities to pretty-print
sub-terms. That is, by returning `no`, the callback allows the traversal to continue.
If it is known that no opportunities to pretty-print exist in a subterm, returning
`{yes, Term}` will stop further inspection in that area.

As an example of how layered pretty-printing can be leveraged, see the pretty-printing
of Merkle Patricia Trees (MPT) in the Aeternity system. MPTs are particularly hard
to read in raw form, partly since terms are encoded twice. The `pp_term/1` callbacks
at the application level therefore first call on a generic helper function, which
converts a tree to a key-value list, then applies application-specific decoding of
the stored terms. Note the trick to tag custom-formatted terms with `'$...'` tags,
both to help the reader and to allow higher levels to detect and further refine
the data.

```erlang
record_fields(_) -> {check_mods, [ aec_accounts ]}.

pp_term(Term) ->
    aeu_mp_trees:tree_pp_term(Term, '$accounts', fun aec_accounts:deserialize/2).
```

The helper function:
```erlang
%% Utility trace support for state tree modules
%%
tree_pp_term(#mpt{} = Term, CacheTag, XForm) ->
    Dec = fun(X) -> pp_mpt_decode(X, CacheTag, XForm) end,
    {yes, tr_ttb:pp_term(tr_ttb:pp_term(Term, aeu_mtrees), Dec)};
tree_pp_term(_, _, _) ->
    no.

pp_mpt_decode({'$mpt', L}, Tag, XForm) ->
    {yes, {Tag, [{K, XForm(K, V)}
                 || {K, V} <- L]}};
pp_mpt_decode(_, _, _) ->
    no.
```

## Record pretty-printing

The pretty-printer uses a generalized version of the `record_print_fun` used in
`io_lib_pretty.erl`. This way, `record_fields(Term)` can be exported from the
callback module. In addition to the normal `{yes, FieldNames} | no` returns,
the callbacks can also return `{check_mods, Modules}`, instructing the caller
to inspect any `record_fields/1` callbacks of the listed modules.

## Shell tracing

Shell tracing can make use of the same instrumented pretty-printing via the
function `tr_ttb:dbg_tracer(Options)` function. This starts a `dbg` tracer
which calls on the pretty-printing callbacks described above. As formatting
is likely to be slower, it is recommended that tracing is stopped using the
function `tr_ttb:dbg_stop()`, which waits until the tracer process has processed
queued trace messages before stopping it.

The optional `Options` argument is a map, and supports the following options:
```
fd           - the output descriptor. Defaults to 'user'
print_header - whether to print the preamble mainly meant for emacs. Defaults to 'false'
limit        - How many lines of trace output to print. Defaults to 'infinity'
time_resolution - millisecond | microsecond. Defaults to 'millisecond'
```

In the future, more log formatting options may be added.
Pull requests are welcome.
