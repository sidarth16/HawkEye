from slither.slither import Slither
from slither.core.declarations.function import Function



def get_all_conditional_nodes(function: Function) -> list:  
    """
    Checks function expression for requre or condition checks on msg.sender / _msgSender.
    Returns list of all expression involving msg-sender checks
    """

    all_functions = function.all_internal_calls() + [function] + function.modifiers

    all_nodes = [f.nodes for f in all_functions if isinstance(f, Function)]
    all_nodes = [item for sublist in all_nodes for item in sublist]
    all_conditional_nodes = [
        str(n.expression) for n in all_nodes 
        if n.contains_if() or n.contains_require_or_assert() or '=='in str(n.expression) or '!='in str(n.expression)
    ]

    return all_conditional_nodes

# check msgSender checks on functions and returns if any
def get_msg_sender_checks(function: Function, msg_sender_funcs: list) -> list:  
    """
    Checks function expression for requre or condition checks on msg.sender / _msgSender.
    Returns list of all expression involving msg-sender checks
    """

    all_functions = function.all_internal_calls() + [function] + function.modifiers

    all_nodes = [f.nodes for f in all_functions if isinstance(f, Function)]
    all_nodes = [item for sublist in all_nodes for item in sublist]

    all_conditional_nodes = [
        n for n in all_nodes 
        if n.contains_if() or n.contains_require_or_assert() or '=='in str(n.expression)
    ]
    all_conditional_nodes_on_msg_sender = [
        str(n.expression)
        for n in all_conditional_nodes
        # if "msg.sender" in [v.name for v in n.solidity_variables_read]
        # Check for msg.sender or functions returning msg.sender
        if (
            ("msg.sender" in [v.name for v in n.solidity_variables_read]) or 
            ("sender" in str(n.expression)) or 
            ("tx.origin" in [v.name for v in n.solidity_variables_read]) or 
            any([fname+'(' in str(n.expression) for fname in msg_sender_funcs ]) )
    ]
    return all_conditional_nodes_on_msg_sender


# check msgSender checks on functions and returns if any
def get_msg_sender_checks_no_if(function: Function, msg_sender_funcs: list) -> list:  
    """
    Checks function expression for requre or condition checks on msg.sender / _msgSender.
    Returns list of all expression involving msg-sender checks
    """

    all_functions = function.all_internal_calls() + [function] + function.modifiers

    all_nodes = [f.nodes for f in all_functions if isinstance(f, Function)]
    all_nodes = [item for sublist in all_nodes for item in sublist]

    all_conditional_nodes = [
        n for n in all_nodes 
        if n.contains_require_or_assert() or '=='in str(n.expression)
    ]
    all_conditional_nodes_on_msg_sender = [
        str(n.expression)
        for n in all_conditional_nodes
        # if "msg.sender" in [v.name for v in n.solidity_variables_read]
        # Check for msg.sender or functions returning msg.sender
        if (
            ("msg.sender" in [v.name for v in n.solidity_variables_read]) or 
            ("sender" in str(n.expression)) or 
            ("tx.origin" in [v.name for v in n.solidity_variables_read]) or 
            any([fname+'(' in str(n.expression) for fname in msg_sender_funcs ]) )
    ]
    return all_conditional_nodes_on_msg_sender



def is_returning_msg_sender(function: Function) -> bool:
        """
            Determine if the function returns `msg.sender` directly or through aliased address variables.

            This includes:
            - Functions that explicitly returns `msg.sender`
            - Functions that returns a variable which was directly or transitively assigned from `msg.sender`

            Covers:
                - Direct returns:
                    ```
                    return msg.sender
                    ```
                - Aliased returns:
                    ```
                    address a = msg.sender;
                    return a;
                    ```

            Does not cover :
                - Returns via internal function calls, even if those functions return `msg.sender`:
                    ```
                    function _getUser() internal view returns (address) {
                            return _msgSender(); // _msgSender() returns msg.sender
                    }
                    ```

        Returns
            (bool)
        """
        from slither.core.solidity_types import ElementaryType
        from slither.slithir.operations import Return, Assignment

        

        # Skip analysis if function doesn't return or doesn't return an address.
        if not function.returns or not all(
            ret.type == ElementaryType("address") for ret in function.returns
        ):
            function._is_returning_msg_sender = False
            return False

        return_vars = []
        assignment_map = {}

        for node in function.nodes:
            for ir in node.irs:
                # Direct return of msg.sender
                if isinstance(ir, Return):
                    ir_return_vars = [i.name for i in ir.values if hasattr(i, "name")]
                    if "msg.sender" in ir_return_vars:
                        return True
                    return_vars.extend(ir_return_vars)

                # Track assignments where an address-typed variable is assigned.
                # This helps trace msg.sender aliases through reassignments.
                if (
                    isinstance(ir, Assignment)
                    and ir.lvalue.type == ElementaryType("address")
                    and hasattr(ir.lvalue, "name")
                    and hasattr(ir.rvalue, "name")
                ):
                    lval, rval = ir.lvalue.name, ir.rvalue.name
                    assignment_map[lval] = assignment_map.get(rval, rval)

        for var in return_vars:
            if var not in assignment_map:
                continue
            var = assignment_map[var]
            if var == "msg.sender":
                return True

        return False


def get_function_trace(sl: Slither):
    """
    Returns a dict of canonical-function-name -> Function Trace list.
    Trace list consists all functions that can be triggered from the context function.
    """
    trace = {}

    # Map internal calls with the source function
    for contract in sl.contracts:
        for function in contract.functions : 
            if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name :
                continue
            internal_calls = []
            for call in function.all_internal_calls():
                try: 
                    func = call.function
                    _ = call.function.canonical_name
                    internal_calls.append(func)
                except Exception as e: 
                    continue
            trace[function.canonical_name] = internal_calls
    return trace

    
def get_function_trace_with_args_passed(sl: Slither):
    """
    Returns a dict of canonical-function-name -> (Function Trace list, args passed).
    Trace list consists all functions that can be triggered from the context function.
    """
    trace = {}

    # Map internal calls with the source function
    for contract in sl.contracts:
        for function in contract.functions : 
            if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name :
                continue
            if function.is_constructor:
                continue
            internal_calls = []

            for call in function.all_internal_calls()+function.all_library_calls():
                try: 
                    func = call.function
                    _ = call.function.canonical_name
                    args_passed =  call.arguments
                    # contr
                    internal_calls.append((func, args_passed))
                except Exception as e: 
                    continue
            trace[function.canonical_name] = internal_calls

    # # resolve internal maps 
    # def expand(func):
    #     calls = trace.get(func, [])
    #     for callee in trace.get(func, []):
    #         calls += expand(callee)
    #     # remove duplicates while preserving order
    #     seen, result = set(), []
    #     for c in calls:
    #         if c not in seen:
    #             seen.add(c)
    #             result.append(c)
    #     return result
    
    # return {f: expand(f) for f in trace}
    return trace
