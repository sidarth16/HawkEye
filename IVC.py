from utils import *

from slither.slithir.operations import *

def filter_function_without_proper_access_control(sl: Slither, result:dict):

    #function trace 
    ftrace = get_function_trace(sl)
    msg_sender_funcs = []
    for contract in sl.contracts:
        for function in contract.functions :
            if is_returning_msg_sender(function):
                fname = function.name
                # print(fname)
                msg_sender_funcs.append(fname)

    flagged_funcs = []
    for func_canonical_name in result:
        contract_name = func_canonical_name.split('.')[0]
        fobj = sl.get_contract_from_name(contract_name)[0].get_function_from_canonical_name(func_canonical_name)
        flagged_funcs.append(fobj)

    # print([i.name for i in flagged_funcs ])

    # Run Checks on flagged_funcs
    for func in flagged_funcs:
        if func.contract_declarer.is_interface :
            continue

        fname = func.canonical_name
        msg_sender_checks = []
        modifiers = []
        print(fname)

        
        funcs_to_check = [func] + ftrace[fname]
        # print([i.canonical_name for i in funcs_to_check])
        for fobj in funcs_to_check:
            msg_sender_checks.extend(get_msg_sender_checks(fobj, msg_sender_funcs))
            modifiers.extend([i.name for i in fobj.modifiers])
        print('Access Control Checks: ' , msg_sender_checks)

        # modifiers Role based and Owner Based or has Only-admin/owner/...
        if any(['ROLE' in i.upper() or 'OWNER' in i.upper() or 'ONLY' in i.upper() for i in modifiers]):
            print("✅ Proper Access Control Checking Done")
            result.pop(fname)
            continue

        if len(msg_sender_checks)>0  : 
            msg_sender_checks_upd = []
            [msg_sender_checks_upd.extend(i.split('||')) for i in msg_sender_checks]

            weak_AC_checks = [i for i in msg_sender_checks_upd if (('tx.origin' in i)or('isContract(' in i)or('!=' in i))]

            if len(msg_sender_checks_upd) > len(weak_AC_checks) :
                print("✅ Proper Access Control Checking Done")
                result.pop(fname)

        print()

    return result


def check_input_validation(function:Function, farg_vars=None):
    var_to_calls = {}
    all_vars_to_check = []
    unvalidated_var_ext_call = []
    
    fname = function.canonical_name
    # print(fname)

    if not farg_vars:
        farg_vars = function.parameters
    # print(f'Func parameters : ', [i.name for i in farg_vars])

    # get funcs that are make external calls
    ext_calls = function.external_calls_as_expressions

    if len(ext_calls)>0:

        # clean calls content
        ext_calls = [''.join(i.source_mapping.content.strip().split()) for i in ext_calls]

        # get all ext calls and called contract variable
        ext_contract_vars = []
        for call in ext_calls:
            if (('.send' in call or '.sendValue(' in call) and any([i in fname for i in ['withdraw', 'redeem']])) or ('rescue' in fname):
                continue
            ext_contract = call.split('.')[0].split('(')[-1].split(')')[0]
            ext_contract_vars.append(ext_contract)
            if ext_contract in var_to_calls:
                var_to_calls[ext_contract].append(call)
            else:
                var_to_calls[ext_contract] = [call]

        ext_contract_vars = list(set(ext_contract_vars))
        # print(f'ext_contract_vars: {ext_contract_vars}')


        # get all local vars
        vars = [var for var in function.variables if not(var.is_constant or var.is_immutable or var.is_storage or var in function.parameters) and var.name]
        # vars = [var for var in function.variables if not(var.is_constant or var.is_immutable or var.is_storage)]

        # print('local_vars : ', [i.name for i in vars])

        # get derivation of these local vars:
        tainted_vars = [] #vars that are derived from user inputs
        tainted_derivations = [i.name for i in farg_vars] + ['msg.sender', 'msg.data', 'tx.origin', 'msg.value']
        for node in function.nodes:
            for ir in node.irs:
                # print(type(ir))
                lval, rval = None, None
                if (
                    isinstance(ir, Assignment)
                    # and ir.lvalue.type == ElementaryType("address")
                    and hasattr(ir.lvalue, "name")
                    and hasattr(ir.rvalue, "name")
                    ):
                    lval, rval = ir.lvalue.name, ir.rvalue.name

                elif (isinstance(ir, Unpack)):
                    # print(ir.expression.source_mapping.content)
                    lval =  ir.expression.source_mapping.content.split('=')[0].strip()
                    rval =  ir.expression.source_mapping.content.split('=')[-1].strip()

                if lval and rval : 
                    # print(f'lval, rval : {lval, rval}')

                    for var in vars:
                        if var.name in lval :
                            if any([i in rval for i in tainted_derivations]):
                                tainted_vars.append(var)


        print('tainted_vars : ', [i.name for i in tainted_vars])
        vars_to_check = list(set(tainted_vars)) + farg_vars
        all_vars_to_check.extend(vars_to_check)
        # print('checking_vars : ', [i.name for i in tainted_vars])


        # get tainted_vars that are used for extrernal call contract
        vars_to_check = list(set([var for var in vars_to_check if any([var.name in i for i in ext_contract_vars]) and len(var.name)>0]))
        print('tainted and input vars_to_check : ', [i.name for i in vars_to_check])


        # check if tainted variables are used in conditional statements
        condt_nodes = [
            str(n.expression) for n in function.nodes 
            if n.contains_if() or n.contains_require_or_assert() or '=='in str(n.expression) or '!='in str(n.expression)
        ]
        # print(condt_nodes)

        # print()
        if len(vars_to_check)>0:
            for var in vars_to_check:
                validated = False
                for node in condt_nodes :
                    # print(' => checking: ', node)
                    if var.name in node : 
                        # check for var.mint(), var.name(), , and ignore REGISTRY.legit(<var>)
                        if '.' in node and 'msg.'not in node:
                            node = str(node)
                            var_name_ind = node.find(var.name)
                            node = node[var_name_ind:]
                            f_ind = node.find('.')
                            if f_ind:
                                if not any([node[f_ind:].startswith(i) for i in ['.name(', '.symbol(']]):
                                    continue

                                # if not (('.name(' in node )or( '.symbol(' in node)):
                                #     continue

                        # print('   => Validation Found')
                        validated = True
                        break

                if not validated:
                    if (var.canonical_name, var_to_calls[var.name]) not in unvalidated_var_ext_call:
                        unvalidated_var_ext_call.append((var.canonical_name, var_to_calls[var.name]))
                        print('❌ unvalidated tainted/inp var in calls :', var.name)

                    

        # print('all_vars_to_check', [i.name for i in all_vars_to_check])
        # print('unvalidated_address_ext_call', [i for i in unvalidated_address_ext_call])

        # print()
    return all_vars_to_check, unvalidated_var_ext_call


def update_result(func_name, var_ext_calls:list, result:dict):
    if len(var_ext_calls)>0:
        # var_ext_calls = list(set(var_ext_calls))
        var_calls = []
        for var,calls in var_ext_calls:
            if (var, calls) not in var_calls:
                var_calls.append((var, calls))
        if func_name in result : 
            result[func_name].extend(var_calls)
            # result[func_name] = list(set(list(result[func_name])))
        else:
            result[func_name] = var_calls

        print('✨RESULT: ', result)
    return result


def run(sl):
    ftrace = get_function_trace_with_args_passed(sl)
    result = {}

    for contract in sl.contracts:
        if not(contract.is_interface) and len(contract.derived_contracts)==0:
            for function in contract.functions :
                if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name or function.is_constructor :
                    continue
                if function.visibility not in ['public', 'external'] or function.view :
                    continue
                # if function.view() or  :
                #     continue
                # if 'depositToGasZipERC20' not in function.name :
                #     continue
                # if 'executeAction' not in function.name :
                #     continue    
                
                vars_to_check, unvalidated_var_ext_call = check_input_validation(function)
                # print('✨',unvalidated_var_ext_call)
                result = update_result(function.canonical_name, unvalidated_var_ext_call, result)
                if vars_to_check:
                    print(f'vars_to_check({function.canonical_name}) : {[i.name for i in vars_to_check]}')
                    for func, args_passed in ftrace[function.canonical_name]:
                        # print(func.name)
                        func_args = [i.name for i in func.parameters]
                        # print(func_args)

                        tainted_vars_passed_as_arg = []
                        upd_vars_to_check = []
                        args_passed_var_name = [i.name for i in args_passed]
                        for var in vars_to_check:
                            if var.name in args_passed_var_name:
                                ind = args_passed_var_name.index(var.name)
                                tainted_vars_passed_as_arg.append(func.parameters[ind])
                                upd_vars_to_check.append(func.parameters[ind])
                            else:
                                upd_vars_to_check.append(var)

                        # 'swapData' passed as '_swap' to another func => check for '_swap' 


                        # print(f'{func.name} : {func_args}')
                        if any([i.name in args_passed_var_name for i in vars_to_check]):
                            # print('==>', func.name)
                            # print([i.name for i in vars_to_check])
                            # print([i.name for i in upd_vars_to_check])
                            # print('tainted_vars_passed_as_arg: ', [i.name for i in tainted_vars_passed_as_arg])
                            _, unvalidated_var_ext_call = check_input_validation(func, farg_vars=upd_vars_to_check)
                            # unvalidated_var_ext_call = [i for i in unvalidated_var_ext_call if i[0].split('.')[-1] in tainted_vars_passed_as_arg]
                            result = update_result(function.canonical_name, unvalidated_var_ext_call, result)
                    print()

    result = filter_function_without_proper_access_control(sl, result)
    # print()
    return result
                