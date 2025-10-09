from utils import *

ADMIN_FUNC_KEYWORDS = {
    # AC-001: Unvalidated Admin/Governance Updates (callable by anyone)
    'root' : ['update', 'set', 'remove'],
    'merkle' : ['update', 'set', 'remove'],
    'hash' : ['update', 'set', 'remove'],
    'secret' : ['update', 'set', 'remove'],
    'config' : ['update', 'set', 'remove'],
    'router' : ['update', 'set', 'remove'],
    'oracle' : ['update', 'set', 'remove'],
    'owner' : ['set', 'update', 'transfer', 'remove', 'renounce'],
    'admin' : ['set', 'update', 'transfer', 'remove', 'renounce'],
    'role' : ['set', 'update', 'remove', 'renounce'],


    # AC-002: Unvalidated Upgrade/init functions (callable by anyone)
    'implementation' : ['update', 'set', 'remove'],
    'upgrade' : ['to'],
    

    # AC-003: Unvalidated Flashloan/Callback Entrypoints (Without Caller Validation)
    'executeOperation' : [''], #AAVE callback
    'callFunction' : [''] , #dYdX callback
    'flashloan' : ['on', 'receive', '3156', 'execute']
    
}


def update_result(fname:str, category:str, result:dict, state_meta:dict):
    if (category in result) and fname:
        if fname in state_meta:
            result[category].append( (set(state_meta[fname]), fname) )
        else:
            result[category].append( ((''),fname))
    return result


def run(sl:Slither):
    result = {
        'no_AC_checks': [],
        # 'improper_AC_state' : [],
        'weak_AC_checks' : []
    }
    state_meta = {}    #Map functions with admin state_var being updated

    #function trace 
    ftrace = get_function_trace(sl)

    msg_sender_funcs = []
    for contract in sl.contracts:
        for function in contract.functions :
            if is_returning_msg_sender(function):
                fname = function.name
                # print(fname)
                msg_sender_funcs.append(fname)
    # print('MsgSender funcs : ', msg_sender_funcs)

    admin_funcs = []

    for contract in sl.contracts:
        if not(contract.is_interface) and len(contract.derived_contracts)==0:

            for function in contract.functions :
                if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name or function.is_constructor :
                    continue
                fname = function.name

                # get admin funcs that are public / external
                for key in ADMIN_FUNC_KEYWORDS:
                    # print(key)
                    if(
                        (key.upper() in fname.upper()) and 
                        any([i.upper() in fname.upper() for i in ADMIN_FUNC_KEYWORDS[key]]) and
                        (function.visibility in ["public", "external"])
                    ):
                        # print()
                        # print(fname)
                        # print(function.visibility)
                        # print(get_msg_sender_checks(function, msg_sender_funcs))
                        admin_funcs.append(function)

                # check admin state variables written       
                all_state_vars_written = [i for i in function.state_variables_written if not(i.is_immutable or i.is_constant)]
                admin_state_vars_written = [
                    i.canonical_name for i in all_state_vars_written 
                        if any([key.upper() in i.name.upper() for key in ADMIN_FUNC_KEYWORDS.keys()]) 
                ]
                if admin_state_vars_written:
                    # print(fname)
                    # print(admin_state_vars_written)
                    if function.visibility in ["public", "external"]:
                        admin_funcs.append(function)
                        # update to state-meta
                        if function.canonical_name in state_meta:
                            state_meta[function.canonical_name].extend(admin_state_vars_written)
                        else:
                            state_meta[function.canonical_name] = admin_state_vars_written

                    admin_funcs.extend(
                        [i for i in list(function.all_reachable_from_functions) if i.visibility in ["public", "external"]]
                    )
                

    admin_funcs = list(set(admin_funcs))
    # print([i.name for i in admin_funcs])

    # Run Checks on admin funcs 
    for func in admin_funcs:
        if func.contract_declarer.is_interface :
            continue
        fname = func.canonical_name
        print(fname)
        msg_sender_checks = []
        modifiers = []

        funcs_to_check = [func] + ftrace[func.canonical_name]
        # print([i.canonical_name for i in funcs_to_check])
        for fobj in funcs_to_check:
            msg_sender_checks.extend(get_msg_sender_checks(fobj, msg_sender_funcs))
            modifiers.extend([i.name for i in fobj.modifiers])
        print('Access Control Checks: ' , msg_sender_checks)

        if len(msg_sender_checks)>0  : 
            weak_AC_checks = [i for i in msg_sender_checks if (('tx.origin' in i)or('isContract(' in i))or(('!=' in i)and('require' in i))]
            
            # blacklist_checks = [i for i in msg_sender_checks if (('!=' in i)and('require' in i))]
            # if len(blacklist_checks) == len(msg_sender_checks):
            #     print("❌  Improper Access Control Checks: Only Blacklisting  Mechanism Found")
            #     result['weak_AC_checks'].append(fname)

            if len(weak_AC_checks) == len(msg_sender_checks):
                print("❌  Improper Access Control Checks: Only Blacklisting  Mechanism Found")
                # result['weak_AC_checks'].append(fname)
                result = update_result(fname, 'weak_AC_checks',  result, state_meta)
                print('✨Result : ',result) 
            else:
                print("✅ Proper Access Control Checking Done")

        # modifiers Role based and Owner Based or has Only-admin/owner/...
        elif any(['ROLE' in i.upper() or 'OWNER' in i.upper() or 'ONLY' in i.upper() for i in modifiers]):
            print("✅ Proper Access Control Checking Done")

        else:
            print("❌ High Risk: No Access Control Checks")
            # result['no_AC_checks'].append(fname)
            result = update_result(fname, 'no_AC_checks',  result, state_meta)

        print()
                        
    print("detector script completed")
    return result
