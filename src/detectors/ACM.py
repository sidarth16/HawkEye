from src.utils import *

def get_all_msg_sender_funcs(sl):
    msg_sender_funcs = []
    for contract in sl.contracts:
        for function in contract.functions :
            if is_returning_msg_sender(function):
                fname = function.name
                msg_sender_funcs.append(fname)
    return msg_sender_funcs


def run(sl):
    result = {
        "unbounded_admin_mint" : [],
        "public_mint_without_economic_gate" : [],
        "weak_access_control" : []
    }

    #function trace 
    ftrace = get_function_trace(sl)

    msg_sender_funcs = get_all_msg_sender_funcs(sl)
    # print(f'MsgSender funcs : {msg_sender_funcs}\n', )

    mint_funcs = []

    for contract in sl.contracts:
        if  not(contract.is_library) and not(contract.is_interface) and len(contract.derived_contracts)==0:
            for function in contract.functions :
                if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name or function.is_constructor:
                    continue

                if(
                    any(['_mint('.upper() in f.canonical_name.upper() for f in ftrace[function.canonical_name]]) and
                    (function.visibility in ["public", "external"])
                ):
                    mint_funcs.append(function)


    mint_funcs = list(set(mint_funcs))
    # print([i.canonical_name for i in mint_funcs])

    # Run Checks on admin funcs 
    for func in mint_funcs:
        if func.contract_declarer.is_interface:
            continue
        
        print(func.canonical_name)

        msg_sender_checks = []
        condt_nodes = []
        modifiers = []

        funcs_to_check = [func] + ftrace[func.canonical_name]
        # print([i.canonical_name for i in funcs_to_check])
        for fobj in funcs_to_check:
            msg_sender_checks.extend(get_msg_sender_checks(fobj, msg_sender_funcs))
            condt_nodes.extend(get_all_conditional_nodes(fobj))
            modifiers.extend([i.name for i in fobj.modifiers])

        # print(msg_sender_checks)

        if len(msg_sender_checks)>0  : 
            weak_AC_checks = [
                i for i in msg_sender_checks 
                    if (('tx.origin' in i)or('isContract(' in i))or(('!=' in i)and('require' in i))
            ]
            if len(weak_AC_checks) == len(msg_sender_checks):
                print("❌  Weak Access Control Checks")
                result['weak_access_control'].append(func.canonical_name)
            # else:
            # print("✅ Proper Access Control Checking Done")
            
            # check for unbounded admin mint
            unbounded_mint = True
            if any(['SUPPLY' in i.upper() or 'CAP' in i.upper() for i in condt_nodes]): #totalSupply() / cap() [ERC20 Capped]
                unbounded_mint = False

            if unbounded_mint: 
                print('❌ High Risk: Unbounded Admin Mint in ',func.canonical_name)
                result['unbounded_admin_mint'].append(func.canonical_name)
        
        # modifiers Role based and Owner Based or has Only-admin/owner/...
        elif any(['ROLE' in i.upper() or 'OWNER' in i.upper() or 'ONLY' in i.upper() for i in modifiers]):
            print("✅ Proper Access Control Checking Done")

        else:
            print("❌ High Risk: No Access Control Checks")
            # check for economic gate in PUBLIC MINT
            economic_gate = False
            if(
                (func.payable and 
                any(['MSG.VALUE' in i.upper() for i in condt_nodes])) or 
                any(['DEPOSIT' in i.upper() for i in condt_nodes])  # TODO: more conditionals key to add

            ): 
                economic_gate = True
                print('✅ Economic Gate in public Mint in ',func.canonical_name)
            if not economic_gate: 
                print('❌ High Risk: No Economic Gate in public Mint in ',func.canonical_name)
                result['public_mint_without_economic_gate'].append(func.canonical_name)


        print()
    return result
                        
