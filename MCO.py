from slither.slither import Slither

def run(sl:Slither):
    result = {
        "vault_core" : [],
        "token" : [],
        "upgrade" : [],
        "access_role" : [],
    }

    CONTRACTS_KEY = ["ERC4626", "ERC20", "Ownable", "UUPSUpgradeable", "BeaconProxy", "TransparentUpgradeableProxy"]
    FUNCTIONS_KEY = [
        "deposit", "redeem", "withdraw",
        "mint", "burn", "update", 
        "upgradeTo", "upgradeToAndCall", "initialize",
        "grantRole", "revokeRole", "setRoleAdmin"    
    ]

    for contract in sl.contracts:
        if  not(contract.is_library) and not(contract.is_interface) and len(contract.derived_contracts)==0:
            for function in contract.functions :
                if 'slitherConstructorConstantVariables' in function.name or 'slitherConstructorVariables' in function.name :
                    continue
                if function.visibility not in ["public", "external"] :
                    continue

                fname = function.name
                matched_keys = [i for i in CONTRACTS_KEY if function.contract_declarer.name.startswith(i)]
                if len(matched_keys)>0:
                    # print(function.canonical_name, any([i in function.name for i in FUNCTIONS_KEY ]), len(function.overridden_by)==0) 
                    if any([i in function.name for i in FUNCTIONS_KEY ]) and len(function.overridden_by)==0:
                        # missing_override_funcs.append(function.canonical_name)
                        for key in matched_keys:
                            if key in ['ERC4626']: 
                                if function.canonical_name not in result['vault_core']:
                                    result['vault_core'].append(function.canonical_name)
                            if key in ['ERC20']: 
                                if function.canonical_name not in result['token']:
                                    result['token'].append(function.canonical_name)
                            if key in ['"UUPSUpgradeable", "BeaconProxy", "TransparentUpgradeableProxy"']:
                                if function.canonical_name not in result['upgrade']:
                                    result['upgrade'].append(function.canonical_name)
                            if key in ['Ownable']: 
                                if function.canonical_name not in result['access_role']:
                                    result['access_role'].append(function.canonical_name)
                            
                        print(function.canonical_name, ':', [i for i in FUNCTIONS_KEY if i in function.name] )
                        print("❌ High Risk: Critical Function not Overriden and is Exposed")

    return result
                        
