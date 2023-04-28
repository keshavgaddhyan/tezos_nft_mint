import smartpy as sp

# Types #

t_operator_permission = sp.TRecord(
    owner=sp.TAddress, operator=sp.TAddress, token_id=sp.TNat
).layout(("owner", ("operator", "token_id")))

t_update_operators_params = sp.TList(
    sp.TVariant(
        add_operator=t_operator_permission, remove_operator=t_operator_permission
    )
)

t_transfer_batch = sp.TRecord(
    from_=sp.TAddress,
    txs=sp.TList(
        sp.TRecord(
            to_=sp.TAddress,
            token_id=sp.TNat,
            amount=sp.TNat,
        ).layout(("to_", ("token_id", "amount")))
    ),
).layout(("from_", "txs"))

t_transfer_params = sp.TList(t_transfer_batch)

t_balance_of_request = sp.TRecord(owner=sp.TAddress, token_id=sp.TNat).layout(
    ("owner", "token_id")
)

t_balance_of_response = sp.TRecord(
    request=t_balance_of_request, balance=sp.TNat
).layout(("request", "balance"))

t_balance_of_params = sp.TRecord(
    callback=sp.TContract(sp.TList(t_balance_of_response)),
    requests=sp.TList(t_balance_of_request),
).layout(("requests", "callback"))

# Policies #

class OwnerOrOperatorTransfer:
    """(Transfer Policy) Only owner and operators can transfer tokens.

    Operators allowed.
    """

    def init_policy(self, contract):
        self.name = "owner-or-operator-transfer"
        self.supports_transfer = True
        self.supports_operator = True
        contract.update_initial_storage(
            operators=sp.big_map(tkey=t_operator_permission, tvalue=sp.TUnit)
        )

    def check_tx_transfer_permissions(self, contract, from_, to_, token_id):
        sp.verify(
            (sp.sender == from_)
            | contract.data.operators.contains(
                sp.record(owner=from_, operator=sp.sender, token_id=token_id)
            ),
            message="FA2_NOT_OPERATOR",
        )

    def check_operator_update_permissions(self, contract, operator_permission):
        sp.verify(operator_permission.owner == sp.sender, "FA2_NOT_OWNER")

    def is_operator(self, contract, operator_permission):
        return contract.data.operators.contains(operator_permission)
    
# Common #

class Common(sp.Contract):
    """Common logic between Fa2Nft, Fa2Fungible and Fa2SingleAsset."""

    def __init__(self, policy=None, metadata_base=None, token_metadata={}):
        if policy is None:
            self.policy = OwnerOrOperatorTransfer()
        else:
            self.policy = policy
        self.update_initial_storage(
            token_metadata=sp.big_map(
                token_metadata,
                tkey=sp.TNat,
                tvalue=sp.TRecord(
                    token_id=sp.TNat, token_info=sp.TMap(sp.TString, sp.TBytes)
                ).layout(("token_id", "token_info")),
            )
        )
        self.policy.init_policy(self)
        self.generate_contract_metadata("metadata_base", metadata_base)

    def is_defined(self, token_id):
        return self.data.token_metadata.contains(token_id)

    def generate_contract_metadata(self, filename, metadata_base=None):
        """Generate a metadata json file with all the contract's offchain views
        and standard TZIP-126 and TZIP-016 key/values."""
        if metadata_base is None:
            metadata_base = {
                "name": "FA2 contract",
                "version": "1.0.0",
                "description": "This implements FA2 (TZIP-012) using SmartPy.",
                "interfaces": ["TZIP-012", "TZIP-016"],
                "authors": ["SmartPy <https://smartpy.io/#contact>"],
                "homepage": "https://smartpy.io/ide?template=FA2.py",
                "source": {
                    "tools": ["SmartPy"],
                    "location": "https://gitlab.com/SmartPy/smartpy/-/raw/master/python/templates/FA2.py",
                },
                "permissions": {"receiver": "owner-no-hook", "sender": "owner-no-hook"},
            }
        offchain_views = []
        for f in dir(self):
            attr = getattr(self, f)
            if isinstance(attr, sp.OnOffchainView):
                if attr.kind == "offchain":
                    offchain_views.append(attr)
        metadata_base["views"] = offchain_views
        metadata_base["permissions"]["operator"] = self.policy.name
        self.init_metadata(filename, metadata_base)

    def balance_of_batch(self, requests):
        """Mapping of balances."""
        sp.set_type(requests, sp.TList(t_balance_of_request))

        def f_process_request(req):
            sp.result(
                sp.record(
                    request=req,
                    balance=self.balance_(req.owner, req.token_id),
                )
            )

        return requests.map(f_process_request)

    # Entry points

    @sp.entry_point
    def update_operators(self, batch):
        """Accept a list of variants to add or remove operators who can perform
        transfers on behalf of the owner."""
        sp.set_type(batch, t_update_operators_params)
        if self.policy.supports_operator:
            with sp.for_("action", batch) as action:
                with action.match_cases() as arg:
                    with arg.match("add_operator") as operator:
                        self.policy.check_operator_update_permissions(self, operator)
                        self.data.operators[operator] = sp.unit
                    with arg.match("remove_operator") as operator:
                        self.policy.check_operator_update_permissions(self, operator)
                        del self.data.operators[operator]
        else:
            sp.failwith("FA2_OPERATORS_UNSUPPORTED")

    @sp.entry_point
    def balance_of(self, params):
        """Send the balance of multiple account / token pairs to a callback
        address.

        `balance_of_batch` must be defined in the child class.
        """
        sp.set_type(params, t_balance_of_params)
        sp.transfer(
            self.balance_of_batch(params.requests), sp.mutez(0), params.callback
        )

    @sp.entry_point
    def transfer(self, batch):
        """Accept a list of transfer operations between a source and multiple
        destinations.

        `transfer_tx_` must be defined in the child class.
        """
        sp.set_type(batch, t_transfer_params)
        if self.policy.supports_transfer:
            with sp.for_("transfer", batch) as transfer:
                with sp.for_("tx", transfer.txs) as tx:
                    # The ordering of sp.verify is important: 1) token_undefined, 2) transfer permission 3) balance
                    sp.verify(self.is_defined(tx.token_id), "FA2_TOKEN_UNDEFINED")
                    self.policy.check_tx_transfer_permissions(
                        self, transfer.from_, tx.to_, tx.token_id
                    )
                    with sp.if_(tx.amount > 0):
                        self.transfer_tx_(transfer.from_, tx)
        else:
            sp.failwith("FA2_TX_DENIED")

    # Offchain views

    @sp.offchain_view(pure=True)
    def all_tokens(self):
        """OffchainView: Return the list of all the token IDs known to the contract."""
        sp.result(sp.range(0, self.data.last_token_id))

    @sp.offchain_view(pure=True)
    def is_operator(self, params):
        """Return whether `operator` is allowed to transfer `token_id` tokens
        owned by `owner`."""
        sp.set_type(params, t_operator_permission)
        sp.result(self.policy.is_operator(self, params))

    @sp.offchain_view(pure=True)
    def get_balance(self, params):
        """Return the balance of an address for the specified `token_id`."""
        sp.set_type(
            params,
            sp.TRecord(owner=sp.TAddress, token_id=sp.TNat).layout(
                ("owner", "token_id")
            ),
        )
        sp.result(self.balance_(params.owner, params.token_id))

    @sp.offchain_view(pure=True)
    def total_supply(self, params):
        """Return the total number of tokens for the given `token_id`."""
        sp.verify(self.is_defined(params.token_id), "FA2_TOKEN_UNDEFINED")
        sp.result(sp.set_type_expr(self.supply_(params.token_id), sp.TNat))

# Base classes #

class Fa2Nft(Common):
    """Base class for a FA2 NFT contract.

    Respects the FA2 standard.
    """

    ledger_type = "NFT"

    def __init__(
        self, metadata, token_metadata=[], ledger={}, policy=None, metadata_base=None
    ):
        ledger, token_metadata = self.initial_mint(token_metadata, ledger)
        self.init(
            ledger=sp.big_map(ledger, tkey=sp.TNat, tvalue=sp.TAddress),
            metadata=sp.set_type_expr(metadata, sp.TBigMap(sp.TString, sp.TBytes)),
            last_token_id=sp.nat(len(token_metadata)),
        )
        Common.__init__(
            self,
            policy=policy,
            metadata_base=metadata_base,
            token_metadata=token_metadata,
        )

    def initial_mint(self, token_metadata=[], ledger={}):
        """Perform a mint before the origination.

        Returns `ledger` and `token_metadata`.
        """
        token_metadata_dict = {}
        for token_id, metadata in enumerate(token_metadata):
            token_metadata_dict[token_id] = sp.record(
                token_id=token_id, token_info=metadata
            )
        for token_id, address in ledger.items():
            if token_id not in token_metadata_dict:
                raise Exception(
                    "Ledger contains token_id with no corresponding metadata"
                )
        return (ledger, token_metadata_dict)

    def balance_(self, owner, token_id):
        sp.verify(self.is_defined(token_id), "FA2_TOKEN_UNDEFINED")
        return sp.eif(self.data.ledger[token_id] == owner, 1, 0)

    def supply_(self, token_id):
        sp.verify(self.is_defined(token_id), "FA2_TOKEN_UNDEFINED")
        return sp.nat(1)

    def transfer_tx_(self, from_, tx):
        sp.verify(
            (tx.amount == 1) & (self.data.ledger[tx.token_id] == from_),
            message="FA2_INSUFFICIENT_BALANCE",
        )
        # Do the transfer
        self.data.ledger[tx.token_id] = tx.to_

# Mixins #

class Admin:
    """(Mixin) Provide the basics for having an administrator in the contract.

    Adds an `administrator` attribute in the storage record. Provides a
    `set_administrator` entrypoint. Provides a `is_administrator` meta-
    programming function.
    """

    def __init__(self, administrator):
        self.update_initial_storage(administrator=administrator)

    def is_administrator(self, sender):
        return sender == self.data.administrator

    @sp.entry_point
    def set_administrator(self, params):
        """(Admin only) Set the contract administrator."""
        sp.verify(self.is_administrator(sp.sender), message="FA2_NOT_ADMIN")
        self.data.administrator = params


class ChangeMetadata:
    """(Mixin) Provide an entrypoint to change contract metadata.

    Requires the `Admin` mixin.
    """

    @sp.entry_point
    def set_metadata(self, metadata):
        """(Admin only) Set the contract metadata."""
        sp.verify(self.is_administrator(sp.sender), message="FA2_NOT_ADMIN")
        self.data.metadata = metadata

# Helpers #

def make_metadata(symbol, name, decimals):
    """Helper function to build metadata JSON bytes values."""
    return sp.map(
        l={
            "decimals": sp.utils.bytes_of_string("%d" % decimals),
            "name": sp.utils.bytes_of_string(name),
            "symbol": sp.utils.bytes_of_string(symbol),
        }
    )

# CODE #

class Nft(Fa2Nft, Admin, ChangeMetadata):
    def __init__(self, admin, **kwargs):
        Fa2Nft.__init__(self, **kwargs)
        Admin.__init__(self, admin)
        
    @sp.entry_point
    def mint(self, owner, token_info):
        sp.verify(self.is_administrator(sp.sender), "FA2_NOT_ADMIN")
        token_id = self.data.last_token_id
        self.data.ledger[token_id] = owner
        self.data.token_metadata[token_id] = sp.record(
            token_id=token_id, token_info=token_info
        )

        self.data.last_token_id += 1
        
    @sp.offchain_view()
    def get_usage(self, token_id):
        token_info = self.data.token_metadata[token_id].token_info
        usage = sp.unpack(token_info["usage"], sp.TIntOrNat).open_some()
        sp.result(usage)
    
    @sp.entry_point
    def update_usage(self, token_id):
        token_info = self.data.token_metadata[token_id].token_info
        usage = sp.unpack(token_info["usage"], sp.TIntOrNat).open_some()
        usage +=1
        self.data.token_metadata[token_id].token_info["usage"] = sp.pack(usage)
    

    @sp.offchain_view()
    def get_owner(self, token_id):
         sp.result(self.data.ledger[token_id])

# TEST #

@sp.add_test(name="NFT TEST")
def test():
    sc =  sp.test_scenario()
    tanoy=sp.address("tz1Vf4cQ6dcywPXVY6QZnsMELEzXNSX9yMxL")
    abby=sp.address("tz1PaBo1wAwoSipwW2ubbotpywAZaPuC3oQ9")

    metadata_base = {
    "name": "NFT Contract",
    "version": "1.0.0",
    "description": "This implements the NFT contract for Pirata",
    "interfaces": ["TZIP-012", "TZIP-016"],
    "authors": ["Keshav Gaddhyan"],
    "homepage": "",
    "source": {
        "tools": ["SmartPy"],
        "location": "https://gitlab.com/SmartPy/smartpy/-/raw/master/python/templates/FA2.py",
    },
    "permissions": {"receiver": "owner-no-hook", "sender": "owner-no-hook"},
    }
    
    nft_pirata = Nft(admin=abby, metadata=sp.utils.metadata_of_url(
        "ipfs://QmRbmXcd2yfNVdgHL7oYWS2yd3tztr2NZiqP2LFuw3voPW"), metadata_base=metadata_base)
    
    sc += nft_pirata


    sc.show(sp.record(tanoy=tanoy, abby=abby))
    
    sc.h2("Mint")
    nft_pirata.mint(
        owner=tanoy,
        token_info = sp.map({
            "": sp.utils.bytes_of_string("ipfs://QmTKHffrVCKda3WKs1qyyJna7EjHM5Wdzf3LJVeejgaz61"),
            "usage": sp.pack(0)
        })
    ).run(sender=abby)
    sc.verify(nft_pirata.data.ledger[0] == tanoy)

    sc.h2("Transfer")
    nft_pirata.transfer(
        [
            sp.record(
                from_=tanoy,
                txs=[sp.record(to_=abby, amount=1, token_id=0)],
            ),
        ]
    ).run(sender=tanoy)

    sc.verify(nft_pirata.data.ledger[0] == abby)

    sc.h2("Transfer")
    nft_pirata.transfer(
        [
            sp.record(
                from_=tanoy,
                txs=[sp.record(to_=abby, amount=1, token_id=0)],
            ),
        ]
    ).run(sender=tanoy, valid=False, exception="FA2_INSUFFICIENT_BALANCE")

    sc.h2("Check owner")
    sc.verify((nft_pirata.get_owner(0)) == abby)
    sc.show(nft_pirata.get_owner(0))
    
    sc.h2("Update usage")
    nft_pirata.update_usage(0).run(sender=tanoy)

    sc.h2("Check usage")
    sc.verify(nft_pirata.get_usage(0) == 1)
    sc.show(nft_pirata.get_usage(0))


# DEPLOYMENT #

# sp.add_compilation_target("Pirata Contract",Nft(admin=sp.address("tz1gAnLW5sqkT8qn1sY8pzP6NGAGkbhm8fG1"), metadata=sp.utils.metadata_of_url("ipfs://QmRbmXcd2yfNVdgHL7oYWS2yd3tztr2NZiqP2LFuw3voPW")))
