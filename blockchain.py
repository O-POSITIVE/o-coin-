"""The actual chain: blocks linked by hash, proof-of-work mining, and full
chain validation. This is a real, working blockchain in the literal
technical sense — not a database table pretending to be one. Every block
genuinely has to satisfy a computationally-expensive proof-of-work
condition to be accepted, and the chain can be independently re-verified
by anyone from scratch, from genesis, using nothing but is_chain_valid().

Deliberately built lean rather than as a fork of Bitcoin/Dogecoin/Litecoin's
own C++ codebase (see O-coin/README.md for the full reasoning and the
roadmap toward that heavier infrastructure later) — no real P2P discovery
protocol yet (node.py's /nodes/register + /nodes/resolve are a genuine
"longest valid chain wins" consensus implementation, just without
automatic peer discovery — peers are added by hand for now); real Scrypt
mining IS implemented (see Block.compute_hash), same algorithm and same
real parameters Litecoin/Dogecoin use, not a placeholder.

Four upgrades baked in from the start rather than retrofitted later, in
answer to "cheap, fast, efficient, secure":
  - CHEAP: transactions carry a small FEE (see transaction.py), kept
    deliberately tiny by design — the "low gas price" lever.
  - FAST: difficulty RETARGETS toward a short target block time (see
    _maybe_retarget) — the same mechanism every real PoW chain uses to
    keep block times roughly constant as total mining power on the
    network rises and falls. TARGET_BLOCK_TIME is 15 seconds on purpose —
    Dogecoin-fast, not Bitcoin-slow.
  - EFFICIENT: miners fill a block with the HIGHEST-FEE pending
    transactions first (see build_candidate_block) rather than
    first-in-first-out, so limited block space always goes to whoever's
    actually paying for priority, same as every real fee market.
  - SECURE: every transaction is individually signed with real ECDSA
    (see transaction.py, same curve family Bitcoin uses) and every
    block's entire transaction set is committed to by a Merkle root, so
    tampering with ANYTHING — a single transaction's amount, a
    signature, a whole block — breaks a hash chain that's cheap to
    verify and computationally expensive to fake. is_chain_valid() is
    the "trust nothing, verify everything from genesis" function that
    makes this a real guarantee rather than a promise.
"""
import hashlib
import json
import time

from pow_hash import header_fields_to_hash

from transaction import Transaction


class Block:
    def __init__(self, index, transactions, previous_hash, target, timestamp=None, nonce=0, staker_address=None):
        self.index = index
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions  # list[Transaction]
        self.previous_hash = previous_hash
        # Stored ON the block (not just read from the chain's current
        # difficulty) so historical blocks stay independently verifiable
        # even after later retargets change what "valid" means for NEW
        # blocks — is_chain_valid() checks each block against the target
        # IT recorded, never against today's target. Means two different
        # things depending on the block: a PoW difficulty target for a
        # mined block, or a PoS difficulty target for a staked one (see
        # staker_address) — never both, only one production method wins
        # per block.
        self.target = target
        self.nonce = nonce
        # None for an ordinary mined (PoW) block. A real address for a
        # STAKED (PoS) block — set, this block wasn't found by brute-force
        # hashing at all, it was minted by this address demonstrating
        # ownership of a large-enough, long-enough-untouched balance (see
        # compute_stake_kernel_hash and Blockchain.build_stake_block).
        self.staker_address = staker_address
        self.merkle_root = self.compute_merkle_root()

    def compute_merkle_root(self):
        """A simplified Merkle tree: pair up transaction hashes and hash
        each pair together, repeating until one hash remains. This is
        what lets a block commit to its *entire* transaction set with a
        single fixed-size hash — tampering with any one transaction
        anywhere in the block changes this root, which changes the
        block's own hash, which breaks every block after it (see
        Blockchain.is_chain_valid). An empty block (genesis) gets a
        root of all zeros.
        """
        if not self.transactions:
            return "0" * 64
        layer = [tx.hash() for tx in self.transactions]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])  # odd one out pairs with itself
            layer = [
                hashlib.sha256((layer[i] + layer[i + 1]).encode()).hexdigest()
                for i in range(0, len(layer), 2)
            ]
        return layer[0]

    def header_string(self):
        # Exactly what gets hashed for proof-of-work — deliberately just
        # the header fields (not the full transaction list), same as real
        # chains: the merkle_root already commits to the transactions, so
        # re-hashing the whole transaction list on every nonce attempt
        # during mining would be needless repeated work.
        return json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "target": self.target,
            "nonce": self.nonce,
        }, sort_keys=True)

    def compute_hash(self):
        # Real, ASIC-resistant Scrypt PoW hash — see pow_hash.py's own
        # docstring for the full reasoning. Shared with miner.py's local
        # search loop via that one module specifically so the two can
        # never silently drift out of sync with each other.
        return header_fields_to_hash(self.index, self.timestamp, self.merkle_root, self.previous_hash, self.target, self.nonce)

    def meets_target(self):
        return int(self.compute_hash(), 16) < self.target

    def compute_stake_kernel_hash(self):
        """The proof-of-STAKE equivalent of compute_hash()/meets_target()
        — but deliberately NOT the same (Scrypt, memory-hard, meant to be
        slow-ish) hash used for PoW search. There's no brute-force search
        happening here at all: plain, fast SHA-256 over previous_hash +
        staker_address + the CURRENT SECOND (int(timestamp), floored —
        not sub-second precision) is exactly the point. A staker gets
        ONE kernel value per second, full stop, because the input space
        is just "which second is it" — there's no nonce field to grind
        through here, so waiting for real wall-clock time to pass is the
        only way to get a new attempt. That's what stops proof-of-stake
        from secretly becoming a second proof-of-COMPUTE race for
        whoever has the fastest CPU: your odds of success scale with
        your stake weight (see Blockchain.build_stake_block /
        _validate_stake_proof), never with how many hashes you can crunch
        per second, because you only ever get one shot per second no
        matter how fast your machine is."""
        s = f"{self.previous_hash}{self.staker_address}{int(self.timestamp)}"
        return hashlib.sha256(s.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index, "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash, "target": self.target, "nonce": self.nonce,
            "staker_address": self.staker_address,
            "merkle_root": self.merkle_root, "hash": self.compute_hash(),
        }

    @staticmethod
    def from_dict(d):
        return Block(
            d["index"], [Transaction.from_dict(t) for t in d["transactions"]],
            d["previous_hash"], d["target"], d["timestamp"], d["nonce"],
            staker_address=d.get("staker_address"),
        )


class Blockchain:
    # Starting target: a block hash (treated as a 256-bit number) has to
    # come out below this to be valid. Tuned specifically for Scrypt's
    # real, much-slower-than-SHA-256 rate — that's the entire point of
    # using it, but it means the difficulty that felt right for a plain
    # SHA-256 chain would be wildly too hard here. Benchmarked
    # hashlib.scrypt at these exact parameters in this environment: ~4000
    # hashes/sec on one CPU core. 2**256 // 2**13 needs on average 2**13
    # (~8,200) attempts — a couple of seconds at that rate, easy enough
    # for the first blocks to come quickly, with _maybe_retarget() taking
    # over from there. Matches how Speepcoin's own starting difficulty was
    # deliberately picked easy (see contracts/Speepcoin.sol) for the same
    # reason: don't make early miners sit idle for ages before the
    # network's real difficulty has ever been calibrated.
    INITIAL_TARGET = 2 ** 256 // 2 ** 13
    MAX_TARGET = 2 ** 256 // 2 ** 8  # retargeting can never make it easier than this, same ceiling idea Speepcoin's contract uses
    TARGET_BLOCK_TIME = 15  # seconds — short and Dogecoin-fast on purpose, not Bitcoin-slow
    RETARGET_INTERVAL = 10  # re-check every 10 blocks
    MAX_ADJUSTMENT_FACTOR = 4  # difficulty can at most 4x or /4 in one retarget, same anti-whiplash cap Speepcoin's contract uses

    # ── Emission curve — smooth EXPONENTIAL decay toward a permanent
    # floor, not Bitcoin/Dogecoin-style discrete halving and not a
    # straight linear ramp either (an earlier version of this file used a
    # linear ramp — replaced because a reward that flattens out completely
    # stops responding to anything and stagnates; a reward that keeps
    # shrinking forever, geometrically, stays "alive" — always a little
    # smaller than last year, same as a dollar's real purchasing power —
    # while a floor (REWARD_FLOOR) still guarantees miners will always be
    # paid something, so the chain never has to defend itself on
    # transaction fees alone once emission gets small).
    #
    # The DECAY RATE itself isn't arbitrary: it's set to shrink the
    # reward by ANNUAL_DECAY_PERCENT (currently 3%) of its distance above
    # the floor every ~year of blocks — 3% because that's the commonly
    # cited long-run historical average for US CPI inflation (the Fed's
    # explicit modern target is 2%; 3% is the broader ~100-year average).
    # The idea: block reward should lose "real" value at roughly the same
    # pace the dollar does, rather than at some unrelated made-up rate.
    # This is a judgment call, not a law of nature — ANNUAL_DECAY_PERCENT
    # is a single named constant specifically so it's easy to revisit if
    # actual inflation data suggests a different long-run number later.
    #
    # Consensus-critical code can't use raw floating-point exponentiation
    # (math.pow/** with a fractional exponent) — libm implementations
    # aren't guaranteed bit-identical across platforms for transcendental
    # functions, so two perfectly honest nodes could compute two
    # different "correct" rewards for the same height and fork over
    # nothing. Fixed-point exponentiation-by-squaring (_fixed_pow below)
    # solves this the same way real on-chain compound-interest/decay math
    # is done in Solidity DeFi (e.g. ABDKMath64x64): the per-block decay
    # ratio is pre-derived ONCE, offline (see the comment above
    # REWARD_DECAY_RATE_FIXED), baked in as a fixed integer literal, and
    # every node then only ever does integer multiply/shift — no library
    # transcendental call anywhere in the actual per-block calculation.
    BASE_REWARD = 100
    REWARD_FLOOR = 0.5  # the permanent asymptote — reward gets arbitrarily close to this but is mathematically incapable of ever reaching or crossing it
    FRAC_BITS = 64  # fixed-point precision used for the decay math below (Q0.64 — values are integers representing value * 2**64)
    ANNUAL_DECAY_PERCENT = 3  # documented above — long-run US CPI average, not the Fed's 2% target, chosen for a "long set period of time" per the design brief

    # REWARD_DECAY_RATE_FIXED is DERIVED from ANNUAL_DECAY_PERCENT and
    # TARGET_BLOCK_TIME — it is not itself an independent knob. It's kept
    # as a hardcoded integer literal (rather than computed fresh at
    # import time) specifically so no node ever runs a floating-point
    # transcendental function as part of starting up its consensus logic
    # — see the class docstring above for why that matters. The tradeoff
    # is that changing ANNUAL_DECAY_PERCENT or TARGET_BLOCK_TIME requires
    # regenerating this literal by hand; the self-check right after this
    # class (using _derive_rate_fixed, a dev-only helper) exists
    # specifically to catch anyone who tunes one without the other —
    # it'll refuse to start with a clear regenerate-it-like-this message
    # instead of silently running a curve that doesn't match its own
    # documented decay rate.
    REWARD_DECAY_RATE_FIXED = 18446743806639241216

    # Minted directly into genesis, before any mining happens — a
    # deliberate, one-time, fully transparent allocation (see
    # README/commit history for exactly who and how much and why), not
    # something that can be added later without every node agreeing to a
    # rule change. Real precedent for minting supply at genesis rather
    # than starting from zero: XRP Ledger's entire supply was created
    # this way. sender="0" (the same coinbase convention used for every
    # mining reward) since these coins are also being newly created, not
    # transferred from an existing balance.
    GENESIS_PREMINE_ADDRESS = "3b770ab425c217f6615442fcc0517ad8445cf4ba"
    GENESIS_PREMINE_AMOUNT = 5_000_000_000

    @staticmethod
    def _derive_rate_fixed(annual_decay_percent, target_block_time, frac_bits=64):
        """Dev-only — recomputes what REWARD_DECAY_RATE_FIXED *should* be
        for the given ANNUAL_DECAY_PERCENT/TARGET_BLOCK_TIME. Uses plain
        floating-point math (math.pow with a fractional exponent), which
        is exactly what reward_at_height() is NOT allowed to do — the
        difference is this function's result never decides whether a
        block is valid, it's only ever compared against the hardcoded
        REWARD_DECAY_RATE_FIXED literal as a staleness check (see below
        the class), or run by hand after deliberately tuning the decay
        rate/block time to get the new literal to paste in."""
        seconds_per_year = 365.25 * 24 * 3600
        blocks_per_year = seconds_per_year / target_block_time
        r_annual = 1 - annual_decay_percent / 100
        r_block = r_annual ** (1 / blocks_per_year)
        return round(r_block * (1 << frac_bits))

    @staticmethod
    def _fixed_pow(base_fixed, exponent, frac_bits=64):
        """base_fixed ** exponent, computed entirely in fixed-point
        integer math via exponentiation by squaring (O(log exponent)
        multiplications, each immediately truncated back down to
        frac_bits so intermediate values never grow unbounded). No float,
        no library transcendental call — same integer result on every
        machine, every time, for the same inputs."""
        result = 1 << frac_bits  # 1.0 in fixed point
        b = base_fixed
        while exponent > 0:
            if exponent & 1:
                result = (result * b) >> frac_bits
            b = (b * b) >> frac_bits
            exponent >>= 1
        return result

    @classmethod
    def reward_at_height(cls, height):
        """Exponential decay from BASE_REWARD toward REWARD_FLOOR — gets
        arbitrarily close, never reaches or crosses it. See the class
        docstring block above for why this replaced a straight linear
        ramp, and why the decay rate is 3%/year."""
        one = 1 << cls.FRAC_BITS
        floor_fixed = round(cls.REWARD_FLOOR * one)  # exact: 0.5 * 2**64 == 2**63, no rounding error
        base_fixed = cls.BASE_REWARD * one
        factor_fixed = cls._fixed_pow(cls.REWARD_DECAY_RATE_FIXED, height, cls.FRAC_BITS)
        excess_fixed = ((base_fixed - floor_fixed) * factor_fixed) >> cls.FRAC_BITS
        reward_fixed = floor_fixed + excess_fixed
        # The only floating-point operation in the whole calculation: one
        # final division, which (unlike pow/exp/log) IEEE 754 guarantees
        # is correctly rounded — identical on every platform. Rounded to
        # 6 decimal places purely for a clean, displayable amount.
        return round(reward_fixed / one, 6)

    # A block's timestamp can't be more than this far in the future
    # (clock drift / dishonest miners lying to skew future retargets) — the
    # same "not too far ahead" sanity check Bitcoin enforces.
    MAX_FUTURE_DRIFT_SECONDS = 2 * 60 * 60
    # ...and can't be older than the MEDIAN of the last this-many blocks —
    # median (not "must be after the single previous block") specifically
    # because it can't be manipulated by any one miner controlling just
    # one recent block, only by controlling a majority of the whole
    # window, which is a much higher bar. Same idea as Bitcoin's
    # median-time-past rule, just over a shorter window to match this
    # chain's much shorter block time.
    MEDIAN_TIME_WINDOW = 11

    # Blocks at or before (latest - CHECKPOINT_DEPTH) are treated as
    # PERMANENT — replace_chain() will refuse any candidate chain that
    # disagrees with our own history at or before that depth, no matter
    # how much longer or how validly-mined the candidate is. This is the
    # direct, standard mitigation for the fact that a small/new chain
    # doesn't yet have Bitcoin/Dogecoin-scale distributed hashpower behind
    # it: it trades away a small amount of pure "longest chain always
    # wins, no exceptions" decentralization for a hard guarantee that
    # nobody — regardless of hashpower — can rewrite history past this
    # point. 20 blocks at a 15s target is ~5 minutes of "not yet
    # permanent" — tunable; lower is more paranoid but makes checkpointed
    # history stale faster, higher is the reverse.
    CHECKPOINT_DEPTH = 20

    # ── Proof-of-stake (Peercoin-style hybrid consensus) ────────────
    # PoW stays the chain's PRIMARY security mechanism — this is a
    # supplementary second way to produce a block, coexisting on the
    # same chain, not a replacement. That's a deliberate, real echo of
    # Peercoin's own actual design (PoS was introduced alongside PoW,
    # not instead of it). Real Peercoin is UTXO-based, so "staking"
    # there literally spends-and-recreates a specific aged coin (a
    # "coinstake" transaction carrying coin-age as a weighting factor).
    # O-Coin's ledger is account-based (see get_balance) — there's no
    # per-coin age to track, so this adapts the same ECONOMIC idea (your
    # chance of producing a block scales with how much you hold, checked
    # against real wall-clock time, at effectively zero energy cost) to
    # a flat balance-weighted model instead: stake weight is simply an
    # address's current whole-coin balance, floored to an integer (same
    # "avoid float in a consensus decision" reasoning as everywhere else
    # in this file — sub-1-OCN balances just don't get any stake weight,
    # a deliberate, harmless simplification for a hobby chain).
    #
    # PoS gets its OWN separate difficulty target (pos_target) and its
    # own independent retargeting (_maybe_retarget_pos) — mixing PoS
    # block timestamps into PoW's retarget window (or vice versa) would
    # corrupt both signals, since they're measuring two unrelated
    # things (hashpower vs. total actively-staking balance).
    #
    # POS_INITIAL_TARGET is deliberately a FORMULA, not a hardcoded
    # literal like REWARD_DECAY_RATE_FIXED — this is pure integer
    # division (no transcendental function), so there's no cross-
    # platform float-determinism risk in computing it fresh, and doing
    # so means it automatically stays sensible if TARGET_BLOCK_TIME or
    # GENESIS_PREMINE_AMOUNT are ever retuned, with nothing to remember
    # to regenerate by hand. It assumes roughly the whole premine is the
    # initial active stake (true for early solo testing) — like PoW's
    # own INITIAL_TARGET, it only has to be a reasonable starting guess,
    # because retargeting corrects it from real observed timing after
    # that.
    POS_MAX_TARGET = 2 ** 256 // 2 ** 4  # PoS retargeting can never make it easier than this
    POS_RETARGET_INTERVAL = 10  # re-check every 10 PoS blocks (mirrors PoW's RETARGET_INTERVAL)
    # A staked block earns a much smaller reward than a mined one —
    # proportional, real reasoning: PoW's reward has to be big enough to
    # cover real electricity/hardware cost, which is what actually makes
    # a 51%-attack expensive. Staking costs (near) nothing, so paying it
    # the same would undermine PoW's role as the chain's primary
    # security spend without adding any real security in return — this
    # mirrors Peercoin's real ~1%-ish annual "interest" framing for
    # staking rewards, deliberately modest rather than a full subsidy.
    POS_REWARD_FRACTION = 0.1

    def __init__(self):
        self.chain = []
        self.mempool = []  # list[Transaction] waiting to be mined
        self.current_target = self.INITIAL_TARGET
        self.pos_target = 2 ** 256 // (self.TARGET_BLOCK_TIME * max(1, self.GENESIS_PREMINE_AMOUNT))
        self._create_genesis_block()
        self._rebuild_balance_index()

    def _create_genesis_block(self):
        premine_tx = Transaction(
            sender="0", recipient=self.GENESIS_PREMINE_ADDRESS, amount=self.GENESIS_PREMINE_AMOUNT,
            fee=0, timestamp=0,
        )
        genesis = Block(0, [premine_tx], "0" * 64, self.current_target, timestamp=0, nonce=0)
        self.chain.append(genesis)

    @property
    def latest_block(self):
        return self.chain[-1]

    # ── Difficulty retargeting (the "fast" lever) ───────────────────
    @staticmethod
    def _retarget_ratio(actual_time, expected_time, max_adjustment_factor):
        ratio = actual_time / expected_time
        return max(1 / max_adjustment_factor, min(max_adjustment_factor, ratio))

    def _maybe_retarget(self):
        """Called right after a PoW block is accepted. Every
        RETARGET_INTERVAL PoW blocks, compares how long that batch
        actually took against TARGET_BLOCK_TIME * RETARGET_INTERVAL, and
        nudges current_target proportionally — found blocks too fast
        (lots of mining power) -> lower target (harder); too slow ->
        raise it (easier). This is the exact mechanism that keeps a real
        PoW chain's block time roughly steady over time instead of
        drifting as total network hashpower changes.

        Deliberately only counts PoW blocks (staker_address is None) —
        genesis included, same as before PoS existed, but any staked
        blocks interleaved in the chain are skipped entirely. Counting
        them here would corrupt this signal: a fast staked block doesn't
        mean mining power went up, it just means someone staked, and
        mixing the two would make PoW difficulty chase a rhythm that has
        nothing to do with actual hashpower."""
        pow_blocks = [b for b in self.chain if b.staker_address is None]
        n = len(pow_blocks) - 1  # PoW blocks mined so far, excluding genesis
        if n < self.RETARGET_INTERVAL or n % self.RETARGET_INTERVAL != 0:
            return
        window_start = pow_blocks[-1 - self.RETARGET_INTERVAL]
        window_end = pow_blocks[-1]
        actual_time = max(1, window_end.timestamp - window_start.timestamp)
        expected_time = self.TARGET_BLOCK_TIME * self.RETARGET_INTERVAL
        ratio = self._retarget_ratio(actual_time, expected_time, self.MAX_ADJUSTMENT_FACTOR)
        new_target = int(self.current_target * ratio)
        self.current_target = min(new_target, self.MAX_TARGET)

    def _maybe_retarget_pos(self):
        """PoS's own fully independent difficulty retarget — same
        mechanism as _maybe_retarget above, applied only to PoS blocks'
        own timestamps (staker_address is not None; genesis never
        qualifies, so no "-1" adjustment is needed here the way PoW's
        version excludes genesis). Kept completely separate from PoW's
        retarget so the two block-production methods never interfere
        with each other's difficulty signal."""
        pos_blocks = [b for b in self.chain if b.staker_address is not None]
        n = len(pos_blocks)
        if n < self.POS_RETARGET_INTERVAL or n % self.POS_RETARGET_INTERVAL != 0:
            return
        window_start = pos_blocks[-self.POS_RETARGET_INTERVAL]
        window_end = pos_blocks[-1]
        actual_time = max(1, window_end.timestamp - window_start.timestamp)
        expected_time = self.TARGET_BLOCK_TIME * self.POS_RETARGET_INTERVAL
        ratio = self._retarget_ratio(actual_time, expected_time, self.MAX_ADJUSTMENT_FACTOR)
        new_target = int(self.pos_target * ratio)
        self.pos_target = min(new_target, self.POS_MAX_TARGET)

    # ── Mempool / transactions ────────────────────────────────────────
    # Track A, Phase A2/A3: reject any op-bearing transaction before this
    # height, so the multi-asset cutover is a deliberate, coordinated event
    # rather than something that could activate by surprise the moment this
    # code merely ships. Deliberately a huge placeholder, not "current tip +
    # small buffer" — the real value has to be chosen WITH the user at
    # actual deployment time (this is the hard-fork line: every node must be
    # running this code before it, see docs/07-onchain-dex-plan.md A2). Until
    # that's deliberately lowered, op-bearing transactions can't activate on
    # the real chain even if this code reaches it.
    TX_SCHEMA_ACTIVATION_HEIGHT = 1_000_000

    # Recognized ops. A5's AMM pool ops get added to this set when that
    # phase is actually built — never an open "anything goes" op namespace.
    KNOWN_OPS = {"transfer_asset", "stake_pool_deposit", "stake_pool_withdraw"}

    # Protocol-recognized liquid-staking pool address (Track A, Phase A4) —
    # a plain SHA-256 hash, deterministic and identical on every node, that
    # no real ECDSA keypair can ever match (finding a private key whose
    # public key hashes to a CHOSEN value is exactly as hard as breaking
    # SHA-256 itself). That's what makes this pool genuinely keyless: it can
    # accumulate deposits and receive staking rewards with no private key
    # existing for it anywhere, because blocks on this chain were never
    # signed by their staker/miner in the first place — a PoS block's
    # validity depends only on kernel-hash math against the staker
    # address's BALANCE (see compute_stake_kernel_hash /
    # _validate_stake_proof), never a signature proving ownership of that
    # address. Any node can run `python node.py --stake <this address>` and
    # legitimately produce real staked blocks crediting this pool, exactly
    # the same way it would for a real user's own address. This is a
    # materially safer design than docs/07-onchain-dex-plan.md's original
    # assumption (written without the real staking code checked out) that a
    # server-held operator signing key would be required — there is no key
    # to protect, lose, or leak, because nothing here is keyed at all.
    STAKE_POOL_ADDRESS = hashlib.sha256(b"STAKE_POOL:OCN").hexdigest()[:40]

    @staticmethod
    def _asset_id_of(tx):
        """The asset a plain transfer or transfer_asset op moves — "OCN" by
        default (every transaction that existed before Phase A2), or
        whatever transfer_asset's op_data names. The stake-pool ops handle
        their own OCN/stOCN accounting directly inside
        _apply_transaction_to_balance_dict and never reach this function."""
        if tx.op == "transfer_asset" and tx.op_data:
            return tx.op_data.get("asset_id", "OCN")
        return "OCN"

    @staticmethod
    def _validate_op(tx):
        """Structural validation of an op-bearing transaction — raises
        ValueError with a human-readable reason, same convention as
        add_transaction. Called from both add_transaction (mempool gate) and
        accept_block/is_chain_valid (block gate) so a malformed op can never
        reach the chain by skipping mempool admission (e.g. a block
        submitted directly by a miner/peer)."""
        if tx.op not in Blockchain.KNOWN_OPS:
            raise ValueError(f"Unknown transaction op: {tx.op}")
        if tx.op == "transfer_asset":
            asset_id = (tx.op_data or {}).get("asset_id") if tx.op_data else None
            if not isinstance(asset_id, str) or not asset_id:
                raise ValueError("transfer_asset requires op_data.asset_id (non-empty string)")
            if asset_id == "OCN":
                raise ValueError('transfer_asset cannot move "OCN" — use a plain transfer (op=None) for OCN itself')
            if tx.amount <= 0:
                raise ValueError("transfer_asset requires amount > 0")
        elif tx.op == "stake_pool_deposit":
            if tx.recipient != Blockchain.STAKE_POOL_ADDRESS:
                raise ValueError(f"stake_pool_deposit must send to the pool address ({Blockchain.STAKE_POOL_ADDRESS}), not {tx.recipient}")
            if tx.amount <= 0:
                raise ValueError("stake_pool_deposit requires amount > 0")
        elif tx.op == "stake_pool_withdraw":
            if tx.recipient != tx.sender:
                raise ValueError("stake_pool_withdraw redeems to the sender's own address — recipient must equal sender")
            if tx.amount <= 0:
                raise ValueError("stake_pool_withdraw requires amount > 0 (the stOCN amount being redeemed)")

    @staticmethod
    def _stake_pool_exchange_rate(balances, asset_supply):
        """OCN-per-stOCN, Lido-style rebasing: starts at 1.0 (empty pool —
        the first depositor mints 1:1) and rises as the pool's OCN balance
        grows from staking rewards while stOCN supply stays fixed between
        deposits/withdrawals. A pure function of (balances, asset_supply),
        exactly as independently re-derivable by every node as everything
        else in this file — never a separately-signed or separately-stored
        number."""
        stocn_supply = asset_supply.get("stOCN", 0)
        if stocn_supply <= 0:
            return 1.0
        pool_ocn = balances.get((Blockchain.STAKE_POOL_ADDRESS, "OCN"), 0)
        return pool_ocn / stocn_supply

    def stake_pool_status(self):
        """Read-only snapshot for node.py's /stake_pool/status — current
        exchange rate (OCN redeemable per stOCN), total OCN actually staked
        in the pool, and total stOCN in circulation. Always derived from
        the live self.balances/self.asset_supply index, never separately
        tracked/stored."""
        return {
            "pool_address": self.STAKE_POOL_ADDRESS,
            "exchange_rate": self._stake_pool_exchange_rate(self.balances, self.asset_supply),
            "total_staked_ocn": self.balances.get((self.STAKE_POOL_ADDRESS, "OCN"), 0),
            "total_stocn_supply": self.asset_supply.get("stOCN", 0),
        }

    @staticmethod
    def _apply_transaction_to_balance_dict(balances, tx, asset_supply):
        """The one place transaction accounting actually happens, for every
        transaction/op kind this chain knows about. Operates on passed-in
        dicts rather than self.balances/self.asset_supply directly so it can
        be reused both for the real index (_rebuild_balance_index/
        accept_block) and for throwaway local/scratch dicts (get_balance's
        explicit chain= scan, is_chain_valid's from-scratch candidate-chain
        walk, add_transaction's pending-mempool preview) without duplicating
        this logic anywhere and risking the copies drifting apart.

        Returns the list of (address, asset_id) balance keys this call
        DEBITED (subtracted from) — callers doing balance-sufficiency
        checks use this to verify none of them went negative, without
        needing their own per-op knowledge of what gets debited by what
        (this is what closes a real gap A3 originally had: its block-level
        check verified the ASSET side of a transfer_asset but never the fee
        side, since that check was hand-written per-op instead of derived
        generically like this)."""
        debited = []
        if tx.op == "stake_pool_deposit":
            # Exchange rate computed from state as it stands BEFORE this
            # deposit's own effects are applied below — every node sees the
            # identical prior state and so computes the identical rate,
            # which is what makes this protocol-computed mint deterministic
            # and independently re-derivable rather than a separately-
            # signed claim.
            # rate is OCN-per-stOCN (see _stake_pool_exchange_rate) — as the
            # pool earns rewards, each stOCN becomes redeemable for MORE
            # OCN, so a deposit of `amount` OCN must mint FEWER stOCN as the
            # rate rises: divide OCN by OCN-per-stOCN to get stOCN units.
            rate = Blockchain._stake_pool_exchange_rate(balances, asset_supply)
            minted = round(tx.amount / rate, 6) if rate > 0 else tx.amount
            if tx.sender != "0":
                sender_ocn_key = (tx.sender, "OCN")
                balances[sender_ocn_key] = balances.get(sender_ocn_key, 0) - tx.total_cost()
                debited.append(sender_ocn_key)
            pool_key = (tx.recipient, "OCN")  # tx.recipient == STAKE_POOL_ADDRESS, enforced by _validate_op
            balances[pool_key] = balances.get(pool_key, 0) + tx.amount
            stocn_key = (tx.sender, "stOCN")
            balances[stocn_key] = balances.get(stocn_key, 0) + minted
            asset_supply["stOCN"] = asset_supply.get("stOCN", 0) + minted
            return debited
        if tx.op == "stake_pool_withdraw":
            # Inverse of the deposit formula above: redeeming `amount`
            # stOCN units at rate (OCN-per-stOCN) gives back that many OCN —
            # multiply, don't divide.
            rate = Blockchain._stake_pool_exchange_rate(balances, asset_supply)
            redeemed_ocn = round(tx.amount * rate, 6)
            stocn_key = (tx.sender, "stOCN")
            balances[stocn_key] = balances.get(stocn_key, 0) - tx.amount
            debited.append(stocn_key)
            asset_supply["stOCN"] = asset_supply.get("stOCN", 0) - tx.amount
            if tx.sender != "0":
                fee_key = (tx.sender, "OCN")
                balances[fee_key] = balances.get(fee_key, 0) - tx.fee
                debited.append(fee_key)
            pool_key = (Blockchain.STAKE_POOL_ADDRESS, "OCN")
            balances[pool_key] = balances.get(pool_key, 0) - redeemed_ocn
            recipient_key = (tx.recipient, "OCN")  # tx.recipient == tx.sender, enforced by _validate_op
            balances[recipient_key] = balances.get(recipient_key, 0) + redeemed_ocn
            return debited
        # Plain transfer (op=None) or transfer_asset — the original A1/A3
        # accounting: net total_cost() for the sender when the moved asset
        # IS OCN, a fee-only OCN debit plus a separate asset debit
        # otherwise; the recipient always just gains the amount, in
        # whatever asset moved.
        asset_id = Blockchain._asset_id_of(tx)
        if tx.sender != "0":
            if asset_id == "OCN":
                key = (tx.sender, "OCN")
                balances[key] = balances.get(key, 0) - tx.total_cost()
                debited.append(key)
            else:
                fee_key = (tx.sender, "OCN")
                balances[fee_key] = balances.get(fee_key, 0) - tx.fee
                debited.append(fee_key)
                asset_key = (tx.sender, asset_id)
                balances[asset_key] = balances.get(asset_key, 0) - tx.amount
                debited.append(asset_key)
        recipient_key = (tx.recipient, asset_id)
        balances[recipient_key] = balances.get(recipient_key, 0) + tx.amount
        return debited

    def _apply_transaction_to_balances(self, tx):
        self._apply_transaction_to_balance_dict(self.balances, tx, self.asset_supply)

    def _rebuild_balance_index(self):
        """Full walk of self.chain, recomputing every address's balance
        (across every asset_id seen) AND every non-OCN asset's total
        circulating supply from scratch. Called whenever self.chain is
        replaced WHOLESALE — genesis creation, load_chain() adopting the
        startup chain, replace_chain() swapping in a candidate — as opposed
        to growing by one block, which accept_block updates incrementally
        instead (see _apply_transaction_to_balances)."""
        self.balances = {}
        self.asset_supply = {}
        for block in self.chain:
            for tx in block.transactions:
                self._apply_transaction_to_balances(tx)

    def get_balance(self, address, asset_id="OCN", include_pending=False, chain=None):
        """Balance of one (address, asset_id) pair. No account/balance table
        exists anywhere — a wallet's balance is always *derived* from
        transaction history, same as every real UTXO-model or account-model
        chain; there's nothing else to trust or that could get out of sync.

        Accepts an explicit `chain` (used by is_chain_valid when checking a
        CANDIDATE chain's stake weights/balances against ITS OWN history,
        not necessarily this instance's currently-accepted one) — that path
        stays a full from-scratch scan: the index only ever reflects
        self.chain as currently adopted, and validating a not-yet-adopted
        candidate must stay fully independent of it. Every other (the
        overwhelming majority of) caller passes no chain and gets the O(1)
        indexed lookup instead of a full scan. Both paths funnel through
        _apply_transaction_to_balance_dict so they can never compute two
        different answers for the same chain."""
        if chain is not None:
            local, local_supply = {}, {}
            for block in chain:
                for tx in block.transactions:
                    self._apply_transaction_to_balance_dict(local, tx, local_supply)
            balance = local.get((address, asset_id), 0)
        else:
            balance = self.balances.get((address, asset_id), 0)
        if include_pending:
            pending_local, pending_supply = {}, {}
            for tx in self.mempool:
                self._apply_transaction_to_balance_dict(pending_local, tx, pending_supply)
            balance += pending_local.get((address, asset_id), 0)
        return balance

    def add_transaction(self, tx: Transaction):
        """Raises ValueError with a human-readable reason on rejection —
        callers (the HTTP API) turn that straight into an error response."""
        if not tx.is_valid():
            raise ValueError("Transaction signature is invalid (or fee is below the network minimum)")
        if tx.op is not None:
            if (self.latest_block.index + 1) < self.TX_SCHEMA_ACTIVATION_HEIGHT:
                raise ValueError(f"op-bearing transactions are not active until block {self.TX_SCHEMA_ACTIVATION_HEIGHT}")
            self._validate_op(tx)
        # Replay/double-inclusion guard: a signed transaction's hash is
        # fully deterministic from its own fields (see
        # Transaction.to_signing_string) — nothing about a signature
        # limits it to being honored only ONCE, the way a UTXO (Bitcoin)
        # or an account nonce (Ethereum) would. Without this check, the
        # exact same already-broadcast, already-signed transaction could
        # be resubmitted (by anyone, not just the original sender — it's
        # public once broadcast) and mined again, debiting the sender and
        # crediting the recipient a second time for one authorization
        # the sender only actually signed once. Caught for real during
        # this project's own end-to-end testing, not theoretical.
        if any(tx.hash() == pending.hash() for pending in self.mempool):
            raise ValueError("Transaction already pending (resubmitting an identical signed transaction doesn't authorize it a second time)")
        if any(tx.hash() == t.hash() for block in self.chain for t in block.transactions):
            raise ValueError("Transaction already confirmed on-chain (a signed transaction can only ever be honored once)")
        if tx.sender != "0":
            # Checks against balance MINUS whatever's already pending in the
            # mempool from this same sender — otherwise someone could submit
            # two transactions spending the same coins twice before either
            # one is actually mined (a real double-spend, the exact problem
            # proof-of-work chains exist to solve for confirmed blocks —
            # this closes the same gap one step earlier, at mempool-
            # acceptance time). Generic across every op: preview confirmed +
            # already-pending + this new tx on a throwaway copy, then check
            # every balance bucket THIS tx itself debited didn't go negative
            # — the same "apply on a scratch copy, then check what got
            # debited" pattern accept_block/is_chain_valid use for their own
            # block-level version of this check, so there's exactly one
            # place that knows what each op debits, not three.
            preview_balances = dict(self.balances)
            preview_supply = dict(self.asset_supply)
            for pending in self.mempool:
                self._apply_transaction_to_balance_dict(preview_balances, pending, preview_supply)
            debited_keys = self._apply_transaction_to_balance_dict(preview_balances, tx, preview_supply)
            for key in debited_keys:
                if preview_balances.get(key, 0) < 0:
                    addr, asset = key
                    raise ValueError(f"Insufficient {asset} balance: {addr} would go to {preview_balances[key]}")
        self.mempool.append(tx)
        return tx.hash()

    # ── Mining ───────────────────────────────────────────────────────
    def build_candidate_block(self, miner_address, max_transactions=50):
        """A 'block template' — everything a miner needs to start
        searching for a valid nonce, EXCEPT the nonce itself. Mirrors
        get_mining_template()'s job on the HTTP API side; kept here too
        so the node can also mine its own blocks directly (used by
        /mine and local testing).

        Highest-fee-first (the "efficient" lever): with limited space per
        block, sorting the mempool by fee descending before truncating to
        max_transactions means paying a bit more is what actually buys
        priority, same as every real fee market — instead of strictly
        first-in-first-out, which has no way to express "this one's more
        urgent to me."

        The coinbase transaction pays the miner the base reward PLUS
        every fee from the transactions actually included — exactly how
        real chains incentivize miners to keep including transactions
        even as the block reward itself shrinks over a chain's lifetime.
        """
        included = sorted(self.mempool, key=lambda t: t.fee, reverse=True)[:max_transactions]
        total_fees = sum(t.fee for t in included)
        block_reward = self.reward_at_height(self.latest_block.index + 1)
        reward_tx = Transaction(sender="0", recipient=miner_address, amount=block_reward + total_fees, fee=0)
        return Block(
            index=self.latest_block.index + 1,
            transactions=[reward_tx] + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.current_target,
        )

    def build_pool_block(self, shares: dict, max_transactions=50):
        """Same idea as build_candidate_block, except the single coinbase
        transaction becomes one PER contributing address, each paid
        proportional to how many shares (near-miss proofs of real work —
        see node.py's pool endpoints) they submitted, instead of the
        entire reward going to whoever happened to find the one winning
        nonce. `shares` is {address: share_count} and must be non-empty —
        it is deliberately NOT based on shares submitted *during* the
        round this block belongs to (that would be circular: the payout
        has to be baked into the coinbase, hence the merkle root, before
        any miner can start searching for this exact block's nonce).
        node.py instead calls this with the *previous* round's completed
        share tally — the same "pay based on already-closed work" fix
        real mining pools use (PPLNS-style), which is what makes it safe
        to fix the payout list before mining begins.

        Integer division leaves a small remainder (the reward doesn't
        always divide evenly across contributors) — that dust goes to
        whichever address contributed the most shares, a simple
        deterministic tie-break rather than trying to split fractional
        units perfectly."""
        if not shares:
            raise ValueError("build_pool_block requires a non-empty shares tally")
        included = sorted(self.mempool, key=lambda t: t.fee, reverse=True)[:max_transactions]
        total_fees = sum(t.fee for t in included)
        total_reward = self.reward_at_height(self.latest_block.index + 1) + total_fees
        total_shares = sum(shares.values())
        reward_txs = []
        distributed = 0
        for address, count in shares.items():
            cut = (total_reward * count) // total_shares if total_shares else 0
            if cut > 0:
                reward_txs.append(Transaction(sender="0", recipient=address, amount=cut, fee=0))
                distributed += cut
        remainder = total_reward - distributed
        if remainder > 0:
            top_address = max(sorted(shares.keys()), key=lambda a: shares[a])
            # top_address may already have a reward_tx above — a second
            # small coinbase tx to the same address is completely valid,
            # nothing requires coinbase recipients to be unique.
            reward_txs.append(Transaction(sender="0", recipient=top_address, amount=remainder, fee=0))
        return Block(
            index=self.latest_block.index + 1,
            transactions=reward_txs + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.current_target,
        )

    def mine_block(self, miner_address, max_transactions=50):
        """Does the actual proof-of-work search itself, in-process — used
        for local testing and by the standalone Python REPL. The real
        miner (miner.py) does this same search OUTSIDE the node process
        (mirroring Speepcoin's miner.js) and submits a finished block via
        the HTTP API instead, so mining work can run on a different
        machine than the node itself."""
        block = self.build_candidate_block(miner_address, max_transactions)
        block = proof_of_work(block)
        self.accept_block(block)
        return block

    def stake_weight_of(self, address, chain=None):
        """An address's staking power — its current confirmed balance,
        floored to a whole coin (see the class docstring above
        POS_MAX_TARGET for why: avoiding float in a consensus-relevant
        weight, same reasoning as everywhere else in this file).
        Splitting one balance across many addresses doesn't increase
        total success odds — probability scales linearly with weight, so
        N addresses each holding 1/N of a balance have exactly the same
        combined chance as one address holding all of it. That's what
        makes stake weight Sybil-resistant the same way hashpower is."""
        return int(self.get_balance(address, chain=chain))

    def build_stake_block(self, staker_address, max_transactions=50):
        """A PoS 'block template' — everything try_stake needs except
        the actual kernel check against the current second. Mirrors
        build_candidate_block, with two differences: it's paid at
        POS_REWARD_FRACTION of the normal reward (see that constant's
        docstring), and target here is pos_target, not current_target."""
        weight = self.stake_weight_of(staker_address)
        if weight < 1:
            raise ValueError(f"{staker_address} has no stakeable balance (needs at least 1 whole O-Coin)")
        included = sorted(self.mempool, key=lambda t: t.fee, reverse=True)[:max_transactions]
        total_fees = sum(t.fee for t in included)
        stake_reward = round(self.reward_at_height(self.latest_block.index + 1) * self.POS_REWARD_FRACTION, 6)
        reward_tx = Transaction(sender="0", recipient=staker_address, amount=stake_reward + total_fees, fee=0)
        return Block(
            index=self.latest_block.index + 1,
            transactions=[reward_tx] + included,
            previous_hash=self.latest_block.compute_hash(),
            target=self.pos_target,
            staker_address=staker_address,
        )

    def try_stake(self, staker_address, max_transactions=50):
        """One single kernel-check attempt, right now, for staker_address
        — call this roughly once per second (see node.py's staking
        thread) rather than in a tight loop; a second try before the
        wall clock has actually advanced to a new second recomputes the
        exact same kernel hash and can't possibly succeed where the
        first attempt didn't (see compute_stake_kernel_hash — there's no
        nonce to vary). Returns the accepted Block on success, None on a
        failed attempt (not an error — failing most seconds is normal
        and expected, same as failing most nonces is normal for PoW)."""
        block = self.build_stake_block(staker_address, max_transactions)
        weight = self.stake_weight_of(staker_address)
        kernel_int = int(block.compute_stake_kernel_hash(), 16)
        if kernel_int >= block.target * weight:
            return None
        self.accept_block(block)
        return block

    @staticmethod
    def _median_time(preceding_blocks):
        """Median timestamp of up to the last MEDIAN_TIME_WINDOW blocks
        BEFORE the one being validated. Median specifically (not "must be
        after the single immediately-previous block") because manipulating
        a median requires controlling a majority of the whole window, not
        just the one most recent block — the same reasoning Bitcoin's
        median-time-past rule uses."""
        window = preceding_blocks[-Blockchain.MEDIAN_TIME_WINDOW:]
        timestamps = sorted(b.timestamp for b in window)
        return timestamps[len(timestamps) // 2]

    def _validate_timestamp(self, block: Block, preceding_blocks):
        if block.timestamp > time.time() + self.MAX_FUTURE_DRIFT_SECONDS:
            raise ValueError("Block timestamp is too far in the future")
        if preceding_blocks and block.timestamp <= self._median_time(preceding_blocks):
            raise ValueError("Block timestamp is not after the median of recent block times (possible difficulty-retarget manipulation)")

    def _validate_stake_proof(self, block: Block):
        """PoS equivalent of the PoW target+meets_target() checks in
        accept_block below — called INSTEAD of them when
        block.staker_address is set. Weight is read from self.chain as
        it stands right now, i.e. BEFORE this candidate block is
        appended — a staker is judged on the balance they actually held
        at the moment they'd have needed to produce this block, not on
        anything this block itself pays them."""
        if block.target != self.pos_target:
            raise ValueError(f"Block was staked against a stale PoS difficulty target (expected {self.pos_target}, got {block.target})")
        weight = self.stake_weight_of(block.staker_address)
        if weight < 1:
            raise ValueError(f"{block.staker_address} has no stakeable balance to justify this block")
        kernel_int = int(block.compute_stake_kernel_hash(), 16)
        if kernel_int >= block.target * weight:
            raise ValueError("Stake kernel hash does not meet the PoS difficulty target for this staker's weight")

    def accept_block(self, block: Block):
        """Validates and appends a block that was mined OR staked
        elsewhere (by node.py's /mining/submit, its staking thread, or
        here). Raises ValueError on any failure — never silently drops
        an invalid block. This function, together with is_chain_valid()
        below, IS the chain's security model: every rule that makes
        O-Coin hard to cheat (correct proof-of-work OR proof-of-stake,
        correct reward math, every transaction genuinely signed by its
        real sender, honest timestamps) is enforced right here,
        unconditionally, for every block from any source — mined,
        staked, submitted by an external miner, or received from a peer
        during sync."""
        if block.previous_hash != self.latest_block.compute_hash():
            raise ValueError("Block does not build on the current chain tip (someone else's block won the race, or this one is stale)")
        if block.index != self.latest_block.index + 1:
            raise ValueError("Block index out of sequence")
        self._validate_timestamp(block, self.chain)
        if block.staker_address is not None:
            self._validate_stake_proof(block)
            block_subsidy = round(self.reward_at_height(block.index) * self.POS_REWARD_FRACTION, 6)
        else:
            if block.target != self.current_target:
                raise ValueError(f"Block was mined against a stale difficulty target (expected {self.current_target}, got {block.target})")
            if not block.meets_target():
                raise ValueError("Block hash does not meet the difficulty target — nonce is not a valid proof of work")
            block_subsidy = self.reward_at_height(block.index)
        if block.merkle_root != block.compute_merkle_root():
            raise ValueError("Merkle root does not match the block's actual transactions")
        # One coinbase transaction for a solo-mined block, or MANY for a
        # pool-mined one (one per contributing address, proportional to
        # their share of the work — see build_pool_block) — either way,
        # what actually matters is that they SUM to (approximately) the
        # reward this block is entitled to, no more, no less. Nothing
        # about solo vs. pool vs. staked distribution changes the total
        # amount of new O-Coin a block is allowed to create — a staked
        # block's total is just smaller, per POS_REWARD_FRACTION. A
        # small epsilon tolerance, not exact equality, on purpose:
        # reward_at_height() returns a float, and splitting a float
        # reward across several coinbase transactions (build_pool_block)
        # involves float subtraction/addition that isn't guaranteed
        # bit-exactly reversible — real financial code never compares
        # floats for exact equality for the same reason.
        reward_txs = [tx for tx in block.transactions if tx.sender == "0"]
        expected_reward = block_subsidy + sum(tx.fee for tx in block.transactions if tx.sender != "0")
        if not reward_txs or abs(sum(tx.amount for tx in reward_txs) - expected_reward) > 1e-6:
            raise ValueError("Block's coinbase transaction(s) do not sum to the expected reward + collected fees")
        # Defense in depth against transaction replay (see
        # add_transaction's docstring for the full reasoning) — that
        # check protects the normal mempool path, but a block can also
        # arrive directly (from a miner, or a peer during sync) without
        # ever passing through add_transaction, so the same guarantee
        # has to be re-enforced here too. Deliberately scoped to SIGNED
        # transactions only (sender != "0") — coinbase transactions have
        # no signature to replay, and a pool-mined block legitimately
        # contains several coinbase entries to different (sometimes the
        # same) address on purpose, see build_pool_block.
        signed_hashes = [tx.hash() for tx in block.transactions if tx.sender != "0"]
        if len(signed_hashes) != len(set(signed_hashes)):
            raise ValueError("Block contains the same signed transaction more than once")
        confirmed_hashes = {t.hash() for b in self.chain for t in b.transactions if t.sender != "0"}
        if any(h in confirmed_hashes for h in signed_hashes):
            raise ValueError("Block replays a transaction that's already confirmed earlier in the chain")
        for tx in block.transactions:
            if not tx.is_valid():
                raise ValueError(f"Block contains an invalid transaction: {tx.hash()}")
        # Track A, Phase A2/A3: op-bearing transactions get their OWN
        # block-level invariant checks — unlike OCN transfers (whose balance
        # sufficiency is ONLY ever checked at mempool-admission time, a
        # pre-existing, deliberately out-of-scope gap for A1/A2/A3 — see
        # docs/07-onchain-dex-plan.md's ground constraints), a new asset type
        # has no such inherited coverage, so a malicious block could
        # otherwise manufacture spends against a balance that was never
        # really there. Checked against a running copy seeded from the
        # currently-indexed balances (not self.balances itself — this block
        # isn't appended yet) so multiple ops from the same sender within
        # one block are checked cumulatively against each other, not just
        # independently against pre-block state.
        op_txs = [tx for tx in block.transactions if tx.op is not None]
        if op_txs:
            if block.index < self.TX_SCHEMA_ACTIVATION_HEIGHT:
                raise ValueError(f"Block contains op-bearing transactions before activation height {self.TX_SCHEMA_ACTIVATION_HEIGHT}")
            # Validated on a throwaway copy — self.balances/self.asset_supply
            # only get their REAL update below, once, uniformly for every
            # transaction in the block (op or not), so this can never
            # double-apply an op transaction's effects.
            scratch_balances = dict(self.balances)
            scratch_supply = dict(self.asset_supply)
            for tx in op_txs:
                self._validate_op(tx)
                debited_keys = self._apply_transaction_to_balance_dict(scratch_balances, tx, scratch_supply)
                for key in debited_keys:
                    if scratch_balances.get(key, 0) < 0:
                        addr, asset = key
                        raise ValueError(f"Block contains an op transaction that would drive {addr}'s {asset} balance negative")
        self.chain.append(block)
        # O(1) incremental update — the common case, a full rebuild would
        # be wasteful here since only this one block's worth of
        # transactions actually changed anything (see _rebuild_balance_index
        # for the wholesale-replacement counterpart to this).
        for tx in block.transactions:
            self._apply_transaction_to_balances(tx)
        # Remove any mempool transactions that made it into this block —
        # by hash, so this works regardless of which miner/node actually
        # produced the block.
        mined_hashes = {tx.hash() for tx in block.transactions}
        self.mempool = [tx for tx in self.mempool if tx.hash() not in mined_hashes]
        if block.staker_address is not None:
            self._maybe_retarget_pos()
        else:
            self._maybe_retarget()

    # ── Validation / consensus (the "secure" lever) ─────────────────
    def is_chain_valid(self, chain=None):
        """Re-derives every block's hash from scratch and checks the
        whole chain links together correctly and every block meets ITS
        OWN recorded proof-of-work target — this is the function that
        makes the whole thing trustworthy without trusting whoever's node
        you're talking to: anyone can run this against any claimed chain
        and get the same true/false answer, using nothing but math. This
        is what node.py's /nodes/resolve calls before ever adopting a
        peer's claimed chain — a malicious or buggy peer can SEND
        whatever it wants, it just can't get an invalid chain ACCEPTED.
        Retargeting history is deliberately NOT re-simulated here (that
        would mean replaying _maybe_retarget/_maybe_retarget_pos
        block-by-block to confirm every historical target was the
        "correct" one for its era) — a real, well-scoped next step (see
        the README roadmap), but every block's own target is still
        independently checked against its own hash (PoW) or kernel
        (PoS), which is the part that actually prevents tampering with
        past blocks. Reward correctness IS fully re-checked here (unlike
        target history) — a chain that mints itself extra O-Coin out of
        nowhere is exactly the kind of thing "independently re-verify
        from scratch" has to catch, PoS or PoW.

        Note: computing a staked block's stake_weight_of requires
        walking chain[:i] (this candidate chain's OWN history up to that
        point, not necessarily self.chain) — for a long chain with many
        staked blocks this is the one place validation cost grows faster
        than linear; a real balance-index/UTXO-set would fix that later
        (see README roadmap) but is out of scope for this lean a v1."""
        chain = chain if chain is not None else self.chain
        if not chain or chain[0].previous_hash != "0" * 64:
            return False
        # Track A, Phase A2/A3: independently re-derived, running balances
        # for this CANDIDATE chain specifically (never self.balances — this
        # function must never trust that a candidate ever passed through
        # accept_block) so op-bearing transactions' block-level invariant
        # (see accept_block) can be re-checked from scratch here too, the
        # same "trust nothing, verify everything" standard every other rule
        # in this function already holds itself to. Maintained incrementally
        # as the loop below walks the chain in increasing order, one
        # block's worth of transactions at a time.
        running_balances = {}
        running_asset_supply = {}
        for tx in chain[0].transactions:
            self._apply_transaction_to_balance_dict(running_balances, tx, running_asset_supply)
        for i in range(1, len(chain)):
            block, prev = chain[i], chain[i - 1]
            if block.previous_hash != prev.compute_hash():
                return False
            if block.index != prev.index + 1:
                return False
            try:
                self._validate_timestamp(block, chain[:i])
            except ValueError:
                return False
            if block.staker_address is not None:
                weight = self.stake_weight_of(block.staker_address, chain=chain[:i])
                if weight < 1:
                    return False
                if int(block.compute_stake_kernel_hash(), 16) >= block.target * weight:
                    return False
                block_subsidy = round(self.reward_at_height(block.index) * self.POS_REWARD_FRACTION, 6)
            else:
                if not block.meets_target():
                    return False
                block_subsidy = self.reward_at_height(block.index)
            if block.merkle_root != block.compute_merkle_root():
                return False
            reward_txs = [tx for tx in block.transactions if tx.sender == "0"]
            expected_reward = block_subsidy + sum(tx.fee for tx in block.transactions if tx.sender != "0")
            if not reward_txs or abs(sum(tx.amount for tx in reward_txs) - expected_reward) > 1e-6:
                return False
            # Same replay guard as accept_block (see that method's
            # comment for the full reasoning) — re-checked independently
            # here since is_chain_valid has to catch everything on its
            # own, from scratch, without trusting that every block ever
            # passed through accept_block's checks in the first place.
            signed_hashes = [tx.hash() for tx in block.transactions if tx.sender != "0"]
            if len(signed_hashes) != len(set(signed_hashes)):
                return False
            confirmed_hashes = {t.hash() for b in chain[:i] for t in b.transactions if t.sender != "0"}
            if any(h in confirmed_hashes for h in signed_hashes):
                return False
            # Same op/asset-balance invariant accept_block enforces (see
            # that method's comment for the full reasoning), re-derived
            # from scratch against running_balances/running_asset_supply as
            # accumulated up to (but not including) this block. Validated
            # on a throwaway scratch copy — running_balances/
            # running_asset_supply only get their REAL update below, once,
            # uniformly for every transaction in the block, so this can
            # never double-apply an op transaction's effects.
            op_txs = [tx for tx in block.transactions if tx.op is not None]
            if op_txs:
                if block.index < self.TX_SCHEMA_ACTIVATION_HEIGHT:
                    return False
                scratch_balances = dict(running_balances)
                scratch_supply = dict(running_asset_supply)
                for tx in op_txs:
                    try:
                        self._validate_op(tx)
                    except ValueError:
                        return False
                    debited_keys = self._apply_transaction_to_balance_dict(scratch_balances, tx, scratch_supply)
                    for key in debited_keys:
                        if scratch_balances.get(key, 0) < 0:
                            return False
            for tx in block.transactions:
                self._apply_transaction_to_balance_dict(running_balances, tx, running_asset_supply)
            for tx in block.transactions:
                if not tx.is_valid():
                    return False
        return True

    def _diverges_before_checkpoint(self, candidate_chain):
        """True if candidate_chain disagrees with our own history at or
        before our checkpoint boundary — the actual enforcement behind
        "nobody can rewrite history past this point, regardless of
        hashpower." Checked BEFORE the (much more expensive) full
        is_chain_valid() pass, so a chain attempting to rewrite ancient
        history gets rejected immediately rather than after fully
        re-validating it."""
        checkpoint_index = max(0, len(self.chain) - self.CHECKPOINT_DEPTH)
        if len(candidate_chain) <= checkpoint_index:
            return True  # shorter than our own checkpointed history — can't possibly agree with all of it
        for i in range(checkpoint_index + 1):
            if candidate_chain[i].compute_hash() != self.chain[i].compute_hash():
                return True
        return False

    def replace_chain(self, candidate_chain):
        """The 'longest valid chain wins' consensus rule every PoW chain
        uses to resolve disagreement between nodes — EXCEPT past the
        checkpoint boundary, where "longest and valid" is no longer
        enough; it also has to agree with what we've already checkpointed.
        Returns True if the candidate replaced our chain, False if it was
        rejected (shorter, invalid, or attempting to rewrite checkpointed
        history)."""
        if len(candidate_chain) <= len(self.chain):
            return False
        if self._diverges_before_checkpoint(candidate_chain):
            return False
        if not self.is_chain_valid(candidate_chain):
            return False
        self.chain = candidate_chain
        self._rebuild_balance_index()
        # The chain's last block might be either type — its own .target
        # only tells us ONE of current_target/pos_target, never both, so
        # each needs to be picked up from the last block of ITS OWN kind
        # instead of blindly reading candidate_chain[-1].target (which
        # would silently corrupt whichever difficulty didn't just produce
        # the tip block).
        last_pow = next((b for b in reversed(candidate_chain) if b.staker_address is None), None)
        last_pos = next((b for b in reversed(candidate_chain) if b.staker_address is not None), None)
        if last_pow is not None:
            self.current_target = last_pow.target
        if last_pos is not None:
            self.pos_target = last_pos.target
        self.mempool = []  # conservative: a reorg can invalidate assumptions about what's still pending
        return True


# Self-check, run once at import time: catches the single most likely
# emission-curve tuning mistake — changing ANNUAL_DECAY_PERCENT or
# TARGET_BLOCK_TIME without regenerating REWARD_DECAY_RATE_FIXED to
# match. Comparing floats here is safe (this never feeds a consensus
# decision, only this developer-facing check), and the tolerance is wide
# enough to absorb ordinary cross-platform libm noise in the last few
# bits while still catching a real, deliberate parameter change, which
# shifts the rate by far more than that.
_expected_rate = Blockchain._derive_rate_fixed(Blockchain.ANNUAL_DECAY_PERCENT, Blockchain.TARGET_BLOCK_TIME, Blockchain.FRAC_BITS)
if abs(_expected_rate - Blockchain.REWARD_DECAY_RATE_FIXED) > 1_000_000:
    raise RuntimeError(
        f"REWARD_DECAY_RATE_FIXED ({Blockchain.REWARD_DECAY_RATE_FIXED}) is stale for the "
        f"current ANNUAL_DECAY_PERCENT={Blockchain.ANNUAL_DECAY_PERCENT} / "
        f"TARGET_BLOCK_TIME={Blockchain.TARGET_BLOCK_TIME} (expected ~{_expected_rate}). "
        f"Regenerate it with: python -c \"from blockchain import Blockchain as B; "
        f"print(B._derive_rate_fixed(B.ANNUAL_DECAY_PERCENT, B.TARGET_BLOCK_TIME))\" "
        f"and paste the printed value in as the new REWARD_DECAY_RATE_FIXED."
    )
del _expected_rate


def proof_of_work(block: Block) -> Block:
    """The actual brute-force search: try nonces until the block's hash,
    read as a number, happens to come out below the target. This is real,
    genuine computational work — there's no shortcut, you just have to
    try nonces until you get lucky, which is exactly what makes
    proof-of-work meaningful as a "proof" of anything (spending real CPU
    time is the whole point)."""
    block.nonce = 0
    while not block.meets_target():
        block.nonce += 1
    return block
