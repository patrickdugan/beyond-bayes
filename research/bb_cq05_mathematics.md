# BB-CQ-05: calibrated memory under a delayed amendment schedule

This derivation accompanies the [registered protocol](bb_cq05_protocol.md),
committed remotely at `2e605f1d522c130e3f931aa4b552f83c31aad393` before the
new twelve-slot disclosure curve. It uses the finite model specified there.
The [CQ04 protocol](bb_cq04_protocol.md) supplies the original likelihood and
mixed-count comparison. The [CQ03 memory analysis](bb_cq03_verified_amendment_memory.md)
studies named replacements under a different generative contract.

## 1. Probability space and disclosure time

Let the regime be `K in {0,1,2}`, with

```
pi = (9/20, 7/20, 1/5),
t  = (19/20, 13/20, 3/20).
```

Select a set `S` of `j` distinct indices uniformly from the `n` slots,
independently of `K`. Selection occurs before any observations. Conditional
on `K,S`, generate mutually independent variables as follows:

* For `i` outside `S`, the old match bit `X_i` has Bernoulli parameter `t_K`.
* At indices in `S`, the old bits are fair; their replacements `Y_i` have
  Bernoulli parameter `t_K`.

Define the accepted vector `Z` by retaining `X_i` outside `S` and using
`Y_i` inside it. Its conditional law given `K` is the product of `n`
Bernoulli laws with parameter `t_K`. Moreover, the joint law of `(K,Z)`
does not depend on `S`.

In the delayed contract an encoder observes the complete old vector `X`
while `S` remains hidden. It must choose its retained state before the
schedule is disclosed. A later message supplies `S` and its replacement
bits. A full-history predictor can then recover the accepted vector.

The early contract supplies `S` before encoding. The predictor can identify
the `n-j` informative old observations immediately. Both contracts give
the same accepted observations at the endpoint, while their timing permits
different encodings.

All results below condition on a fixed `n,j`. Known labels have already
been incorporated into match bits using the complementary-channel model.

## 2. The initial delayed posterior is a count posterior

Write `m=sum_i X_i`. For a concrete vector `x` with `m` ones, let `v` count
the ones of `x` that fall inside the hidden set. There are
`C(m,v) C(n-m,j-v)` schedules with that value of `v`, so

```
Pr(X=x | K=k)
 = [2^(-j) / C(n,j)]
   * sum_v C(m,v) C(n-m,j-v)
           t_k^(m-v) (1-t_k)^(n-j-m+v).
```

The sum runs over feasible `v`; a binomial coefficient outside its natural
range is zero. This expression depends on the old vector through `m`.
For the count itself, define

```
L_k(m;j,n)
 = sum_u Bin(n-j,u;t_k) Bin(j,m-u;1/2),
```

where `Bin(a,b;p)=C(a,b) p^b (1-p)^(a-b)`. Exchangeability gives

```
Pr(X=x | K=k) = L_k(m;j,n) / C(n,m).
```

The combinatorial divisor is common to the regimes. Consequently,

```
Pr(K=k | X=x) = pi_k L_k(m;j,n) / sum_l pi_l L_l(m;j,n).
```

An initial count encoder therefore preserves the complete posterior of
`K` under the delayed contract. Later disclosure of `S` can make the
discarded positions relevant. A Bayesian state that preserves the joint
information about `(K,S)` can accommodate that disclosure; the marginal
posterior of `K` has a narrower sufficiency claim.

For the registered `n=12`, exact finite checks establish distinct initial
posterior vectors at each `m=0,...,12` for `j=1,...,11`. This injectivity
supports the supplementary-tag count in Section 6. The general memory
argument itself uses only injectivity of the final posterior.

## 3. Progressive disclosure of old values

Fix an outcome-independent ordering of `S`. Let `R_r` be its first `r`
indices, and put

```
u = sum_(i outside S) X_i,
s = sum_(i in R_r) X_i,
w = sum_(i in S minus R_r) X_i,
q = sum_(i in S) Y_i.
```

Then `m=u+s+w`. Conditional on `K`, these counts have independent laws

```
u ~ Binomial(n-j,t_K),    s ~ Binomial(r,1/2),
w ~ Binomial(j-r,1/2),   q ~ Binomial(j,t_K).
```

At a fixed reveal budget, the observed reduced data are `(m,S,Y,X_Rr)`.
Their posterior depends on the values through `(m-s,q)`:

```
p_r(k)
 proportional to pi_k * Bin(j,q;t_k)
                     * sum_u Bin(n-j,u;t_k)
                             Bin(j-r,m-s-u;1/2).
```

The factor `Bin(r,s;1/2)` cancels in posterior normalization. It remains
part of the probability mass when averaging outcomes. Using specific
replacement vectors and disclosed old vectors gives the same posterior,
because their combinatorial factors also cancel across regimes.

At `r=0` this is the CQ04 aggregate-optimal posterior. When `r=j`, the
unrevealed fair count is zero and the valid count is known as `u=m-s`.
The posterior reduces to

```
p_full(k)
 proportional to pi_k * t_k^(u+q) * (1-t_k)^(n-u-q).
```

This is the calibrated posterior after observing all accepted bits.
Ordering and reveal budgets are fixed independently of the bit outcomes.
Choosing which old values to reveal after inspecting them would require
the selection rule to appear in the likelihood.

## 4. The information sets needed for the Brier identity

Let

```
H   = sigma(S, X, Y),
G_r = sigma(S, sum_i X_i, Y, X_Rr).
```

Here `Y` denotes the indexed replacement vector. The fields `G_r` are
nested as the fixed reveal prefix grows, and each is contained in `H`.
The accepted vector `Z` is measurable with respect to `H`. Once `S,Z`
are given, the remaining old bits in `S` are independent fair noise, and
`S` is independent of `(K,Z)`. It follows that

```
Pr(K=k | H) = Pr(K=k | Z) = p_full(k).
```

The distinction between `H` and `sigma(Z)` matters. The reduced observations
include old fair bits that the accepted vector does not contain, so one
cannot justify the tower step by claiming `G_r` is contained in `sigma(Z)`.
The field `H` supplies the common containing information set. Thus

```
p_r = E[p_full | G_r].
```

Let `e_K` be the one-hot regime vector. Use the unhalved Brier loss
`B(a,K)=||a-e_K||^2`. For any probability vector `a` measurable with
respect to `G_r`, conditioning on that field gives

```
E[B(a,K) | G_r] = ||a-p_r||^2 + 1 - ||p_r||^2.
```

Therefore `p_r` uniquely minimizes conditional expected Brier loss.
Expanding squared norms and using the tower identity yields

```
E[B(p_r,K)] - E[B(p_full,K)]
 = E[||p_r-p_full||^2].
```

For an approximate predictor `a`, the complete decomposition is

```
E[B(a,K)] - E[B(p_full,K)]
 = E[||a-p_r||^2] + E[||p_r-p_full||^2].
```

This separates the error relative to the best predictor with the available
observations from the loss caused by the reduced information. A future
learned predictor can be assessed against both terms.

For consecutive reveal budgets the same argument gives

```
E[B(p_r,K)] - E[B(p_(r+1),K)]
 = E[||p_(r+1)-p_r||^2] >= 0.
```

This is a population expectation. An individual realized loss or posterior
distance can move in either direction after the next disclosed bit.

The exact integration weight for a tuple `(k,u,s,w,q)` is

```
pi_k * Bin(n-j,u;t_k) * Bin(r,s;1/2)
     * Bin(j-r,w;1/2) * Bin(j,q;t_k).
```

The weights sum to one, including tuples where a replacement leaves a
report unchanged. Uniform schedule identities have already been integrated
out through symmetry. Small-domain checks can keep every concrete schedule
and bit vector to verify this reduction independently.

## 5. A compact calibrated state when the schedule is early

With `S` known before encoding, retain
`u=sum_(i outside S) X_i`. After `ell` accepted replacements, let their
match total be `q_ell`. The calibrated posterior is

```
Pr(K=k | early observations through ell)
 proportional to pi_k * t_k^(u+q_ell)
                     * (1-t_k)^(n-j+ell-u-q_ell).
```

The update adds the new match bit to the retained count. The informative
sample count is `n-j+ell`, supplied by the public stage. This equals full
Bayes before correction and after every accepted replacement.

For `n=12,j=6`, the initial numeric state has seven possible values and
fits in three bits. A four-bit count field accommodates every later stage.
Those counts assume that the program receives the stage and admitted event
identity externally. An implementation that also stores the schedule,
tracks versions, or detects repeated inputs must account for that state.

## 6. Exact memory for delayed, named revisions

Consider a deterministic encoder `E(x)` chosen before the hidden schedule
is disclosed. It must return the exact final posterior for every schedule
of size `j` and every replacement vector with positive probability under
the model. Assume `1 <= j < n`.

Take two distinct old histories `x,y`, and set `d_i=x_i-y_i`. Put `h=n-j`.
There is an `h`-element subset `T` for which `sum_(i in T) d_i` is nonzero.
To prove this, suppose every such subset sum were zero. For any indices
`a,b`, an `h`-subset can be chosen to contain `a` and exclude `b` because
`1 <= h < n`. Comparing its sum with the sum after exchanging `a` for
`b` gives `d_a=d_b`. Every coordinate would equal one constant `c`, and
`h*c=0` would force `c=0`, contradicting `x != y`.

Reveal the common schedule `S=T^c` and choose the same replacement vector
for both histories, for example all zeros. The resulting accepted match
counts differ. Every such old history, schedule, and replacement vector
has positive probability because all prior masses and all channel
probabilities lie strictly between zero and one.

The ECA04 final posterior is injective in its match count `a`. In
particular, its first two posterior odds satisfy

```
p_full(0) / p_full(1)
 = (9/7) * (1/7)^n * (133/13)^a.
```

These odds change strictly with `a`. Hence the chosen legal continuation
distinguishes `x` and `y`. Any encoder that merges them must give an
incorrect posterior on at least one of those continuations.

All `2^n` old histories therefore need distinct encoder states. At least
`n` bits are necessary for a fixed-width exact encoding, and storing the
old bit vector attains that bound. The theorem concerns one later batch
of named replacements; repeated amendment sequences are unnecessary for
the argument.

For the registered twelve-slot fixture, the initial posterior labels
identify the initial match count. Suppose that label must be retained
and an additional fixed-width tag is attached. A count fiber has
`C(n,m)` histories, each needing a different tag. The largest fiber at
`n=12` has

```
C(12,6) = 924,
ceil(log2(924)) = 10.
```

Ten supplementary bits are necessary and sufficient for that retained-label
format; a lexicographic index within each count fiber supplies a tag.
The combined state can be encoded in twelve bits if the representation
is chosen jointly. Adding a separately allocated count field and tag does
not establish a larger minimum for unconstrained encoders.

These are worst-case cardinality bounds for exact answers on all legal
continuations. They do not bound approximate recovery, average-case loss,
the dimension of real-valued states, or total system storage. For a
finite-state randomized encoder with probability-one correctness, distinct
histories must assign positive probability to disjoint sets of encoded
values. The same distinguishing continuation proves that requirement.

## 7. What an external verifier can supply

A verifier holding the old vector can compute the old match total in the
amended set,

```
v = sum_(i in S) X_i.
```

Given the retained initial total `m` and new total `q`, the numerical
updater obtains the accepted count as `m-v+q`. The message `v` has `j+1`
possible values, so a fixed-width encoding uses `ceil(log2(j+1))` bits.
At `j=6` this is three bits. A trusted accepted total would also suffice.

This message is available after the schedule is known to the verifier.
It does not provide an encoder with advance knowledge of the future set.
The archive that computes it retains the source information used in the
memory theorem.

The registered reveal curve counts individual old values disclosed in a
fixed prefix. Its first budget recovering 90 percent of the Brier gap is
a property of that family. The aggregate `v` message demonstrates that
this budget cannot be read as an optimal communication lower bound.

The numerical update assumes correct messages. The synthetic archive
checks old and new values against complete predecessor and successor
states, together with versions and pinned digests. That local check
provides a test of structural consistency under the fixture's trusted
archive assumption. Physical acquisition, remote authority, and freshness
require an independently specified system. Their storage and verification
costs remain outside the numeric count fields described here.
