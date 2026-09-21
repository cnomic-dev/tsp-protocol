"""
tsp_protocol.dream
===================
Offline replay evaluation of ternary match policies, adapted from
Dream-RSI (Zheng et al., arXiv:2609.14858): logged traffic is treated as a
replay world, candidate policies are "dreamed" over it without any new
inference calls, and the best one — the incumbent included — is selected
for redeployment.

What carries over, and what does not
------------------------------------
* Carries over: the core move. Choosing a cache policy online needs long,
  costly runs before its hit/error trade-off is visible; a recorded log
  answers the same question offline, for every candidate, at zero inference
  cost. Selection over {incumbent} ∪ candidates gives the paper's guarantee:
  the chosen policy scores >= the incumbent *on the fixed history* — and,
  as in the paper, nothing more than that (no guarantee on future traffic).

* Does not carry over: the LLM policy-development agent. Dream-RSI searches
  a vast space of policy *programs*; here the space is finite and small
  (semantics.candidate_policies(): ~40 behaviourally distinct rules), so
  "dreaming" is exhaustive enumeration. Adding an LLM author would add cost
  and nondeterminism for no gain.

* The support condition is stricter. Dream-RSI's replay is valid because
  every node's outcome is pre-recorded, and a policy can never be credited
  for outcomes outside the recorded tree. The analogue here: every log
  entry must carry its ground-truth `answer_key` — i.e. the log was
  collected in shadow mode, where inference ran for every request even if
  the live cache hit. A log that only recorded the answers of *misses* has
  no ground truth for the counterfactual "what if this had hit a different
  entry", so it cannot score a hit as right or wrong. replay() refuses
  such entries instead of guessing.

Replay score (analogue of Dream-RSI Eq. 1)
------------------------------------------
    V = saved_calls / N  -  lam * false_hits / N
saved_calls = correct hits (inference avoided, answer still right);
false_hits  = hits that served an answer whose answer_key differs;
lam         = how many saved calls one wrong answer is worth losing.
`lam` is an operator choice, not something replay can learn: without it the
objective is maximised by hitting on everything.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, Hashable, Iterable, List, Optional, Sequence, Tuple

from .semantics import EpsPolicy, candidate_policies, distance

Triple = Tuple[int, int, int]


@dataclass(frozen=True)
class LogEntry:
    """
    One shadow-logged request.
    content_key : what the request is about (e.g. hash of normalized source
                  text, or a cross-language alignment id). Matching never
                  crosses content keys.
    triple      : its (I, C, O) decomposition.
    answer_key  : equivalence class of the correct response (e.g. hash of the
                  normalized output, or a human label). Two responses with the
                  same answer_key are interchangeable. REQUIRED.
    """
    content_key: Hashable
    triple: Triple
    answer_key: Optional[Hashable]


@dataclass
class ReplayResult:
    policy: str
    n: int
    hits: int
    false_hits: int
    inference_calls: int
    score: float

    @property
    def hit_rate(self) -> float:
        return self.hits / self.n if self.n else 0.0

    @property
    def false_hit_rate(self) -> float:
        return self.false_hits / self.hits if self.hits else 0.0


def _name(policy) -> str:
    return getattr(policy, "name", repr(policy))


def replay(policy: Callable[[Triple, Triple], bool], log: Sequence[LogEntry],
           lam: float = 5.0) -> ReplayResult:
    """
    Replay one log (one "world") under a match policy.
    Requests are processed in log order against a cache that starts empty,
    as it would online: on a miss, inference runs and its answer is stored;
    on a hit, the stored answer is served and compared with ground truth.
    Among matching cached triples, the closest (chordal) one is served — the
    same tie-break SemanticCache.get() uses.
    """
    cache: Dict[Hashable, Dict[Triple, Hashable]] = {}
    hits = false_hits = calls = 0
    for i, e in enumerate(log):
        if e.answer_key is None:
            raise ValueError(
                f"log entry {i} has no answer_key: replay needs shadow-mode ground "
                "truth for every request (see module docstring)")
        q = tuple(e.triple)
        bucket = cache.setdefault(e.content_key, {})
        best, best_d = None, float("inf")
        for t, ans in bucket.items():
            if policy(q, t):
                d = distance(q, t)
                if d < best_d:
                    best, best_d = ans, d
        if best is not None:
            hits += 1
            if best != e.answer_key:
                false_hits += 1
        else:
            calls += 1
            bucket[q] = e.answer_key
    n = len(log)
    saved = hits - false_hits
    score = (saved - lam * false_hits) / n if n else 0.0
    return ReplayResult(_name(policy), n, hits, false_hits, calls, score)


def evaluate(policy, worlds: Iterable[Sequence[LogEntry]], lam: float = 5.0) -> Tuple[float, List[ReplayResult]]:
    """Mean replay score over several logs (the paper's V^m = mean_i V_i^m)."""
    results = [replay(policy, w, lam) for w in worlds]
    mean = sum(r.score for r in results) / len(results) if results else 0.0
    return mean, results


def dream(worlds: Sequence[Sequence[LogEntry]], incumbent=None, candidates=None,
          lam: float = 5.0) -> Dict[str, Any]:
    """
    Evaluate every candidate policy on the fixed history and select the best.
    The incumbent (default: SPEC eps = 0.65) is always in the candidate set,
    so the selected policy's mean replay score is >= the incumbent's on this
    history. Ties are broken toward the incumbent, so a policy is only
    replaced when replay shows a strict improvement.
    """
    worlds = [list(w) for w in worlds]
    if not worlds:
        raise ValueError("dream() needs at least one logged world")
    incumbent = incumbent if incumbent is not None else EpsPolicy(0.65)
    pool = [incumbent] + [p for p in (candidates or candidate_policies()) if p != incumbent]

    table = []
    for p in pool:
        mean, per_world = evaluate(p, worlds, lam)
        tot_n = sum(r.n for r in per_world)
        tot_h = sum(r.hits for r in per_world)
        tot_f = sum(r.false_hits for r in per_world)
        table.append({
            "policy": p, "name": _name(p), "score": mean,
            "hit_rate": tot_h / tot_n if tot_n else 0.0,
            "false_hit_rate": tot_f / tot_h if tot_h else 0.0,
        })
    inc = table[0]
    best = max(table, key=lambda r: r["score"])
    if best["score"] <= inc["score"]:
        best = inc
    ranked = sorted(table, key=lambda r: -r["score"])
    return {"selected": best, "incumbent": inc, "ranking": ranked, "lam": lam,
            "n_worlds": len(worlds), "n_requests": sum(len(w) for w in worlds)}
