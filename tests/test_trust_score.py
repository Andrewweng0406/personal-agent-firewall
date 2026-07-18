from app.risk.trust_score import compute_trust_profile


def test_no_history_is_neutral_and_uses_base_threshold_unchanged():
    profile = compute_trust_profile(70, [])

    assert profile.trust_score == 50
    assert profile.effective_threshold == 70
    assert profile.event_count == 0


def test_repeated_containment_events_lower_the_threshold():
    history = [{"decision": "denied_auto_contained", "behavior_lane": "red"}] * 3

    profile = compute_trust_profile(70, history)

    assert profile.trust_score < 50
    assert profile.effective_threshold < 70


def test_repeated_clean_allowed_events_raise_the_threshold():
    history = [{"decision": "allowed", "behavior_lane": "green"}] * 30

    profile = compute_trust_profile(70, history)

    assert profile.trust_score > 50
    assert profile.effective_threshold > 70


def test_denied_without_containment_penalizes_less_than_auto_contained():
    plain_denied_history = [{"decision": "denied", "behavior_lane": "yellow"}] * 3
    contained_history = [{"decision": "denied_auto_contained", "behavior_lane": "red"}] * 3

    plain_profile = compute_trust_profile(70, plain_denied_history)
    contained_profile = compute_trust_profile(70, contained_history)

    assert plain_profile.trust_score > contained_profile.trust_score


def test_trust_score_is_clamped_to_0_and_100():
    very_bad_history = [{"decision": "denied_auto_contained", "behavior_lane": "red"}] * 20
    very_good_history = [{"decision": "allowed", "behavior_lane": "green"}] * 1000

    bad_profile = compute_trust_profile(70, very_bad_history)
    good_profile = compute_trust_profile(70, very_good_history)

    assert bad_profile.trust_score == 0
    assert good_profile.trust_score == 100


def test_effective_threshold_never_exceeds_the_outer_ceiling_even_at_max_trust():
    very_good_history = [{"decision": "allowed", "behavior_lane": "green"}] * 1000

    profile = compute_trust_profile(95, very_good_history)  # already near the ceiling

    assert profile.trust_score == 100
    assert profile.effective_threshold <= 90


def test_effective_threshold_never_drops_below_the_outer_floor_even_at_zero_trust():
    very_bad_history = [{"decision": "denied_auto_contained", "behavior_lane": "red"}] * 20

    profile = compute_trust_profile(10, very_bad_history)  # already near the floor

    assert profile.trust_score == 0
    assert profile.effective_threshold >= 25


def test_max_trust_can_only_relax_the_threshold_by_a_small_bounded_amount():
    # This is the core safety property: trust must never be able to raise
    # the threshold high enough to swallow real static evidence (e.g. a
    # protected-path overwrite, which the AST analyzer alone already scores
    # 80). A maximally-trusted agent gets at most a small amount of extra
    # leeway -- never enough to erase that kind of concrete finding.
    very_good_history = [{"decision": "allowed", "behavior_lane": "green"}] * 1000

    profile = compute_trust_profile(70, very_good_history)

    assert profile.trust_score == 100
    assert profile.effective_threshold <= 80  # 70 base + at most +10


def test_zero_trust_can_tighten_the_threshold_much_more_aggressively():
    very_bad_history = [{"decision": "denied_auto_contained", "behavior_lane": "red"}] * 20

    profile = compute_trust_profile(70, very_bad_history)

    assert profile.trust_score == 0
    assert profile.effective_threshold <= 55  # 70 base - at least -15


def test_allowed_but_not_green_lane_does_not_earn_a_clean_bonus():
    history = [{"decision": "allowed", "behavior_lane": "yellow"}] * 10

    profile = compute_trust_profile(70, history)

    assert profile.trust_score == 50
    assert profile.effective_threshold == 70


def test_event_count_reflects_history_length():
    history = [{"decision": "allowed", "behavior_lane": "green"}] * 7

    profile = compute_trust_profile(70, history)

    assert profile.event_count == 7
