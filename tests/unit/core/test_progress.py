"""Jauge d'activité : montrer que ça travaille, et à quoi.

Sur une opération longue, une interface immobile est indiscernable d'une
interface plantée. Ces tests portent sur la matière affichée — phase, jetons,
durée — indépendamment de toute IHM.
"""

from src.mirai.core.progress import (
    SPINNER_FRAMES,
    NullProgress,
    RunProgress,
)


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_estimates_tokens_from_characters():
    progress = RunProgress()
    progress.on_text("x" * 40)
    assert progress.tokens == 10          # 40 / 4
    assert progress.is_exact is False


def test_exact_usage_overrides_the_estimate():
    """Si le relais envoie `usage`, il fait autorité."""
    progress = RunProgress()
    progress.on_text("x" * 4000)
    progress.exact_tokens(137)

    assert progress.tokens == 137
    assert progress.is_exact is True


def test_reasoning_counts_but_names_a_different_phase():
    """Distinguer « réfléchit » de « rédige » : l'utilisateur veut savoir."""
    progress = RunProgress()
    progress.on_reasoning("y" * 20)

    assert progress.phase == "Réflexion"
    assert progress.tokens == 5


def test_text_switches_the_phase_to_writing():
    progress = RunProgress()
    progress.on_reasoning("y" * 20)
    progress.on_text("bonjour")
    assert progress.phase == "Rédaction"


def test_tool_phase_can_be_set_explicitly():
    progress = RunProgress()
    progress.set_phase("Action sur le document")
    assert progress.phase == "Action sur le document"


def test_spinner_cycles_without_repeating_immediately():
    progress = RunProgress()
    frames = [progress.spin() for _ in range(len(SPINNER_FRAMES))]
    assert frames == list(SPINNER_FRAMES)
    assert progress.spin() == SPINNER_FRAMES[0], "le cycle doit boucler"


def test_elapsed_uses_the_injected_clock():
    clock = FakeClock()
    progress = RunProgress(now=clock)
    clock.advance(12.4)
    assert int(progress.elapsed) == 12


def test_render_shows_phase_tokens_and_duration():
    clock = FakeClock()
    progress = RunProgress(now=clock)
    progress.on_text("x" * 400)
    clock.advance(7)

    line = progress.render()

    assert "Rédaction" in line
    assert "100 tk" in line
    assert "7 s" in line
    assert line[0] in SPINNER_FRAMES


def test_render_marks_estimated_counts():
    """Ne jamais faire passer une approximation pour une mesure."""
    progress = RunProgress()
    progress.on_text("x" * 400)
    assert "~100 tk" in progress.render()

    progress.exact_tokens(88)
    rendered = progress.render()
    assert "88 tk" in rendered
    assert "~" not in rendered


def test_render_omits_tokens_before_anything_arrives():
    progress = RunProgress()
    assert "tk" not in progress.render()


def test_large_counts_are_readable():
    progress = RunProgress()
    progress.exact_tokens(12400)
    assert "12 400 tk" in progress.render()


def test_render_can_avoid_advancing_the_spinner():
    progress = RunProgress()
    first = progress.render(spin=False)
    second = progress.render(spin=False)
    assert first == second


def test_null_progress_accepts_everything():
    """Hors interface, la jauge doit être inerte sans jamais gêner."""
    progress = NullProgress()
    progress.on_text("x")
    progress.on_reasoning("y")
    progress.exact_tokens(5)
    progress.set_phase("peu importe")
