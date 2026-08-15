"""Animate a real Lenstra ECM trace produced by :mod:`ecc_factor`.

Render from the repository root with:

    uv run --extra animation manim -pql \
        examples/manim_ecm_factorization.py EcmFactorizationScene
"""

from __future__ import annotations

from math import cos, sin, tau

from manim import (
    BLUE,
    DOWN,
    FadeIn,
    FadeOut,
    GREEN,
    Indicate,
    LEFT,
    ORANGE,
    RED,
    RIGHT,
    Scene,
    Text,
    Transform,
    UP,
    VGroup,
    WHITE,
    Write,
    YELLOW,
    Circle,
    Dot,
    Rectangle,
)

try:
    from examples.ecm_animation_data import LONG_COMPOSITE, build_ecm_story
except ModuleNotFoundError:  # Manim adds the scene's directory to sys.path.
    from ecm_animation_data import LONG_COMPOSITE, build_ecm_story


def short_integer(value: int | None, head: int = 9, tail: int = 7) -> str:
    """Keep large values readable on screen."""

    if value is None:
        return "point at infinity"
    digits = str(value)
    if len(digits) <= head + tail + 1:
        return digits
    return f"{digits[:head]}...{digits[-tail:]}"


class EcmFactorizationScene(Scene):
    """Walk through actual SDK events for a deterministic 42-digit factorization."""

    def construct(self) -> None:
        factors, events = build_ecm_story()

        title = Text("Lenstra ECM: a factor appears when division fails", font_size=34)
        title.to_edge(UP)
        number = Text(f"N = {LONG_COMPOSITE}", font_size=25, color=YELLOW)
        number.next_to(title, DOWN, buff=0.35)
        academic = Text(
            "Academic visualization — not production cryptography",
            font_size=18,
            color=ORANGE,
        ).to_edge(DOWN)
        self.play(Write(title), FadeIn(number), FadeIn(academic))

        steps = VGroup(
            Text("1  Pick a curve and point modulo N", font_size=24),
            Text("2  Multiply P by every prime power <= B1", font_size=24),
            Text("3  Try to invert each point-addition denominator", font_size=24),
            Text("4  A failed inverse reveals gcd(denominator, N)", font_size=24),
        ).arrange(DOWN, aligned_edge=LEFT, buff=0.22)
        steps.move_to(DOWN * 0.25)
        self.play(FadeIn(steps, shift=UP * 0.2))
        self.wait(1)
        self.play(FadeOut(steps))

        ring = Circle(radius=1.42, color=BLUE).shift(LEFT * 3.25 + DOWN * 0.45)
        ring_label = Text("successive points in E(Z/NZ)", font_size=19, color=BLUE)
        ring_label.next_to(ring, DOWN, buff=0.2)
        point = Dot(ring.get_right(), color=YELLOW, radius=0.09)

        panel = Rectangle(width=6.5, height=3.2, color=WHITE)
        panel.shift(RIGHT * 2.7 + DOWN * 0.35)
        curve_label = Text("waiting for a curve", font_size=21)
        curve_label.move_to(panel.get_top() + DOWN * 0.38)
        formula = Text("y^2 = x^3 + ax + b  (mod N)", font_size=22)
        formula.next_to(curve_label, DOWN, buff=0.32)
        operation = Text("stage-one multiplication", font_size=20, color=YELLOW)
        operation.next_to(formula, DOWN, buff=0.35)

        track = Rectangle(width=5.2, height=0.22, color=BLUE)
        track.next_to(operation, DOWN, buff=0.35)
        fill = Rectangle(
            width=0.01,
            height=0.18,
            stroke_width=0,
            fill_color=GREEN,
            fill_opacity=1,
        )
        fill.align_to(track, LEFT).move_to(track.get_left() + RIGHT * 0.005)

        self.play(
            FadeIn(ring),
            FadeIn(ring_label),
            FadeIn(point),
            FadeIn(panel),
            FadeIn(curve_label),
            FadeIn(formula),
            FadeIn(operation),
            FadeIn(track),
            FadeIn(fill),
        )

        for event in events:
            if event.code == "ecm.curve":
                new_curve_label = Text(
                    f"curve {event.data['curve']} / 50    B1 = {event.data['bound']}",
                    font_size=21,
                    color=BLUE,
                ).move_to(curve_label)
                new_formula = Text(
                    "a = "
                    + short_integer(int(event.data["a"]))
                    + "    b = "
                    + short_integer(int(event.data["b"])),
                    font_size=18,
                ).move_to(formula)
                empty_fill = Rectangle(
                    width=0.01,
                    height=0.18,
                    stroke_width=0,
                    fill_color=GREEN,
                    fill_opacity=1,
                )
                empty_fill.align_to(track, LEFT).move_to(track.get_left() + RIGHT * 0.005)
                self.play(
                    Transform(curve_label, new_curve_label),
                    Transform(formula, new_formula),
                    Transform(fill, empty_fill),
                    run_time=0.45,
                )

            elif event.code == "ecm.multiply":
                completed = int(event.data["completed"])
                total = int(event.data["total"])
                power = int(event.data["power"])
                angle = (int(event.data["point_x"] or 0) % 360) / 360 * tau
                target = ring.get_center() + ring.radius * (
                    RIGHT * cos(angle) + UP * sin(angle)
                )
                new_operation = Text(
                    f"[{completed:02}/{total}]  P <- {power} P",
                    font_size=20,
                    color=YELLOW,
                ).move_to(operation)
                width = 5.2 * completed / total
                new_fill = Rectangle(
                    width=width,
                    height=0.18,
                    stroke_width=0,
                    fill_color=GREEN,
                    fill_opacity=1,
                )
                new_fill.align_to(track, LEFT)
                new_fill.move_to(track.get_left() + RIGHT * width / 2)
                self.play(
                    point.animate.move_to(target),
                    Transform(operation, new_operation),
                    Transform(fill, new_fill),
                    run_time=0.11,
                )

            elif event.code == "ecm.inverse_failure":
                failed = Text(
                    "No modular inverse exists",
                    font_size=28,
                    color=RED,
                ).move_to(operation)
                gcd_line = Text(
                    "gcd(denominator, N) = " + str(event.data["factor"]),
                    font_size=25,
                    color=GREEN,
                ).next_to(failed, DOWN, buff=0.35)
                self.play(Transform(operation, failed), FadeIn(gcd_line))
                self.play(Indicate(gcd_line, color=GREEN), run_time=1.2)
                self.play(FadeOut(gcd_line))
                break

        factorization = Text(
            f"{LONG_COMPOSITE}\n= {factors[0]} x {factors[1]}",
            font_size=27,
            color=GREEN,
            line_spacing=1.15,
        ).move_to(DOWN * 0.15)
        conclusion = Text(
            "The curve was the search path; the failed inverse exposed the factor.",
            font_size=22,
        ).next_to(factorization, DOWN, buff=0.5)
        self.play(
            FadeOut(VGroup(ring, ring_label, point, panel, curve_label, formula, track, fill, operation)),
            FadeOut(number),
            FadeIn(factorization),
            FadeIn(conclusion),
        )
        self.wait(2)
