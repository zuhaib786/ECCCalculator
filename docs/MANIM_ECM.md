# Animating ECM with Manim

The scene in `examples/manim_ecm_factorization.py` is deliberately driven by the
factorization SDK. It does not replay a hand-written list of plausible steps.
`build_ecm_story()` runs this deterministic calculation:

```python
from ecc_factor import factorize

events = []
factors = factorize(
    1009 * ((1 << 127) - 1),
    method="ecm",
    seed=11,
    trial_limit=100,
    ecm_bound=200,
    ecm_curves=50,
    progress=events.append,
)
```

The input has 42 decimal digits. The small factor `1009` is deliberately above
the trial-preprocessing limit, so ECM—not trial division—must expose it.

## Render with uv

Manim is an optional dependency because the mathematical SDK itself remains
dependency-free.

```console
uv sync --extra animation
uv run --extra animation manim checkhealth
uv run --extra animation manim -pql \
  examples/manim_ecm_factorization.py EcmFactorizationScene
```

Useful render flags:

- `-pql`: low-quality, fast preview and open the result;
- `-pqm`: medium quality;
- `-pqh`: high quality;
- `-s`: render only the final frame.

The scene uses `Text` rather than `MathTex`, so a TeX installation is not needed
for this particular example. Manim itself may still need platform libraries such
as Cairo and Pango; consult Manim's
[uv installation guide](https://docs.manim.community/en/stable/installation/uv.html)
if `checkhealth` reports a missing component.

## Event-to-animation mapping

| SDK event | Meaning | Animation |
| --- | --- | --- |
| `ecm.curve` | A random curve and starting point were selected modulo `N` | Replace curve parameters and reset progress |
| `ecm.multiply` | The point was multiplied by one prime power below `B1` | Move the point marker and advance the bar |
| `ecm.inverse_failure` | A point operation needed a non-invertible denominator | Turn the operation red and show its gcd |
| `factor.split` | The gcd is a non-trivial factor | Reveal the final product |

The circle in the scene is a schematic state space, not a real-plane plot of the
curve. Points modulo a 42-digit composite do not form the continuous curve shown
in introductory real-coordinate diagrams. Keeping that distinction explicit is
part of the lesson.

## Reuse the pattern

The adapter in `examples/ecm_animation_data.py` contains no Manim imports, so it
can also feed a notebook, web visualization, or recorded lecture overlay. A
second scene could consume CFRAC events in the same way:

- `cfrac.convergent` for the continued-fraction expansion;
- `cfrac.relation` for a factor-base-smooth residue;
- `cfrac.dependency` for Gaussian elimination over parity vectors;
- `cfrac.gcd` for the congruence-of-squares split.

Keep rendering separate from the algorithms: SDK callbacks provide data, while
the visualization decides timing, color, layout, and which detail level to show.
