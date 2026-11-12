---
name: CYBERVEIL
description: Native desktop behavior-observation and recorded-evidence console.
colors:
  ink: "#06111F"
  background: "#081827"
  surface: "#10253A"
  surface-raised: "#173149"
  surface-hover: "#1D3B55"
  line: "#284A61"
  accent: "#22D3C5"
  accent-deep: "#0C918C"
  accent-soft: "#90F4EA"
  text: "#F3F8FA"
  muted: "#A9C0CC"
  dim: "#718C9C"
  danger: "#FF6674"
  warning: "#F5C45A"
  info: "#5B9CFF"
  success: "#3DD6A2"
typography:
  display:
    fontSize: "34px"
    fontWeight: 750
  headline:
    fontSize: "30px"
    fontWeight: 700
  title:
    fontSize: "19px"
    fontWeight: 700
  body:
    fontSize: "15px"
  control:
    fontSize: "14px"
    fontWeight: 650
  metric:
    fontSize: "24px"
    fontWeight: 750
  label:
    fontSize: "12px"
  code:
    fontFamily: "Menlo"
    fontSize: "11pt"
rounded:
  field: "11px"
  control: "12px"
  table: "13px"
  raised-panel: "14px"
  action-tile: "15px"
  panel: "16px"
spacing:
  step-8: "8px"
  step-12: "12px"
  step-16: "16px"
  step-18: "18px"
  step-20: "20px"
  step-24: "24px"
  step-28: "28px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "#031A1A"
    rounded: "{rounded.control}"
    padding: "0 18px"
    typography: "{typography.control}"
  button-secondary:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 18px"
    typography: "{typography.control}"
  button-secondary-hover:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.text}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 8px"
  field:
    backgroundColor: "#0B1D2E"
    textColor: "{colors.text}"
    rounded: "{rounded.field}"
    padding: "0 13px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
  action-tile:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.action-tile}"
    padding: "18px 20px"
  table:
    backgroundColor: "#0B1D2E"
    textColor: "{colors.text}"
    rounded: "{rounded.table}"
---

# Design System: CYBERVEIL

## Overview

**Creative North Star: "The Behavior Observation Console"**

CYBERVEIL is an Operate-mode native desktop console. The incumbent world is a deep navy working field with teal instrumentation, pale readable text, fine borders, and restrained luminous atmosphere. Its radar, shield/circuit vocabulary, and quiet line icons make observation the focal task. This record extends that established world; it does not establish a new aesthetic.

State and evidence take priority over decoration. English and Arabic share the same screen family, with Qt layout direction handling right-to-left presentation. The adjacent sandbox-report action inherits the existing secondary control treatment and keeps recorded evidence distinct from local observation.

**Key Characteristics:**
- Navy tonal surfaces with one operating teal accent.
- Large state text, compact metrics, and direct action labels.
- Rounded line controls, native desktop navigation, and evidence-first reports.
- English/Arabic parity with explicit busy and disabled states.

This is a scan of the shipped PySide6/Fusion implementation, principally [theme.py](src/cyberveil/ui/theme.py), [components.py](src/cyberveil/ui/components.py), [pages.py](src/cyberveil/ui/pages.py), and [main_window.py](src/cyberveil/ui/main_window.py). The metaphor names the incumbent instrument; it is not a separately user-selected visual direction. Ground-truth captures are the English/Arabic dashboard, busy, report, and alert images at `tmp/api-{ui,busy,report,alert}-{en,ar}.png`.

## Colors

The palette is restrained: navy tonal layers and a single teal operating accent, with semantic status colors reserved for evidence and state. Frontmatter holds the normative values.

### Primary

- **Operating Teal** (`accent`): primary monitoring action, focus borders, line icons, progress, and radar center.
- **Deep Teal** (`accent-deep`): selection and secondary emphasis.
- **Soft Teal** (`accent-soft`): restrained highlighted text.

### Secondary

These are semantic signals, not extra decorative accents: **Alert Coral** (`danger`), **Caution Amber** (`warning`), **Information Blue** (`info`), and **Observed Success Green** (`success`). Severity remains readable in text; a model score is not a calibrated probability of infection.

### Neutral

- **Navy Field** (`background`) and **Deep Ink** (`ink`): desktop environment and deepest contrast.
- **Panel Navy** (`surface`), **Raised Navy** (`surface-raised`), and **Hover Navy** (`surface-hover`): distinct resting and interactive layers.
- **Steel Divider** (`line`): fine outlines, table structure, and separators.
- **Pale Text** (`text`), **Muted Blue Gray** (`muted`), and **Dim Blue Gray** (`dim`): primary copy, support copy, and subdued metadata/disabled labels respectively. Dim text is not the default reading color.

**The Evidence Keeps Its Source Rule.** Recorded sandbox findings remain labelled as recorded evidence; their controls never imply a local process can be terminated.

## Typography

Hierarchy comes from size and weight rather than decorative display styling. The UI inherits the platform Qt font; no cross-platform heading family or fallback stack is explicitly fixed. That inherited face is observed implementation, not a prescribed brand display face. Logs and raw forensic text explicitly request Menlo. Point sizes and pixel sizes are preserved as authored rather than silently converted.

- **Display:** prominent readiness/observation state.
- **Headline:** screen title.
- **Title:** section and dialog headings.
- **Body:** supporting explanations, with wrapping where the implementation provides it.
- **Control:** action labels; the primary action separately uses a stronger (15px, 750) treatment.
- **Metric / Label:** prominent compact values paired with smaller descriptive labels.
- **Code:** technical log/forensic inspection text; Qt supplies fallback if Menlo is absent.

The brand remains the existing split-color CYBERVEIL wordmark. Its tracked uppercase treatment is identity-specific, not a general heading or eyebrow style. No custom line-height scale is defined in Qt stylesheets.

## Layout

This is a native desktop system, not a responsive website. The main window opens at (1240 × 800) logical pixels and enforces a minimum of (1024 × 700). There is no mobile layout or CSS breakpoint system. Narrow desktop windows retain the native arrangement and use scroll areas for the dashboard/settings bodies rather than inventing mobile navigation.

The header is (72px) high with a centered brand, back navigation on secondary screens, and notification/settings icon controls. Standard page content uses margins of (54px horizontal, 34px top, 42px bottom), with vertical rhythms generally (20–24px). Dashboard hero content pairs state/copy and monitoring actions with a bounded radar; its layout stretch is (3:2). The radar has a (220px) minimum, a (260px) size hint, and a (300px) maximum. Metrics form one horizontal strip; history, logs, and report routes are three substantial adjacent action tiles.

English uses left-to-right Qt layout; Arabic switches the window and dialogs to right-to-left. Preserve readable mixed-direction identifiers and actual translated copy rather than mechanically mirroring strings. The captured report view places long evidence in a scrollable text browser. Native window scaling and scroll behavior are the current adaptation mechanism; a future reflow requires separate verification.

## Elevation & Depth

Panels use solid tonal layers and thin borders rather than cast shadows. Two low-opacity radial ambient fields are painted into the navy backdrop, while the radar uses a local teal glow and a scanning sweep. There are no drop-shadow elevation tokens. This restrained luminosity belongs to the incumbent instrument and does not justify glowing control outlines everywhere.

**The Task Before Atmosphere Rule.** Keep readiness, the current operation, and its available action readable before the luminous decoration.

Radar motion is stateful: a (36ms) timer advances the sweep by (3°) while active; reduced-motion mode stops that timer and retains a static instrument. Ordinary controls have direct color/border changes; no transition-duration or easing scale is defined.

## Shapes

Soft rectangular surfaces use the observed radius family in frontmatter: larger panels, slightly tighter raised panels and navigation tiles, then controls and inputs. Fine (1px) borders supply structure; keyboard focus uses a teal (2px) border. Circular geometry belongs to the radar, not to general containers. The custom icon family uses rounded line caps/joins and familiar shield, report, history, log, and control forms.

## Components

### Buttons

The primary monitoring action uses solid teal and dark text. Secondary actions use raised navy, a fine steel border, and pale text; sandbox-report analysis uses this established secondary treatment. Resting controls have a (42px) minimum height with horizontal padding from frontmatter. Hover increases surface contrast; press darkens it; focus draws the teal border. Disabled controls use dim text and a darker navy field where the common disabled selector applies. Danger actions have their own red stylesheet and must be checked in their actual disabled state rather than inferred from color alone.

Header ghost controls are icon-only, with translated accessible names and tooltips. Danger styling is reserved for consequential remediation; the alert dialog defaults focus to the safe ignore action.

### Chips

The existing compact lab badge identifies the academic context with pale teal text, a dark teal field, and a fine teal outline. It is an observed status marker, not a generic section-kicker pattern or a required new component on every page.

### Cards / Containers

Panels are solid navy with rounded outlines; raised panels step up tonally. Internal padding follows context: the main state panel is more generous, while facts and forms remain compact. Metric values live in one band with top/bottom separators, not a new card per number.

### Inputs / Fields

Text, combo, and numeric fields share a recessed navy background, steel border, rounded field corners, and (42px) minimum height. Focus uses the common teal border; selection uses deep teal. Use native keyboard behavior and labelled fields rather than placeholder-only instructions.

### Navigation

Back, notifications, and settings stay in the native header. Dashboard routes use large secondary tiles with teal line icons and direct action labels. Selected records are reached through history/notifications/reports rather than introducing a web-style sidebar. Tables use alternating recessed navy rows, teal-navy headers, row selection, and no editable cells for evidence lists.

### Radar and operational state

The radar is the recurring instrument: concentric rings, crosshairs, a center point, and restrained signal dots. The adjacent text is the authoritative state. The animated sweep indicates observation activity; it is not evidence that an infection was found or prevented.

### Recorded sandbox evidence

The dashboard places **Analyze sandbox report** beneath the live-operation panel, beside explicit copy that recorded CAPE/Cuckoo Windows API calls are classified and no sample is executed. During analysis the action stays disabled and the adjacent text shows progress; the stored busy flag preserves that state through language changes. Completion opens the existing report family, with evidence source and model context retained. A flagged import also opens its recorded-evidence alert automatically; the finding remains in Notifications. Unflagged imports open the report without an alert, and previous findings are not reopened.

Sandbox alerts use the existing severity/facts dialog but say recorded behavior was flagged. Local blocking is disabled for imported sandbox and forensic evidence. The historic PID sentinel is non-actionable. Preserve flagged and unflagged results and distinguish execution time from import time. Experimental classifier limitations, misses, and failed quality gates belong with the evidence: see the [Windows API model card](docs/WINDOWS_API_MODEL_CARD.md), [real-detection result](docs/REAL_DETECTION_RESULT_20261101.md), and [original model card](docs/MODEL_CARD.md). These screens do not establish live API capture, fileless proof, local detonation, or reliable protection.

The sidecar's HTML/CSS examples are portable visual translations of native Qt components for the design panel. They are not a second production UI or a new interaction specification. Its generated tonal ramps are viewing aids, not additional application colors.

## Do's and Don'ts

### Do:
- **Do** keep the radar and plain-language observation state dominant on the dashboard.
- **Do** preserve secondary styling and adjacent no-execution explanation for sandbox-report analysis.
- **Do** preserve busy state when changing language, and keep historical evidence non-actionable for local blocking.
- **Do** pair status colors with readable labels, evidence, and scores.
- **Do** verify native normal-width, narrow-width, keyboard-focus, and Arabic right-to-left states.

### Don't:
- **Don't** promote imported execution evidence into a claim of active infection, live API capture, fileless proof, or reliable protection.
- **Don't** introduce mobile navigation or a new visual direction into this desktop extension.
- **Don't** use success color or an unflagged result as proof that a sample is safe.
- **Don't** turn the existing lab badge, punctuation alert marker, or inherited platform heading face into a mandatory new-screen pattern.
