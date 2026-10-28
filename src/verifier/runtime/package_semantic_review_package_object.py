"""Tier-0 consequence review for the retained package OBJECT residue.

Terminology: application programming interface (API); Hypertext Markup Language
(HTML); JavaScript Object Notation (JSON); line feed (LF); Extensible Markup
Language (XML).

Semantic ownership leaves nine deliberately heterogeneous repository files on
``vstd-package-object``: generated reader-facing site assets, package/tool
configuration, and the static accelerator registry.  ``OBJECT`` is only their
common structural base; it is not an exemption from consequence roles.

The executable orientation-preview asset implements a bounded browser event
loop and therefore needs transaction, measurement, sensor, controller, and
actuator declarations.  Its protocol role is not established by source and
stays UNRESOLVED.  ``pyproject.toml`` supplies package,
build, entry-point, package-data, and test-selection rules and therefore needs
a policy declaration.  The remaining static bytes are included in every
refutation denominator but are not mistaken for the mechanisms they describe.

A DNE (DOES_NOT_APPLY) basis is never established by prose.  It requires a
closure witness computed from the exact current bytes of all nine files: every
outward edge (identifier and member-pair vocabulary of the browser asset, hook
attributes, script and stylesheet references, CSS escapes and string references,
SVG animation, and pyproject-declared build, dependency, entry-point,
package-data and pytest edges) must be enumerated and closed to owned sources.
A malformed pyproject.toml is an open edge carrying a PACKAGE_OBJECT_REVIEW_
code, never a crash.  Documentation that names a ledger, order or payment is a referent,
not a mechanism, and cannot refute or establish a role.  An open witness keeps
the candidate kind UNRESOLVED, which is never exemption.

This module is declarative and fail closed.  It does not execute browser code,
build or install the package, acquire accelerator observations, establish that
the generated documentation is current, or prove Tier-1-plus conformance.  A
complete current-byte preflight and recapture happens before a copied row is
changed, so source drift cannot yield a partially current review.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import posixpath
import re
import tomllib
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared


PACKAGE_OBJECT_ID = "vstd-package-object"

# This is the exact final residue after the 432-child semantic ownership
# catalog, semantic-review policy owner, and test/fixture owner are installed.
# New files must receive an explicit owner; they cannot silently enlarge this
# catchall and inherit the decisions below.
PACKAGE_OBJECT_PATHS = (
    "docs/assets/orientation-previews.js",
    "docs/assets/site.css",
    "docs/assets/vstd-overview.png",
    "docs/assets/vstd-overview.svg",
    "docs/guides.html",
    "docs/index.html",
    "docs/reference.html",
    "pyproject.toml",
    "src/verifier/hardware/accelerator_registry.json",
)
PACKAGE_OBJECT_PATH_DIGEST = (
    "15e60826272e9fa245b208fc8cab7e52af63e05a38d76400a5c878ea742383c6"
)
MAX_PACKAGE_OBJECT_PATHS = 9
MAX_PACKAGE_OBJECT_SOURCE_BYTES = 1_048_576

_BROWSER_PATHS = ("docs/assets/orientation-previews.js",)
_POLICY_PATHS = ("pyproject.toml",)

REVIEW_KINDS = _shared.REVIEW_KINDS
# PROTOCOL is deliberately absent: orientation-previews.js is one page-local
# listener and timer state machine with no serialized participant exchange,
# message identity, compatibility negotiation, or process or remote boundary.
# That is not established source, so the role is UNRESOLVED rather than applied.
APPLICABLE_KINDS = (
    "TRANSACTION",
    "MEASUREMENT",
    "SENSOR",
    "CONTROLLER",
    "ACTUATOR",
    "POLICY",
)
REFUTED_KINDS = ("LEDGER", "ASSET", "MARKET", "ROBOT", "FINBOT")
ROLE_PATHS = {
    "TRANSACTION": _BROWSER_PATHS,
    "MEASUREMENT": _BROWSER_PATHS,
    "SENSOR": _BROWSER_PATHS,
    "CONTROLLER": _BROWSER_PATHS,
    "ACTUATOR": _BROWSER_PATHS,
    "POLICY": _POLICY_PATHS,
}

CLAIM_BOUNDARY = (
    "Exact-current-source Tier-0 consequence classification and declaration "
    "review for the nine retained vstd-package-object files only. A refutation "
    "is claimed only where a closure witness over those exact bytes closes; "
    "declared external edges (build, dependency, console-script, package-data "
    "and pytest option edges, and outward links) leave it open. It does not execute the "
    "browser asset, build, test, install or publish the package, acquire "
    "accelerator observations, establish generated-document freshness, prove "
    "declaration truth, close the installed package or external tools, or "
    "establish Tier-1-plus conformance."
)


_BASE_PROFILE = _shared._Profile(
    name="retained package OBJECT residue",
    scope=(
        "Represent the nine exact retained package files: static generated-site "
        "bytes, one bounded orientation-preview browser interaction, package and "
        "tool configuration, and a static accelerator-profile registry."
    ),
    mechanism=(
        "The browser asset installs finite DOM event listeners and updates one "
        "tooltip; pyproject.toml supplies declarative inputs to selected build, "
        "installation and test tools. Other retained files are static bytes only."
    ),
    participants=(
        "For the browser role, the document, window, repository-preview links, "
        "user-generated browser events and one tooltip element. For policy, the "
        "caller-selected Python packaging, installer and pytest tools."
    ),
    inputs=(
        "Current DOM links and data attributes, pointer/focus/keyboard/resize "
        "events, viewport geometry, and the exact project metadata and tool tables "
        "in pyproject.toml."
    ),
    authority=(
        "The loaded page authorizes mutation of its own preview tooltip and link "
        "accessibility attributes. A caller separately chooses whether a packaging "
        "or test tool may consume pyproject.toml; no release authority is created."
    ),
    states=(
        "The preview has absent-or-installed, hidden-or-visible, no-active-link or "
        "one-active-link, timer-pending, rendered and positioned states. Package "
        "configuration is inactive until a selected compatible tool consumes it."
    ),
    ordering=(
        "Create and append the tooltip before listener use; cancel a prior timer "
        "before delayed show or hide; render before animation-frame positioning; "
        "tool-specific pyproject tables apply only when the selected tool reads them."
    ),
    commands=(
        "Create, append, replace and position tooltip DOM nodes; set or remove "
        "attributes; hide or reveal the tooltip; blur the active link. Packaging "
        "configuration itself issues no command until consumed by an external tool."
    ),
    targets=(
        "One page-local tooltip, repository-preview link attributes and browser "
        "focus state; and, separately, the configuration inputs of explicitly "
        "selected packaging, installation and pytest tools."
    ),
    effect_domains=(
        "CURRENT_BROWSER_DOCUMENT_UI_ONLY for orientation previews; DECLARATIVE_"
        "PACKAGE_TOOL_CONFIGURATION_ONLY for pyproject.toml. No physical, money, "
        "market, publication, release or deployment effect is authorized."
    ),
    effects=(
        "The script can change page-local DOM, style, visibility, accessibility "
        "attributes and focus. A selected external tool may use pyproject rules to "
        "choose build inputs, entry points, package data or tests."
    ),
    commit=(
        "A preview update commits only when its ordered synchronous DOM mutations "
        "return and any scheduled positioning callback runs; no atomic DOM "
        "transaction is claimed. Static configuration has no commit by itself."
    ),
    retry=(
        "Repeated or reordered browser events cancel only the currently stored timer "
        "and can repeat page-local mutations; there is no durable duplicate ledger. "
        "Repeated tool invocation is a new external operation."
    ),
    timing=(
        "Show and hide delays are 250 ms and 120 ms respectively, with positioning "
        "deferred to requestAnimationFrame. Browser scheduling, rendering latency "
        "and external tool completion are not guaranteed."
    ),
    limits=(
        "The preview applies only to matching repository links in one current "
        "document, one tooltip, current viewport dimensions and supported DOM APIs. "
        "The policy applies only to named pyproject tables and compatible tools."
    ),
    observations=(
        "Pointer, focus, blur, Escape and resize events; current active link; tooltip "
        "visibility; link and viewport rectangles; viewport width/height; tooltip "
        "height; and selected tool interpretation of exact pyproject fields."
    ),
    units=(
        "CSS pixels for browser geometry, milliseconds for delay constants, one "
        "active-link identity and Boolean visibility; package versions and path "
        "patterns remain declarative strings."
    ),
    failure=(
        "Missing matching links is an intentional no-op. Unsupported DOM APIs, "
        "exceptions or intervening events can leave only a prefix of UI mutations; "
        "missing or incompatible tooling cannot be treated as policy enforcement."
    ),
    recovery=(
        "A later supported browser event may render and reposition the tooltip or "
        "hide it; page reload reconstructs state. Tool failures require inspection "
        "before a separately authorized fresh build, install or test invocation."
    ),
    boundary=(
        "Static HTML, CSS, images, API descriptions and accelerator registry records "
        "do not execute the APIs or observations they describe. Browser UI mutation "
        "is not publication, physical control, real-money authority or confinement."
    ),
)


_ROLE_PROFILES = {
    "TRANSACTION": replace(
        _BASE_PROFILE,
        name="orientation-preview DOM update transaction",
        scope=(
            "Coordinate the ordered page-local mutations needed to show, render, "
            "position or hide the one orientation-preview tooltip in response to a "
            "selected browser event."
        ),
        inputs=(
            "A matching current link, its data attributes, current active-link and "
            "timer state, current tooltip state, and the triggering browser event."
        ),
        authority=(
            "Authority is confined to DOM nodes created or selected by the loaded "
            "orientation-preview script in its current document; it grants no "
            "network, filesystem, publication or package-management authority."
        ),
        targets=(
            "The page-local tooltip children, class, width, position and hidden flag; "
            "the selected link's aria-describedby and focus; activeLink and timer."
        ),
        effects=(
            "Show/render/position and hide paths perform several ordered DOM and "
            "in-memory mutations; an exception can expose a partial update."
        ),
        commit=(
            "Synchronous mutations commit individually; positioning is a later "
            "animation-frame callback. The source defines no rollback or all-or-"
            "nothing commit across the compound update."
        ),
        retry=(
            "A new event cancels the stored timer where specified but does not dedupe "
            "already completed DOM mutations or an already queued animation frame."
        ),
        boundary=(
            "The transaction is a transient browser-document UI update only; it "
            "does not write storage, send a request, publish documentation, build a "
            "package, or establish external finality."
        ),
    ),
    "MEASUREMENT": replace(
        _BASE_PROFILE,
        name="orientation-preview layout measurement",
        mechanism=(
            "Read link.getBoundingClientRect, window.innerWidth/innerHeight and "
            "card.offsetHeight, then derive clamped tooltip width, left and top CSS "
            "pixel coordinates for the current rendered document."
        ),
        inputs=(
            "The current browser layout of one selected link and tooltip plus the "
            "current viewport dimensions at the position callback."
        ),
        observations=(
            "Link rectangle edges, viewport width and height, tooltip rendered height, "
            "and the derived width, left and top coordinates."
        ),
        units="CSS pixels in the current viewport coordinate frame.",
        timing=(
            "The observation occurs during show or resize handling and, after render, "
            "inside a requestAnimationFrame callback; it has no persisted timestamp."
        ),
        limits=(
            "The method is valid only for the current document, viewport, link, tooltip "
            "content and browser layout engine; the configured margin is 12 CSS pixels."
        ),
        boundary=(
            "These are browser-layout observations used for placement, not physical "
            "measurements, display calibration, historical telemetry or evidence that "
            "the generated documentation is semantically current."
        ),
    ),
    "SENSOR": replace(
        _BASE_PROFILE,
        name="orientation-preview browser-input sensor",
        mechanism=(
            "Register mouseenter, mouseleave, focus, blur, keydown and resize listeners; "
            "inspect event keys, hover/focus state and current DOM geometry."
        ),
        observations=(
            "Presence and ordering of selected browser events, Escape key identity, "
            "hover/focus predicates, active-link identity and current layout values."
        ),
        targets=(
            "The current loaded browser document and window only; no operating-system, "
            "physical-device or remote observation source is addressed."
        ),
        units=(
            "Discrete event identities and Boolean DOM predicates, milliseconds for "
            "debounce delays, and CSS pixels for acquired layout geometry."
        ),
        timing=(
            "Event arrival uses browser dispatch order; show/hide sampling follows "
            "250/120 ms timers and placement can wait for the next animation frame."
        ),
        failure=(
            "Missing matching links yields no installed sensor. Unsupported APIs, "
            "lost events, timer delay or stale layout can prevent or age an observation; "
            "the source provides no completeness claim."
        ),
        boundary=(
            "The sensor acquires page-local digital interaction and layout state only; "
            "it is not a physical sensor, user-identity proof, accessibility audit, or "
            "complete record of interaction."
        ),
    ),
    "CONTROLLER": replace(
        _BASE_PROFILE,
        name="orientation-preview feedback controller",
        scope=(
            "Keep at most one repository-orientation preview selected and place its "
            "tooltip inside the current viewport while responding to pointer, focus, "
            "Escape and resize feedback."
        ),
        commands=(
            "Cancel or schedule show/hide timers, select or clear activeLink, render "
            "content, position the tooltip, update accessibility attributes, and blur "
            "the link on Escape."
        ),
        authority=(
            "The controller may command only its current page-local tooltip and selected "
            "link state through browser DOM APIs."
        ),
        limits=(
            "One tooltip and one active link, 12-pixel margins, a maximum 420-pixel "
            "width, current viewport bounds and available browser scheduling APIs."
        ),
        failure=(
            "Loss or reordering of events, delayed timers, layout changes between "
            "measurement and mutation, or DOM exceptions can leave stale or partial UI "
            "state; no safety-critical stability property is claimed."
        ),
        boundary=(
            "This is a transient UI controller, not an autonomous AGENT, package "
            "release controller, physical plant controller or guaranteed accessibility "
            "mechanism."
        ),
    ),
    "ACTUATOR": replace(
        _BASE_PROFILE,
        name="orientation-preview DOM actuator",
        commands=(
            "Create and append the aside, replace and append text children, set class, "
            "role, aria-describedby, width, left, top and hidden values, remove the "
            "accessibility attribute, and invoke link.blur."
        ),
        targets=(
            "The current page's script-created tooltip, matching repository-preview "
            "links and browser focus state."
        ),
        effect_domains=(
            "CURRENT_BROWSER_DOCUMENT_UI_ONLY; no persistence, network, filesystem, "
            "package build, publication, physical actuator or financial endpoint."
        ),
        authority=(
            "Authority derives only from execution in the current document and is "
            "bounded to its DOM APIs and selected elements."
        ),
        observations=(
            "The source directly reads hidden, activeLink, hover/focus predicates and "
            "layout geometry, but defines no independent acknowledgement that every "
            "requested render or focus effect was perceived by a user."
        ),
        units=(
            "DOM node and attribute identities, Boolean visibility and CSS-pixel width "
            "and coordinates in the current viewport."
        ),
        limits=(
            "Only the selected tooltip and link nodes are addressed; width is capped at "
            "420 CSS pixels and positions are clamped to 12-pixel viewport margins."
        ),
        boundary=(
            "Actuation ends at page-local DOM and focus mutation. It does not establish "
            "rendering, accessibility, user comprehension, publication or an effect "
            "outside the current browser document."
        ),
    ),
    "POLICY": replace(
        _BASE_PROFILE,
        name="Verifier package and tool configuration policy",
        scope=(
            "Configure the verifier-standard distribution metadata, Python floor, "
            "pinned build requirements, optional dependency groups, console aliases, "
            "package-data selection and pytest discovery defaults."
        ),
        inputs=(
            "The exact pyproject project, build-system, optional-dependencies, scripts, "
            "setuptools.package-data and pytest.ini_options tables plus the selected "
            "consumer tool and invocation."
        ),
        ordering=(
            "TOML and tool-specific semantics govern table interpretation; explicit "
            "command-line or environment choices may override defaults according to the "
            "selected tool, and no cross-tool precedence is invented here."
        ),
        authority=(
            "Repository maintainers author the file, while an operator or build system "
            "separately authorizes a named tool invocation. Configuration text alone "
            "does not authorize installation, publication, release or dependency fetch."
        ),
        states=(
            "The policy is inert as repository bytes; it becomes an input only when a "
            "compatible selected packaging, installer or pytest tool parses it."
        ),
        mechanism=(
            "Compatible external tools parse their named TOML tables and enforce only "
            "the fields within their own invocation; this module does not assert that a "
            "tool was invoked or honored every field."
        ),
        observations=(
            "Decision evidence is the current exact pyproject.toml digest plus the "
            "separately observable selected tool, arguments and resulting build, install "
            "or test output; the file alone is not execution evidence."
        ),
        limits=(
            "Only declared tables and compatible tool versions are covered. Optional "
            "groups remain optional, dependencies are not automatically trusted, and "
            "entry-point naming does not establish installed reachability."
        ),
        failure=(
            "Missing, invalid, incompatible, bypassed or overridden policy remains "
            "unavailable or externally determined; no successful build, test, install "
            "or release is inferred from valid TOML."
        ),
        boundary=(
            "The policy defines package/tool inputs but does not execute a tool, fetch a "
            "dependency, install an entry point, include every intended byte, publish a "
            "distribution or qualify a release."
        ),
    ),
}


_REASONS = {
    "LEDGER": (
        "vstd-package-object does not apply as LEDGER: the closure witness over "
        "orientation-previews.js finds no storage, network, or log-writing identifier or "
        "member pair outside its pinned vocabulary, the static site files and "
        "accelerator_registry.json carry no outward or executable hook, and pyproject.toml "
        "declares no external edge; prose naming a ledger API in reference.html is a referent, "
        "not a posting mechanism."
    ),
    "TRANSACTION": (
        "vstd-package-object applies as TRANSACTION because orientation-previews.js "
        "coordinates multiple page-local DOM, accessibility, focus and in-memory state "
        "mutations whose commit, partial-failure and repeated-event boundaries matter."
    ),
    "ASSET": (
        "vstd-package-object does not apply as ASSET: the closure witness over "
        "orientation-previews.js finds no state-writing, storage, or network member pair outside "
        "its pinned vocabulary, accelerator_registry.json is inert declaration data with no "
        "outward edge, and pyproject.toml declares no external edge, so the object contains no "
        "asset-state mechanism; registry values are not interpreted as rights records."
    ),
    "MARKET": (
        "vstd-package-object does not apply as MARKET: the closure witness over "
        "orientation-previews.js finds no order, matching, pricing, or settlement mechanism "
        "outside its pinned vocabulary, accelerator_registry.json and the static pages are inert "
        "or referent text, and pyproject.toml declares no external edge; layout ordering in "
        "site.css is not a market order."
    ),
    "MEASUREMENT": (
        "vstd-package-object applies as MEASUREMENT because orientation-previews.js "
        "reads current link, tooltip and viewport geometry and derives placement in a "
        "defined CSS-pixel frame with explicit timing and validity limits."
    ),
    "SENSOR": (
        "vstd-package-object applies as SENSOR because orientation-previews.js acquires "
        "pointer, focus, keyboard and resize events plus current DOM geometry through "
        "browser listeners and layout APIs with sampling and fault boundaries."
    ),
    "CONTROLLER": (
        "vstd-package-object applies as CONTROLLER because orientation-previews.js uses "
        "event, hover, focus, active-link and viewport feedback to schedule and command "
        "bounded show, hide, render and positioning behavior."
    ),
    "ACTUATOR": (
        "vstd-package-object applies as ACTUATOR because orientation-previews.js accepts "
        "controller decisions and causes page-local DOM, style, accessibility, visibility "
        "and focus effects on specifically bounded targets."
    ),
    "POLICY": (
        "vstd-package-object applies as POLICY because pyproject.toml defines scoped "
        "package, build, dependency-group, command-alias, package-data and test-discovery "
        "rules consumed at named external tool enforcement points."
    ),
    "ROBOT": (
        "vstd-package-object does not apply as ROBOT: the closure witness over "
        "orientation-previews.js finds no navigator device, serial, USB, Bluetooth, WebSocket, or "
        "geolocation member pair outside its pinned vocabulary, the static site files carry no "
        "outward or executable hook, and pyproject.toml declares no external edge, so the nine "
        "files form no agent-to-actuator path."
    ),
    "FINBOT": (
        "vstd-package-object does not apply as FINBOT: the closure witness over "
        "orientation-previews.js finds no payment, network, or financial-endpoint member pair "
        "outside its pinned vocabulary, the static pages carry no outward hook outside the owned "
        "set, and pyproject.toml declares no external edge, so the nine files create no "
        "money-movement path."
    ),
}


def _basis(kind: str, *, closed: bool = False) -> str:
    """Select only an explicitly catalogued answer; omission remains unknown.

    A refutation is a candidate until a closure witness over the exact current
    bytes is closed.  Without that witness it is UNRESOLVED, never exemption.
    """
    if kind in APPLICABLE_KINDS:
        return "APPLIES"
    if kind in REFUTED_KINDS and closed:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _unresolved_reason(kind: str) -> str:
    return (
        "Migration retains this applicability question. Static ownership "
        "alone cannot refute a " + kind + " role."
    )


def _obligation_reason(kind: str) -> str:
    return (
        _REASONS[kind]
        + " This Tier-0 declaration names the exact reviewed source boundary "
        "only; execution, declaration truth, generated-byte freshness and "
        "Tier-1-plus fulfillment remain unestablished."
    )


def _path_digest(paths: tuple[str, ...]) -> str:
    return sha256("\n".join(paths).encode("utf-8")).hexdigest()


# Closure witness.  Each pinned set below is the exact vocabulary of the current
# bytes, computed by ``_js_members`` and re-derived by the tests.  Any new
# identifier, member pair, or computed access leaves the witness open, so a
# changed asset reopens review rather than inheriting the old refutations.
_JS_PATH = "docs/assets/orientation-previews.js"
_JS_VOCABULARY: frozenset[str] = frozenset(
    {
        "$", "Math", "activeElement", "activeLink", "addEventListener", "append",
        "blur", "body", "bottom", "card", "className", "clearTimeout", "const",
        "createElement", "dataset", "document", "element", "event", "false", "for",
        "getBoundingClientRect", "hidden", "hide", "id", "if", "innerHeight",
        "innerWidth", "key", "left", "length", "let", "link", "links", "margin",
        "matches", "max", "min", "null", "of", "offsetHeight", "orientationConcept",
        "orientationDefinition", "position", "px", "querySelectorAll", "rect",
        "removeAttribute", "render", "replaceChildren", "requestAnimationFrame",
        "return", "setAttribute", "setTimeout", "show", "style", "tag", "text",
        "textContent", "textElement", "timer", "top", "true", "width", "window",
    }
)
_JS_MEMBER_PAIRS: frozenset[str] = frozenset(
    {
        "Math.max", "Math.min", "body.append", "card.append", "card.className",
        "card.hidden", "card.id", "card.offsetHeight", "card.replaceChildren",
        "card.setAttribute", "card.style", "dataset.orientationConcept",
        "dataset.orientationDefinition", "document.activeElement",
        "document.addEventListener", "document.body", "document.createElement",
        "document.querySelectorAll", "element.className", "element.textContent",
        "event.key", "link.addEventListener", "link.blur", "link.dataset",
        "link.getBoundingClientRect", "link.matches", "link.removeAttribute",
        "link.setAttribute", "links.length", "rect.bottom", "rect.left", "rect.top",
        "style.left", "style.top", "style.width", "window.addEventListener",
        "window.innerHeight", "window.innerWidth",
    }
)
_FORBIDDEN_JS_NAMES = frozenset(
    {
        "BroadcastChannel",
        "Function",
        "MessageChannel",
        "Proxy",
        "Reflect",
        "ServiceWorker",
        "SharedWorker",
        "Worker",
        "WebSocket",
        "XMLHttpRequest",
        "EventSource",
        "FileReader",
        "bluetooth",
        "console",
        "cookie",
        "eval",
        "fetch",
        "geolocation",
        "globalThis",
        "importScripts",
        "indexedDB",
        "innerHTML",
        "insertAdjacentHTML",
        "localStorage",
        "location",
        "navigator",
        "opener",
        "outerHTML",
        "postMessage",
        "sendBeacon",
        "serial",
        "sessionStorage",
        "showOpenFilePicker",
        "usb",
    }
)
_TIMER_CALLS = frozenset({"requestAnimationFrame", "setInterval", "setTimeout"})
# A line comment ends at every ECMAScript LineTerminator, not only LF.  The lexer
# never guesses between a regular-expression literal and a comment or division:
# any slash that is not part of a comment token is lexed alone and opens the
# witness, and a regex literal always begins with such a slash.
_JS_TOKEN = re.compile(
    r"//[^\n\r  ]*"
    r"|/\*.*?\*/"
    r"|'(?:\\.|[^'\\\n\r])*'"
    r"|\"(?:\\.|[^\"\\\n\r])*\""
    r"|`(?:\\.|[^`\\])*`"
    r"|[A-Za-z_$][A-Za-z0-9_$]*"
    r"|\d\w*"
    r"|\?\.|\.\.\.|\S",
    re.DOTALL,
)
# Restricted sinks.  Each named call must take an allowlisted literal first
# argument, and a bare reference to a restricted name opens the witness because an
# alias would escape the argument check.  No script-bearing element can be created.
_JS_TEXT_TAGS = frozenset({"p", "small", "span", "strong"})
_JS_CREATED_TAGS = _JS_TEXT_TAGS | frozenset({"aside"})
_JS_SCRIPT_BEARING_TAGS = frozenset(
    {"base", "embed", "form", "frame", "iframe", "link", "meta", "object", "script", "style"}
)
_JS_LITERAL_ARGUMENTS = {
    "createElement": _JS_CREATED_TAGS,
    "removeAttribute": frozenset({"aria-describedby"}),
    "querySelectorAll": frozenset({'a[data-orientation-preview="repository"]'}),
    "setAttribute": frozenset({"aria-describedby", "role"}),
    "textElement": _JS_TEXT_TAGS,
}
# An unclosed style element runs to the end of the document, so it is scanned to
# the end; an unquoted style attribute value is a region too.
_CSS_STYLE_REGION = re.compile(
    r"<\s*style\b[^>]*>(.*?)(?:<\s*/\s*style\s*>|\Z)"
    r"|\bstyle\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))",
    re.IGNORECASE | re.DOTALL,
)
_CSS_LINE_BREAK = re.compile(r"[\n\r\f]")
# Any SVG animation element, and any attributeName, can rewrite an href or a
# navigation target.  A positive bound is not established, so these always open.
_ANIMATION_OR_ATTRIBUTE_NAME = re.compile(
    r"<\s*(?:[\w.-]+:)?(?:animate|animatecolor|animatemotion|animatetransform"
    r"|set|discard|handler|listener)\b"
    r"|(?<![\w:-])attributename\s*=",
    re.IGNORECASE,
)
_XML_ENTITY = re.compile(r"<!\s*entity\b", re.IGNORECASE)
_JS_SCHEME_OR_ROOT = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|/|\\)")
_EXECUTABLE_CONTAINER = re.compile(
    r"<\s*/?\s*(?:iframe|object|embed|form|base|frame|frameset|applet|portal|webview"
    r"|dialog|foreignobject|feimage)\b",
    re.IGNORECASE,
)
_EVENT_HOOK = re.compile(r"[\s\"'/<]on[a-z]+\s*=", re.IGNORECASE)
# SVG/XML namespace prefixes are aliases for the element namespace, not part of
# the executable element's semantic name; ``<s:script>`` must not evade review.
_SCRIPT_TAG = re.compile(r"<\s*(?:[\w.-]+:)?script\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SOURCE = re.compile(r"\bsrc\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_OUTWARD_REFERENCE = re.compile(
    r"\b(?:href|src|xlink:href|action|formaction|poster|data|srcset|background"
    r"|codebase|manifest|usemap|longdesc|cite|ping)\s*=\s*"
    r"(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))",
    re.IGNORECASE,
)
_CSS_URL = re.compile(
    r"url\(\s*(?:\"([^\"]*)\"|'([^']*)'|([^)\s]*))\s*\)", re.IGNORECASE
)
_STATIC_HOOK = re.compile(
    r"javascript\s*:|http-equiv\s*=|\bsrcdoc\s*=|@import\b|(?<![\w-])expression\s*\("
    r"|(?<![\w-])behavior\s*:|-moz-binding|@namespace",
    re.IGNORECASE,
)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _js_tokens(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Lex code tokens, skipping comments and keeping string-literal kinds.

    Template bodies are lexed as code as well, so an interpolated ``${...}``
    expression cannot hide an identifier inside a literal.  A template body that
    holds comment-like text is refused: an engine reads it as characters, while
    this lexer would skip the rest of the line and hide code after it.
    """
    tokens: list[tuple[str, str]] = []
    violations: list[str] = []
    for match in _JS_TOKEN.finditer(text):
        raw = match.group()
        head = raw[0]
        if raw.startswith(("//", "/*")):
            continue
        # A lone quote or backtick is not a literal; it stays an operator and opens.
        if head in "'\"" and len(raw) > 1:
            tokens.append(("str", raw))
        elif head == "`" and len(raw) > 1:
            tokens.append(("tpl", raw))
            body = raw[1:-1]
            if "//" in body or "/*" in body:
                violations.append("comment-like text in template literal")
            inner, inner_violations = _js_tokens(body)
            tokens.extend(inner)
            violations.extend(inner_violations)
        elif head.isalpha() or head in "_$":
            tokens.append(("id", raw))
        elif head.isdigit():
            tokens.append(("num", raw))
        elif raw in (".", "?."):
            tokens.append(("dot", "."))
        else:
            tokens.append(("op", raw))
    return tokens, violations


def _js_at(tokens: list[tuple[str, str]], index: int) -> tuple[str, str]:
    """Return the token at ``index``, or a blank operator outside the stream."""
    return tokens[index] if 0 <= index < len(tokens) else ("op", "")


def _js_call_violations(name: str, tokens: list[tuple[str, str]], index: int) -> list[str]:
    """Check one restricted name: it must be called with an allowlisted first argument."""
    following = _js_at(tokens, index + 1)
    if (
        name == "textElement"
        and _js_at(tokens, index - 1) == ("id", "const")
        and following == ("op", "=")
    ):
        return []  # the single declaration; each call is checked where it occurs
    if following != ("op", "("):
        return ["bare reference to " + name]
    if name in _TIMER_CALLS:
        # The callback must be a parameterless arrow literal, so a string or a
        # dataset value can never reach the code-evaluating form of the timer.
        if tokens[index + 2 : index + 6] == [("op", "("), ("op", ")"), ("op", "="), ("op", ">")]:
            return []
        return ["timer callback is not a literal arrow function: " + name]
    first = _js_at(tokens, index + 2)
    if name == "createElement" and first == ("id", "tag"):
        return []  # the identifier is validated by _js_tag_violations
    if (
        first[0] == "str"
        and first[1][1:-1] in _JS_LITERAL_ARGUMENTS[name]
        and _js_at(tokens, index + 3) in (("op", ","), ("op", ")"))
    ):
        return []
    return [name + " argument outside allowlist"]


def _js_tag_violations(tokens: list[tuple[str, str]]) -> list[str]:
    """Admit ``tag`` only as textElement's parameter or createElement's argument.

    The helper's tag is then bound only to literals at textElement's call sites,
    which the call check above enforces, so a dynamic tag cannot reach createElement.
    """
    violations: list[str] = []
    for index, token in enumerate(tokens):
        if token != ("id", "tag"):
            continue
        previous = _js_at(tokens, index - 1)
        following = _js_at(tokens, index + 1)
        declared = (
            previous == ("op", "(")
            and following == ("op", ",")
            and _js_at(tokens, index - 2) == ("op", "=")
            and _js_at(tokens, index - 3) == ("id", "textElement")
        )
        passed = (
            previous == ("op", "(")
            and following == ("op", ")")
            and _js_at(tokens, index - 2) == ("id", "createElement")
        )
        if not (declared or passed):
            violations.append(
                "tag identifier outside textElement parameter or createElement argument"
            )
    return violations


def _js_members(text: str) -> tuple[frozenset[str], frozenset[str], list[str]]:
    """Return identifiers, member pairs, and every closure violation in ``text``."""
    tokens, violations = _js_tokens(text)
    if "<!--" in text or "-->" in text:
        violations.append("HTML-like comment token")
    violations.extend(_js_tag_violations(tokens))
    identifiers = frozenset(value for kind, value in tokens if kind == "id")
    pairs: set[str] = set()
    for index, (kind, value) in enumerate(tokens):
        previous = _js_at(tokens, index - 1)
        following = _js_at(tokens, index + 1)
        if kind == "id":
            if value in _FORBIDDEN_JS_NAMES or value not in _JS_VOCABULARY:
                violations.append("identifier " + value)
            if value in _JS_LITERAL_ARGUMENTS or value in _TIMER_CALLS:
                violations.extend(_js_call_violations(value, tokens, index))
        elif kind == "num":
            if not re.fullmatch(r"[0-9]+", value):
                violations.append("non-decimal numeric literal " + value)
        elif kind == "dot":
            if previous[0] != "id" or following[0] != "id":
                violations.append("member access on a non-identifier")
            else:
                pair = previous[1] + "." + following[1]
                pairs.add(pair)
                if pair not in _JS_MEMBER_PAIRS:
                    violations.append("member pair " + pair)
        elif kind == "op":
            if value == "[":
                if previous[0] in ("id", "str", "tpl") or previous[1] in (")", "]"):
                    violations.append("computed member access")
                elif following[0] in ("str", "tpl"):
                    violations.append("computed member access with literal key")
            elif value == "/":
                violations.append("regex-ambiguous or division slash")
            elif value == "\\":
                violations.append("backslash outside a literal")
            elif value in ("'", '"', "`"):
                violations.append("unterminated string or template literal")
            elif not value.isascii():
                violations.append("non-ASCII code character")
    return identifiers, frozenset(pairs), violations


def _js_closure_violations(text: str) -> list[str]:
    _, _, violations = _js_members(text)
    return violations


def _resolve_owned(owner: str, target: str) -> str | None:
    """Return the owned path a reference names, or ``None`` for an outward edge."""
    if "&" in target or "\\" in target or _JS_SCHEME_OR_ROOT.match(target):
        return None
    if target in ("", "#") or target.startswith("#"):
        return owner
    relative = posixpath.normpath(
        posixpath.join(posixpath.dirname(owner), target.split("#", 1)[0].split("?", 1)[0])
    )
    return relative if relative in PACKAGE_OBJECT_PATHS else None


def _css_open_edges(owner: str, css: str) -> list[str]:
    """Refuse CSS escapes and quoted strings that a URL-taking function may read.

    A backslash can spell ``url``, ``import`` or any keyword, so every escape opens
    the witness.  A quoted string is a reference only inside parentheses, where
    ``url()``, ``image-set()``, ``cross-fade()`` and ``src()`` place their operands;
    top-level font names and ``content`` strings stay inert.
    """
    opened: list[str] = []
    if "\\" in css:
        opened.append("CSS backslash escape")
    depth = 0
    index = 0
    while index < len(css):
        char = css[index]
        if char in "\"'":
            end = css.find(char, index + 1)
            if end == -1 or _CSS_LINE_BREAK.search(css, index + 1, end):
                opened.append("unterminated CSS string")
                break
            value = css[index + 1 : end]
            if depth and _resolve_owned(owner, value) is None:
                opened.append("CSS string reference outside an owned source: " + value)
            index = end + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        index += 1
    return opened


def _static_open_edges(owner: str, text: str) -> list[str]:
    opened: list[str] = []
    if _EXECUTABLE_CONTAINER.search(text):
        opened.append("executable or nested container element")
    if _EVENT_HOOK.search(text):
        opened.append("event-handler attribute")
    if _STATIC_HOOK.search(text):
        opened.append("executable or dynamic hook")
    if _XML_ENTITY.search(text):
        opened.append("XML entity declaration")
    if _ANIMATION_OR_ATTRIBUTE_NAME.search(text):
        opened.append("SVG animation element can rewrite a reference attribute")
    for match in _SCRIPT_TAG.finditer(text):
        source = _SCRIPT_SOURCE.search(match.group(1))
        if source is None or _resolve_owned(owner, source.group(1)) != _JS_PATH:
            opened.append("script edge outside the owned executable asset")
    for match in list(_OUTWARD_REFERENCE.finditer(text)) + list(_CSS_URL.finditer(text)):
        target = next(group for group in match.groups() if group is not None)
        if _resolve_owned(owner, target) is None:
            opened.append("outward reference " + target)
    if owner.endswith(".css"):
        opened.extend(_css_open_edges(owner, text))
    else:
        for match in _CSS_STYLE_REGION.finditer(text):
            region = next(group for group in match.groups() if group is not None)
            opened.extend(_css_open_edges(owner, region))
    return opened


_PYPROJECT_MALFORMED = "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED"


def _pyproject_open_edges(text: str) -> list[str]:
    """Return every outward pyproject edge; malformed shapes fail closed with a code.

    A present or absent [build-system] always opens: the backend and requirement
    acquisition are external, and PEP 518 supplies a default backend when the table
    is missing.  Every pytest table opens, and so does every package-data glob,
    since a glob can select files outside the nine.
    """
    try:
        data = tomllib.loads(text)
    except (ValueError, RecursionError):
        return [_PYPROJECT_MALFORMED + ": unparseable TOML"]
    opened: list[str] = []
    build = data.get("build-system")
    if build is None:
        opened.append("build-system absent: PEP 518 default backend reaches outside the closure")
    elif type(build) is not dict:
        opened.append(_PYPROJECT_MALFORMED + ": build-system is not a table")
    else:
        opened.append("build backend and requirement acquisition declared in build-system")
    project = data.get("project", {})
    if type(project) is not dict:
        opened.append(_PYPROJECT_MALFORMED + ": project is not a table")
    else:
        for key in (
            "dependencies",
            "optional-dependencies",
            "scripts",
            "gui-scripts",
            "entry-points",
            "dynamic",
        ):
            if project.get(key):
                opened.append("project." + key + " external edge")
    tools = data.get("tool", {})
    if type(tools) is not dict:
        opened.append(_PYPROJECT_MALFORMED + ": tool is not a table")
        return opened
    for name, table in tools.items():
        if type(table) is not dict:
            opened.append(_PYPROJECT_MALFORMED + ": tool." + name + " is not a table")
        elif name == "setuptools" and set(table) <= {"package-data"}:
            package_data = table.get("package-data", {})
            if type(package_data) is not dict:
                opened.append(_PYPROJECT_MALFORMED + ": tool.setuptools.package-data is not a table")
            elif package_data:
                opened.append("package-data glob edge: " + ", ".join(sorted(package_data)))
        elif name == "pytest":
            opened.append("pytest option edge: tool.pytest")
        else:
            opened.append("tool." + name + " table is unreviewed")
    return opened


def _closure_open_edges(raw: Mapping[str, bytes]) -> list[tuple[str, str]]:
    """Return ``(path, reason)`` for every open outward edge; empty means closed."""
    opened: list[tuple[str, str]] = []
    for path in PACKAGE_OBJECT_PATHS:
        data = raw[path]
        if path.endswith(".png"):
            if not data.startswith(_PNG_SIGNATURE):
                opened.append((path, "not PNG bytes"))
            continue
        if path.endswith(".json"):
            try:
                json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                opened.append((path, "unparseable JSON"))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            opened.append((path, "undecodable bytes"))
            continue
        if path == "pyproject.toml":
            found = _pyproject_open_edges(text)
        elif path == _JS_PATH:
            found = _js_closure_violations(text)
        else:
            found = _static_open_edges(path, text)
        opened.extend((path, item) for item in found)
    return opened


def closure_witness(root: str | Path) -> dict[str, Any]:
    """Return the closure verdict for the exact current bytes under ``root``."""
    selected_root = Path(root).resolve(strict=True)
    _, _, raw = _source_snapshot(selected_root, PACKAGE_OBJECT_PATHS)
    opened = _closure_open_edges(raw)
    return {
        "closed": not opened,
        "open_edges": [path + ": " + reason for path, reason in opened],
        "open_paths": sorted({path for path, _ in opened}),
    }


def _declarations() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for kind in APPLICABLE_KINDS:
        try:
            selected = _shared._DECLARATION_BUILDERS[kind](_ROLE_PROFILES[kind])
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(result).intersection(selected)
        if overlap:
            raise AssertionError(
                "duplicate package-object declaration ids: "
                + ", ".join(sorted(overlap))
            )
        result.update(selected)
    return result


def _catalog_check() -> None:
    if (
        len(PACKAGE_OBJECT_PATHS) != MAX_PACKAGE_OBJECT_PATHS
        or len(PACKAGE_OBJECT_PATHS) != len(set(PACKAGE_OBJECT_PATHS))
        or tuple(sorted(PACKAGE_OBJECT_PATHS)) != PACKAGE_OBJECT_PATHS
        or _path_digest(PACKAGE_OBJECT_PATHS) != PACKAGE_OBJECT_PATH_DIGEST
    ):
        raise AssertionError("package-object source denominator differs")
    if set(APPLICABLE_KINDS) | set(REFUTED_KINDS) != set(_REASONS):
        raise AssertionError("package-object classification matrix differs")
    for kind in REFUTED_KINDS:
        # Each refutation must cite a named owned file it audited; a generic or
        # copied sentence cannot satisfy the exact-evidence requirement.
        if not any(Path(path).name in _REASONS[kind] for path in PACKAGE_OBJECT_PATHS):
            raise AssertionError("package-object refutation cites no owned source: " + kind)
    if len({_REASONS[kind] for kind in REFUTED_KINDS}) != len(REFUTED_KINDS):
        raise AssertionError("package-object refutations repeat a reason")
    if not (
        set(APPLICABLE_KINDS) == set(ROLE_PATHS) == set(_ROLE_PROFILES)
    ):
        raise AssertionError("package-object applicable-role denominator differs")
    if len(REFUTED_KINDS) != len(set(REFUTED_KINDS)):
        raise AssertionError("package-object repeats a refuted kind")
    if not set(REFUTED_KINDS) <= set(REVIEW_KINDS):
        raise AssertionError("package-object refutes an unsupported kind")
    if set(APPLICABLE_KINDS) & set(REFUTED_KINDS):
        raise AssertionError("package-object applies and refutes one kind")
    if any(
        not paths or not set(paths) <= set(PACKAGE_OBJECT_PATHS)
        for paths in ROLE_PATHS.values()
    ):
        raise AssertionError("package-object role evidence leaves owned source")
    if any(not reason.strip() for reason in _REASONS.values()):
        raise AssertionError("package-object reason is empty")
    if _JS_CREATED_TAGS & _JS_SCRIPT_BEARING_TAGS:
        raise AssertionError("package-object browser vocabulary creates a script-bearing element")
    if not _JS_VOCABULARY or _JS_VOCABULARY & _FORBIDDEN_JS_NAMES:
        raise AssertionError("package-object browser vocabulary admits a forbidden name")
    if any(
        pair.count(".") != 1
        or any(part not in _JS_VOCABULARY for part in pair.split("."))
        for pair in _JS_MEMBER_PAIRS
    ):
        raise AssertionError("package-object member pair leaves the browser vocabulary")

    expected = {
        row["id"]: set(row["declaration_fields"])
        for kind in APPLICABLE_KINDS
        for row in _shared._contract_rows(kind)
    }
    declarations = _declarations()
    if len(declarations) != 18 or set(declarations) != set(expected):
        raise AssertionError("package-object declaration denominator differs")
    for obligation_id, fields in declarations.items():
        if set(fields) != expected[obligation_id] or any(
            type(value) is not str or not value.strip() or len(value) > 8192
            for value in fields.values()
        ):
            raise AssertionError(
                "package-object declaration fields differ: " + obligation_id
            )


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive deterministic review with no captured digests."""
    return {
        PACKAGE_OBJECT_ID: {
            "primary_kind": "OBJECT",
            "owned_paths": list(PACKAGE_OBJECT_PATHS),
            "classification": {
                kind: {
                    "status": _basis(kind),
                    "reason": (
                        _unresolved_reason(kind)
                        if _basis(kind) == "UNRESOLVED"
                        else _REASONS[kind]
                    ),
                    "evidence_paths": list(
                        ROLE_PATHS[kind]
                        if _basis(kind) == "APPLIES"
                        else PACKAGE_OBJECT_PATHS
                        if _basis(kind) == "DOES_NOT_APPLY"
                        else ()
                    ),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations()),
            "claim_boundary": CLAIM_BOUNDARY,
        }
    }


def review_counts() -> dict[str, int]:
    declarations = _declarations()
    return {
        "objects": 1,
        "paths": len(PACKAGE_OBJECT_PATHS),
        "decisions": len(REVIEW_KINDS),
        "applies": len(APPLICABLE_KINDS),
        "does_not_apply": sum(_basis(kind) == "DOES_NOT_APPLY" for kind in REVIEW_KINDS),
        "closure_gated_candidates": len(REFUTED_KINDS),
        "unresolved": sum(_basis(kind) == "UNRESOLVED" for kind in REVIEW_KINDS),
        "declarations": len(declarations),
        "declaration_fields": sum(len(fields) for fields in declarations.values()),
    }


def _owned_file_paths(row: Mapping[str, Any]) -> tuple[str, ...]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(type(item) is not str for item in surfaces):
        raise ValueError("PACKAGE_OBJECT_REVIEW_SURFACES_INVALID")
    paths = tuple(
        sorted(item.removeprefix("file:") for item in surfaces if item.startswith("file:"))
    )
    if any(not path for path in paths) or len(paths) != len(set(paths)):
        raise ValueError("PACKAGE_OBJECT_REVIEW_SURFACES_INVALID")
    if len(paths) > MAX_PACKAGE_OBJECT_PATHS:
        raise ValueError("PACKAGE_OBJECT_REVIEW_PATH_CAPACITY_EXHAUSTED")
    return paths


def _source_snapshot(
    root: Path, paths: tuple[str, ...]
) -> tuple[list[dict[str, str]], int, dict[str, bytes]]:
    """Capture exact in-root ordinary files under an aggregate byte ceiling.

    A source must resolve to its own requested spelling under ``root``.  Symlinks,
    junctions, case-folded spellings and hard-linked aliases (link count above one)
    are refused, so the bytes read are the bytes named by the path.
    """
    evidence: list[dict[str, str]] = []
    raw_by_path: dict[str, bytes] = {}
    total = 0
    for path in paths:
        candidate = root.joinpath(*path.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
            if (
                candidate.is_symlink()
                or not resolved.is_relative_to(root)
                or resolved.relative_to(root).as_posix() != path
                or not resolved.is_file()
                or os.stat(resolved).st_nlink != 1
            ):
                raise OSError("source is not an exact in-root ordinary file")
            raw = resolved.read_bytes()
        except OSError as exc:
            raise ValueError(
                "PACKAGE_OBJECT_REVIEW_SOURCE_UNAVAILABLE:" + path
            ) from exc
        total += len(raw)
        if total > MAX_PACKAGE_OBJECT_SOURCE_BYTES:
            raise ValueError("PACKAGE_OBJECT_REVIEW_SOURCE_CAPACITY_EXHAUSTED")
        raw_by_path[path] = raw
        evidence.append(
            {"path": path, "sha256": "sha256:" + sha256(raw).hexdigest()}
        )
    return evidence, total, raw_by_path


def apply_package_semantic_review_package_object(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the nine-path retained package-object review atomically."""
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_OBJECT_REVIEW_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_OBJECT_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str
        or type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_OBJECT_REVIEW_FILES_INVALID")

    row = rows.get(PACKAGE_OBJECT_ID)
    if type(row) is not dict:
        raise ValueError("PACKAGE_OBJECT_REVIEW_OBJECT_MISSING:" + PACKAGE_OBJECT_ID)
    if row.get("object_id") != PACKAGE_OBJECT_ID or row.get("kind") != "OBJECT":
        raise ValueError(
            "PACKAGE_OBJECT_REVIEW_PRIMARY_KIND_DIFFERS:" + PACKAGE_OBJECT_ID
        )
    owned = _owned_file_paths(row)
    if (
        owned != PACKAGE_OBJECT_PATHS
        or _path_digest(owned) != PACKAGE_OBJECT_PATH_DIGEST
    ):
        raise ValueError("PACKAGE_OBJECT_REVIEW_OWNERSHIP_DIFFERS:" + PACKAGE_OBJECT_ID)

    current, opening_size, opening_raw = _source_snapshot(
        selected_root, PACKAGE_OBJECT_PATHS
    )
    for reference in current:
        if files.get(reference["path"]) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_OBJECT_REVIEW_SOURCE_DIFFERS:"
                + PACKAGE_OBJECT_ID
                + ":"
                + reference["path"]
            )
    evidence_by_path = {item["path"]: item for item in current}
    # The witness is derived from the same bytes whose digests were just matched.
    # A refutation that the witness cannot close is UNRESOLVED, and its only
    # admissible candidate evidence is the owned source that carries the open edge.
    opened_edges = _closure_open_edges(opening_raw)
    closed = not opened_edges
    open_paths = tuple(
        path for path in PACKAGE_OBJECT_PATHS if any(item == path for item, _ in opened_edges)
    )

    classification = row.get("classification")
    obligations = row.get("obligations")
    specializations = row.get("specializations")
    if type(classification) is not dict or type(obligations) is not dict:
        raise ValueError("PACKAGE_OBJECT_REVIEW_BINDINGS_INVALID:" + PACKAGE_OBJECT_ID)
    if (
        type(specializations) is not list
        or any(type(kind) is not str for kind in specializations)
        or len(specializations) != len(set(specializations))
    ):
        raise ValueError(
            "PACKAGE_OBJECT_REVIEW_SPECIALIZATIONS_INVALID:" + PACKAGE_OBJECT_ID
        )

    # Consequence-kind specializations refine OBJECT.  They are not ownership
    # root-role decisions. A label that this exact review refutes must fail,
    # because retaining it would leave a contradictory obligation surface.
    for kind in REVIEW_KINDS:
        if _basis(kind, closed=closed) != "APPLIES" and kind in specializations:
            raise ValueError(
                "PACKAGE_OBJECT_REVIEW_LABEL_CONFLICT:"
                + PACKAGE_OBJECT_ID
                + ":"
                + kind
            )

    live_obligations = {
        kind: {
            item["id"]: tuple(item["declaration_fields"])
            for item in _shared._contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    known_obligations = {
        obligation_id
        for selected in live_obligations.values()
        for obligation_id in selected
    }
    for obligation_id in obligations:
        if (
            type(obligation_id) is not str
            or obligation_id.split("-", 1)[0] in REVIEW_KINDS
            and obligation_id not in known_obligations
        ):
            raise ValueError(
                "PACKAGE_OBJECT_REVIEW_OBLIGATION_UNKNOWN:"
                + PACKAGE_OBJECT_ID
                + ":"
                + str(obligation_id)
            )

    preserve_decisions: set[str] = set()
    preserve_obligations: set[str] = set()
    remove_obligations: set[str] = set()
    unresolved_candidates: dict[str, list[dict[str, str]]] = {}
    owned_set: set[str] = set(PACKAGE_OBJECT_PATHS)
    for kind in REVIEW_KINDS:
        basis = _basis(kind, closed=closed)
        decision = classification.get(kind)
        if basis == "UNRESOLVED":
            code = (
                "PACKAGE_OBJECT_REVIEW_DECISION_CONFLICT:"
                + PACKAGE_OBJECT_ID
                + ":"
                + kind
            )
            # A complete APPLIES or DOES_NOT_APPLY row that this catalog no longer
            # establishes is stale or forged; it is never erased into UNRESOLVED.
            allowed = set(open_paths) if kind in REFUTED_KINDS else owned_set
            if decision is not None and not _shared._unresolved_decision(
                decision,
                files,
                allowed,
                kind=kind,
                code=code,
            ):
                raise ValueError(code)
            # The canonical reason applies even when no candidate evidence is listed,
            # so a substituted reason cannot hide behind empty evidence.
            if (
                decision is not None
                and decision.get("status") == "UNRESOLVED"
                and decision.get("reason") != _unresolved_reason(kind)
            ):
                raise ValueError(code)
            # A closure-gated refutation's candidate list is the whole open-edge
            # witness or nothing; a partial or relabeled list is not that witness.
            if (
                kind in REFUTED_KINDS
                and decision is not None
                and decision.get("evidence")
                and [item["path"] for item in decision["evidence"]] != list(open_paths)
            ):
                raise ValueError(code)
            if kind in REFUTED_KINDS:
                unresolved_candidates[kind] = [
                    deepcopy(evidence_by_path[path]) for path in open_paths
                ]
            elif decision is not None and decision["evidence"]:
                unresolved_candidates[kind] = [
                    deepcopy(evidence_by_path[item["path"]])
                    for item in decision["evidence"]
                ]
        else:
            paths = (
                ROLE_PATHS[kind]
                if basis == "APPLIES"
                else PACKAGE_OBJECT_PATHS
            )
            expected_decision = {
                "status": basis,
                "reason": _REASONS[kind],
                "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
            }
            if _shared._preserve_explicit_decision(
                decision,
                expected_decision,
                files,
                owned_set,
                object_id=PACKAGE_OBJECT_ID,
                kind=kind,
            ):
                preserve_decisions.add(kind)

        for obligation_id, fields in live_obligations[kind].items():
            binding = obligations.get(obligation_id)
            if basis == "APPLIES":
                expected_evidence = [
                    deepcopy(evidence_by_path[path]) for path in ROLE_PATHS[kind]
                ]
                if _shared._preserve_explicit_obligation(
                    binding,
                    fields,
                    _obligation_reason(kind),
                    expected_evidence,
                    files,
                    owned_set,
                    object_id=PACKAGE_OBJECT_ID,
                    obligation_id=obligation_id,
                ):
                    preserve_obligations.add(obligation_id)
            elif binding is not None:
                prefix = (
                    "PACKAGE_OBJECT_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                    if basis == "DOES_NOT_APPLY"
                    else "PACKAGE_OBJECT_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                )
                code = prefix + PACKAGE_OBJECT_ID + ":" + obligation_id
                if not _shared._blank_obligation(
                    binding,
                    fields,
                    files,
                    owned_set,
                    code=code,
                ):
                    raise ValueError(code)
                remove_obligations.add(obligation_id)

    # Recapture every source after all semantic conflicts have passed.  The
    # deep copy below is untouched if any source changes during preflight.
    closing, closing_size, _ = _source_snapshot(selected_root, PACKAGE_OBJECT_PATHS)
    if closing != current or closing_size != opening_size:
        raise ValueError("PACKAGE_OBJECT_REVIEW_SOURCE_CHANGED:" + PACKAGE_OBJECT_ID)

    result = deepcopy(rows)
    selected = result[PACKAGE_OBJECT_ID]
    for kind in REVIEW_KINDS:
        if kind in preserve_decisions:
            continue
        basis = _basis(kind, closed=closed)
        if basis == "UNRESOLVED":
            selected["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": _unresolved_reason(kind),
                "evidence": deepcopy(unresolved_candidates.get(kind, [])),
            }
        else:
            paths = (
                ROLE_PATHS[kind]
                if basis == "APPLIES"
                else PACKAGE_OBJECT_PATHS
            )
            selected["classification"][kind] = {
                "status": basis,
                "reason": _REASONS[kind],
                "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
            }
    for obligation_id in remove_obligations:
        selected["obligations"].pop(obligation_id, None)
    for obligation_id, declaration in _declarations().items():
        if obligation_id in preserve_obligations:
            continue
        kind = obligation_id.split("-", 1)[0]
        selected["obligations"][obligation_id] = {
            "reason": _obligation_reason(kind),
            "evidence": [
                deepcopy(evidence_by_path[path]) for path in ROLE_PATHS[kind]
            ],
            "declaration": dict(declaration),
        }
    for kind in REVIEW_KINDS:
        if kind in APPLICABLE_KINDS and kind not in selected["specializations"]:
            selected["specializations"].append(kind)
    return result


__all__ = [
    "APPLICABLE_KINDS",
    "CLAIM_BOUNDARY",
    "MAX_PACKAGE_OBJECT_PATHS",
    "MAX_PACKAGE_OBJECT_SOURCE_BYTES",
    "PACKAGE_OBJECT_ID",
    "PACKAGE_OBJECT_PATHS",
    "PACKAGE_OBJECT_PATH_DIGEST",
    "REFUTED_KINDS",
    "REVIEW_KINDS",
    "ROLE_PATHS",
    "apply_package_semantic_review_package_object",
    "closure_witness",
    "review_counts",
    "review_document",
]
