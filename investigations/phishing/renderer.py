"""
FEROXSEI Phishing · Template Renderer
====================================
Renders GoPhish-compatible template variables:

  {{.FirstName}}   {{.LastName}}   {{.Email}}   {{.Position}}
  {{.URL}}         {{.TrackingURL}} {{.From}}   {{.RId}}

Also supports custom variables: {{.CustomVar}}
"""

from __future__ import annotations
import re
import html
import uuid


# ── Variable registry ─────────────────────────────────────────────────────────
BUILTIN_VARS = {
    "FirstName", "LastName", "Email", "Position",
    "URL", "TrackingURL", "From", "RId",
    "Company", "FullName",
}


def render_template(
    template_html: str,
    target: dict,
    campaign_url: str = "",
    tracking_url: str = "",
    sender_name: str = "",
    rid: str = "",
) -> str:
    """
    Substitute all {{.Var}} placeholders in *template_html* using *target* data.

    Parameters
    ----------
    template_html : str
        Raw HTML/text of the phishing template.
    target : dict
        Keys: email, first, last, position, (any custom fields)
    campaign_url : str
        Landing page URL embedded via {{.URL}}.
    tracking_url : str
        Open-tracking pixel URL embedded via {{.TrackingURL}}.
    sender_name : str
        Display name of the sender for {{.From}}.
    rid : str
        Unique recipient ID for tracking; auto-generated if empty.

    Returns
    -------
    str
        Rendered HTML/text with all variables substituted.
    """
    if not rid:
        rid = str(uuid.uuid4())[:8]

    full_name = f"{target.get('first', '')} {target.get('last', '')}".strip()

    # Append rid as query param if urls provided
    sep = "&" if "?" in campaign_url else "?"
    campaign_url_rid = f"{campaign_url}{sep}rid={rid}" if campaign_url else ""
    tracking_url_rid = f"{tracking_url}{sep}rid={rid}" if tracking_url else ""

    substitutions: dict[str, str] = {
        "FirstName":   target.get("first", ""),
        "LastName":    target.get("last", ""),
        "FullName":    full_name,
        "Email":       target.get("email", ""),
        "Position":    target.get("position", ""),
        "URL":         campaign_url_rid,
        "TrackingURL": tracking_url_rid,
        "From":        sender_name,
        "RId":         rid,
        "Company":     target.get("company", ""),
    }

    # Merge any custom fields from target dict
    for k, v in target.items():
        key = k.capitalize()
        if key not in substitutions:
            substitutions[key] = str(v)

    # Perform substitution - iterate keys, use split/join to avoid regex issues
    result = template_html
    for var_name, value in substitutions.items():
        placeholder = "{{." + var_name + "}}"
        result = value.join(result.split(placeholder))

    return result


def render_subject(subject: str, target: dict, rid: str = "") -> str:
    """Render template variables in an email subject line."""
    return render_template(subject, target, rid=rid)


def extract_variables(template_html: str) -> list[str]:
    """Return list of all {{.Var}} variable names found in a template."""
    pattern = re.compile(r'\{\{\.(\w+)\}\}')
    return list(dict.fromkeys(pattern.findall(template_html)))


def preview_template(template_html: str, sample_data: dict | None = None) -> str:
    """
    Render a template with sample data for preview purposes.
    Returns safe HTML with all variables substituted.
    """
    sample = sample_data or {
        "email":    "john.doe@acme.com",
        "first":    "John",
        "last":     "Doe",
        "position": "Engineer",
        "company":  "Acme Corp",
    }
    return render_template(
        template_html,
        target=sample,
        campaign_url="https://feroxsei-phish.local/landing",
        tracking_url="https://feroxsei-phish.local/track/open.png",
        sender_name="IT Security Team",
        rid="preview01",
    )
