"""
FEROXSEI Phishing Investigation Package
=====================================
Provides the phishing simulation engine, email sender, and tracking server.

Structure:
  engine.py   - Campaign runner: picks templates, renders per-target, queues send
  sender.py   - SMTP delivery with TOR-proxy support + identity rotation
  tracker.py  - HTTP micro-server for open-pixel / click / submit tracking
  renderer.py - Template variable substitution (GoPhish-compatible {{.Var}})
"""

from .engine import PhishingEngine
from .sender import PhishingSender
from .tracker import PhishingTracker
from .renderer import render_template

__all__ = ["PhishingEngine", "PhishingSender", "PhishingTracker", "render_template"]
