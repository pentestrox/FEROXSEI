"""
FEROXSEI OSINT - New Module Template
Copy this file to modules/my_module.py and fill in the class.
The engine will auto-discover it on next startup.
"""
from __future__ import annotations
from .base import BaseOSINTModule


class MyModule(BaseOSINTModule):
    NAME  = "myModule"        # unique key, used in DB and config
    LABEL = "My Module"       # display name
    ICON  = "🆕"              # emoji shown in UI
    ORDER = 90                # execution order (0=first, 99=last)
    REQUIRES_TOR = False      # set True if TOR must be active
    EXPERIMENTAL = True       # mark as beta

    def run(self, scan_id: str, target: str, config: dict) -> None:
        # Your OSINT logic here.
        # self.http.get(url, scan_id, self.NAME)  - TOR-aware HTTP with auto traffic log
        # self.db.save_finding(scan_id, self.NAME, "info", "Title", "Description")
        # self.patterns.scan_text(text)  - pattern match against text
        self.db.save_finding(
            scan_id, self.NAME, "info",
            "Example Finding",
            "Replace this with your module logic",
            tags=["example", "template"]
        )
