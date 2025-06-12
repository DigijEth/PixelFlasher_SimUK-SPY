#!/usr/bin/env python
#
# Spyware detector & remover for PixelFlasher
#
# Copyright (C) 2025  Badabing2005
# SPDX‑License‑Identifier: AGPL‑3.0‑or‑later

import wx
import wx.lib.mixins.listctrl as listmix
import contextlib
import json
import subprocess
from threading import Thread
from pathlib import Path
from runtime import adb, run, get_phone
from i18n import _
import images

# ----------------------------------------------------------------------------
# Helper – low‑tech IOC database (package name → description)
# ----------------------------------------------------------------------------
SIG_DB_PATH = Path(__file__).with_name("spyware_signatures.json")

def load_signature_db() -> dict[str, str]:
    if SIG_DB_PATH.exists():
        with SIG_DB_PATH.open(encoding="utf‑8") as fp:
            return json.load(fp)
    return {}

SIG_DB = load_signature_db()

# ----------------------------------------------------------------------------
# UI – list control
# ----------------------------------------------------------------------------
class ResultList(wx.ListCtrl, listmix.ListCtrlAutoWidthMixin):
    COLS = (
        (_("Package"), 350),
        (_("Status"), 120),
        (_("Detection"), 400),
    )

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT|wx.BORDER_SUNKEN)
        for idx, (hdr, width) in enumerate(self.COLS):
            self.InsertColumn(idx, hdr, width=width)
        listmix.ListCtrlAutoWidthMixin.__init__(self)

# ----------------------------------------------------------------------------
# Dialog
# ----------------------------------------------------------------------------
class SpywareDetectorDlg(wx.Dialog):
    def __init__(self, parent):
        super().__init__(parent, title=_("Detect Spyware"), size=(900, 500))

        panel = wx.Panel(self)
        vbox  = wx.BoxSizer(wx.VERTICAL)

        self.listctrl = ResultList(panel)
        vbox.Add(self.listctrl, 1, wx.EXPAND|wx.ALL, 5)

        btn_box = wx.BoxSizer(wx.HORIZONTAL)
        self.btn_scan   = wx.Button(panel, label=_("Scan"))
        self.btn_remove = wx.Button(panel, label=_("Uninstall selected"))
        self.btn_close  = wx.Button(panel, id=wx.ID_CLOSE, label=_("Close"))
        btn_box.Add(self.btn_scan); btn_box.AddSpacer(10)
        btn_box.Add(self.btn_remove); btn_box.AddStretchSpacer()
        btn_box.Add(self.btn_close)
        vbox.Add(btn_box, 0, wx.EXPAND|wx.ALL, 5)

        panel.SetSizer(vbox)

        self.btn_scan.Bind(wx.EVT_BUTTON, self.on_scan)
        self.btn_remove.Bind(wx.EVT_BUTTON, self.on_remove)
        self.btn_close.Bind(wx.EVT_BUTTON, lambda _e: self.Close())

        self.Layout()
        self.CenterOnParent()

    # ---------------------------------------------------------------------
    # Scan logic – runs on worker thread, updates listctrl on UI thread
    # ---------------------------------------------------------------------
    def on_scan(self, _evt):
        self.listctrl.DeleteAllItems()
        Thread(target=self._worker_scan, daemon=True).start()

    def _worker_scan(self):
        phone = get_phone()
        if not phone:
            wx.CallAfter(wx.MessageBox, _("No device connected."), _("Error"))
            return

        pkgs = adb("shell", "pm", "list", "packages", "-3").stdout.split()
        for pkg_line in pkgs:
            pkg = pkg_line.removeprefix("package:")
            detect = SIG_DB.get(pkg)
            status_str = _("Suspicious") if detect else _("Clean")
            idx = self.listctrl.InsertItem(self.listctrl.GetItemCount(), pkg)
            self.listctrl.SetItem(idx, 1, status_str)
            self.listctrl.SetItem(idx, 2, detect or "")
            if detect:
                self.listctrl.SetItemBackgroundColour(idx, wx.Colour(255, 230, 230))

    # ---------------------------------------------------------------------
    # Remove selected packages
    # ---------------------------------------------------------------------
    def on_remove(self, _evt):
        sel = []
        idx = self.listctrl.GetFirstSelected()
        while idx != -1:
            sel.append(self.listctrl.GetItemText(idx))
            idx = self.listctrl.GetNextSelected(idx)

        if not sel:
            return

        msg = _("Uninstall the following?\n\n") + "\n".join(sel)
        if wx.MessageBox(msg, _("Confirm"), style=wx.ICON_WARNING|wx.YES_NO) != wx.YES:
            return

        Thread(target=self._worker_uninstall, args=(sel,), daemon=True).start()

    def _worker_uninstall(self, pkgs):
        for p in pkgs:
            adb("shell", "pm", "uninstall", "--user", "0", p)
        wx.CallAfter(self.on_scan, None)  # refresh list
