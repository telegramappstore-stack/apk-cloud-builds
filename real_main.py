#!/usr/bin/env python3
"""
Aminium Studio - Kivy / Android app.

Flow: Token -> Radar (clean IPs) -> Build -> Configs, plus "Saved" (everything built on this phone).

All networking / scanning / Cloudflare / config logic lives in aminium_core.py; this file is only UI:
  * animated splash screen
  * light, modern look (cards, gradient header, rounded inputs, bottom navigation)
  * live RADAR animation while scanning for clean IPs (found IPs show up as glowing blips)
  * one-tap "Create API token" button that opens Cloudflare's token page with every permission
    Aminium needs already selected
"""
import json
import math
import os
import re
import threading
import uuid as uuidlib
import zlib
from pathlib import Path

from kivy.animation import Animation
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, Rectangle, RoundedRectangle, Triangle
from kivy.graphics.texture import Texture
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, ObjectProperty, StringProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import Screen, SlideTransition
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.utils import platform

import aminium_core as core

# ───────────────────────────── Android runtime permissions ─────────────────────────────
if platform == "android":
    try:
        from android.permissions import request_permissions, Permission  # type: ignore
        request_permissions([Permission.INTERNET, Permission.ACCESS_NETWORK_STATE])
    except Exception:
        pass

# ───────────────────────────── palette ─────────────────────────────
C_PRIMARY = (0.98, 0.74, 0.08, 1)     # golden yellow
C_CYAN = (0.99, 0.80, 0.15, 1)        # light yellow accent
C_TEXT = (0.20, 0.14, 0.04, 1)
C_MUTED = (0.52, 0.44, 0.26, 1)
C_OK = (0.07, 0.58, 0.30, 1)
C_ERR = (0.82, 0.20, 0.25, 1)
C_SURFACE = (1.0, 1.0, 1.0, 1)        # cards / popups
C_FIELD = (1.0, 0.97, 0.87, 1)    # inputs
C_BG = (1.0, 0.985, 0.94, 1)

TABS = [
    ("token", "Token", "Step 1  -  Connect Cloudflare"),
    ("scan", "Radar", "Step 2  -  Find clean IPs"),
    ("build", "Build", "Step 3  -  Deploy your panel"),
    ("output", "Configs", "Step 4  -  Your configs"),
    ("manage", "Saved", "Everything you built on this phone"),
]

FORMATS_UI = [
    ("auto", "Auto (recommended)", ""),
    ("xray", "Xray", "?format=xray"),
    ("clash", "Clash", "?format=clash"),
    ("singbox", "sing-box", "?format=singbox"),
    ("patt", "Patt", "?format=patt"),
    ("v2ray", "Plain links", "?format=base64"),
]


def gradient_texture(c1, c2, vertical=True):
    """Tiny 2-pixel texture that the GPU stretches into a smooth gradient."""
    size = (1, 2) if vertical else (2, 1)
    tex = Texture.create(size=size, colorfmt="rgba")
    first, second = (c2, c1) if vertical else (c1, c2)   # texture row 0 is the bottom
    buf = bytes(int(max(0, min(1, v)) * 255) for v in (*first, *second))
    tex.blit_buffer(buf, colorfmt="rgba", bufferfmt="ubyte")
    tex.mag_filter = "linear"
    tex.min_filter = "linear"
    return tex


# ───────────────────────────── KV (layout + styles) ─────────────────────────────
KV = r"""
#:import dp kivy.metrics.dp
#:set C_PRIMARY (0.98, 0.74, 0.08, 1)
#:set C_CYAN (0.99, 0.80, 0.15, 1)
#:set C_TEXT (0.20, 0.14, 0.04, 1)
#:set C_MUTED (0.52, 0.44, 0.26, 1)
#:set C_SURFACE (1, 1, 1, 1)
#:set C_FIELD (1.0, 0.97, 0.87, 1)

<H1@Label>:
    bold: True
    font_size: "18sp"
    color: C_TEXT
    size_hint_y: None
    height: self.texture_size[1] + dp(2)
    halign: "left"
    valign: "middle"
    text_size: self.width, None

<Body@Label>:
    font_size: "13sp"
    color: 0.30, 0.23, 0.08, 1
    size_hint_y: None
    height: self.texture_size[1] + dp(2)
    halign: "left"
    valign: "top"
    text_size: self.width, None

<Muted@Label>:
    font_size: "12sp"
    color: C_MUTED
    size_hint_y: None
    height: self.texture_size[1] + dp(2)
    halign: "left"
    valign: "top"
    text_size: self.width, None

<FieldLabel@Label>:
    font_size: "12sp"
    bold: True
    color: C_MUTED
    size_hint_y: None
    height: dp(22)
    halign: "left"
    valign: "bottom"
    text_size: self.width, self.height

<Page>:
    orientation: "vertical"
    padding: dp(14)
    spacing: dp(12)
    size_hint_y: None
    height: self.minimum_height

<Card>:
    orientation: "vertical"
    padding: dp(16)
    spacing: dp(10)
    size_hint_y: None
    height: self.minimum_height
    canvas.before:
        Color:
            rgba: 0.55, 0.38, 0.02, 0.12
        RoundedRectangle:
            pos: self.x, self.y - dp(3)
            size: self.size
            radius: [dp(22)]
        Color:
            rgba: C_SURFACE
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(22)]
        Color:
            rgba: 0.90, 0.68, 0.08, 0.28
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(22)
            width: dp(1)
        Color:
            rgba: 0.98, 0.76, 0.10, 0.95
        RoundedRectangle:
            pos: self.x + dp(22), self.top - dp(2)
            size: self.width - dp(44), dp(2)
            radius: [dp(1)]

<RoundButton>:
    size_hint_y: None
    height: dp(48)
    bold: True
    font_size: "14sp"
    color: self.fg
    canvas.before:
        Color:
            rgba: (0.98, 0.74, 0.08, 0.30) if (self.kind == "primary" and not self.disabled) else (0, 0, 0, 0)
        RoundedRectangle:
            pos: self.x - dp(2), self.y - dp(4)
            size: self.width + dp(4), self.height + dp(4)
            radius: [dp(17)]
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(15)]
        Color:
            rgba: (1, 1, 1, 1) if (self.kind == "primary" and not self.disabled) else (0, 0, 0, 0)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(15)]
            texture: app.grad_h
        Color:
            rgba: (1, 1, 1, 0.10) if not self.disabled else (0, 0, 0, 0)
        RoundedRectangle:
            pos: self.x + dp(8), self.y + self.height * 0.55
            size: self.width - dp(16), self.height * 0.38
            radius: [dp(10)]

<RoundInput>:
    multiline: False
    size_hint_y: None
    height: dp(46)
    background_normal: ""
    background_active: ""
    background_disabled_normal: ""
    background_color: 0, 0, 0, 0
    foreground_color: 0.20, 0.14, 0.04, 1
    disabled_foreground_color: 0.45, 0.38, 0.20, 1
    cursor_color: C_CYAN
    cursor_width: dp(2)
    hint_text_color: 0.68, 0.60, 0.40, 1
    selection_color: 0.98, 0.76, 0.10, 0.35
    font_size: "15sp"
    padding: [dp(14), max(dp(10), (self.height - self.line_height) / 2)]
    canvas.before:
        Color:
            rgba: (1, 1, 1, 1) if self.focus else C_FIELD
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
        Color:
            rgba: C_CYAN if self.focus else (0.90, 0.68, 0.08, 0.45)
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(14)
            width: dp(1.4) if self.focus else dp(1)

<RoundSpinner>:
    size_hint_y: None
    height: dp(46)
    background_normal: ""
    background_down: ""
    background_color: 0, 0, 0, 0
    color: 0.20, 0.14, 0.04, 1
    font_size: "15sp"
    halign: "left"
    valign: "middle"
    text_size: self.width - dp(46), self.height
    padding_x: dp(14)
    canvas.before:
        Color:
            rgba: C_FIELD
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
        Color:
            rgba: 0.90, 0.68, 0.08, 0.45
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(14)
            width: dp(1)
        Color:
            rgba: C_CYAN
        Line:
            points: self.right - dp(28), self.center_y + dp(3), self.right - dp(21), self.center_y - dp(4), self.right - dp(14), self.center_y + dp(3)
            width: dp(1.5)

<SpinnerOption>:
    background_normal: ""
    background_down: ""
    background_color: (1.0, 0.92, 0.62, 1) if self.state == "down" else (1, 1, 1, 1)
    color: 0.20, 0.14, 0.04, 1
    size_hint_y: None
    height: dp(44)
    font_size: "15sp"

<SoftBar>:
    size_hint_y: None
    height: dp(8)
    canvas:
        Color:
            rgba: 0.90, 0.68, 0.08, 0.20
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(4)]
        Color:
            rgba: C_CYAN
        RoundedRectangle:
            pos: self.pos
            size: max(self.height, self.width * min(1.0, self.value)), self.height
            radius: [dp(4)]

<StatBox>:
    orientation: "vertical"
    padding: dp(8)
    canvas.before:
        Color:
            rgba: C_SURFACE
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(18)]
        Color:
            rgba: 0.90, 0.68, 0.08, 0.28
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(18)
            width: dp(1)
    Label:
        text: root.value
        bold: True
        font_size: "20sp"
        color: root.accent
    Label:
        text: root.caption
        font_size: "10sp"
        bold: True
        color: C_MUTED

<NavTab>:
    font_size: "12sp"
    bold: self.active
    color: (0.68, 0.45, 0.0, 1) if self.active else C_MUTED
    canvas.before:
        Color:
            rgba: (0.98, 0.76, 0.10, 0.22) if self.active else (0, 0, 0, 0)
        RoundedRectangle:
            pos: self.x + dp(6), self.y + dp(8)
            size: self.width - dp(12), self.height - dp(16)
            radius: [dp(16)]
        Color:
            rgba: C_CYAN if self.active else (0, 0, 0, 0)
        RoundedRectangle:
            pos: self.x + self.width * 0.32, self.top - dp(3)
            size: self.width * 0.36, dp(3)
            radius: [dp(2)]

<IpRow>:
    size_hint_y: None
    height: dp(54)
    padding: dp(12), dp(6)
    spacing: dp(8)
    canvas.before:
        Color:
            rgba: C_SURFACE
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
        Color:
            rgba: 0.90, 0.68, 0.08, 0.28
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(14)
            width: dp(1)
    BoxLayout:
        orientation: "vertical"
        Label:
            text: root.ip
            bold: True
            font_size: "14sp"
            color: C_TEXT
            halign: "left"
            valign: "bottom"
            text_size: self.size
        Label:
            text: root.meta
            font_size: "11sp"
            color: C_MUTED
            halign: "left"
            valign: "top"
            text_size: self.size
    Label:
        text: str(root.score)
        bold: True
        font_size: "15sp"
        size_hint_x: None
        width: dp(46)
        color: (0.05, 0.50, 0.25, 1) if root.score >= 70 else ((0.72, 0.46, 0.02, 1) if root.score >= 40 else (0.78, 0.18, 0.22, 1))
        canvas.before:
            Color:
                rgba: (0.84, 0.96, 0.88, 1) if root.score >= 70 else ((1, 0.94, 0.78, 1) if root.score >= 40 else (1, 0.88, 0.89, 1))
            RoundedRectangle:
                pos: self.x, self.y + dp(8)
                size: self.width, self.height - dp(16)
                radius: [dp(10)]

<DeployRow>:
    BoxLayout:
        size_hint_y: None
        height: dp(22)
        Label:
            text: root.title
            bold: True
            font_size: "15sp"
            color: C_TEXT
            halign: "left"
            valign: "middle"
            shorten: True
            text_size: self.size
    Muted:
        text: root.subtitle
    BoxLayout:
        size_hint_y: None
        height: dp(40)
        spacing: dp(8)
        RoundButton:
            text: "Load"
            height: dp(40)
            on_release: app.load_deployment(root.index)
        RoundButton:
            text: "Rename"
            kind: "soft"
            height: dp(40)
            on_release: app.rename_deployment_prompt(root.index)
        RoundButton:
            text: "Delete"
            kind: "danger"
            height: dp(40)
            on_release: app.delete_deployment_prompt(root.index)
    BoxLayout:
        size_hint_y: None
        height: dp(40)
        spacing: dp(8)
        RoundButton:
            text: "Update IPs"
            height: dp(40)
            on_release: app.update_ips_prompt(root.index)
        RoundButton:
            text: "Open panel"
            kind: "soft"
            height: dp(40)
            on_release: app.open_panel_of(root.index)
        RoundButton:
            text: "Copy sub link"
            kind: "soft"
            height: dp(40)
            on_release: app.copy_sub_of(root.index)

<LogBar>:
    size_hint_y: None
    height: dp(30)
    padding: dp(30), 0, dp(14), 0
    canvas.before:
        Color:
            rgba: 1.0, 0.95, 0.78, 1
        Rectangle:
            pos: self.pos
            size: self.size
        Color:
            rgba: C_CYAN
        Rectangle:
            pos: self.x + dp(14), self.center_y - dp(3)
            size: dp(6), dp(6)
    Label:
        id: lbl_log
        text: root.last
        font_size: "11sp"
        color: C_MUTED
        halign: "left"
        valign: "middle"
        shorten: True
        text_size: self.size

<ToastLabel>:
    size_hint: None, None
    size: self.texture_size[0] + dp(32), self.texture_size[1] + dp(18)
    pos_hint: {"center_x": .5, "y": .16}
    font_size: "13sp"
    color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgba: 0.30, 0.21, 0.03, 0.97
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(18)]
        Color:
            rgba: 0.98, 0.78, 0.20, 0.9
        Line:
            rounded_rectangle: self.x, self.y, self.width, self.height, dp(18)
            width: dp(1.1)

<Radar>:
    size_hint_y: None
    height: min(self.width, dp(340))
    Label:
        text: root.title
        bold: True
        font_size: "13sp"
        color: 0.62, 0.42, 0.0, 1
        size_hint: None, None
        size: self.texture_size
        pos_hint: {"center_x": .5, "top": .975}
    Label:
        text: root.subtitle
        font_size: "12sp"
        color: 0.48, 0.38, 0.15, 1
        size_hint: None, None
        size: self.texture_size
        pos_hint: {"center_x": .5, "y": .03}

<Ring>:
    size_hint: None, None
    size: dp(150), dp(150)
    pos_hint: {"center_x": .5}
    Label:
        text: root.text
        bold: True
        font_size: "26sp"
        color: C_TEXT

FloatLayout:
    BoxLayout:
        orientation: "vertical"
        canvas.before:
            Color:
                rgba: 1.0, 0.985, 0.94, 1
            Rectangle:
                pos: self.pos
                size: self.size
            Color:
                rgba: 0.98, 0.76, 0.10, 0.10
            Ellipse:
                pos: self.x - self.width * 0.55, self.top - self.width * 0.75
                size: self.width * 1.3, self.width * 1.3
            Ellipse:
                pos: self.x - self.width * 0.40, self.top - self.width * 0.60
                size: self.width * 1.0, self.width * 1.0
            Ellipse:
                pos: self.x - self.width * 0.25, self.top - self.width * 0.45
                size: self.width * 0.7, self.width * 0.7
            Color:
                rgba: 1.0, 0.88, 0.40, 0.14
            Ellipse:
                pos: self.right - self.width * 0.75, self.y - self.width * 0.55
                size: self.width * 1.3, self.width * 1.3
            Ellipse:
                pos: self.right - self.width * 0.60, self.y - self.width * 0.40
                size: self.width * 1.0, self.width * 1.0
            Ellipse:
                pos: self.right - self.width * 0.45, self.y - self.width * 0.25
                size: self.width * 0.7, self.width * 0.7

        GradientBox:
            size_hint_y: None
            height: dp(68)
            padding: dp(16), dp(11)
            spacing: dp(12)
            Label:
                text: "A"
                bold: True
                font_size: "22sp"
                color: 0.20, 0.14, 0.04, 1
                size_hint_x: None
                width: dp(46)
                canvas.before:
                    Color:
                        rgba: 1, 1, 1, 0.24
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [dp(15)]
            BoxLayout:
                orientation: "vertical"
                Label:
                    text: "Aminium Studio"
                    bold: True
                    font_size: "19sp"
                    color: 0.20, 0.14, 0.04, 1
                    halign: "left"
                    valign: "bottom"
                    text_size: self.size
                Label:
                    id: hdr_sub
                    text: ""
                    font_size: "12sp"
                    color: 0.35, 0.25, 0.02, 0.95
                    halign: "left"
                    valign: "top"
                    text_size: self.size

        ScreenManager:
            id: sm

        LogBar:
            id: logbar
            on_release: app.show_log()

        BoxLayout:
            id: nav
            size_hint_y: None
            height: dp(60)
            padding: dp(6), 0
            canvas.before:
                Color:
                    rgba: 1, 1, 1, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
                Color:
                    rgba: 0.90, 0.68, 0.08, 0.20
                Rectangle:
                    pos: self.x, self.top
                    size: self.width, dp(1)


<TokenScreen>:
    name: "token"
    ScrollView:
        bar_width: dp(3)
        Page:
            Card:
                H1:
                    text: "New to Cloudflare?"
                Body:
                    text: "Aminium runs on your own free Cloudflare account. If you do not have one yet, sign up first (free plan is enough)."
                RoundButton:
                    text: "Create a free Cloudflare account"
                    height: dp(52)
                    on_release: app.open_signup_page()
                Muted:
                    text: "1. Enter email + password and sign up\n2. Open the verification email and confirm it\n3. Come back here and continue below. Already have an account? Skip this card."

            Card:
                H1:
                    text: "Connect Cloudflare"
                Body:
                    text: "One tap opens Cloudflare's token page with every permission Aminium needs already ticked. Press Continue, then Create Token, copy it and come back."
                RoundButton:
                    text: "Create API token (all permissions)"
                    height: dp(52)
                    on_release: app.open_token_page()
                Muted:
                    text: "Pre-selected:  Pages: Edit  |  Workers Scripts: Edit  |  Workers KV Storage: Edit  |  D1: Edit  |  Account Settings: Read  |  Account Analytics: Read  |  Zone: Read  |  DNS: Edit"
                RoundButton:
                    text: "Open the tokens page manually"
                    kind: "soft"
                    on_release: app.open_token_page(True)

            Card:
                H1:
                    text: "Your token"
                Muted:
                    text: "Stored only on this phone (app-private storage)."
                FieldLabel:
                    text: "API token (or Global API Key)"
                BoxLayout:
                    size_hint_y: None
                    height: dp(46)
                    spacing: dp(8)
                    RoundInput:
                        id: f_token
                        password: True
                    RoundButton:
                        text: "Paste"
                        kind: "soft"
                        height: dp(46)
                        size_hint_x: None
                        width: dp(84)
                        on_release: app.paste_token()
                FieldLabel:
                    text: "Email (only for a Global API Key)"
                RoundInput:
                    id: f_email
                BoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    spacing: dp(8)
                    RoundButton:
                        text: "Save && verify"
                        on_release: app.on_save_token()
                    RoundButton:
                        text: "Forget token"
                        kind: "danger"
                        on_release: app.on_forget_token()
                Label:
                    id: lbl_token_state
                    text: ""
                    font_size: "12sp"
                    color: C_MUTED
                    size_hint_y: None
                    height: self.texture_size[1] + dp(4)
                    halign: "left"
                    text_size: self.width, None
                FieldLabel:
                    text: "Account"
                RoundSpinner:
                    id: sp_account
                    text: "(verify token first)"
                    on_text: app.on_pick_account(self.text)


<ScanScreen>:
    name: "scan"
    ScrollView:
        bar_width: dp(3)
        Page:
            Radar:
                id: radar
            BoxLayout:
                size_hint_y: None
                height: dp(64)
                spacing: dp(10)
                StatBox:
                    id: st_tested
                    caption: "TESTED"
                StatBox:
                    id: st_found
                    caption: "CLEAN IPs"
                    accent: 0.09, 0.64, 0.29, 1
                StatBox:
                    id: st_time
                    caption: "SECONDS"
            Card:
                SoftBar:
                    id: pb_scan
                Muted:
                    id: lbl_scan_stats
                    text: "Ready when you are. Turn any VPN off first."
                FieldLabel:
                    text: "Connection"
                RoundSpinner:
                    id: sp_conn
                    text: "TLS"
                    values: ["TLS", "No TLS"]
                FieldLabel:
                    text: "Search depth"
                RoundSpinner:
                    id: sp_depth
                    text: "Normal"
                    values: ["Quick", "Normal", "Deep"]
                BoxLayout:
                    size_hint_y: None
                    height: dp(52)
                    spacing: dp(8)
                    RoundButton:
                        id: btn_scan
                        text: "Start scan"
                        height: dp(52)
                        on_release: app.on_scan()
                    RoundButton:
                        id: btn_stop
                        text: "Stop"
                        kind: "danger"
                        height: dp(52)
                        size_hint_x: None
                        width: dp(100)
                        disabled: True
                        on_release: app.on_stop_scan()
            Card:
                H1:
                    text: "Clean IPs"
                Muted:
                    id: lbl_ip_empty
                    text: "(none yet)"
                BoxLayout:
                    id: ip_list
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: dp(6)
                BoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    spacing: dp(8)
                    RoundButton:
                        text: "Copy all IPs"
                        kind: "soft"
                        on_release: app.copy_ips()
                    RoundButton:
                        text: "Continue to build"
                        on_release: app.goto("build")


<BuildScreen>:
    name: "build"
    ScrollView:
        bar_width: dp(3)
        Page:
            Card:
                H1:
                    text: "Build your panel"
                Body:
                    id: lbl_build_sum
                    text: ""
                FieldLabel:
                    text: "Deploy to"
                RoundSpinner:
                    id: sp_mode
                    text: "Workers (recommended)"
                    values: ["Workers (recommended)", "Pages (pages.dev)"]
                FieldLabel:
                    text: "Panel source (built into the app, or pick a zip)"
                BoxLayout:
                    size_hint_y: None
                    height: dp(46)
                    spacing: dp(8)
                    RoundInput:
                        id: f_source
                    RoundButton:
                        text: "Pick"
                        kind: "soft"
                        height: dp(46)
                        size_hint_x: None
                        width: dp(84)
                        on_release: app.pick_source_file()
                FieldLabel:
                    text: "Project name"
                RoundInput:
                    id: f_project
                FieldLabel:
                    text: "ADMIN_PASSWORD"
                RoundInput:
                    id: f_pass
                FieldLabel:
                    text: "PANEL_PATH"
                RoundInput:
                    id: f_panel
                FieldLabel:
                    text: "Custom domain (optional)"
                RoundInput:
                    id: f_domain
                FieldLabel:
                    text: "Temporary proxy for the panel (optional)  e.g. 1.2.3.4:8080 or socks5://1.2.3.4:1080"
                RoundInput:
                    id: f_proxy
                RoundButton:
                    id: btn_autoproxy
                    text: "Smart connection: ON"
                    kind: "soft"
                    on_release: app.toggle_autoproxy()
                RoundButton:
                    text: "Re-roll random values"
                    kind: "soft"
                    on_release: app.roll_all()

            Card:
                Ring:
                    id: ring
                Label:
                    id: lbl_build_stage
                    text: "Waiting for you."
                    font_size: "13sp"
                    color: C_MUTED
                    size_hint_y: None
                    height: self.texture_size[1] + dp(4)
                    halign: "center"
                    text_size: self.width, None
                RoundButton:
                    id: btn_build
                    text: "Build my configs"
                    height: dp(54)
                    on_release: app.on_build()


<OutputScreen>:
    name: "output"
    ScrollView:
        bar_width: dp(3)
        Page:
            Card:
                H1:
                    text: "Your configs"
                Body:
                    id: lbl_out_info
                    text: "Nothing built yet. Go through steps 1-3, or load one from the Saved tab."
                FieldLabel:
                    text: "Format"
                RoundSpinner:
                    id: sp_fmt
                    text: "Auto (recommended)"
                    values: ["Auto (recommended)", "Xray", "Clash", "sing-box", "Patt", "Plain links"]
                    on_text: app.on_pick_fmt(self.text)
                FieldLabel:
                    text: "Subscription link"
                RoundInput:
                    id: f_sub_url
                    readonly: True
                BoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    spacing: dp(8)
                    RoundButton:
                        text: "Copy link"
                        on_release: app.copy_sub_url()
                    RoundButton:
                        text: "Save all to device"
                        kind: "soft"
                        on_release: app.save_all_configs()
                FieldLabel:
                    text: "Preview"
                RoundInput:
                    id: f_preview
                    multiline: True
                    readonly: True
                    height: dp(240)
                    padding: [dp(14), dp(12)]
                    font_size: "12sp"


<ManageScreen>:
    name: "manage"
    BoxLayout:
        orientation: "vertical"
        padding: dp(14), dp(14), dp(14), 0
        spacing: dp(12)
        Card:
            H1:
                text: "Saved configs"
            Muted:
                text: "Everything you built on this phone. Load one back into the Configs tab, update its clean IPs, rename it, or remove it."
            RoundButton:
                text: "Databases (D1) - view / delete"
                kind: "soft"
                on_release: app.open_db_manager()
        ScrollView:
            bar_width: dp(3)
            BoxLayout:
                id: manage_list
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(12)
                padding: 0, 0, 0, dp(14)
"""


# ───────────────────────────── custom widgets ─────────────────────────────
class Page(BoxLayout):
    pass


class Card(BoxLayout):
    pass


class RoundInput(TextInput):
    pass


class RoundSpinner(Spinner):
    pass


class RoundButton(ButtonBehavior, Label):
    kind = StringProperty("primary")      # primary | soft | danger | ghost
    bg_color = ListProperty([0.98, 0.74, 0.08, 1])
    fg = ListProperty([1, 1, 1, 1])

    _PALETTE = {
        "primary": ((0.98, 0.74, 0.08, 1), (0.25, 0.16, 0.0, 1)),
        "soft": ((1.0, 0.94, 0.72, 1), (0.50, 0.34, 0.0, 1)),
        "danger": ((1.0, 0.90, 0.91, 1), (0.78, 0.18, 0.22, 1)),
        "ghost": ((0, 0, 0, 0), (0.52, 0.44, 0.26, 1)),
    }

    def __init__(self, **kw):
        super().__init__(**kw)
        self.halign = "center"
        self.valign = "middle"
        self.bind(kind=self._recalc, state=self._recalc, disabled=self._recalc)
        self._recalc()

    def _recalc(self, *_):
        bg, fg = self._PALETTE.get(self.kind, self._PALETTE["primary"])
        if self.disabled:
            bg, fg = (0.95, 0.92, 0.84, 1), (0.70, 0.64, 0.48, 1)
        elif self.state == "down":
            bg = (bg[0] * 0.86, bg[1] * 0.86, bg[2] * 0.86, bg[3])
        self.bg_color = list(bg)
        self.fg = list(fg)


class NavTab(ButtonBehavior, Label):
    active = BooleanProperty(False)
    target = StringProperty("")


class SoftBar(Widget):
    value = NumericProperty(0)


class StatBox(BoxLayout):
    value = StringProperty("0")
    caption = StringProperty("")
    accent = ListProperty([0.80, 0.55, 0.0, 1])


class IpRow(BoxLayout):
    ip = StringProperty("")
    meta = StringProperty("")
    score = NumericProperty(0)


class DeployRow(Card):
    title = StringProperty("")
    subtitle = StringProperty("")
    index = NumericProperty(0)


class LogBar(ButtonBehavior, BoxLayout):
    last = StringProperty("Ready.")


class ToastLabel(Label):
    pass


class GradientBox(BoxLayout):
    c1 = ListProperty(C_PRIMARY)
    c2 = ListProperty([1.0, 0.86, 0.30, 1])

    def __init__(self, **kw):
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw, c1=self._draw, c2=self._draw)
        self._draw()

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(1, 1, 1, 1)
            Rectangle(pos=self.pos, size=self.size, texture=gradient_texture(self.c1, self.c2, vertical=False))


class Radar(FloatLayout):
    """Animated radar. While a scan runs the sweep spins fast; every probed IP appears as a blip:
    clean IPs stay as glowing green dots with a pulse ring, failed probes flash red and fade."""
    title = StringProperty("STANDBY")
    subtitle = StringProperty("Press Start scan")
    active = BooleanProperty(False)

    def __init__(self, **kw):
        super().__init__(**kw)
        self._angle = 90.0
        self._t = 0.0
        self._blips = []
        self._known = set()
        Clock.schedule_interval(self._tick, 1 / 30.0)

    def reset(self):
        self._blips = []
        self._known = set()

    def feed(self, recent):
        for ip, ok in recent:
            if ip in self._known:
                continue
            self._known.add(ip)
            h = zlib.crc32(ip.encode())
            self._blips.append({"a": h % 360, "r": 0.16 + 0.80 * (((h >> 9) % 1000) / 1000.0), "ok": ok, "age": 0.0})
        good = [b for b in self._blips if b["ok"]]
        if len(good) > 140:
            drop = set(map(id, good[: len(good) - 140]))
            self._blips = [b for b in self._blips if id(b) not in drop]

    def _tick(self, dt):
        if self.get_root_window() is None or self.width < 10:
            return
        self._t += dt
        self._angle = (self._angle - (150.0 if self.active else 28.0) * dt) % 360
        for b in self._blips:
            b["age"] += dt
        self._blips = [b for b in self._blips if b["ok"] or b["age"] < 1.6]
        self._draw()

    def _draw(self):
        c = self.canvas.before
        c.clear()
        rad = math.radians
        with c:
            Color(1.0, 0.97, 0.84, 1)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(24)])
            cx, cy = self.center
            R = min(self.width, self.height) / 2 - dp(34)
            Color(0.98, 0.76, 0.10, 0.14)
            Ellipse(pos=(cx - R, cy - R), size=(2 * R, 2 * R))
            Color(0.85, 0.60, 0.05, 0.38)
            for k in (1.0, 0.75, 0.5, 0.25):
                Line(circle=(cx, cy, R * k), width=dp(0.9))
            Color(0.85, 0.60, 0.05, 0.22)
            Line(points=[cx - R, cy, cx + R, cy], width=dp(0.8))
            Line(points=[cx, cy - R, cx, cy + R], width=dp(0.8))
            # sweep with fading trail
            steps, span = 26, 72.0
            for i in range(steps):
                a0 = rad(self._angle + i * span / steps)
                a1 = rad(self._angle + (i + 1) * span / steps)
                Color(0.98, 0.74, 0.08, (0.40 if self.active else 0.24) * (1 - i / steps) ** 1.7)
                Triangle(points=[cx, cy, cx + R * math.cos(a0), cy + R * math.sin(a0),
                                 cx + R * math.cos(a1), cy + R * math.sin(a1)])
            a = rad(self._angle)
            Color(0.80, 0.55, 0.0, 0.95)
            Line(points=[cx, cy, cx + R * math.cos(a), cy + R * math.sin(a)], width=dp(1.6))
            # blips
            oks = [b for b in self._blips if b["ok"]]
            pulsing = set(map(id, oks[-25:]))
            for b in self._blips:
                ang = rad(b["a"])
                x = cx + R * b["r"] * math.cos(ang)
                y = cy + R * b["r"] * math.sin(ang)
                if b["ok"]:
                    if id(b) in pulsing:
                        p = (self._t * 1.5 + b["a"] / 360.0) % 1
                        Color(0.10, 0.65, 0.35, 0.55 * (1 - p))
                        Line(circle=(x, y, dp(4) + dp(15) * p), width=dp(1))
                    Color(0.07, 0.60, 0.30, 1)
                    Ellipse(pos=(x - dp(3.5), y - dp(3.5)), size=(dp(7), dp(7)))
                else:
                    fade = max(0.0, 1 - b["age"] / 1.6)
                    Color(0.85, 0.25, 0.30, 0.55 * fade)
                    Ellipse(pos=(x - dp(2.2), y - dp(2.2)), size=(dp(4.4), dp(4.4)))
            Color(0.80, 0.55, 0.0, 1)
            Ellipse(pos=(cx - dp(3), cy - dp(3)), size=(dp(6), dp(6)))


class Ring(FloatLayout):
    """Circular progress. Spins while busy with no progress yet, otherwise shows value (0..1)."""
    value = NumericProperty(0)
    busy = BooleanProperty(False)
    text = StringProperty("")

    def __init__(self, **kw):
        super().__init__(**kw)
        self._rot = 0.0
        self.bind(pos=self._draw, size=self._draw, value=self._draw, busy=self._draw)
        Clock.schedule_interval(self._spin, 1 / 30.0)
        self._draw()

    def _spin(self, dt):
        if self.busy and self.value <= 0.01 and self.get_root_window() is not None:
            self._rot = (self._rot + 330 * dt) % 360
            self._draw()

    def _draw(self, *_):
        c = self.canvas.before
        c.clear()
        with c:
            cx, cy = self.center
            r = min(self.size) / 2 - dp(10)
            w = dp(9)
            Color(0.90, 0.68, 0.08, 0.20)
            Line(circle=(cx, cy, r), width=w)
            if self.busy and self.value <= 0.01:
                Color(0.98, 0.76, 0.10, 0.25)
                Line(circle=(cx, cy, r, self._rot, self._rot + 100), width=w * 2.2, cap="round")
                Color(*C_CYAN)
                Line(circle=(cx, cy, r, self._rot, self._rot + 100), width=w, cap="round")
            elif self.value > 0.005:
                Color(0.98, 0.76, 0.10, 0.25)
                Line(circle=(cx, cy, r, 0, 360 * min(1.0, self.value)), width=w * 2.2, cap="round")
                Color(*C_CYAN)
                Line(circle=(cx, cy, r, 0, 360 * min(1.0, self.value)), width=w, cap="round")


class Splash(FloatLayout):
    """Full-screen animated intro that fades out by itself."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self._t = 0.0
        self._tex = gradient_texture(C_PRIMARY, C_CYAN, vertical=True)
        self._logo = Label(text="A", bold=True, font_size="46sp", color=(0.20, 0.14, 0.04, 1), size_hint=(None, None),
                           size=(dp(96), dp(96)), pos_hint={"center_x": .5, "center_y": .58})
        self._word = "Aminium"
        self._name = Label(text="", bold=True, font_size="40sp", color=(0.20, 0.14, 0.04, 1), size_hint=(None, None),
                           size=(dp(320), dp(56)), pos_hint={"center_x": .5, "center_y": .43})
        self._tag = Label(text="Telegram id : illuyj", font_size="15sp", color=(0.20, 0.14, 0.04, 1), opacity=0,
                          size_hint=(None, None), size=(dp(320), dp(30)), pos_hint={"center_x": .5, "center_y": .37})
        for w in (self._logo, self._name, self._tag):
            self.add_widget(w)
        self._ev = Clock.schedule_interval(self._tick, 1 / 30.0)
        Clock.schedule_once(self.dismiss, 3.2)

    def on_touch_down(self, touch):
        return True

    def on_touch_move(self, touch):
        return True

    def on_touch_up(self, touch):
        return True

    def _tick(self, dt):
        self._t += dt
        # logo pops in, the name is typed letter by letter, then the Telegram line fades in
        pop = min(1.0, self._t / 0.5)
        self._logo.opacity = pop
        self._logo.font_size = f"{int(30 + 16 * (1 - (1 - pop) ** 3))}sp"
        n = max(0, min(len(self._word), int((self._t - 0.5) / 0.14)))
        self._name.text = self._word[:n]
        self._tag.opacity = max(0.0, min(1.0, (self._t - 1.5) / 0.7))
        c = self.canvas.before
        c.clear()
        with c:
            Color(1, 1, 1, 1)
            Rectangle(pos=self.pos, size=self.size, texture=self._tex)
            cx, cy = self.width / 2, self.height * 0.58
            for k in range(3):
                p = (self._t * 0.55 + k / 3.0) % 1
                Color(1, 1, 1, 0.30 * (1 - p))
                Line(circle=(cx, cy, dp(50) + dp(120) * p), width=dp(1.4))
            Color(1, 1, 1, 0.22)
            RoundedRectangle(pos=(cx - dp(48), cy - dp(48)), size=(dp(96), dp(96)), radius=[dp(30)])
            bw = dp(180)
            bx, by = cx - bw / 2, self.height * 0.30
            Color(1, 1, 1, 0.28)
            RoundedRectangle(pos=(bx, by), size=(bw, dp(5)), radius=[dp(3)])
            Color(1, 1, 1, 0.95)
            RoundedRectangle(pos=(bx, by), size=(max(dp(5), bw * min(1.0, self._t / 3.0)), dp(5)), radius=[dp(3)])

    def dismiss(self, *_):
        a = Animation(opacity=0, duration=0.5)

        def done(*_):
            self._ev.cancel()
            if self.parent:
                self.parent.remove_widget(self)
        a.bind(on_complete=done)
        a.start(self)


class TokenScreen(Screen):
    pass


class ScanScreen(Screen):
    pass


class BuildScreen(Screen):
    pass


class OutputScreen(Screen):
    pass


class ManageScreen(Screen):
    pass


# ───────────────────────────── the app ─────────────────────────────
class AminiumApp(App):
    title = "Aminium Studio"
    grad_h = ObjectProperty(None)

    def build(self):
        Window.clearcolor = C_BG
        self.grad_h = gradient_texture(C_PRIMARY, C_CYAN, vertical=False)
        try:
            Window.softinput_mode = "below_target"      # keyboard pushes the focused field up
        except Exception:
            pass
        self._ready = False
        self.cfg = self.load_cfg()
        self.token = self.cfg.get("token", "")
        self.email = self.cfg.get("email", "")
        self.accounts = []
        self.account_id = self.cfg.get("account_id")
        self._acc_values = []
        self.token_ok = False
        core.set_auto_proxy(self.cfg.get("auto_proxy", True))
        core.set_proxy_logger(lambda s: self.log(s))
        core.VPN_PROMPT = self.ask_vpn_toggle
        self.job = None
        self.ips = []
        self.rec = None
        self.out = None
        self.cur_fmt = "auto"
        self.log_lines = []
        self._shown_found = -1
        self.deployments = core.load_deployments()

        root = Builder.load_string(KV)
        self.root_widget = root
        self.sm = root.ids.sm
        self.sm.transition = SlideTransition(duration=0.22)
        self.logbar = root.ids.logbar
        self.hdr_sub = root.ids.hdr_sub
        for scr in (TokenScreen(), ScanScreen(), BuildScreen(), OutputScreen(), ManageScreen()):
            self.sm.add_widget(scr)

        self.tabs = {}
        for name, label, _sub in TABS:
            tab = NavTab(text=label, target=name)
            tab.bind(on_release=lambda t: self.goto(t.target))
            root.ids.nav.add_widget(tab)
            self.tabs[name] = tab

        root.add_widget(Splash())
        self._ready = True
        self.goto("token", animate=False)
        Clock.schedule_once(lambda dt: self.init_fields(), 0)
        return root

    # ---------- helpers ----------
    def cfg_path(self):
        return core.APP_DIR / "aminium_studio_config.json"

    def load_cfg(self):
        try:
            return json.loads(self.cfg_path().read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_cfg(self):
        self.cfg["token"] = self.token
        self.cfg["email"] = self.email
        try:
            core.APP_DIR.mkdir(parents=True, exist_ok=True)
            self.cfg_path().write_text(json.dumps(self.cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            self.log(f"Could not save settings: {e}")

    def log(self, msg):
        def ui(*_):
            line = str(msg)
            self.log_lines.append(line)
            self.log_lines = self.log_lines[-300:]
            self.logbar.last = line.replace("\n", " ")
            if line.startswith("ERROR"):
                self.toast(line[:90])
        Clock.schedule_once(ui, 0)

    def toast(self, text):
        t = ToastLabel(text=text, opacity=0)
        self.root_widget.add_widget(t)
        anim = Animation(opacity=1, duration=0.15) + Animation(opacity=1, duration=1.7) + Animation(opacity=0, duration=0.4)
        anim.bind(on_complete=lambda *_: self.root_widget.remove_widget(t))
        anim.start(t)

    def show_log(self):
        box = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(8))
        from kivy.uix.scrollview import ScrollView
        sv = ScrollView(bar_width=dp(3))
        lab = Label(text="\n".join(self.log_lines) or "(empty)", color=C_TEXT, font_size="11sp",
                    size_hint_y=None, halign="left", valign="top")
        lab.bind(width=lambda i, w: setattr(i, "text_size", (w, None)),
                 texture_size=lambda i, s: setattr(i, "height", s[1]))
        sv.add_widget(lab)
        box.add_widget(sv)
        btn = RoundButton(text="Close", height=dp(44))
        box.add_widget(btn)
        pop = self.make_popup("Activity log", box, (0.94, 0.8))
        btn.bind(on_release=lambda *_: pop.dismiss())
        pop.open()

    def make_popup(self, title, content, size_hint):
        return Popup(title=title, content=content, size_hint=size_hint, background="",
                     background_color=C_SURFACE, title_color=C_TEXT, separator_color=C_CYAN)

    def set_status(self, label, text, kind="info"):
        label.text = text
        label.color = {"ok": C_OK, "err": C_ERR}.get(kind, C_MUTED)

    def open_url(self, url):
        try:
            if platform == "android":
                from jnius import autoclass  # type: ignore
                Intent = autoclass("android.content.Intent")
                Uri = autoclass("android.net.Uri")
                Activity = autoclass("org.kivy.android.PythonActivity")
                Activity.mActivity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            else:
                import webbrowser
                webbrowser.open(url)
            return True
        except Exception as e:
            from kivy.core.clipboard import Clipboard
            Clipboard.copy(url)
            self.log(f"Could not open the browser ({e}). The link was copied - paste it into your browser.")
            return False

    def goto(self, name, animate=True):
        order = [t[0] for t in TABS]
        cur = self.sm.current if self.sm.screen_names else name
        if animate and name != cur and cur in order:
            self.sm.transition.direction = "left" if order.index(name) > order.index(cur) else "right"
        self.sm.current = name
        for n, tab in self.tabs.items():
            tab.active = (n == name)
        self.hdr_sub.text = next(t[2] for t in TABS if t[0] == name)
        if name == "manage":
            self.refresh_manage_list()
        if name == "build":
            self.refresh_build_summary()

    BUILTIN_LABEL = "Built-in panel"

    def find_default_zip(self):
        if core.builtin_available():
            return self.BUILTIN_LABEL
        dirs = [core.APP_DIR, Path(core.__file__).resolve().parent, Path(__file__).resolve().parent, Path.cwd()]
        for d in dirs:
            p = d / "aminium-pages.zip"
            if p.exists():
                return str(p)
        return ""

    def init_fields(self):
        t = self.sm.get_screen("token")
        t.ids.f_token.text = self.token
        t.ids.f_email.text = self.email
        if self.token:
            self.set_status(t.ids.lbl_token_state, "Token loaded from this phone. Press 'Save & verify'.")
        self.roll_all()
        self.sm.get_screen("build").ids.f_proxy.text = self.cfg.get("panel_proxy", "")
        self._paint_autoproxy()

    # ---------- step 1: token ----------
    def open_token_page(self, manual=False):
        url = core.TOKEN_URL if manual else core.token_template_url()
        if self.open_url(url):
            self.toast("Opening Cloudflare...")
            self.log("Cloudflare token page opened. Press Continue -> Create Token, then copy the token.")

    def open_signup_page(self):
        if self.open_url("https://dash.cloudflare.com/sign-up"):
            self.toast("Opening Cloudflare sign-up...")
            self.log("Sign up, confirm the email Cloudflare sends you, then come back and press 'Create API token'.")

    def paste_token(self):
        from kivy.core.clipboard import Clipboard
        txt = (Clipboard.paste() or "").strip()
        if txt:
            self.sm.get_screen("token").ids.f_token.text = txt
            self.toast("Pasted")
        else:
            self.toast("Clipboard is empty")

    def on_save_token(self):
        t = self.sm.get_screen("token")
        tok = t.ids.f_token.text.strip()
        if not tok:
            return self.log("ERROR: paste the API token first.")
        self.token, self.email = tok, t.ids.f_email.text.strip()
        self.set_status(t.ids.lbl_token_state, "Checking the token...")

        def work():
            try:
                cf = core.CF(self.token, self.log, self.email)
                info = cf.verify()
                all_accs = cf.accounts()
                if not all_accs:
                    raise core.CFError("No account visible to this token (add 'Account Settings: Read').")
                accs = cf.usable_accounts(all_accs)
                self.accounts = accs
                vals = [f"{a['name']} ({a['id'][:6]})" for a in accs]
                self._acc_values = vals
                saved = self.cfg.get("account_id")
                pick = next((i for i, a in enumerate(accs) if a["id"] == saved), 0)
                self.account_id = accs[pick]["id"]

                def ui(*_):
                    t.ids.sp_account.values = vals
                    t.ids.sp_account.text = vals[pick]
                    self.token_ok = True
                    self.set_status(t.ids.lbl_token_state,
                                    f"Token is valid ({info.get('status')}). {len(accs)} of {len(all_accs)} account(s) usable - "
                                    "pick the one to build in, then continue to the Radar tab.", "ok")
                    self.save_cfg()
                    self.toast("Token verified")
                Clock.schedule_once(ui, 0)
            except Exception as e:
                self.log(f"Token check failed: {e}")

                def ui2(*_):
                    self.token_ok = False
                    self.set_status(t.ids.lbl_token_state, f"Token check failed: {e}", "err")
                Clock.schedule_once(ui2, 0)
        threading.Thread(target=work, daemon=True).start()

    def on_forget_token(self):
        self.token, self.email, self.token_ok = "", "", False
        self.accounts = []
        self.account_id = None
        self._acc_values = []
        t = self.sm.get_screen("token")
        t.ids.f_token.text = ""
        t.ids.f_email.text = ""
        t.ids.sp_account.values = ["(verify token first)"]
        t.ids.sp_account.text = "(verify token first)"
        self.set_status(t.ids.lbl_token_state, "")
        self.save_cfg()
        self.log("Token removed from this phone.")

    # ---------- step 2: scan (radar) ----------
    def scan_form(self):
        s = self.sm.get_screen("scan")
        tls = s.ids.sp_conn.text == "TLS"
        depth = core.DEPTH[s.ids.sp_depth.text]
        return {
            "host": core.SPEED_HOST, "port": 443 if tls else 80, "count": depth["count"],
            "threads": depth["threads"], "timeout": 5.0, "rounds": 3, "target": depth["target"],
            "mode": "spread", "custom": "", "verify": True, "neighbors": True, "auto": True,
            "ws": False, "speed": False,
        }

    def on_scan(self):
        if self.job and self.job.phase in ("diagnosing", "scanning", "speed", "finishing"):
            return
        s = self.sm.get_screen("scan")
        cfg = core.Config.from_dict(self.scan_form())
        self.job = core.ScanJob(cfg, self.log)
        job = self.job
        self._shown_found = -1
        s.ids.radar.reset()
        s.ids.radar.active = True
        s.ids.radar.title = "SCANNING"
        s.ids.radar.subtitle = "0 clean IPs found"
        s.ids.pb_scan.value = 0
        s.ids.btn_scan.disabled = True
        s.ids.btn_scan.text = "Scanning..."
        s.ids.btn_stop.disabled = False
        s.ids.lbl_ip_empty.text = "Searching..."
        s.ids.ip_list.clear_widgets()
        Clock.schedule_once(lambda dt: self.poll_scan(), 0.3)

        def go():
            try:
                job.run()
            except Exception as e:
                self.log(f"ERROR: scan crashed: {e}")
            Clock.schedule_once(lambda dt: self.scan_finished(), 0)
        threading.Thread(target=go, daemon=True).start()

    def on_stop_scan(self):
        if self.job:
            self.job.stop.set()
            self.log("Stopping...")

    PHASE_TITLES = {"diagnosing": "CHECKING NETWORK", "scanning": "SCANNING", "speed": "SPEED TEST",
                    "finishing": "FINISHING", "done": "COMPLETE", "stopped": "STOPPED", "idle": "STARTING"}

    def poll_scan(self):
        job = self.job
        if not job:
            return
        s = self.sm.get_screen("scan")
        snap = job.snapshot()
        self.update_scan_ui(s, snap)
        if snap["phase"] in ("diagnosing", "scanning", "speed", "finishing", "idle"):
            Clock.schedule_once(lambda dt: self.poll_scan(), 0.4)

    def update_scan_ui(self, s, snap):
        radar = s.ids.radar
        radar.feed(snap.get("recent", []))
        radar.title = self.PHASE_TITLES.get(snap["phase"], snap["phase"].upper())
        radar.subtitle = f"{snap['found']} clean IPs found"
        s.ids.st_tested.value = f"{snap['tested']}/{snap['total']}" if snap["total"] else str(snap["tested"])
        s.ids.st_found.value = str(snap["found"])
        s.ids.st_time.value = str(int(snap["elapsed"]))
        s.ids.lbl_scan_stats.text = f"{snap['phase']}  -  {snap['tested']} of {snap['total']} tested"
        if snap["total"]:
            target = min(1.0, snap["tested"] / snap["total"])
            Animation(value=target, duration=0.35).start(s.ids.pb_scan)
        if snap["found"] != self._shown_found:
            self._shown_found = snap["found"]
            self.fill_ip_rows(s, snap["results"], limit=8)

    def fill_ip_rows(self, s, results, limit=60):
        box = s.ids.ip_list
        box.clear_widgets()
        ordered = sorted(results, key=lambda r: -r["score"])[:limit]
        s.ids.lbl_ip_empty.text = "" if ordered else "(none yet)"
        for r in ordered:
            meta = f"{r.get('colo') or '--'}   |   {r.get('total', '?')} ms   |   jitter {r.get('jitter', '?')}"
            box.add_widget(IpRow(ip=r["ip"], meta=meta, score=int(r["score"])))

    def scan_finished(self):
        s = self.sm.get_screen("scan")
        s.ids.btn_scan.disabled = False
        s.ids.btn_scan.text = "Start scan"
        s.ids.btn_stop.disabled = True
        s.ids.radar.active = False
        snap = self.job.snapshot() if self.job else {"results": [], "phase": "done", "tested": 0, "total": 0,
                                                       "found": 0, "elapsed": 0, "recent": []}
        self.update_scan_ui(s, snap)
        results = sorted(snap["results"], key=lambda r: -r["score"])
        self.ips = [r["ip"] for r in results]
        self.fill_ip_rows(s, results, limit=60)
        if not results:
            s.ids.lbl_ip_empty.text = "Nothing found - see the log (tap the bar above the tabs)."
        s.ids.pb_scan.value = 1.0
        s.ids.radar.title = "COMPLETE" if results else "NO RESULT"
        self.log(f"Finished: {len(self.ips)} clean IPs.")
        self.toast(f"{len(self.ips)} clean IPs found")

    def copy_ips(self):
        if not self.ips:
            return self.toast("No IPs yet")
        from kivy.core.clipboard import Clipboard
        Clipboard.copy("\n".join(self.ips))
        self.toast("IPs copied")

    # ---------- step 3: build ----------
    def roll_all(self):
        b = self.sm.get_screen("build")
        b.ids.f_project.text = core.rnd_name()
        b.ids.f_pass.text = core.rnd(20)
        b.ids.f_panel.text = "/" + core.rnd(10, core.LOWER)
        self._ws_path = "/stream/" + core.rnd(18, core.LOWER)
        self._cron = core.rnd(24)
        self._uuid = str(uuidlib.uuid4())
        if not b.ids.f_source.text:
            b.ids.f_source.text = self.find_default_zip()

    def pick_source_file(self):
        b = self.sm.get_screen("build")
        if core.builtin_available() and b.ids.f_source.text != self.BUILTIN_LABEL:
            b.ids.f_source.text = self.BUILTIN_LABEL
            return self.toast("Using the panel built into the app")
        if platform == "android":
            return self.pick_with_android_picker()
        self.pick_with_kivy_chooser()

    def pick_with_android_picker(self):
        """Android's own file picker (works on every Android version, no storage permission needed).
        The chosen file is copied into the app's private folder, so it is found automatically next time."""
        try:
            from android import activity  # type: ignore
            from jnius import autoclass  # type: ignore
            Intent = autoclass("android.content.Intent")
            Activity = autoclass("org.kivy.android.PythonActivity")
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            activity.bind(on_activity_result=self._on_picked)
            # no Intent.createChooser(): pyjnius cannot match a Python str to its CharSequence argument
            Activity.mActivity.startActivityForResult(intent, 4242)
        except Exception as e:
            self.log(f"ERROR: Android file picker failed: {e}")

    def _on_picked(self, request_code, result_code, intent):
        if request_code != 4242:
            return
        try:
            from android import activity  # type: ignore
            activity.unbind(on_activity_result=self._on_picked)
        except Exception:
            pass
        if result_code != -1 or intent is None:      # -1 == RESULT_OK
            return
        try:
            from jnius import autoclass  # type: ignore
            Activity = autoclass("org.kivy.android.PythonActivity")
            uri = intent.getData()
            pfd = Activity.mActivity.getContentResolver().openFileDescriptor(uri, "r")
            fd = pfd.detachFd()
            with os.fdopen(fd, "rb") as f:
                data = f.read()
            core.APP_DIR.mkdir(parents=True, exist_ok=True)
            dest = core.APP_DIR / "aminium-pages.zip"
            dest.write_bytes(data)
            core.load_source(str(dest))               # validates: must contain _worker.js
        except Exception as e:
            return self.log(f"ERROR: that file cannot be used: {e}")

        def ui(*_):
            self.sm.get_screen("build").ids.f_source.text = str(dest)
            self.toast("Panel zip loaded")
            self.log(f"Panel zip copied to {dest}")
        Clock.schedule_once(ui, 0)

    def pick_with_kivy_chooser(self):
        b = self.sm.get_screen("build")
        try:
            from kivy.uix.filechooser import FileChooserListView
            start = next((p for p in (str(core.APP_DIR), os.path.expanduser("~/Downloads"), os.path.expanduser("~"))
                          if os.path.isdir(p)), "/")
            box = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(6))
            fc = FileChooserListView(path=start, filters=["*.zip"])
            box.add_widget(fc)
            row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
            ok = RoundButton(text="Select")
            cancel = RoundButton(text="Cancel", kind="soft")
            row.add_widget(ok)
            row.add_widget(cancel)
            box.add_widget(row)
            pop = self.make_popup("Choose aminium-pages.zip", box, (0.95, 0.85))

            def choose(*_):
                if fc.selection:
                    b.ids.f_source.text = fc.selection[0]
                pop.dismiss()
            ok.bind(on_release=choose)
            cancel.bind(on_release=lambda *_: pop.dismiss())
            pop.open()
        except Exception as e:
            self.log(f"ERROR: file chooser unavailable: {e}")

    def refresh_build_summary(self):
        b = self.sm.get_screen("build")
        n = len(self.ips)
        tls = self.sm.get_screen("scan").ids.sp_conn.text == "TLS"
        ports = len(core.TLS_PORTS if tls else core.PLAIN_PORTS)
        b.ids.lbl_build_sum.text = (f"{n} clean IPs (+ your worker's own address)  x  {ports} ports  x  2 protocols"
                                    f"  =  up to {(n + 1) * ports * 2} configs.   Connection: {'TLS' if tls else 'No TLS'}")

    def on_build(self):
        b = self.sm.get_screen("build")
        project = b.ids.f_project.text.strip().lower()
        source = b.ids.f_source.text.strip()
        if not self.token:
            return self.log("ERROR: add and verify your Cloudflare token first (Token tab).")
        if not self.ips:
            return self.log("ERROR: no clean IPs yet - run the Radar scan first.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,56}", project or ""):
            return self.log("ERROR: project name: lowercase letters, digits and '-' only.")
        if source in ("", self.BUILTIN_LABEL, core.BUILTIN):
            if not core.builtin_available():
                return self.log("ERROR: no panel inside the app - tap Pick and choose aminium-pages.zip.")
            source = core.BUILTIN
        elif not Path(source).exists():
            return self.log("ERROR: source zip not found - tap Pick and choose aminium-pages.zip again.")
        if not b.ids.f_pass.text:
            return self.log("ERROR: ADMIN_PASSWORD is empty.")
        panel = b.ids.f_panel.text.strip()
        if panel and not panel.startswith("/"):
            panel = "/" + panel
            b.ids.f_panel.text = panel
        mode = "workers" if b.ids.sp_mode.text.startswith("Workers") else "pages"
        tls = self.sm.get_screen("scan").ids.sp_conn.text == "TLS"
        form = {
            "pass": b.ids.f_pass.text, "ws_path": self._ws_path, "cron": self._cron, "uuid": self._uuid,
            "decoy": "", "tg_token": "", "tg_secret": "", "tg_admins": "", "domain": b.ids.f_domain.text.strip().lower(),
            "d1": True, "verify_ws": True, "scan": self.scan_form(), "ips": list(self.ips), "keep": 100, "tls": tls,
            "proxy": b.ids.f_proxy.text.strip(), "auto_proxy": bool(self.cfg.get("auto_proxy", True)),
            "net": "", "frag_len": "", "frag_int": "",
        }
        self.cfg["panel_proxy"] = form["proxy"]
        self.save_cfg()
        b.ids.btn_build.disabled = True
        b.ids.btn_build.text = "Building..."
        b.ids.ring.value = 0
        b.ids.ring.busy = True
        b.ids.ring.text = ""

        def stage(text, frac):
            def ui(*_):
                b.ids.lbl_build_stage.text = text
                b.ids.ring.text = f"{int(frac * 100)}%"
                Animation(value=frac, duration=0.4).start(b.ids.ring)
            Clock.schedule_once(ui, 0)

        def reset_button(msg=None):
            b.ids.btn_build.disabled = False
            b.ids.btn_build.text = "Build my configs"
            b.ids.ring.busy = False
            if msg:
                b.ids.lbl_build_stage.text = msg

        def work():
            try:
                result = core.run_build(self.token, self.email, self.accounts, self.account_id, project, source, panel, mode,
                                        form, self.log, stage)
                self.rec, self.out = result["rec"], result["out"]
                self.deployments = core.add_deployment(self.rec)

                def ui(*_):
                    reset_button("Done!")
                    b.ids.ring.text = "100%"
                    Animation(value=1.0, duration=0.3).start(b.ids.ring)
                    self.render_output()
                    self.goto("output")
                Clock.schedule_once(ui, 0)
            except Exception as e:
                self.log(f"ERROR: {e}")
                Clock.schedule_once(lambda dt: reset_button("Something went wrong - tap the log bar for details."), 0)
        threading.Thread(target=work, daemon=True).start()

    # ---------- step 4: configs ----------
    def render_output(self):
        o = self.sm.get_screen("output")
        if not self.rec:
            o.ids.lbl_out_info.text = "Nothing built yet."
            return
        n = len(self.out["links"]) if self.out else 0
        o.ids.lbl_out_info.text = (f"{n} configs  -  {len(self.rec.get('ips', []))} clean IPs\n"
                                   f"Panel:  {self.rec['base']}{self.rec['panel_path']}\nPassword:  {self.rec['password']}")
        self.on_pick_fmt(o.ids.sp_fmt.text)

    def on_pick_fmt(self, label):
        if not getattr(self, "_ready", False):
            return
        try:
            o = self.sm.get_screen("output")
        except Exception:
            return
        key, _, q = next((x for x in FORMATS_UI if x[1] == label), FORMATS_UI[0])
        self.cur_fmt = key
        if not self.out:
            o.ids.f_sub_url.text = ""
            o.ids.f_preview.text = "No configs available yet."
            return
        o.ids.f_sub_url.text = self.out["sub"] + ("" if key == "auto" else q)
        o.ids.f_preview.text = (self.out["text"].get(key) or "(empty)")[:4000]

    def copy_sub_url(self):
        o = self.sm.get_screen("output")
        if not o.ids.f_sub_url.text:
            return self.toast("Nothing to copy yet")
        from kivy.core.clipboard import Clipboard
        Clipboard.copy(o.ids.f_sub_url.text)
        self.toast("Link copied")

    def save_all_configs(self):
        if not (self.rec and self.out):
            return self.log("Nothing to save yet.")
        try:
            folder = core.save_all(self.rec, self.out, self.log)
            self.log(f"Saved to {folder}")
            self.toast("Saved on this phone")
        except Exception as e:
            self.log(f"ERROR: save failed: {e}")

    # ---------- "Saved" screen ----------
    # ---------- smart connection: when it is OFF, ask for a VPN off/on and retry ----------
    def ask_vpn_toggle(self, what=""):
        ev = threading.Event()
        res = {"ok": False}

        def ui(*_):
            content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(10))
            lab = Label(text="The connection failed.\n\nTurn your VPN OFF, then ON again, wait a few seconds and press Retry.",
                        color=C_TEXT, font_size="13sp", halign="center", valign="middle")
            lab.bind(size=lambda i, s: setattr(i, "text_size", s))
            content.add_widget(lab)
            b_ok = RoundButton(text="Retry")
            b_no = RoundButton(text="Cancel", kind="ghost")
            content.add_widget(b_ok)
            content.add_widget(b_no)
            pop = self.make_popup("Smart connection", content, (0.9, 0.5))
            pop.auto_dismiss = False

            def done(ok):
                res["ok"] = ok
                pop.dismiss()
                ev.set()
            b_ok.bind(on_release=lambda *_: done(True))
            b_no.bind(on_release=lambda *_: done(False))
            pop.open()
        Clock.schedule_once(ui, 0)
        ev.wait(900)
        return res["ok"]

    # ---------- account / proxy toggles ----------
    def on_pick_account(self, text):
        if text in self._acc_values:
            i = self._acc_values.index(text)
            if i < len(self.accounts):
                self.account_id = self.accounts[i]["id"]
                self.cfg["account_id"] = self.account_id
                self.save_cfg()
                self.log(f"Account selected: {text}")

    def _paint_autoproxy(self):
        on = bool(self.cfg.get("auto_proxy", True))
        try:
            self.sm.get_screen("build").ids.btn_autoproxy.text = "Smart connection: " + ("ON" if on else "OFF")
        except Exception:
            pass

    def toggle_autoproxy(self):
        self.cfg["auto_proxy"] = not bool(self.cfg.get("auto_proxy", True))
        core.set_auto_proxy(self.cfg["auto_proxy"])
        self.save_cfg()
        self._paint_autoproxy()

    # ---------- databases (D1) ----------
    def _work_account(self):
        return self.account_id or core.selected_account_id(self.accounts, None)

    def open_db_manager(self):
        if not (self.token and self.accounts):
            return self.toast("Verify your token in step 1 first")
        acc = self._work_account()
        content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(10))
        info = Label(text="Loading databases...", color=C_MUTED, font_size="13sp", size_hint_y=None, height=dp(36),
                     halign="left", valign="middle")
        info.bind(width=lambda w, v: setattr(w, "text_size", (v, None)))
        content.add_widget(info)
        sv = ScrollView(bar_width=dp(3))
        box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(10))
        box.bind(minimum_height=box.setter("height"))
        sv.add_widget(box)
        content.add_widget(sv)
        close = RoundButton(text="Close", kind="soft")
        content.add_widget(close)
        popup = self.make_popup("D1 databases", content, (0.94, 0.86))
        close.bind(on_release=lambda *_: popup.dismiss())
        popup.open()

        def load():
            try:
                cf = core.CF(self.token, self.log, self.email)
                dbs = cf.d1_list(acc)
            except Exception as e:
                self.log(f"Could not list databases: {e}")
                Clock.schedule_once(lambda dt: setattr(info, "text", f"Could not list databases: {e}"), 0)
                return
            used = {r.get("d1_id"): (r.get("label") or r.get("project")) for r in core.load_deployments() if r.get("d1_id")}

            def ui(*_):
                box.clear_widgets()
                info.text = f"{len(dbs)} database(s) in this account. The free plan allows only a few (usually 10)."
                if not dbs:
                    box.add_widget(Label(text="No databases.", color=C_MUTED, size_hint_y=None, height=dp(40)))
                for db in dbs:
                    uid = db.get("uuid", "")
                    tag = f"\nused by: {used[uid]}" if uid in used else "\nnot used by any saved config"
                    size = db.get("file_size")
                    sz = f"  |  {int(size) // 1024} KB" if isinstance(size, (int, float)) else ""
                    row = Card()
                    lab = Label(text=f"{db.get('name', '?')}\n{uid[:8]}...  {str(db.get('created_at', ''))[:10]}{sz}{tag}",
                                color=C_TEXT, font_size="12sp", halign="left", valign="middle", size_hint_y=None)
                    lab.bind(width=lambda w, v: setattr(w, "text_size", (v, None)))
                    lab.bind(texture_size=lambda w, ts: setattr(w, "height", ts[1] + dp(4)))
                    row.add_widget(lab)
                    bt = RoundButton(text="Delete", kind="danger", height=dp(40))
                    bt.bind(on_release=lambda _b, d=db: self._confirm_db_delete(cf, acc, d, used, popup))
                    row.add_widget(bt)
                    box.add_widget(row)
            Clock.schedule_once(ui, 0)
        threading.Thread(target=load, daemon=True).start()

    def _confirm_db_delete(self, cf, acc, db, used, parent_popup):
        uid = db.get("uuid", "")
        warn = ("\nWARNING: a saved panel uses it - that panel will stop working." if uid in used else "")
        content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(12))
        content.add_widget(Label(text=f"Delete database \"{db.get('name')}\" permanently?{warn}", color=C_TEXT,
                                 font_size="13sp", halign="center"))
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        yes = RoundButton(text="Delete", kind="danger")
        no = RoundButton(text="Cancel", kind="soft")
        row.add_widget(yes)
        row.add_widget(no)
        content.add_widget(row)
        pop = self.make_popup("Confirm", content, (0.88, 0.4))
        no.bind(on_release=lambda *_: pop.dismiss())

        def go(*_):
            pop.dismiss()

            def work():
                try:
                    cf.d1_delete(acc, uid)
                    core.forget_d1(uid)
                    self.toast("Database deleted")
                except Exception as e:
                    self.log(f"Delete failed: {e}")
                Clock.schedule_once(lambda dt: (parent_popup.dismiss(), self.open_db_manager()), 0)
            threading.Thread(target=work, daemon=True).start()
        yes.bind(on_release=go)
        pop.open()

    # ---------- saved configs: extra actions ----------
    def open_panel_of(self, index):
        items = core.load_deployments()
        index = int(index)
        if 0 <= index < len(items):
            r = items[index]
            self.open_url(f"{r['base']}{r.get('panel_path', '/panel')}")

    def copy_sub_of(self, index):
        items = core.load_deployments()
        index = int(index)
        if 0 <= index < len(items) and items[index].get("sub"):
            from kivy.core.clipboard import Clipboard
            Clipboard.copy(items[index]["sub"])
            self.toast("Subscription link copied")

    def update_ips_prompt(self, index):
        items = core.load_deployments()
        index = int(index)
        if not (0 <= index < len(items)):
            return
        rec = items[index]
        content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(10))
        content.add_widget(Label(text="Each IP is tested against this panel's worker from this network; only working ones are written. "
                                      "If none works, the panel stays unchanged.\nBe on the network you want to use now.", color=C_TEXT, font_size="12sp",
                                 halign="center", valign="middle"))
        b_new = RoundButton(text=f"Use the new Radar IPs ({len(self.ips)})")
        b_old = RoundButton(text=f"Re-test the saved IPs ({len(rec.get('ips', []))})", kind="soft")
        b_no = RoundButton(text="Cancel", kind="ghost")
        for b in (b_new, b_old, b_no):
            content.add_widget(b)
        pop = self.make_popup("Update clean IPs", content, (0.9, 0.55))
        b_no.bind(on_release=lambda *_: pop.dismiss())

        def run(pool):
            pop.dismiss()
            if not pool:
                return self.toast("No IPs - run the Radar first")
            self.toast("Updating IPs - watch the log bar")

            def work():
                try:
                    new = core.update_deployment_ips(dict(rec), pool, self.scan_form(), self.log,
                                                     stage=lambda t, f: self.log(t))
                    core.replace_deployment(index, new)
                    self.log(f"Done: {len(new['ips'])} working IPs now in the panel.")
                    self.toast(f"{len(new['ips'])} IPs updated")
                except Exception as e:
                    self.log(f"Update failed: {e}")
                    self.toast("Update failed - see the log")
                Clock.schedule_once(lambda dt: self.refresh_manage_list(), 0)
            threading.Thread(target=work, daemon=True).start()
        b_new.bind(on_release=lambda *_: run(list(self.ips)))
        b_old.bind(on_release=lambda *_: run(list(rec.get("ips", []))))
        pop.open()

    def refresh_manage_list(self):
        m = self.sm.get_screen("manage")
        box = m.ids.manage_list
        box.clear_widgets()
        self.deployments = core.load_deployments()
        if not self.deployments:
            box.add_widget(Card_empty())
            return
        total = len(self.deployments)
        for i, rec in enumerate(reversed(self.deployments)):
            real_index = total - 1 - i
            title = rec.get("label") or rec.get("project", "(unnamed)")
            sub = f"{rec.get('base', '')}\ncreated {rec.get('created', '')}   |   {len(rec.get('ips', []))} clean IPs"
            box.add_widget(DeployRow(title=title, subtitle=sub, index=real_index))

    def load_deployment(self, index):
        items = core.load_deployments()
        index = int(index)
        if not (0 <= index < len(items)):
            return
        rec = items[index]
        self.rec = rec
        self.log(f"Loading configs of {rec['project']} ...")

        def work():
            try:
                out = core.fetch_configs(rec["sub"], self.log) if rec.get("sub") else None
            except Exception as e:
                self.log(f"Could not load: {e}")
                out = None
            self.out = out

            def ui(*_):
                self.render_output()
                self.goto("output")
            Clock.schedule_once(ui, 0)
        threading.Thread(target=work, daemon=True).start()

    def rename_deployment_prompt(self, index):
        items = core.load_deployments()
        index = int(index)
        if not (0 <= index < len(items)):
            return
        content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(12))
        ti = RoundInput(text=items[index].get("label") or items[index].get("project", ""))
        content.add_widget(ti)
        btn = RoundButton(text="Save")
        content.add_widget(btn)
        popup = self.make_popup("Rename this config", content, (0.88, 0.34))

        def do_save(*_):
            core.rename_deployment(items, index, ti.text.strip() or items[index].get("project", ""))
            popup.dismiss()
            self.refresh_manage_list()
        btn.bind(on_release=do_save)
        popup.open()

    def delete_deployment_prompt(self, index):
        items = core.load_deployments()
        index = int(index)
        if not (0 <= index < len(items)):
            return
        content = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(12))
        name = items[index].get("label") or items[index].get("project", "")
        content.add_widget(Label(text=f"Remove \"{name}\" from this list?\n(The first button keeps the Cloudflare project; the last one also deletes it from Cloudflare.)",
                                 color=C_TEXT, font_size="13sp", halign="center"))
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        b_yes = RoundButton(text="Delete", kind="danger")
        b_no = RoundButton(text="Cancel", kind="soft")
        row.add_widget(b_yes)
        row.add_widget(b_no)
        content.add_widget(row)
        b_all = RoundButton(text="Delete + remove from Cloudflare (project, D1, KV)", kind="danger")
        content.add_widget(b_all)
        popup = self.make_popup("Confirm delete", content, (0.9, 0.5))

        def do_delete(*_):
            core.delete_deployment(items, index, log=self.log, also_remove_remote=False)
            popup.dismiss()
            self.refresh_manage_list()

        def do_delete_all(*_):
            popup.dismiss()
            if not self.token:
                return self.toast("Verify your token first")

            def work():
                core.delete_deployment(items, index, token=self.token, email=self.email, log=self.log, also_remove_remote=True)
                Clock.schedule_once(lambda dt: self.refresh_manage_list(), 0)
            threading.Thread(target=work, daemon=True).start()
        b_all.bind(on_release=do_delete_all)
        b_yes.bind(on_release=do_delete)
        b_no.bind(on_release=lambda *_: popup.dismiss())
        popup.open()


def Card_empty():
    c = Card()
    lab = Label(text="No configs built yet.", color=C_MUTED, size_hint_y=None, height=dp(40))
    c.add_widget(lab)
    return c


if __name__ == "__main__":
    AminiumApp().run()
