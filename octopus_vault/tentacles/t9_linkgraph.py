import math
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QMessageBox, QToolTip
)
from PyQt6.QtCore import Qt, QPointF, QRectF, pyqtSignal
from PyQt6.QtGui import QPainter, QPen, QBrush, QColor, QFont, QPainterPath
from core.database import get_connection


class GraphCanvas(QWidget):
    node_clicked = pyqtSignal(str, int)  # name, subject_id

    def __init__(self):
        super().__init__()
        self.nodes = []   # {id, label, x, y, color, type}
        self.edges = []   # {from_id, to_id, label}
        self.setMinimumHeight(400)
        self.setMouseTracking(True)
        self._drag_node = None
        self._drag_offset = QPointF()
        self._hovered = None

    def set_graph(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges
        self._layout()
        self.update()

    def _layout(self):
        if not self.nodes:
            return
        # Simple circular layout for subjects, radial for attributes
        subjects = [n for n in self.nodes if n["type"] == "subject"]
        attrs = [n for n in self.nodes if n["type"] != "subject"]

        cx, cy = self.width() / 2 or 400, self.height() / 2 or 250
        r = min(cx, cy) * 0.55

        for i, n in enumerate(subjects):
            angle = (2 * math.pi * i) / max(len(subjects), 1) - math.pi / 2
            n["x"] = cx + r * math.cos(angle)
            n["y"] = cy + r * math.sin(angle)

        # Place attribute nodes near their connected subject
        for n in attrs:
            connected = [e for e in self.edges if e["to_id"] == n["id"] or e["from_id"] == n["id"]]
            if connected:
                other_id = connected[0]["from_id"] if connected[0]["to_id"] == n["id"] else connected[0]["to_id"]
                parent = next((s for s in subjects if s["id"] == other_id), None)
                if parent:
                    angle = math.atan2(parent["y"] - cy, parent["x"] - cx)
                    offset = 80
                    n["x"] = parent["x"] + offset * math.cos(angle + 0.5)
                    n["y"] = parent["y"] + offset * math.sin(angle + 0.5)
                    continue
            n["x"] = cx
            n["y"] = cy

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#0A0A0A"))

        if not self.nodes:
            painter.setPen(QColor("#003300"))
            painter.setFont(QFont("Courier New", 12))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "// NO SUBJECTS IN THIS CASE\n// ADD SUBJECTS TO SEE LINK GRAPH")
            return

        # Draw grid
        painter.setPen(QPen(QColor("#0D0D0D"), 1))
        for x in range(0, self.width(), 40):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 40):
            painter.drawLine(0, y, self.width(), y)

        # Draw edges
        for edge in self.edges:
            src = next((n for n in self.nodes if n["id"] == edge["from_id"]), None)
            dst = next((n for n in self.nodes if n["id"] == edge["to_id"]), None)
            if not src or not dst:
                continue
            pen = QPen(QColor("#003300"), 1, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawLine(int(src["x"]), int(src["y"]), int(dst["x"]), int(dst["y"]))

            # Edge label at midpoint
            mx = (src["x"] + dst["x"]) / 2
            my = (src["y"] + dst["y"]) / 2
            painter.setPen(QColor("#005500"))
            painter.setFont(QFont("Courier New", 8))
            painter.drawText(int(mx) - 20, int(my) - 4, edge.get("label", ""))

        # Draw nodes
        for node in self.nodes:
            x, y = int(node["x"]), int(node["y"])
            is_hovered = self._hovered and self._hovered["id"] == node["id"]

            if node["type"] == "subject":
                r = 22
                color = QColor("#00FF41") if is_hovered else QColor("#002200")
                border = QColor("#00FF41")
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(border, 2))
                painter.drawEllipse(x - r, y - r, r * 2, r * 2)
                painter.setPen(QColor("#00FF41"))
                painter.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
            else:
                r = 14
                type_colors = {
                    "email":    ("#001a33", "#0088FF"),
                    "username": ("#1a0033", "#AA00FF"),
                    "phone":    ("#1a1a00", "#FFFF00"),
                    "shared":   ("#330000", "#FF3333"),
                }
                bg, fg = type_colors.get(node["type"], ("#001a00", "#00AA44"))
                painter.setBrush(QBrush(QColor(bg)))
                painter.setPen(QPen(QColor(fg), 1))
                painter.drawRoundedRect(x - r, y - r, r * 2, r * 2, 4, 4)
                painter.setPen(QColor(fg))
                painter.setFont(QFont("Courier New", 7))

            # Label
            label = node["label"]
            if len(label) > 14:
                label = label[:12] + ".."
            fm = painter.fontMetrics()
            tw = fm.horizontalAdvance(label)
            painter.drawText(x - tw // 2, y + r + 14, label)

        painter.end()

    def mouseMoveEvent(self, event):
        pos = event.position()
        self._hovered = None
        for node in self.nodes:
            dx = pos.x() - node["x"]
            dy = pos.y() - node["y"]
            r = 22 if node["type"] == "subject" else 14
            if dx * dx + dy * dy <= r * r:
                self._hovered = node
                self.setCursor(Qt.CursorShape.PointingHandCursor)
                break
        else:
            self.setCursor(Qt.CursorShape.ArrowCursor)

        if self._drag_node:
            self._drag_node["x"] = pos.x() - self._drag_offset.x()
            self._drag_node["y"] = pos.y() - self._drag_offset.y()

        self.update()

    def mousePressEvent(self, event):
        pos = event.position()
        for node in self.nodes:
            dx = pos.x() - node["x"]
            dy = pos.y() - node["y"]
            r = 22 if node["type"] == "subject" else 14
            if dx * dx + dy * dy <= r * r:
                self._drag_node = node
                self._drag_offset = QPointF(dx, dy)
                if node["type"] == "subject":
                    self.node_clicked.emit(node["label"], node["id"])
                break

    def mouseReleaseEvent(self, event):
        self._drag_node = None

    def resizeEvent(self, event):
        self._layout()
        self.update()


class LinkGraphWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.title_lbl = QLabel("> SUBJECT LINK GRAPH")
        self.title_lbl.setObjectName("section_title")

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("REFRESH GRAPH")
        refresh_btn.clicked.connect(self._build_graph)
        btn_row.addWidget(refresh_btn)

        legend_row = QHBoxLayout()
        for color, label in [("#00FF41", "SUBJECT"), ("#0088FF", "EMAIL"),
                              ("#AA00FF", "USERNAME"), ("#FFFF00", "PHONE"),
                              ("#FF3333", "SHARED")]:
            dot = QLabel(f"■ {label}")
            dot.setStyleSheet(f"color: {color}; font-family: 'Courier New'; font-size: 10px;")
            legend_row.addWidget(dot)
        legend_row.addStretch()

        self.info_lbl = QLabel("// Double-click a subject node to view details  |  Drag nodes to rearrange")
        self.info_lbl.setStyleSheet("color: #003300; font-family: 'Courier New'; font-size: 10px;")

        self.canvas = GraphCanvas()
        self.canvas.node_clicked.connect(self._on_node_clicked)

        layout.addWidget(self.title_lbl)
        layout.addLayout(btn_row)
        layout.addLayout(legend_row)
        layout.addWidget(self.info_lbl)
        layout.addWidget(self.canvas, stretch=1)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> LINK GRAPH  //  {case_title.upper()}")
        self._build_graph()

    def _build_graph(self):
        if not self.case_id:
            return
        conn = get_connection()
        subjects = conn.execute(
            "SELECT * FROM subjects WHERE case_id=?", (self.case_id,)
        ).fetchall()
        conn.close()

        nodes = []
        edges = []
        node_id_counter = [1000]

        def next_id():
            node_id_counter[0] += 1
            return node_id_counter[0]

        # Add subject nodes
        for s in subjects:
            nodes.append({"id": s["id"], "label": s["name"], "type": "subject", "x": 0, "y": 0})

        # Build attribute maps to detect shared values
        email_map = {}    # email -> [subject_ids]
        username_map = {}
        phone_map = {}

        for s in subjects:
            for email in (s["emails"] or "").split(","):
                e = email.strip()
                if e:
                    email_map.setdefault(e, []).append(s["id"])
            for uname in (s["usernames"] or "").split(","):
                u = uname.strip()
                if u:
                    username_map.setdefault(u, []).append(s["id"])
            for phone in (s["phones"] or "").split(","):
                p = phone.strip()
                if p:
                    phone_map.setdefault(p, []).append(s["id"])

        # Add attribute nodes + edges
        for val, sids in email_map.items():
            if len(sids) > 1:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "shared", "x": 0, "y": 0})
                for sid in sids:
                    edges.append({"from_id": sid, "to_id": nid, "label": "email"})
            else:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "email", "x": 0, "y": 0})
                edges.append({"from_id": sids[0], "to_id": nid, "label": ""})

        for val, sids in username_map.items():
            if len(sids) > 1:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "shared", "x": 0, "y": 0})
                for sid in sids:
                    edges.append({"from_id": sid, "to_id": nid, "label": "username"})
            else:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "username", "x": 0, "y": 0})
                edges.append({"from_id": sids[0], "to_id": nid, "label": ""})

        for val, sids in phone_map.items():
            if len(sids) > 1:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "shared", "x": 0, "y": 0})
                for sid in sids:
                    edges.append({"from_id": sid, "to_id": nid, "label": "phone"})
            else:
                nid = next_id()
                nodes.append({"id": nid, "label": val[:16], "type": "phone", "x": 0, "y": 0})
                edges.append({"from_id": sids[0], "to_id": nid, "label": ""})

        self.canvas.set_graph(nodes, edges)

    def _on_node_clicked(self, name, subject_id):
        conn = get_connection()
        s = conn.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
        conn.close()
        if s:
            info = (
                f"NAME:      {s['name']}\n"
                f"ALIASES:   {s['aliases'] or '-'}\n"
                f"EMAILS:    {s['emails'] or '-'}\n"
                f"PHONES:    {s['phones'] or '-'}\n"
                f"USERNAMES: {s['usernames'] or '-'}\n"
                f"ADDRESSES: {s['addresses'] or '-'}"
            )
            QMessageBox.information(self, f"// SUBJECT: {name}", info)
