import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsRectItem,
    QGraphicsTextItem, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsPathItem, QInputDialog, QColorDialog, QMenu, QApplication,
    QGraphicsProxyWidget, QTextEdit, QSizeGrip, QLineEdit,
    QDialog, QFormLayout, QDialogButtonBox
)
from PyQt6.QtCore import (
    Qt, QPointF, QRectF, QLineF, pyqtSignal, QObject
)
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPainterPath,
    QLinearGradient, QRadialGradient, QCursor, QTransform
)
from core.database import get_connection


# ─────────────────────────────────────────────
#  PIN (anchor point on each node)
# ─────────────────────────────────────────────
class PinItem(QGraphicsEllipseItem):
    PIN_R = 7

    def __init__(self, parent_node, offset: QPointF, color="#FF3333"):
        super().__init__(-self.PIN_R, -self.PIN_R, self.PIN_R * 2, self.PIN_R * 2, parent_node)
        self.parent_node = parent_node
        self.offset = offset
        self.setPos(offset)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(QColor("#FFFFFF"), 1.2))
        self.setZValue(10)
        self.setAcceptHoverEvents(True)
        self.setCursor(QCursor(Qt.CursorShape.CrossCursor))
        self.connections = []  # ThreadItem refs

    def scene_center(self):
        return self.mapToScene(QPointF(0, 0))

    def hoverEnterEvent(self, event):
        self.setBrush(QBrush(QColor("#FF8888")))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setBrush(QBrush(QColor(self._color if hasattr(self, '_color') else "#FF3333")))
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            scene = self.scene()
            if hasattr(scene, 'start_thread'):
                scene.start_thread(self)
        event.accept()


# ─────────────────────────────────────────────
#  THREAD (red string between two pins)
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  BASE NODE
# ─────────────────────────────────────────────
class BaseNode(QGraphicsRectItem):
    def __init__(self, x, y, w, h, db_id=None, case_id=None):
        super().__init__(0, 0, w, h)
        self.db_id = db_id
        self.case_id = case_id
        self.setPos(x, y)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self._pins = []
        self._build_pins()

    def _build_pins(self):
        r = self.rect()
        positions = [
            QPointF(r.width() / 2, 0),           # top
            QPointF(r.width(), r.height() / 2),   # right
            QPointF(r.width() / 2, r.height()),   # bottom
            QPointF(0, r.height() / 2),            # left
        ]
        colors = ["#FF3333", "#3399FF", "#33FF33", "#FF3333"]
        for pos, col in zip(positions, colors):
            pin = PinItem(self, pos, col)
            self._pins.append(pin)

    def pins(self):
        return self._pins

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self._update_threads()
            self._save_position()
        return super().itemChange(change, value)

    def _update_threads(self):
        for pin in self._pins:
            for thread in pin.connections:
                thread.update_path()

    def _save_position(self):
        if self.db_id:
            try:
                conn = get_connection()
                conn.execute(
                    "UPDATE board_nodes SET x=?, y=? WHERE id=?",
                    (self.pos().x(), self.pos().y(), self.db_id)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.setStyleSheet(
            "background:#0D0D0D;color:#00FF41;border:1px solid #003300;"
            "font-family:'Courier New';font-size:12px;"
        )
        edit_act = menu.addAction("✏  Edit")
        del_act  = menu.addAction("🗑  Delete Node")
        act = menu.exec(event.screenPos())
        if act == del_act:
            scene = self.scene()
            if scene and hasattr(scene, 'remove_node'):
                scene.remove_node(self)
        elif act == edit_act:
            self._edit()

    def _edit(self):
        pass  # overridden in subclasses


# ─────────────────────────────────────────────
#  STICKY NOTE NODE
# ─────────────────────────────────────────────
class StickyNoteNode(BaseNode):
    NOTE_COLORS = ["#FFFF88", "#FFB3BA", "#B3E5FC", "#C8E6C9", "#FFE0B2"]

    def __init__(self, x, y, title="Note", content="", color="#FFFF88", db_id=None, case_id=None):
        super().__init__(x, y, 180, 140, db_id, case_id)
        self.title = title
        self.content = content
        self.color = color
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(QColor("#888800"), 1.5))
        self.setZValue(3)
        self._add_text()

    def _add_text(self):
        # Title
        self._title_item = QGraphicsTextItem(self.title, self)
        self._title_item.setDefaultTextColor(QColor("#333300"))
        self._title_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
        self._title_item.setPos(8, 6)
        self._title_item.setTextWidth(164)

        # Content
        self._content_item = QGraphicsTextItem(self.content, self)
        self._content_item.setDefaultTextColor(QColor("#444400"))
        self._content_item.setFont(QFont("Courier New", 8))
        self._content_item.setPos(8, 28)
        self._content_item.setTextWidth(164)

        # Fold corner
        self._fold = QGraphicsPathItem(self)
        path = QPainterPath()
        path.moveTo(160, 120)
        path.lineTo(180, 120)
        path.lineTo(180, 140)
        path.closeSubpath()
        self._fold.setPath(path)
        self._fold.setBrush(QBrush(QColor("#CCCC44")))
        self._fold.setPen(QPen(Qt.PenStyle.NoPen))

    def _edit(self):
        text, ok = QInputDialog.getMultiLineText(
            None, "Edit Note", "Content:", self.content
        )
        if ok:
            self.content = text
            self._content_item.setPlainText(text)
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_nodes SET title=?, content=? WHERE id=?",
                (self.title, self.content, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  PROFILE CARD NODE
# ─────────────────────────────────────────────
class ProfileCardNode(BaseNode):
    def __init__(self, x, y, title="Unknown", content="", color="#1a1a2e", db_id=None, case_id=None):
        super().__init__(x, y, 160, 180, db_id, case_id)
        self.title = title
        self.content = content
        self.color = color
        self.setBrush(QBrush(QColor("#1a1a2e")))
        self.setPen(QPen(QColor("#4444AA"), 2))
        self.setZValue(3)
        self._add_content()

    def _add_content(self):
        # Avatar silhouette area
        avatar_bg = QGraphicsRectItem(20, 10, 120, 90, self)
        avatar_bg.setBrush(QBrush(QColor("#0D0D2E")))
        avatar_bg.setPen(QPen(QColor("#333366"), 1))

        # Head circle
        head = QGraphicsEllipseItem(55, 18, 50, 50, self)
        head.setBrush(QBrush(QColor("#2a2a4e")))
        head.setPen(QPen(QColor("#4444AA"), 1))

        # Body arc
        body = QGraphicsEllipseItem(30, 62, 100, 60, self)
        body.setBrush(QBrush(QColor("#2a2a4e")))
        body.setPen(QPen(QColor("#4444AA"), 1))

        # Name label
        name_item = QGraphicsTextItem(self.title, self)
        name_item.setDefaultTextColor(QColor("#8888FF"))
        name_item.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        name_item.setPos(8, 104)
        name_item.setTextWidth(144)

        # Info
        info_item = QGraphicsTextItem(self.content[:60], self)
        info_item.setDefaultTextColor(QColor("#555588"))
        info_item.setFont(QFont("Courier New", 7))
        info_item.setPos(8, 130)
        info_item.setTextWidth(144)

        self._name_item = name_item
        self._info_item = info_item

        # Status badge
        self._status = QGraphicsRectItem(4, 4, 14, 14, self)
        self._status.setBrush(QBrush(QColor("#FF3333")))
        self._status.setPen(QPen(Qt.PenStyle.NoPen))

    def _edit(self):
        name, ok = QInputDialog.getText(None, "Edit Profile", "Name:", text=self.title)
        if ok and name:
            self.title = name
            self._name_item.setPlainText(name)
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_nodes SET title=?, content=? WHERE id=?",
                (self.title, self.content, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  DOCUMENT NODE
# ─────────────────────────────────────────────
class DocumentNode(BaseNode):
    def __init__(self, x, y, title="Document", content="", color="#F5F5DC", db_id=None, case_id=None):
        super().__init__(x, y, 160, 200, db_id, case_id)
        self.title = title
        self.content = content
        self.color = color
        self.setBrush(QBrush(QColor("#F5F5DC")))
        self.setPen(QPen(QColor("#888866"), 1.5))
        self.setZValue(3)
        self._add_content()

    def _add_content(self):
        # Folded corner
        fold = QGraphicsPathItem(self)
        path = QPainterPath()
        path.moveTo(130, 0)
        path.lineTo(160, 30)
        path.lineTo(160, 0)
        path.closeSubpath()
        fold.setPath(path)
        fold.setBrush(QBrush(QColor("#CCCCAA")))
        fold.setPen(QPen(Qt.PenStyle.NoPen))

        fold2 = QGraphicsPathItem(self)
        path2 = QPainterPath()
        path2.moveTo(130, 0)
        path2.lineTo(160, 30)
        path2.lineTo(130, 30)
        path2.closeSubpath()
        fold2.setPath(path2)
        fold2.setBrush(QBrush(QColor("#DDDDBB")))
        fold2.setPen(QPen(QColor("#AAAAAA"), 0.5))

        # Title
        t = QGraphicsTextItem(self.title, self)
        t.setDefaultTextColor(QColor("#333300"))
        t.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        t.setPos(8, 8)
        t.setTextWidth(118)
        self._title_item = t

        # Lines (ruled paper effect)
        for i in range(6):
            line = QGraphicsLineItem(10, 50 + i * 22, 150, 50 + i * 22, self)
            line.setPen(QPen(QColor("#CCCCAA"), 0.5))

        # Content text
        c = QGraphicsTextItem(self.content[:120], self)
        c.setDefaultTextColor(QColor("#444433"))
        c.setFont(QFont("Courier New", 7))
        c.setPos(10, 44)
        c.setTextWidth(140)
        self._content_item = c

        # CONFIDENTIAL stamp
        stamp = QGraphicsTextItem("CONFIDENTIAL", self)
        stamp.setDefaultTextColor(QColor("#CC000044"))
        stamp.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
        stamp.setPos(18, 160)
        stamp.setRotation(-20)
        stamp.setOpacity(0.3)

    def _edit(self):
        text, ok = QInputDialog.getMultiLineText(
            None, "Edit Document", "Content:", self.content
        )
        if ok:
            self.content = text
            self._content_item.setPlainText(text[:120])
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_nodes SET title=?, content=? WHERE id=?",
                (self.title, self.content, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  MAP NODE
# ─────────────────────────────────────────────
class MapNode(BaseNode):
    def __init__(self, x, y, title="Location", content="", color="#2d4a2d", db_id=None, case_id=None):
        super().__init__(x, y, 220, 180, db_id, case_id)
        self.title = title
        self.content = content
        self.color = color
        self.setBrush(QBrush(QColor("#1a2e1a")))
        self.setPen(QPen(QColor("#336633"), 2))
        self.setZValue(3)
        self._add_content()

    def _add_content(self):
        # Grid lines (map style)
        for i in range(0, 220, 22):
            v = QGraphicsLineItem(i, 0, i, 180, self)
            v.setPen(QPen(QColor("#1e3a1e"), 0.5))
        for i in range(0, 180, 18):
            h = QGraphicsLineItem(0, i, 220, i, self)
            h.setPen(QPen(QColor("#1e3a1e"), 0.5))

        # Tape corners
        for tx, ty, tw, th in [(0,0,40,8),(180,0,40,8),(0,172,40,8),(180,172,40,8)]:
            tape = QGraphicsRectItem(tx, ty, tw, th, self)
            tape.setBrush(QBrush(QColor("#FFFF8844")))
            tape.setPen(QPen(Qt.PenStyle.NoPen))
            tape.setOpacity(0.6)

        # Scene marker
        marker = QGraphicsEllipseItem(100, 75, 20, 20, self)
        marker.setBrush(QBrush(QColor("#FF3333")))
        marker.setPen(QPen(QColor("#FF0000"), 2))

        cross_h = QGraphicsLineItem(95, 85, 125, 85, self)
        cross_h.setPen(QPen(QColor("#FF0000"), 2))
        cross_v = QGraphicsLineItem(110, 70, 110, 100, self)
        cross_v.setPen(QPen(QColor("#FF0000"), 2))

        # Title
        t = QGraphicsTextItem(self.title, self)
        t.setDefaultTextColor(QColor("#66FF66"))
        t.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        t.setPos(8, 8)
        t.setTextWidth(200)
        self._title_item = t

        # Note
        n = QGraphicsTextItem(self.content, self)
        n.setDefaultTextColor(QColor("#FFFF66"))
        n.setFont(QFont("Courier New", 7))
        n.setPos(8, 150)
        n.setTextWidth(200)
        self._content_item = n

    def _edit(self):
        text, ok = QInputDialog.getText(None, "Edit Location", "Location name:", text=self.title)
        if ok and text:
            self.title = text
            self._title_item.setPlainText(text)
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_nodes SET title=?, content=? WHERE id=?",
                (self.title, self.content, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  TEXT LABEL NODE
# ─────────────────────────────────────────────
class LabelNode(BaseNode):
    TAPE_COLORS = ["#FFFF88AA", "#FF8888AA", "#88AAFFAA"]

    def __init__(self, x, y, title="LABEL", content="", color="#FFFF88", db_id=None, case_id=None):
        super().__init__(x, y, 160, 40, db_id, case_id)
        self.title = title
        self.content = content
        self.color = color
        self.setBrush(QBrush(QColor(color if color else "#FFFF88")))
        self.setPen(QPen(Qt.PenStyle.NoPen))
        self.setOpacity(0.85)
        self.setZValue(4)
        self._add_content()

    def _add_content(self):
        t = QGraphicsTextItem(self.title, self)
        t.setDefaultTextColor(QColor("#333300"))
        t.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        t.setPos(8, 6)
        t.setTextWidth(144)
        self._title_item = t

    def _edit(self):
        text, ok = QInputDialog.getText(None, "Edit Label", "Text:", text=self.title)
        if ok and text:
            self.title = text
            self._title_item.setPlainText(text)
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_nodes SET title=?, content=? WHERE id=?",
                (self.title, self.content, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  ANNOTATION ITEM (freehand drawing)
# ─────────────────────────────────────────────

class AnnotationItem(QGraphicsPathItem):
    def __init__(self, color="#FF0000", width=2):
        super().__init__()
        pen = QPen(QColor(color), width, Qt.PenStyle.SolidLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        self.setZValue(50)
        self._path = QPainterPath()

    def start(self, pt):
        self._path.moveTo(pt)
        self.setPath(self._path)

    def add_point(self, pt):
        self._path.lineTo(pt)
        self.setPath(self._path)


# ─────────────────────────────────────────────
#  IMAGE / PHOTO NODE
# ─────────────────────────────────────────────
class ImageNode(BaseNode):
    def __init__(self, x, y, title="Photo", content="", color="#111111", db_id=None, case_id=None):
        super().__init__(x, y, 200, 180, db_id, case_id)
        self.title        = title
        self.content      = content
        self.color        = color
        self._pixmap_item = None
        self.setBrush(QBrush(QColor("#111111")))
        self.setPen(QPen(QColor("#444444"), 2))
        self.setZValue(3)
        self._add_content()

    def _add_content(self):
        for tx, ty, tw, th in [(0,0,50,10),(150,0,50,10),(0,170,50,10),(150,170,50,10)]:
            tape = QGraphicsRectItem(tx, ty, tw, th, self)
            tape.setBrush(QBrush(QColor("#FFFF8866")))
            tape.setPen(QPen(Qt.PenStyle.NoPen))
            tape.setOpacity(0.7)
        self._img_rect = QGraphicsRectItem(10, 14, 180, 130, self)
        self._img_rect.setBrush(QBrush(QColor("#1a1a1a")))
        self._img_rect.setPen(QPen(QColor("#333333"), 1))
        self._load_pixmap()
        self._title_item = QGraphicsTextItem(self.title, self)
        self._title_item.setDefaultTextColor(QColor("#CCCCCC"))
        self._title_item.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        self._title_item.setPos(10, 150)
        self._title_item.setTextWidth(180)

    def _load_pixmap(self):
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtWidgets import QGraphicsPixmapItem
        import os
        if self._pixmap_item and self.scene():
            self.scene().removeItem(self._pixmap_item)
            self._pixmap_item = None
        if self.content and os.path.exists(self.content):
            pix = QPixmap(self.content).scaled(
                180, 130,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self._pixmap_item = QGraphicsPixmapItem(pix, self)
            self._pixmap_item.setPos(10, 14)
        else:
            ph = QGraphicsTextItem("📷\nNo Image\nDouble-click to load", self)
            ph.setDefaultTextColor(QColor("#444444"))
            ph.setFont(QFont("Courier New", 8))
            ph.setPos(50, 35)

    def mouseDoubleClickEvent(self, event):
        self._edit()

    def _edit(self):
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            None, "Select Image", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
        )
        if path:
            self.content = path
            self._load_pixmap()
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute("UPDATE board_nodes SET title=?, content=? WHERE id=?",
                         (self.title, self.content, self.db_id))
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  TIMELINE NODE
# ─────────────────────────────────────────────
class TimelineNode(BaseNode):
    """A dated event card. Right-click → Sort Timeline arranges all
    TimelineNodes on the board in chronological order."""

    def __init__(self, x, y, title="Event", content="", date_str="",
                 color="#0D1A2E", db_id=None, case_id=None):
        super().__init__(x, y, 200, 90, db_id, case_id)
        self.title    = title
        self.content  = content
        self.date_str = date_str          # stored in color field for simplicity
        self.color    = color
        self.setBrush(QBrush(QColor("#0D1A2E")))
        self.setPen(QPen(QColor("#0055AA"), 2))
        self.setZValue(3)
        self._add_content()

    def _add_content(self):
        # left accent bar
        bar = QGraphicsRectItem(0, 0, 6, 90, self)
        bar.setBrush(QBrush(QColor("#0088FF")))
        bar.setPen(QPen(Qt.PenStyle.NoPen))

        # date badge
        self._date_item = QGraphicsTextItem(self.date_str or "DATE?", self)
        self._date_item.setDefaultTextColor(QColor("#0088FF"))
        self._date_item.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        self._date_item.setPos(12, 6)
        self._date_item.setTextWidth(180)

        # title
        self._title_item = QGraphicsTextItem(self.title, self)
        self._title_item.setDefaultTextColor(QColor("#CCDDFF"))
        self._title_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
        self._title_item.setPos(12, 24)
        self._title_item.setTextWidth(180)

        # content
        self._content_item = QGraphicsTextItem(self.content[:80], self)
        self._content_item.setDefaultTextColor(QColor("#6688AA"))
        self._content_item.setFont(QFont("Courier New", 7))
        self._content_item.setPos(12, 52)
        self._content_item.setTextWidth(180)

    def _edit(self):
        dlg = QDialog()
        dlg.setWindowTitle("Edit Timeline Event")
        dlg.setStyleSheet("background:#0D0D0D;color:#00FF41;"
                          "font-family:'Courier New';font-size:12px;")
        form = QFormLayout(dlg)
        date_in  = QLineEdit(self.date_str)
        title_in = QLineEdit(self.title)
        desc_in  = QTextEdit(self.content)
        desc_in.setMaximumHeight(80)
        lbl_style = "color:#0088FF;"
        for lbl, w in [("DATE (YYYY-MM-DD):", date_in),
                       ("TITLE:", title_in),
                       ("DESCRIPTION:", desc_in)]:
            l = QLabel(lbl)
            l.setStyleSheet(lbl_style)
            form.addRow(l, w)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        form.addRow(btns)
        if dlg.exec():
            self.date_str = date_in.text().strip()
            self.title    = title_in.text().strip() or self.title
            self.content  = desc_in.toPlainText().strip()
            self._date_item.setPlainText(self.date_str or "DATE?")
            self._title_item.setPlainText(self.title)
            self._content_item.setPlainText(self.content[:80])
            self._db_save()

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            # store date_str in the color column (reuse) — or use content
            conn.execute(
                "UPDATE board_nodes SET title=?, content=?, color=? WHERE id=?",
                (self.title, self.content, self.date_str, self.db_id)
            )
            conn.commit()
            conn.close()

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.setStyleSheet(
            "background:#0D0D0D;color:#00FF41;border:1px solid #003300;"
            "font-family:'Courier New';font-size:12px;"
        )
        edit_act = menu.addAction("✏  Edit Event")
        sort_act = menu.addAction("🗓  Sort All Timeline Nodes")
        del_act  = menu.addAction("🗑  Delete Node")
        act = menu.exec(event.screenPos())
        if act == edit_act:
            self._edit()
        elif act == sort_act:
            scene = self.scene()
            if scene and hasattr(scene, "sort_timeline_nodes"):
                scene.sort_timeline_nodes()
        elif act == del_act:
            scene = self.scene()
            if scene and hasattr(scene, "remove_node"):
                scene.remove_node(self)


# ─────────────────────────────────────────────
#  GROUP NODE  (visual cluster / container)
# ─────────────────────────────────────────────
class GroupNode(QGraphicsRectItem):
    """A resizable, labeled container that moves its child nodes with it.
    It sits behind all other nodes (zValue=0). Nodes dragged inside it
    become its children; dragging the group moves them all."""

    GROUP_COLORS = [
        ("#FF330033", "#FF3300"),   # red
        ("#FFAA0033", "#FFAA00"),   # amber
        ("#0055FF33", "#0055FF"),   # blue
        ("#00AA4433", "#00AA44"),   # green
        ("#AA00FF33", "#AA00FF"),   # purple
    ]

    def __init__(self, x, y, w=320, h=220, title="GROUP",
                 color="#FFAA0033", border="#FFAA00",
                 db_id=None, case_id=None):
        super().__init__(0, 0, w, h)
        self.db_id    = db_id
        self.case_id  = case_id
        self.title    = title
        self.color    = color
        self.border   = border
        self._last_pos = QPointF(x, y)  # initialize before setPos
        self.setPos(x, y)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(QColor(border), 2, Qt.PenStyle.DashLine))
        self.setZValue(0)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self._child_nodes = []   # BaseNode refs inside this group

        # title label
        self._title_item = QGraphicsTextItem(title, self)
        self._title_item.setDefaultTextColor(QColor(border))
        self._title_item.setFont(QFont("Courier New", 10, QFont.Weight.Bold))
        self._title_item.setPos(10, 6)

        # resize handle (bottom-right corner)
        self._resize_handle = QGraphicsRectItem(w - 12, h - 12, 12, 12, self)
        self._resize_handle.setBrush(QBrush(QColor(border)))
        self._resize_handle.setPen(QPen(Qt.PenStyle.NoPen))
        self._resize_handle.setOpacity(0.6)
        self._resize_handle.setCursor(QCursor(Qt.CursorShape.SizeFDiagCursor))
        self._resizing = False

    # ── child management ──────────────────────
    def add_child(self, node: "BaseNode"):
        if node not in self._child_nodes:
            self._child_nodes.append(node)

    def remove_child(self, node: "BaseNode"):
        if node in self._child_nodes:
            self._child_nodes.remove(node)

    # ── move children with group ───────────────
    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            delta = value - self._last_pos
            for node in self._child_nodes:
                node.setPos(node.pos() + delta)
                node._update_threads()
            self._last_pos = value
            self._save_position()
        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            r = self.rect()
            lp = event.pos()
            if (r.width() - 16 <= lp.x() <= r.width() and
                    r.height() - 16 <= lp.y() <= r.height()):
                self._resizing = True
                self._resize_start = event.scenePos()
                self._resize_orig  = QPointF(r.width(), r.height())
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._resizing:
            delta = event.scenePos() - self._resize_start
            nw = max(120, self._resize_orig.x() + delta.x())
            nh = max(80,  self._resize_orig.y() + delta.y())
            self.setRect(0, 0, nw, nh)
            self._resize_handle.setRect(nw - 12, nh - 12, 12, 12)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._resizing:
            self._resizing = False
            self._save_position()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def _save_position(self):
        if self.db_id:
            try:
                conn = get_connection()
                conn.execute(
                    "UPDATE board_groups SET x=?, y=?, width=?, height=? WHERE id=?",
                    (self.pos().x(), self.pos().y(),
                     self.rect().width(), self.rect().height(), self.db_id)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.setStyleSheet(
            "background:#0D0D0D;color:#00FF41;border:1px solid #003300;"
            "font-family:'Courier New';font-size:12px;"
        )
        rename_act  = menu.addAction("✏  Rename Group")
        color_act   = menu.addAction("🎨  Change Color")
        absorb_act  = menu.addAction("⬇  Absorb Overlapping Nodes")
        release_act = menu.addAction("⬆  Release All Children")
        menu.addSeparator()
        del_act = menu.addAction("🗑  Delete Group")
        act = menu.exec(event.screenPos())
        if act == rename_act:
            text, ok = QInputDialog.getText(
                None, "Rename Group", "Name:", text=self.title
            )
            if ok and text:
                self.title = text
                self._title_item.setPlainText(text)
                self._db_save()
        elif act == color_act:
            self._cycle_color()
        elif act == absorb_act:
            self._absorb_overlapping()
        elif act == release_act:
            self._child_nodes.clear()
        elif act == del_act:
            scene = self.scene()
            if scene:
                scene.remove_group(self)

    def _cycle_color(self):
        colors = self.GROUP_COLORS
        current = [(c, b) for c, b in colors if c == self.color]
        idx = (colors.index(current[0]) if current else 0)
        self.color, self.border = colors[(idx + 1) % len(colors)]
        self.setBrush(QBrush(QColor(self.color)))
        self.setPen(QPen(QColor(self.border), 2, Qt.PenStyle.DashLine))
        self._title_item.setDefaultTextColor(QColor(self.border))
        self._db_save()

    def _absorb_overlapping(self):
        """Add all BaseNodes that visually overlap this group as children."""
        scene = self.scene()
        if not scene:
            return
        my_rect = self.mapToScene(self.rect()).boundingRect()
        for item in scene.items():
            if isinstance(item, BaseNode):
                node_rect = item.mapToScene(item.rect()).boundingRect()
                if my_rect.intersects(node_rect):
                    self.add_child(item)

    def _db_save(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_groups SET title=?, color=? WHERE id=?",
                (self.title, self.color, self.db_id)
            )
            conn.commit()
            conn.close()


# ─────────────────────────────────────────────
#  SUBJECT IMPORT NODE
# ─────────────────────────────────────────────
class SubjectImportNode(ProfileCardNode):
    def __init__(self, x, y, subject_row, db_id=None, case_id=None):
        info = (f"Aliases: {subject_row['aliases'] or '-'}\n"
                f"Email:   {subject_row['emails']  or '-'}\n"
                f"Phone:   {subject_row['phones']  or '-'}")
        super().__init__(x, y, title=subject_row["name"],
                         content=info, db_id=db_id, case_id=case_id)
        self._subject_id = subject_row["id"]
        self._info_item.setPlainText(info[:80])


# ─────────────────────────────────────────────
#  EVIDENCE IMPORT NODE
# ─────────────────────────────────────────────
class EvidenceImportNode(DocumentNode):
    def __init__(self, x, y, evidence_row, db_id=None, case_id=None):
        super().__init__(x, y,
                         title=evidence_row["title"] or evidence_row["type"],
                         content=evidence_row["content"] or evidence_row["source"] or "",
                         db_id=db_id, case_id=case_id)
        self._evidence_id = evidence_row["id"]
        self._content_item.setPlainText((evidence_row["content"] or "")[:120])


# ─────────────────────────────────────────────
#  THREAD ITEM  (labels + color support)
# ─────────────────────────────────────────────
class ThreadItem(QGraphicsPathItem):
    COLORS = {
        "red":    "#CC0000",
        "green":  "#00AA44",
        "yellow": "#AAAA00",
        "grey":   "#666666",
    }
    # strength 1=weak(thin/dashed), 2=normal, 3=strong(thick), 4=confirmed(thick+solid)
    STRENGTH_WIDTH = {1: 1.0, 2: 1.8, 3: 3.2, 4: 5.0}
    STRENGTH_STYLE = {1: Qt.PenStyle.DashLine, 2: Qt.PenStyle.SolidLine,
                      3: Qt.PenStyle.SolidLine, 4: Qt.PenStyle.SolidLine}
    STRENGTH_LABEL = {1: "WEAK", 2: "NORMAL", 3: "STRONG", 4: "CONFIRMED"}

    def __init__(self, pin_a, pin_b, db_id=None, label="", thread_color="red", strength=2):
        super().__init__()
        self.pin_a        = pin_a
        self.pin_b        = pin_b
        self.db_id        = db_id
        self.label        = label
        self.thread_color = thread_color
        self.strength     = strength
        self._col         = self.COLORS.get(thread_color, "#CC0000")
        self._apply_pen()
        self.setZValue(1)
        self.setAcceptHoverEvents(True)
        pin_a.connections.append(self)
        pin_b.connections.append(self)
        self._label_item = QGraphicsTextItem(self)
        self._label_item.setDefaultTextColor(QColor(self._col))
        self._label_item.setFont(QFont("Courier New", 7))
        self._label_item.setPlainText(label)
        self.update_path()

    def _apply_pen(self):
        pen = QPen(QColor(self._col),
                   self.STRENGTH_WIDTH.get(self.strength, 1.8),
                   self.STRENGTH_STYLE.get(self.strength, Qt.PenStyle.SolidLine))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self.setPen(pen)

    def update_path(self):
        if not self.pin_a or not self.pin_b:
            return
        a  = self.pin_a.scene_center()
        b  = self.pin_b.scene_center()
        cx = (a.x() + b.x()) / 2
        cy = (a.y() + b.y()) / 2 + 30
        path = QPainterPath(a)
        path.quadTo(QPointF(cx, cy), b)
        self.setPath(path)
        self._label_item.setPos(cx - 20, cy - 14)

    def hoverEnterEvent(self, event):
        p = self.pen()
        p.setColor(QColor("#FF6666"))
        p.setWidthF(self.STRENGTH_WIDTH.get(self.strength, 1.8) + 1.5)
        self.setPen(p)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._apply_pen()
        super().hoverLeaveEvent(event)

    def _save_to_db(self):
        if self.db_id:
            conn = get_connection()
            conn.execute(
                "UPDATE board_connections SET label=?, strength=? WHERE id=?",
                (f"{self.thread_color}|{self.label}", self.strength, self.db_id)
            )
            conn.commit()
            conn.close()

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.setStyleSheet(
            "background:#1a0000;color:#FF4444;border:1px solid #660000;"
            "font-family:'Courier New';font-size:12px;"
        )
        edit_lbl  = menu.addAction("✏  Edit Label")
        menu.addSeparator()
        col_red   = menu.addAction("🔴  Red")
        col_green = menu.addAction("🟢  Green (Confirmed)")
        col_yel   = menu.addAction("🟡  Yellow (Suspected)")
        col_grey  = menu.addAction("⚫  Grey (Weak)")
        menu.addSeparator()
        str1 = menu.addAction("〰  Strength: WEAK (dashed)")
        str2 = menu.addAction("─   Strength: NORMAL")
        str3 = menu.addAction("━   Strength: STRONG")
        str4 = menu.addAction("█   Strength: CONFIRMED")
        menu.addSeparator()
        del_act   = menu.addAction("✂  Remove Thread")
        act = menu.exec(event.screenPos())
        scene = self.scene()
        if act == del_act and scene:
            scene.remove_thread(self)
        elif act == edit_lbl:
            txt, ok = QInputDialog.getText(
                None, "Thread Label", "Relationship:", text=self.label
            )
            if ok:
                self.label = txt
                self._label_item.setPlainText(txt)
                self._save_to_db()
        elif act in (col_red, col_green, col_yel, col_grey):
            cmap = {col_red: "red", col_green: "green", col_yel: "yellow", col_grey: "grey"}
            self.thread_color = cmap[act]
            self._col = self.COLORS[self.thread_color]
            self._apply_pen()
            self._label_item.setDefaultTextColor(QColor(self._col))
            self._save_to_db()
        elif act in (str1, str2, str3, str4):
            smap = {str1: 1, str2: 2, str3: 3, str4: 4}
            self.strength = smap[act]
            self._apply_pen()
            self._save_to_db()


# ─────────────────────────────────────────────
#  TEMP THREAD
# ─────────────────────────────────────────────
class TempThreadItem(QGraphicsPathItem):
    def __init__(self, start):
        super().__init__()
        self.start_pt = start
        self.end_pt   = start
        self.setPen(QPen(QColor("#FF6666"), 1.5, Qt.PenStyle.DashLine))
        self.setZValue(100)
        self.update_path()

    def update_end(self, pt):
        self.end_pt = pt
        self.update_path()

    def update_path(self):
        cx   = (self.start_pt.x() + self.end_pt.x()) / 2
        cy   = (self.start_pt.y() + self.end_pt.y()) / 2 + 30
        path = QPainterPath(self.start_pt)
        path.quadTo(QPointF(cx, cy), self.end_pt)
        self.setPath(path)


# ─────────────────────────────────────────────
#  BOARD SCENE
# ─────────────────────────────────────────────
class BoardScene(QGraphicsScene):
    def __init__(self, case_id=None):
        super().__init__()
        self.case_id           = case_id
        self._thread_start_pin = None
        self._temp_thread      = None
        self._mode             = "select"
        self._anno_color       = "#FF0000"
        self._anno_width       = 2
        self._current_anno     = None
        self._nodes            = []
        self._threads          = []
        self._annotations      = []
        self._groups           = []
        self.setSceneRect(-2000, -2000, 6000, 6000)

    def set_mode(self, mode):
        self._mode = mode

    def set_anno_color(self, color):
        self._anno_color = color

    def start_thread(self, pin):
        self._thread_start_pin = pin
        self._temp_thread      = TempThreadItem(pin.scene_center())
        self.addItem(self._temp_thread)

    def mouseMoveEvent(self, event):
        if self._temp_thread:
            self._temp_thread.update_end(event.scenePos())
        if self._mode == "annotate" and self._current_anno:
            self._current_anno.add_point(event.scenePos())
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if self._mode == "annotate" and event.button() == Qt.MouseButton.LeftButton:
            anno = AnnotationItem(self._anno_color, self._anno_width)
            anno.start(event.scenePos())
            self.addItem(anno)
            self._current_anno = anno
            self._annotations.append(anno)
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self._mode == "annotate":
            self._current_anno = None
            return
        if self._temp_thread and event.button() == Qt.MouseButton.LeftButton:
            target_pin = None
            for item in self.items(event.scenePos()):
                if isinstance(item, PinItem) and item is not self._thread_start_pin:
                    target_pin = item
                    break
            if target_pin:
                self._create_thread(self._thread_start_pin, target_pin)
            self.removeItem(self._temp_thread)
            self._temp_thread      = None
            self._thread_start_pin = None
        super().mouseReleaseEvent(event)

    def _create_thread(self, pin_a, pin_b, db_id=None, label="", thread_color="red", strength=2):
        if "|" in label:
            parts        = label.split("|", 1)
            thread_color = parts[0] if parts[0] in ThreadItem.COLORS else "red"
            label        = parts[1]
        thread = ThreadItem(pin_a, pin_b, db_id=db_id, label=label,
                            thread_color=thread_color, strength=strength)
        self.addItem(thread)
        self._threads.append(thread)
        if not db_id:
            self._save_thread(thread)
        return thread

    def _save_thread(self, thread):
        if not self.case_id:
            return
        na = thread.pin_a.parent_node
        nb = thread.pin_b.parent_node
        if not na.db_id or not nb.db_id:
            return
        stored = f"{thread.thread_color}|{thread.label}"
        conn   = get_connection()
        cur    = conn.execute(
            "INSERT INTO board_connections (case_id, from_node_id, to_node_id, label, strength) VALUES (?,?,?,?,?)",
            (self.case_id, na.db_id, nb.db_id, stored, thread.strength)
        )
        thread.db_id = cur.lastrowid
        conn.commit()
        conn.close()

    def remove_thread(self, thread):
        if thread.db_id:
            conn = get_connection()
            conn.execute("DELETE FROM board_connections WHERE id=?", (thread.db_id,))
            conn.commit()
            conn.close()
        for pin in (thread.pin_a, thread.pin_b):
            if thread in pin.connections:
                pin.connections.remove(thread)
        if thread in self._threads:
            self._threads.remove(thread)
        self.removeItem(thread)

    def remove_node(self, node):
        for pin in node.pins():
            for t in list(pin.connections):
                self.remove_thread(t)
        if node.db_id:
            conn = get_connection()
            conn.execute("DELETE FROM board_nodes WHERE id=?", (node.db_id,))
            conn.commit()
            conn.close()
        if node in self._nodes:
            self._nodes.remove(node)
        self.removeItem(node)

    def clear_annotations(self):
        for a in self._annotations:
            self.removeItem(a)
        self._annotations.clear()

    def add_node(self, node_type, x=0, y=0, title="", content="", color="", db_id=None):
        node_map = {
            "sticky":    (StickyNoteNode,  color or "#FFFF88"),
            "profile":   (ProfileCardNode, color or "#1a1a2e"),
            "document":  (DocumentNode,    color or "#F5F5DC"),
            "map":       (MapNode,         color or "#1a2e1a"),
            "label":     (LabelNode,       color or "#FFFF88"),
            "image":     (ImageNode,       color or "#111111"),
            "timeline":  (TimelineNode,    color or "#0D1A2E"),
        }
        if node_type not in node_map:
            return None
        cls, col = node_map[node_type]
        if node_type == "timeline":
            node = cls(x, y, title=title or "EVENT", content=content,
                       date_str=col if col != "#0D1A2E" else "",
                       db_id=db_id, case_id=self.case_id)
            # for timeline, color field stores date_str
            node.date_str = color if color and color != "#0D1A2E" else ""
            node._date_item.setPlainText(node.date_str or "DATE?")
        else:
            node = cls(x, y, title=title or node_type.upper(),
                       content=content, color=col,
                       db_id=db_id, case_id=self.case_id)
        self.addItem(node)
        self._nodes.append(node)
        if not db_id:
            self._db_insert_node(node, node_type)
        return node

    def _db_insert_node(self, node, node_type):
        if not self.case_id:
            return
        conn = get_connection()
        cur  = conn.execute(
            "INSERT INTO board_nodes "
            "(case_id, node_type, title, content, x, y, width, height, color) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (self.case_id, node_type, node.title, node.content,
             node.pos().x(), node.pos().y(),
             node.rect().width(), node.rect().height(),
             getattr(node, "color", "#FFFF88"))
        )
        node.db_id = cur.lastrowid
        conn.commit()
        conn.close()

    def import_subjects(self):
        if not self.case_id:
            return
        import random
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM subjects WHERE case_id=?", (self.case_id,)
        ).fetchall()
        conn.close()
        for i, row in enumerate(rows):
            if any(n.title == row["name"] and isinstance(n, ProfileCardNode)
                   for n in self._nodes):
                continue
            x    = (i % 4) * 210 + random.randint(-15, 15)
            y    = (i // 4) * 250 + random.randint(-15, 15)
            node = SubjectImportNode(x, y, row, case_id=self.case_id)
            self.addItem(node)
            self._nodes.append(node)
            self._db_insert_node(node, "profile")

    def import_evidence(self):
        if not self.case_id:
            return
        import random
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM evidence WHERE case_id=?", (self.case_id,)
        ).fetchall()
        conn.close()
        for i, row in enumerate(rows):
            t = row["title"] or row["type"]
            if any(n.title == t and isinstance(n, DocumentNode)
                   for n in self._nodes):
                continue
            x    = 650 + (i % 3) * 210 + random.randint(-15, 15)
            y    = (i // 3) * 250 + random.randint(-15, 15)
            node = EvidenceImportNode(x, y, row, case_id=self.case_id)
            self.addItem(node)
            self._nodes.append(node)
            self._db_insert_node(node, "document")

    def add_group(self, x=0, y=0, title="GROUP", color="#FFAA0033",
                  border="#FFAA00", db_id=None):
        group = GroupNode(x, y, title=title, color=color, border=border,
                          db_id=db_id, case_id=self.case_id)
        self.addItem(group)
        self._groups.append(group)
        if not db_id:
            self._db_insert_group(group)
        return group

    def _db_insert_group(self, group):
        if not self.case_id:
            return
        conn = get_connection()
        cur  = conn.execute(
            "INSERT INTO board_groups (case_id, title, color, x, y, width, height) "
            "VALUES (?,?,?,?,?,?,?)",
            (self.case_id, group.title, group.color,
             group.pos().x(), group.pos().y(),
             group.rect().width(), group.rect().height())
        )
        group.db_id = cur.lastrowid
        conn.commit()
        conn.close()

    def remove_group(self, group):
        if group.db_id:
            conn = get_connection()
            conn.execute("DELETE FROM board_groups WHERE id=?", (group.db_id,))
            conn.commit()
            conn.close()
        if group in self._groups:
            self._groups.remove(group)
        self.removeItem(group)

    def sort_timeline_nodes(self):
        """Arrange all TimelineNodes in a horizontal row sorted by date_str."""
        tl_nodes = [n for n in self._nodes if isinstance(n, TimelineNode)]
        if not tl_nodes:
            return
        tl_nodes.sort(key=lambda n: n.date_str or "9999")
        start_x, start_y = 100, 600
        gap = 220
        for i, node in enumerate(tl_nodes):
            node.setPos(start_x + i * gap, start_y)
            node._update_threads()
            node._save_position()

    def load_board(self):
        if not self.case_id:
            return
        conn     = get_connection()
        rows     = conn.execute(
            "SELECT * FROM board_nodes WHERE case_id=?", (self.case_id,)
        ).fetchall()
        node_map = {}
        for row in rows:
            node = self.add_node(
                row["node_type"], row["x"], row["y"],
                title=row["title"] or "", content=row["content"] or "",
                color=row["color"] or "", db_id=row["id"]
            )
            if node:
                node_map[row["id"]] = node
        conns = conn.execute(
            "SELECT * FROM board_connections WHERE case_id=?", (self.case_id,)
        ).fetchall()
        for c in conns:
            na = node_map.get(c["from_node_id"])
            nb = node_map.get(c["to_node_id"])
            if na and nb:
                strength = c["strength"] if c["strength"] is not None else 2
                self._create_thread(
                    na.pins()[0], nb.pins()[0],
                    db_id=c["id"], label=c["label"] or "",
                    strength=strength
                )
        # load groups
        try:
            groups = conn.execute(
                "SELECT * FROM board_groups WHERE case_id=?", (self.case_id,)
            ).fetchall()
            for g in groups:
                self.add_group(
                    g["x"], g["y"], title=g["title"] or "GROUP",
                    color=g["color"] or "#FFAA0033", db_id=g["id"]
                )
        except Exception:
            pass
        conn.close()


# ─────────────────────────────────────────────
#  BOARD VIEW
# ─────────────────────────────────────────────
class BoardView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setBackgroundBrush(QBrush(QColor("#8B6914")))
        self._panning   = False
        self._pan_start = None
        self._zoom      = 1.0

    def drawBackground(self, painter, rect):
        painter.fillRect(rect, QColor("#8B6914"))
        import random
        rng  = random.Random(42)
        step = 18
        x0   = int(rect.left()  / step) * step
        y0   = int(rect.top()   / step) * step
        painter.setPen(QPen(QColor("#7A5C10"), 1))
        for gx in range(x0, int(rect.right())  + step, step):
            for gy in range(y0, int(rect.bottom()) + step, step):
                ox = rng.randint(-6, 6)
                oy = rng.randint(-6, 6)
                r  = rng.randint(1, 4)
                painter.drawEllipse(gx + ox, gy + oy, r, r)

    def wheelEvent(self, event):
        factor     = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self._zoom = max(0.2, min(self._zoom * factor, 4.0))
        self.scale(factor, factor)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton or (
            event.button() == Qt.MouseButton.LeftButton and
            event.modifiers() & Qt.KeyboardModifier.AltModifier
        ):
            self._panning   = True
            self._pan_start = event.position().toPoint()
            self.setCursor(QCursor(Qt.CursorShape.ClosedHandCursor))
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._panning and self._pan_start:
            delta           = event.position().toPoint() - self._pan_start
            self._pan_start = event.position().toPoint()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - delta.x()
            )
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - delta.y()
            )
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._panning:
            self._panning = False
            self.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
            event.accept()
            return
        super().mouseReleaseEvent(event)


# ─────────────────────────────────────────────
#  MINI-MAP
# ─────────────────────────────────────────────
class MiniMapWidget(QWidget):
    def __init__(self, view, parent=None):
        super().__init__(parent)
        self.view = view
        self.setFixedSize(200, 140)
        self.setStyleSheet(
            "background:#1a1000;border:1px solid #664400;border-radius:4px;"
        )
        from PyQt6.QtCore import QTimer
        t = QTimer(self)
        t.timeout.connect(self.update)
        t.start(400)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#1a1000"))
        scene = self.view.scene()
        if not scene:
            return
        nodes = [i for i in scene.items() if isinstance(i, BaseNode)]
        if not nodes:
            painter.setPen(QColor("#443300"))
            painter.setFont(QFont("Courier New", 8))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No nodes")
            return
        xs  = [n.scenePos().x() for n in nodes]
        ys  = [n.scenePos().y() for n in nodes]
        ws  = [n.rect().width()  for n in nodes]
        hs  = [n.rect().height() for n in nodes]
        sx1 = min(xs) - 40
        sy1 = min(ys) - 40
        sx2 = max(x + w for x, w in zip(xs, ws)) + 40
        sy2 = max(y + h for y, h in zip(ys, hs)) + 40
        sw  = max(sx2 - sx1, 1)
        sh  = max(sy2 - sy1, 1)
        mw  = self.width()  - 8
        mh  = self.height() - 8
        sc  = min(mw / sw, mh / sh)

        def m(sx, sy):
            return 4 + (sx - sx1) * sc, 4 + (sy - sy1) * sc

        # threads
        painter.setPen(QPen(QColor("#880000"), 1))
        for t in scene.items():
            if isinstance(t, ThreadItem):
                ax, ay = m(t.pin_a.scene_center().x(), t.pin_a.scene_center().y())
                bx, by = m(t.pin_b.scene_center().x(), t.pin_b.scene_center().y())
                painter.drawLine(int(ax), int(ay), int(bx), int(by))

        # nodes
        COLOR_MAP = {
            StickyNoteNode:  "#AAAA00",
            ProfileCardNode: "#4444AA",
            DocumentNode:    "#888866",
            MapNode:         "#336633",
            ImageNode:       "#555555",
            LabelNode:       "#AA6600",
        }
        for node in nodes:
            nx, ny = m(node.scenePos().x(), node.scenePos().y())
            nw = max(node.rect().width()  * sc, 4)
            nh = max(node.rect().height() * sc, 4)
            col = QColor(COLOR_MAP.get(type(node), "#888888"))
            painter.fillRect(int(nx), int(ny), int(nw), int(nh), col)

        # viewport rect
        vr       = self.view.mapToScene(self.view.viewport().rect()).boundingRect()
        vx1, vy1 = m(vr.left(),  vr.top())
        vx2, vy2 = m(vr.right(), vr.bottom())
        painter.setPen(QPen(QColor("#00FF41"), 1))
        painter.setBrush(QBrush(QColor("#00FF4122")))
        painter.drawRect(int(vx1), int(vy1), int(vx2 - vx1), int(vy2 - vy1))
        painter.end()

    def mousePressEvent(self, event):
        scene = self.view.scene()
        nodes = [i for i in scene.items() if isinstance(i, BaseNode)]
        if not nodes:
            return
        xs  = [n.scenePos().x() for n in nodes]
        ys  = [n.scenePos().y() for n in nodes]
        ws  = [n.rect().width()  for n in nodes]
        hs  = [n.rect().height() for n in nodes]
        sx1 = min(xs) - 40
        sy1 = min(ys) - 40
        sw  = max(max(x + w for x, w in zip(xs, ws)) + 40 - sx1, 1)
        sh  = max(max(y + h for y, h in zip(ys, hs)) + 40 - sy1, 1)
        sc  = min((self.width() - 8) / sw, (self.height() - 8) / sh)
        sx  = sx1 + (event.position().x() - 4) / sc
        sy  = sy1 + (event.position().y() - 4) / sc
        self.view.centerOn(sx, sy)


# ─────────────────────────────────────────────
#  STATUS BADGE
# ─────────────────────────────────────────────
BADGE_OPTIONS = ["SUSPECT", "WITNESS", "CLEARED", "UNKNOWN", "PERSON OF INTEREST"]
BADGE_COLORS  = {
    "SUSPECT":            "#FF3333",
    "WITNESS":            "#FFAA00",
    "CLEARED":            "#00FF41",
    "UNKNOWN":            "#888888",
    "PERSON OF INTEREST": "#FF8800",
}


def _apply_status_badge(node, status):
    col = BADGE_COLORS.get(status, "#888888")
    for child in node.childItems():
        if getattr(child, "_is_badge", False):
            if node.scene():
                node.scene().removeItem(child)
    badge = QGraphicsTextItem(f"[ {status} ]", node)
    badge.setDefaultTextColor(QColor(col))
    badge.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
    badge.setPos(8, 158)
    badge._is_badge = True
    node._status.setBrush(QBrush(QColor(col)))
    lines        = [l for l in node.content.split("\n") if not l.startswith("STATUS:")]
    node.content = f"STATUS:{status}\n" + "\n".join(lines)
    if node.db_id:
        conn = get_connection()
        conn.execute("UPDATE board_nodes SET content=? WHERE id=?",
                     (node.content, node.db_id))
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────
#  INVESTIGATION BOARD WINDOW
# ─────────────────────────────────────────────
class InvestigationBoardWindow(QWidget):
    def __init__(self, case_id=None, case_title="", parent=None):
        super().__init__(parent)
        self.case_id    = case_id
        self.case_title = case_title
        self.setWindowTitle("// INVESTIGATION BOARD")
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint
        )
        self.setStyleSheet("background:#0A0A0A;color:#00FF41;")
        self._build_ui()
        self.showFullScreen()
        self._scene.load_board()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── toolbar ──────────────────────────
        bar = QWidget()
        bar.setFixedHeight(46)
        bar.setStyleSheet("background:#080808;border-bottom:1px solid #003300;")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(10, 0, 10, 0)
        bl.setSpacing(5)

        title_lbl = QLabel(
            "📌  INVESTIGATION BOARD" +
            (f"  //  {self.case_title.upper()}" if self.case_title else "")
        )
        title_lbl.setStyleSheet(
            "color:#00FF41;font-family:'Courier New';font-size:13px;"
            "font-weight:bold;letter-spacing:2px;"
        )

        self._btn_select   = self._tb_btn("[ SELECT ]", "#00FF41", True)
        self._btn_annotate = self._tb_btn("[ DRAW ]",   "#FF6666")

        btn_sticky  = self._tb_btn("+ NOTE",      "#FFFF44")
        btn_profile = self._tb_btn("+ PROFILE",   "#8888FF")
        btn_doc     = self._tb_btn("+ DOCUMENT",  "#AAAAAA")
        btn_map     = self._tb_btn("+ MAP",       "#44FF88")
        btn_label   = self._tb_btn("+ LABEL",     "#FF8844")
        btn_image   = self._tb_btn("+ IMAGE",     "#FF88FF")
        btn_timeline= self._tb_btn("+ TIMELINE",  "#0088FF")
        btn_group   = self._tb_btn("+ GROUP",     "#FFAA00")

        btn_imp_sub = self._tb_btn("⬇ SUBJECTS",  "#88AAFF")
        btn_imp_ev  = self._tb_btn("⬇ EVIDENCE",  "#FFAA44")
        btn_badge   = self._tb_btn("🏷 BADGE",     "#FF8888")

        btn_clear   = self._tb_btn("CLR DRAW",    "#FF4444")
        btn_zoom    = self._tb_btn("RESET ZOOM",  "#00AAFF")

        close_btn = QPushButton("✕  CLOSE  [Ctrl+Alt+S]")
        close_btn.setStyleSheet(
            "background:transparent;color:#FF3333;border:1px solid #660000;"
            "font-family:'Courier New';font-size:11px;padding:4px 10px;"
        )
        close_btn.clicked.connect(self.close)

        bl.addWidget(title_lbl)
        bl.addStretch()
        bl.addWidget(self._btn_select)
        bl.addWidget(self._btn_annotate)
        for dot_col in ("#FF0000", "#4488FF", "#FFFF00", "#00FF41"):
            d = self._color_dot(dot_col)
            bl.addWidget(d)
        bl.addWidget(self._sep())
        for btn in [btn_sticky, btn_profile, btn_doc, btn_map, btn_label, btn_image,
                    btn_timeline, btn_group]:
            bl.addWidget(btn)
        bl.addWidget(self._sep())
        for btn in [btn_imp_sub, btn_imp_ev, btn_badge]:
            bl.addWidget(btn)
        bl.addWidget(self._sep())
        bl.addWidget(btn_clear)
        bl.addWidget(btn_zoom)
        bl.addSpacing(10)
        bl.addWidget(close_btn)

        # ── scene + view ─────────────────────
        self._scene = BoardScene(case_id=self.case_id)
        self._view  = BoardView(self._scene)

        # ── canvas wrapper + minimap ──────────
        canvas = QWidget()
        canvas.setContentsMargins(0, 0, 0, 0)
        cl = QVBoxLayout(canvas)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.addWidget(self._view)
        self._minimap = MiniMapWidget(self._view, parent=canvas)
        self._minimap.move(10, 10)
        self._minimap.raise_()

        # ── hint bar ─────────────────────────
        hint = QLabel(
            "  Middle-click / Alt+Drag = Pan  │  Scroll = Zoom  │  "
            "Click pin → drag to pin = Connect  │  Right-click = Options  │  "
            "Double-click image = Load photo  │  Ctrl+Alt+S = Close"
        )
        hint.setStyleSheet(
            "background:#080808;color:#003300;font-family:'Courier New';"
            "font-size:10px;padding:4px 10px;border-top:1px solid #001a00;"
        )

        root.addWidget(bar)
        root.addWidget(canvas, stretch=1)
        root.addWidget(hint)

        # ── signals ───────────────────────────
        self._btn_select.clicked.connect(lambda: self._set_mode("select"))
        self._btn_annotate.clicked.connect(lambda: self._set_mode("annotate"))
        btn_sticky.clicked.connect(lambda: self._add_node("sticky"))
        btn_profile.clicked.connect(lambda: self._add_node("profile"))
        btn_doc.clicked.connect(lambda: self._add_node("document"))
        btn_map.clicked.connect(lambda: self._add_node("map"))
        btn_label.clicked.connect(lambda: self._add_node("label"))
        btn_image.clicked.connect(lambda: self._add_node("image"))
        btn_timeline.clicked.connect(lambda: self._add_node("timeline"))
        btn_group.clicked.connect(self._add_group)
        btn_imp_sub.clicked.connect(self._scene.import_subjects)
        btn_imp_ev.clicked.connect(self._scene.import_evidence)
        btn_badge.clicked.connect(self._assign_badge)
        btn_clear.clicked.connect(self._scene.clear_annotations)
        btn_zoom.clicked.connect(self._reset_zoom)

    # ── helpers ───────────────────────────────
    def _tb_btn(self, text, color="#00FF41", checked=False):
        btn = QPushButton(text)
        btn.setCheckable(True)
        btn.setChecked(checked)
        btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:{color};"
            f"border:1px solid {color}44;font-family:'Courier New';"
            f"font-size:11px;padding:3px 8px;border-radius:2px;}}"
            f"QPushButton:checked{{background:{color}22;border:1px solid {color};}}"
            f"QPushButton:hover{{background:{color}11;}}"
        )
        return btn

    def _color_dot(self, color):
        btn = QPushButton()
        btn.setFixedSize(20, 20)
        btn.setStyleSheet(
            f"background:{color};border-radius:10px;border:2px solid {color}88;"
        )
        btn.clicked.connect(lambda: self._scene.set_anno_color(color))
        return btn

    def _sep(self):
        lbl = QLabel("|")
        lbl.setStyleSheet("color:#003300;font-size:18px;padding:0 2px;")
        return lbl

    def _set_mode(self, mode):
        self._scene.set_mode(mode)
        self._btn_select.setChecked(mode == "select")
        self._btn_annotate.setChecked(mode == "annotate")

    def _add_node(self, node_type):
        import random
        center = self._view.mapToScene(self._view.viewport().rect().center())
        self._scene.add_node(
            node_type,
            center.x() + random.randint(-100, 100),
            center.y() + random.randint(-100, 100)
        )

    def _assign_badge(self):
        from PyQt6.QtWidgets import QMessageBox
        selected = [i for i in self._scene.selectedItems()
                    if isinstance(i, ProfileCardNode)]
        if not selected:
            QMessageBox.information(self, "Badge",
                                    "Please select a Profile Card node first.")
            return
        status, ok = QInputDialog.getItem(
            self, "Assign Status Badge", "Status:",
            BADGE_OPTIONS, 0, False
        )
        if ok:
            _apply_status_badge(selected[0], status)

    def _add_group(self):
        import random
        center = self._view.mapToScene(self._view.viewport().rect().center())
        self._scene.add_group(
            center.x() + random.randint(-80, 80),
            center.y() + random.randint(-80, 80)
        )

    def _reset_zoom(self):
        self._view.resetTransform()
        self._view._zoom = 1.0

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_minimap"):
            self._minimap.move(10, 10)

    def keyPressEvent(self, event):
        if (event.modifiers() == (Qt.KeyboardModifier.ControlModifier |
                                   Qt.KeyboardModifier.AltModifier) and
                event.key() == Qt.Key.Key_S):
            self.close()
        elif event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)
