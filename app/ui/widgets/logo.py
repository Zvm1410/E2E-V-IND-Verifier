from PyQt6.QtGui import QPixmap, QPainter, QColor, QBrush, QPolygon
from PyQt6.QtCore import QPoint


def _colors() -> list[str]:
    return [
        "#E07A5F",
        "#3D405B",
        "#81B29A",
        "#F2CC8F",
        "#2F4858",
        "#B5838D",
    ]


def party_logo_pixmap(index: int, size: int = 72) -> QPixmap:
    """Return a simple generated party-logo QPixmap for `index`.

    The logos are intentionally abstract (basic shapes + colours) so they
    don't resemble any real party. Deterministic by index.
    """
    colors = _colors()
    color = QColor(colors[index % len(colors)])

    pix = QPixmap(size, size)
    pix.fill(QColor("transparent"))

    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # background circle
    p.setBrush(QBrush(color.lighter(140)))
    p.setPen(QColor("transparent"))
    p.drawEllipse(0, 0, size, size)

    # foreground shape (cycle through a set)
    fg = QColor(colors[(index + 2) % len(colors)])
    p.setBrush(QBrush(fg))
    p.setPen(QColor("transparent"))

    shape = index % 5
    margin = int(size * 0.18)
    inner = size - 2 * margin

    if shape == 0:
        # filled square
        p.drawRect(margin, margin, inner, inner)
    elif shape == 1:
        # triangle
        pts = QPolygon([
            QPoint(size // 2, margin),
            QPoint(size - margin, size - margin),
            QPoint(margin, size - margin),
        ])
        p.drawPolygon(pts)
    elif shape == 2:
        # diamond
        pts = QPolygon([
            QPoint(size // 2, margin),
            QPoint(size - margin, size // 2),
            QPoint(size // 2, size - margin),
            QPoint(margin, size // 2),
        ])
        p.drawPolygon(pts)
    elif shape == 3:
        # circle
        p.drawEllipse(margin, margin, inner, inner)
    else:
        # two overlapping bars
        bar_h = inner // 4
        p.drawRect(margin, size // 2 - bar_h - 4, inner, bar_h)
        p.drawRect(margin, size // 2 + 4, inner, bar_h)

    p.end()
    return pix
